import io
import json
import struct
import unittest
from collections import Counter
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import monitor


def pcap(frames, order="<", nano=False):
    magic = 0xa1b23c4d if nano else 0xa1b2c3d4
    data = struct.pack(order + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1)
    for ts, frame in frames:
        fraction = int((ts % 1) * (1e9 if nano else 1e6))
        data += struct.pack(order + "IIII", int(ts), fraction, len(frame), len(frame)) + frame
    return data


def tcp(frame, flags):
    data = bytearray(frame[:38] + bytes(16))
    struct.pack_into("!H", data, 16, 40)
    data[23] = 6
    data[46:48] = bytes([80, flags])
    return bytes(data)


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.frames = list(monitor.demo_records())
        self.first, self.reply = [frame for _, frame in self.frames]

    def aggregate(self, records, limit=2):
        self.stats = Counter()
        return list(monitor.flows(records, limit, 5, self.stats))

    def test_pcap_formats(self):
        for order in ("<", ">"):
            for nano in (True, False):
                self.assertEqual(self.frames, list(monitor.pcap_records(
                    io.BytesIO(pcap(self.frames, order, nano)))))

    def test_invalid_records(self):
        good = pcap(self.frames)
        for blob in (b"", good[:-1], good[:25], good[:32] + b"\xff" * 8):
            with self.assertRaises(ValueError):
                list(monitor.pcap_records(io.BytesIO(blob)))

    def test_pcap_header_and_legacy_original_length(self):
        blob = bytearray(pcap(self.frames))
        struct.pack_into("<I", blob, 36, 0)
        self.assertEqual(self.frames, list(monitor.pcap_records(io.BytesIO(blob))))
        for offset, value in ((16, 0), (20, 0x08000001)):
            bad = blob.copy()
            struct.pack_into("<I", bad, offset, value)
            with self.assertRaises(ValueError):
                list(monitor.pcap_records(io.BytesIO(bad)))

    def test_invalid_header_lengths(self):
        for base, offset, value in ((self.first, 14, 79), (self.first, 17, 15),
                                    (tcp(self.first, 16), 46, 224),
                                    (self.first, 39, 7)):
            bad = bytearray(base)
            bad[offset] = value
            self.assertIsNone(monitor.decode(bad))

    def test_direction_bytes_and_time(self):
        [(flow, reason)] = self.aggregate(self.frames)
        self.assertEqual((2, 24, 48, .125, "capture_end"),
                         (flow.packets, flow.src_bytes, flow.dst_bytes,
                          flow.last - flow.first, reason))

    def test_vlan_and_invalid_frames(self):
        tagged = self.first[:12] + bytes.fromhex("81000001") + self.first[12:]
        self.assertEqual(monitor.decode(self.first)[:-1], monitor.decode(tagged)[:-1])
        self.assertEqual((1,), monitor.decode(tagged)[-1])
        fragmented = self.first[:20] + b"\x20" + self.first[21:]
        self.aggregate([(1, f) for f in (fragmented, self.first[:-1], b"", tagged)])
        self.assertEqual(3, self.stats["skipped_frames"])

    def test_vlan_flows_and_fanout_are_isolated(self):
        def tag(frame, outer, inner):
            return frame[:12] + struct.pack("!HHHH", 0x88a8, outer, 0x8100, inner) + frame[12:]
        records = [(1, tag(self.first, 10, 20)), (2, tag(self.reply, 0x600a, 20)),
                   (3, tag(self.first, 11, 20)), (4, tag(self.first, 10, 21))]
        groups = [flow for flow, _ in self.aggregate(records, limit=4)]
        self.assertEqual([(10, 20), (11, 20), (10, 21)], [f.vlan_ids for f in groups])
        self.assertEqual([2, 1, 1], [f.packets for f in groups])
        evidence = monitor.TrafficEvidence(port_threshold=2)
        for port, flow in enumerate(groups, 80):
            flow.destination = (flow.destination[0], port)
            self.assertEqual([], evidence.observe(flow))

    def test_linux_offloaded_vlan(self):
        for status, tpid, expected in ((0x10, 0, 0x8100), (0x50, 0x88a8, 0x88a8)):
            aux = struct.pack("=IIIHHHH", status, 0, 0, 0, 0, 27, tpid)
            frame = monitor.restore_vlan(self.first, [(263, 8, aux)])
            self.assertEqual(struct.pack("!HH", expected, 27), frame[12:16])
            self.assertEqual((27,), monitor.decode(frame)[-1])
        self.assertEqual(self.first, monitor.restore_vlan(self.first, [(263, 8, bytes(20))]))

    def test_capacity_idle_and_reset(self):
        changed = bytearray(self.first)
        changed[29] = 20
        ends = [reason for _, reason in self.aggregate(
            [(1, self.first), (2, changed), (8, tcp(self.first, 4))], 1)]
        self.assertEqual(["capacity", "idle", "reset"], ends)

    def test_tcp_synack_direction(self):
        [(flow, _)] = self.aggregate([(2, tcp(self.reply, 18)), (2, tcp(self.first, 16))])
        self.assertEqual(("192.0.2.10", 50000), flow.source)
        self.assertEqual(2, flow.packets)

    def test_close_includes_final_ack_then_reused_tuple(self):
        packets = [(1, tcp(self.first, 17)), (2, tcp(self.reply, 17)),
                   (3, tcp(self.first, 16)), (4, tcp(self.first, 2))]
        [(closed, reason), (opened, _)] = self.aggregate(packets)
        self.assertEqual((3, "tuple_reused", 1), (closed.packets, reason, opened.packets))
        self.assertTrue(closed.fin_forward and closed.fin_reverse)

    def test_offline_cli_limit_and_imputation(self):
        with TemporaryDirectory() as folder:
            path = Path(folder) / "fixture.pcap"
            path.write_bytes(pcap(self.frames))
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(0, monitor.main(["--pcap", str(path), "--max-packets", "1"]))
        flow, summary = map(json.loads, output.getvalue().splitlines())
        self.assertEqual(dict(type="summary", frames=1, flows=1, skipped_frames=0), summary)
        self.assertEqual(0, flow["model_inputs"]["dst_bytes"])
        self.assertIn("root_shell", flow["imputed"])
        self.assertIn(flow["experimental_model_class"], monitor.CHECKS)
        self.assertTrue(flow["suggested_check"])

    def test_live_receive_restores_vlan_and_counts_truncation(self):
        # Simulate Linux recvmsg on a host with no packet-socket privileges.
        tci = 45
        control = [(monitor.SOL_PACKET, monitor.PACKET_AUXDATA,
                    struct.pack("=IIIHHHH", 0x50, 0, 0, 0, 0, tci, 0x8100))]
        with (patch.object(monitor.socket, "AF_PACKET", 17, create=True),
              patch.object(monitor.socket, "CMSG_SPACE", return_value=64, create=True),
              patch.object(monitor.socket, "MSG_CTRUNC", 8, create=True),
              patch.object(monitor.socket, "MSG_TRUNC", 32, create=True),
              patch.object(monitor.socket, "socket") as factory):
            sock = factory.return_value.__enter__.return_value
            sock.recvmsg.side_effect = [
                (self.first, control, 0, ()), (self.reply, control, 8, ()),
                (self.reply, control, 32, ()), (self.reply, control, 0, ()),
                TimeoutError,
            ]
            [(flow, reason)] = self.aggregate(monitor.live_records("eth0", 5))
            sock.setsockopt.assert_called_once_with(monitor.SOL_PACKET, monitor.PACKET_AUXDATA, 1)
            self.assertEqual(5, sock.recvmsg.call_count)
            self.assertEqual("capture_end", reason)
            self.assertEqual((tci,), flow.vlan_ids)
            self.assertEqual((2, 24, 48), (flow.packets, flow.src_bytes, flow.dst_bytes))
            self.assertEqual(dict(frames=4, skipped_frames=2), dict(self.stats))
            factory.return_value.__exit__.assert_called_once()

    def test_idle_live_deadline(self):
        with (patch.object(monitor.socket, "AF_PACKET", 17, create=True),
              patch.object(monitor.socket, "CMSG_SPACE", return_value=64, create=True),
              patch.object(monitor.socket, "socket") as factory):
            sock = factory.return_value.__enter__.return_value
            sock.recvmsg.side_effect = TimeoutError
            self.assertEqual([], list(monitor.live_records("eth0", 5)))
            factory.assert_called_once_with(17, monitor.socket.SOCK_RAW, 0)
            sock.bind.assert_called_once_with(("eth0", 3))
            self.assertLessEqual(sock.settimeout.call_args.args[0], 5)

    def test_synthetic_scan_is_observed_without_network_access(self):
        output = io.StringIO()
        with patch.object(monitor.socket, "socket") as network, redirect_stdout(output):
            self.assertEqual(0, monitor.main(["--demo-scan"]))
            network.assert_not_called()
        records = list(map(json.loads, output.getvalue().splitlines()))
        self.assertEqual(12, records[-1]["flows"])
        findings = [finding for flow in records[:-1] for finding in flow["observations"]]
        self.assertEqual(3, len(findings))
        self.assertTrue(all(f["kind"] == "destination_port_fanout" for f in findings))

    def test_normal_flow_has_no_behaviour_observation(self):
        evidence = monitor.TrafficEvidence()
        [(flow, _)] = self.aggregate(self.frames)
        self.assertEqual([], evidence.observe(flow))

    def test_fanout_expires_and_history_stays_bounded(self):
        evidence = monitor.TrafficEvidence(window=5, port_threshold=3, max_peers=2)
        def flow(ip, port, when):
            return monitor.Flow("tcp", (ip, 60000), ("192.0.2.53", port), when, when)
        for port in (1, 2):
            self.assertEqual([], evidence.observe(flow("192.0.2.10", port, 1)))
        self.assertTrue(evidence.observe(flow("192.0.2.10", 3, 2)))
        self.assertEqual([], evidence.observe(flow("192.0.2.10", 4, -10)))
        self.assertEqual([], evidence.observe(flow("192.0.2.10", 4, 10)))
        for index in range(30):
            evidence.observe(flow("192.0.2." + str(index), 5, 11))
        self.assertEqual(2, len(evidence.peers))

    def test_high_rate_requires_measured_duration(self):
        evidence = monitor.TrafficEvidence()
        flow = monitor.Flow("tcp", ("192.0.2.1", 50000), ("192.0.2.2", 443), 1, 1, packets=5000)
        self.assertEqual([], evidence.observe(flow))
        flow.last = 3
        self.assertEqual("high_packet_rate", evidence.observe(flow)[0]["kind"])


if __name__ == "__main__":
    unittest.main()
