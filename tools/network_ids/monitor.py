"""Passive Ethernet/IPv4 TCP and UDP flow monitor. Emit JSON Lines."""
import argparse
from collections import Counter, OrderedDict
from contextlib import ExitStack, closing
from dataclasses import dataclass
from itertools import islice
import json
from pathlib import Path
import socket
import struct
import sys
import time

import detect


MAGIC = {
    bytes.fromhex("d4c3b2a1"): ("<", 1e6), bytes.fromhex("a1b2c3d4"): (">", 1e6),
    bytes.fromhex("4d3cb2a1"): ("<", 1e9), bytes.fromhex("a1b23c4d"): (">", 1e9),
}
SERVICES = {("tcp", 22): "ssh", ("tcp", 80): "http", ("tcp", 443): "http_443",
            ("udp", 53): "domain_u", ("tcp", 53): "domain", ("udp", 123): "ntp_u"}
CHECKS = {
    "normal": "Compare the endpoints and ports with expected applications.",
    "dos": "Compare traffic volume with interface counters and service availability.",
    "probe": "Review firewall logs for connections across destinations or ports.",
    "r2l": "Check authentication logs for the service and capture interval.",
    "u2r": "Check host audit logs for privilege changes during the capture interval.",
}


# Linux UAPI: include/uapi/linux/if_packet.h and include/linux/socket.h.
SOL_PACKET = 263
PACKET_AUXDATA = 8
AUXDATA = struct.Struct("=IIIHHHH")
TP_STATUS_VLAN_VALID = 1 << 4
TP_STATUS_VLAN_TPID_VALID = 1 << 6


class TrafficEvidence:
    """Bounded observations, not learned attack labels or automatic blocking.

    A destination-port fanout is useful evidence even when unavailable NSL-KDD
    features make the model uncertain. Legitimate scanners can trigger it too.
    """
    def __init__(self, window=60.0, port_threshold=10, max_peers=512):
        self.window = window
        self.port_threshold = port_threshold
        self.max_peers = max_peers
        self.peers = OrderedDict()
        self.watermark = 0.0

    def observe(self, flow):
        self.watermark = max(self.watermark, flow.last)
        cutoff = self.watermark - self.window
        key = (flow.vlan_ids, flow.protocol, flow.source[0], flow.destination[0])
        ports = self.peers.pop(key, {})
        ports = {port: when for port, when in ports.items() if when >= cutoff}
        if flow.last >= cutoff:
            ports[flow.destination[1]] = max(ports.get(flow.destination[1], 0), flow.last)
        # Track only enough distinct ports to support the observation. This
        # bounds memory even under adversarial captures with 65,536 ports.
        if len(ports) > self.port_threshold:
            ports = dict(sorted(ports.items(), key=lambda item: item[1])[-self.port_threshold:])
        self.peers[key] = ports
        while len(self.peers) > self.max_peers:
            self.peers.popitem(last=False)
        findings = []
        if flow.last >= cutoff and len(ports) >= self.port_threshold:
            findings.append({
                "kind": "destination_port_fanout",
                "explanation": f"Flows from one apparent source were active on at least {self.port_threshold} ports "
                               f"on one device within {self.window:g} seconds. This can be a port scan "
                               "or an authorized discovery tool.",
                "action": "Check whether an approved scanner was running. If unexpected, review "
                          "the source device and restrict unneeded services in the firewall.",
            })
        duration = flow.last - flow.first
        if duration >= 1.0 and flow.packets / duration >= 1000:
            findings.append({
                "kind": "high_packet_rate",
                "explanation": "This connection averaged at least 1,000 packets per second. "
                               "A large transfer can be legitimate; a flood is another possibility.",
                "action": "Compare with expected transfers and device responsiveness before "
                          "applying rate limits or changing firewall rules.",
            })
        return findings


def pcap_records(stream):
    header = stream.read(24)
    if len(header) != 24 or header[:4] not in MAGIC:
        raise ValueError("expected classic PCAP with an Ethernet link header")
    order, scale = MAGIC[header[:4]]
    major, minor, _, _, snaplen, link = struct.unpack(order + "HHIIII", header[4:])
    if (major, minor) != (2, 4) or link & 0xffff != 1:
        raise ValueError("expected Ethernet PCAP version 2.4")
    if snaplen == 0 or link & 0x0bff0000:
        raise ValueError("invalid PCAP snapshot length or reserved link flags")
    while True:
        record = stream.read(16)
        if not record:
            return
        if len(record) != 16:
            raise ValueError("incomplete PCAP record header")
        sec, fraction, size, _original = struct.unpack(order + "IIII", record)
        if fraction >= scale or size > min(snaplen, 262144):
            raise ValueError("invalid or oversized PCAP record")
        data = stream.read(size)
        if len(data) != size:
            raise ValueError("incomplete PCAP record")
        yield sec + fraction / scale, data


def restore_vlan(frame, ancillary):
    # A Linux NIC or driver may move the outer tag from frame bytes to auxdata.
    for level, kind, value in ancillary:
        if level != SOL_PACKET or kind != PACKET_AUXDATA:
            continue
        if len(value) < AUXDATA.size or len(frame) < 14:
            return b""
        status, _, _, _, _, tci, tpid = AUXDATA.unpack_from(value)
        if status & TP_STATUS_VLAN_VALID:
            if not status & TP_STATUS_VLAN_TPID_VALID:
                tpid = 0x8100
            return frame[:12] + struct.pack("!HH", tpid, tci) + frame[12:]
    return frame


def live_records(interface, seconds):
    if not hasattr(socket, "AF_PACKET"):
        raise ValueError("live capture requires Linux AF_PACKET")
    # Delay reception until bind selects the requested interface (Linux packet(7)).
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0) as sock:
        sock.setsockopt(SOL_PACKET, PACKET_AUXDATA, 1)
        sock.bind((interface, 3))
        control_size = socket.CMSG_SPACE(AUXDATA.size)
        deadline = time.monotonic() + seconds
        while (remaining := deadline - time.monotonic()) > 0:
            sock.settimeout(remaining)
            try:
                data, ancillary, flags, _ = sock.recvmsg(65535 + 64, control_size)
            except socket.timeout:
                return
            if flags & (socket.MSG_CTRUNC | socket.MSG_TRUNC):
                yield time.time(), b""
            else:
                yield time.time(), restore_vlan(data, ancillary)


def decode(data):
    """Lengths describe observed transport payload, including TCP retransmissions."""
    start = 14
    if len(data) < start:
        return
    kind = int.from_bytes(data[12:14], "big")
    vlan_ids = []
    for _ in range(2):
        if kind not in (0x8100, 0x88a8) or len(data) < start + 4:
            break
        vlan_ids.append(int.from_bytes(data[start:start + 2], 'big') & 0xfff)
        kind = int.from_bytes(data[start + 2:start + 4], "big")
        start += 4
    ip = memoryview(data)[start:]
    if kind != 0x0800 or len(ip) < 20 or ip[0] >> 4 != 4:
        return
    ihl = (ip[0] & 15) * 4
    length = int.from_bytes(ip[2:4], "big")
    if not 20 <= ihl <= length <= len(ip) or int.from_bytes(ip[6:8], "big") & 0x3fff:
        return
    segment = ip[ihl:length]
    flags = 0
    if ip[9] == 6 and len(segment) >= 20:
        proto = "tcp"
        header = (segment[12] >> 4) * 4
        if not 20 <= header <= len(segment):
            return
        flags = segment[13]
    elif ip[9] == 17 and len(segment) >= 8:
        proto, header = "udp", 8
        if int.from_bytes(segment[4:6], "big") != len(segment):
            return
    else:
        return
    sport, dport = struct.unpack_from("!HH", segment)
    return (proto, (socket.inet_ntoa(ip[12:16]), sport),
            (socket.inet_ntoa(ip[16:20]), dport), len(segment) - header, flags, tuple(vlan_ids))


@dataclass
class Flow:
    protocol: str
    source: tuple
    destination: tuple
    first: float
    last: float
    packets: int = 0
    src_bytes: int = 0
    dst_bytes: int = 0
    urgent: int = 0
    fin_forward: bool = False
    fin_reverse: bool = False
    vlan_ids: tuple = ()

    def observe(self, timestamp, source, size, flags):
        self.first = min(timestamp, self.first)
        self.last = max(timestamp, self.last)
        self.packets += 1
        self.urgent += bool(flags & 32)
        if source == self.source:
            self.src_bytes += size
            self.fin_forward |= bool(flags & 1)
        else:
            self.dst_bytes += size
            self.fin_reverse |= bool(flags & 1)


def flows(records, limit, idle, stats):
    active = OrderedDict()
    watermark = 0
    for timestamp, frame in records:
        stats["frames"] += 1
        watermark = max(timestamp, watermark)
        while active and watermark - next(iter(active.values()))[1] >= idle:
            yield active.popitem(last=False)[1][0], "idle"
        decoded = decode(frame)
        if decoded is None:
            stats["skipped_frames"] += 1
            continue
        proto, src, dst, size, flags, vlan_ids = decoded
        key = (vlan_ids, proto, *sorted((src, dst)))
        entry = active.pop(key, None)
        if entry and flags & 2 and entry[0].fin_forward and entry[0].fin_reverse:
            yield entry[0], "tuple_reused"
            entry = None
        if entry is None:
            if len(active) >= limit:
                yield active.popitem(last=False)[1][0], "capacity"
            origin, peer = (dst, src) if flags & 18 == 18 else (src, dst)
            flow = Flow(proto, origin, peer, timestamp, timestamp, vlan_ids=vlan_ids)
        else:
            flow = entry[0]
        flow.observe(timestamp, src, size, flags)
        if flags & 4:
            yield flow, "reset"
        else:
            active[key] = flow, watermark
    for flow, _ in active.values():
        yield flow, "capture_end"


def report(flow, reason, model, observations=None):
    values = dict(duration=int(flow.last - flow.first), protocol_type=flow.protocol,
                  src_bytes=flow.src_bytes, dst_bytes=flow.dst_bytes,
                  land=int(flow.source == flow.destination), urgent=flow.urgent)
    service = SERVICES.get((flow.protocol, flow.destination[1]))
    if flow.fin_forward and flow.fin_reverse:
        values["flag"] = "SF"
    if service:
        values["service"] = service
    row = [values.get(name, 0) for name in model["base_features"]]
    vector = detect.featurize(row, model)
    for idx, name in enumerate(model["feature_names"]):
        if name.split("=")[0] not in values:
            vector[idx] = 0.0
    predicted, scores, hidden = detect.forward(vector, model)
    label = model["classes"][predicted]
    return dict(type="flow", vlan_ids=flow.vlan_ids, source=flow.source, destination=flow.destination,
                first=flow.first, last=flow.last, packets=flow.packets, end=reason,
                model_inputs=values, imputed=[n for n in model["base_features"] if n not in values],
                experimental_model_class=label, uncalibrated_score=float(scores[predicted]),
                top_contributions=[(n, c) for n, _, c in
                                   detect.top_features(vector, hidden, model, predicted) if c],
                observations=observations or [],
                explanation=f"Observed {flow.packets} packets in a {flow.protocol.upper()} connection. "
                            "The model estimate uses incomplete features and cannot confirm an intrusion.",
                suggested_check=CHECKS[label],
                remediation=[CHECKS[label], "Confirm the activity with the device owner before changing access.",
                             "Keep devices updated and disable services you do not use."])


def demo_records(scan=False):
    """Synthetic UDP frames for the offline examples."""
    examples = [
            ("192.0.2.10", "192.0.2.53", 50000, 53, 24),
            ("192.0.2.53", "192.0.2.10", 53, 50000, 48)]
    if scan:
        examples = [("192.0.2.10", "192.0.2.53", 50000 + port, port, 0)
                    for port in range(8000, 8012)]
    for idx, (src, dst, sport, dport, size) in enumerate(examples):
        udp = struct.pack("!HHHH", sport, dport, size + 8, 0) + bytes(size)
        ip = struct.pack("!BBHHHBBH4s4s", 69, 0, 20 + len(udp), 1, 0, 64, 17,
                         0, socket.inet_aton(src), socket.inet_aton(dst))
        yield 1.0 + 0.125 * idx, bytes(12) + b"\x08\x00" + ip + udp


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--demo", action="store_true")
    source.add_argument("--demo-scan", action="store_true", help="synthetic port fanout; sends no packets")
    source.add_argument("--pcap", type=Path)
    source.add_argument("--interface", help="Linux Ethernet interface")
    parser.add_argument("--model", type=Path, default=Path(__file__).parent / "out/nids_model.json")
    parser.add_argument("--max-packets", type=int, default=10000)
    parser.add_argument("--max-flows", type=int, default=512, help="simultaneously active flows")
    parser.add_argument("--seconds", type=int, default=30, help="live capture deadline")
    parser.add_argument("--idle", type=int, default=30, help="idle timeout in capture seconds")
    args = parser.parse_args(argv)
    if min(args.max_packets, args.max_flows, args.seconds, args.idle) < 1:
        parser.error("all limits must be positive")
    stats = Counter(frames=0, skipped_frames=0, flows=0)
    try:
        model = detect.load_model(args.model)
        with ExitStack() as stack:
            if args.pcap:
                records = pcap_records(stack.enter_context(args.pcap.open("rb")))
            elif args.interface:
                records = live_records(args.interface, args.seconds)
            else:
                records = demo_records(scan=args.demo_scan)
            stack.enter_context(closing(records))
            evidence = TrafficEvidence()
            for flow, reason in flows(islice(records, args.max_packets), args.max_flows,
                                      args.idle, stats):
                print(json.dumps(report(flow, reason, model, evidence.observe(flow))), flush=True)
                stats["flows"] += 1
        print(json.dumps(dict(type="summary", **stats)))
        return 0
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
