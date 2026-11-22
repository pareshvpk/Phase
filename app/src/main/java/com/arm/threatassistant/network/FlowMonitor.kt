package com.arm.threatassistant.network

import java.util.LinkedHashMap

enum class NetworkFinding { PORT_FANOUT, CONNECTION_BURST, UDP_BURST }
data class FlowSummary(val protocol: String, val host: String, val port: Int,
    val sent: Long, val received: Long, val durationSeconds: Long, val estimate: NetworkModel.Estimate?)

/** Payload-free, bounded metadata. Callers use a monotonic clock. */
class FlowMonitor(
    private val model: NetworkModel?,
    private val clock: () -> Long = { System.nanoTime() / 1_000_000 },
    private val onFinding: (NetworkFinding) -> Unit = {},
    private val onSummary: (FlowSummary) -> Unit = {}
) {
    private data class Flow(val protocol: String, val host: String, val port: Int, val start: Long,
        var last: Long, var sent: Long = 0, var received: Long = 0,
        var datagrams: Int = 0, var window: Long = start)
    private val flows = LinkedHashMap<Long, Flow>(64, .75f, true)
    private val ports = LinkedHashMap<String, LinkedHashMap<Int, Long>>(64, .75f, true)
    private val cooldown = mutableMapOf<NetworkFinding, Long>()
    private val starts = ArrayDeque<Long>()
    private var nextId = 0L
    var completed = 0L; private set
    var sentBytes = 0L; private set
    var receivedBytes = 0L; private set
    @Synchronized fun activeCount() = flows.size

    @Synchronized fun open(protocol: String, host: String, port: Int): Long {
        val now = clock()
        expire(now)
        if (flows.size >= 512) finish(flows.keys.first())
        val id = ++nextId
        flows[id] = Flow(protocol, host, port, now, now)
        val key = "$protocol/$host"
        val history = ports.getOrPut(key) { LinkedHashMap() }
        history.entries.removeAll { now - it.value >= 60_000 }
        history[port] = now
        if (history.size >= 10) emit(NetworkFinding.PORT_FANOUT, now)
        while (history.size > 10) history.remove(history.minBy { it.value }.key)
        while (ports.size > 512) ports.remove(ports.keys.first())
        while (starts.isNotEmpty() && now - starts.first() >= 10_000) starts.removeFirst()
        starts.addLast(now)
        if (starts.size >= 100) emit(NetworkFinding.CONNECTION_BURST, now)
        while (starts.size > 100) starts.removeFirst()
        return id
    }

    @Synchronized fun transfer(id: Long, outbound: Boolean, size: Int, datagram: Boolean = false) {
        require(size >= 0)
        val flow = flows[id] ?: return
        val now = clock()
        flow.last = now
        if (outbound) { flow.sent += size; sentBytes += size } else { flow.received += size; receivedBytes += size }
        if (datagram) {
            val elapsed = now - flow.window
            if (elapsed >= 1_000) {
                if (flow.datagrams * 1_000L >= 1_000L * elapsed) emit(NetworkFinding.UDP_BURST, now)
                flow.window = now
                flow.datagrams = 0
            }
            flow.datagrams++
        }
    }

    @Synchronized fun finish(id: Long) {
        val f = flows.remove(id) ?: return
        val duration = ((f.last - f.start) / 1_000).coerceAtLeast(0)
        val values = mutableMapOf<String, Any>("protocol_type" to f.protocol, "duration" to duration,
            "src_bytes" to f.sent, "dst_bytes" to f.received)
        val service = when (f.protocol to f.port) {
            "tcp" to 22 -> "ssh"; "tcp" to 80 -> "http"; "tcp" to 443 -> "http_443"
            "tcp" to 53 -> "domain"; "udp" to 53 -> "domain_u"; "udp" to 123 -> "ntp_u"
            else -> null
        }
        if (service != null) values["service"] = service
        // Stream forwarding cannot observe TCP flags, urgent fields or login behaviour.
        val estimate = model?.predict(values)
        completed++
        onSummary(FlowSummary(f.protocol, f.host, f.port, f.sent, f.received, duration, estimate))
    }

    @Synchronized fun expire(now: Long = clock()) {
        // Transport owners expire their sockets. Never discard the ID of a live,
        // temporarily idle connection: later bytes must still be accounted for.
        ports.entries.removeAll { (_, history) -> history.values.all { now - it >= 60_000 } }
    }
    @Synchronized fun close() { flows.keys.toList().forEach(::finish); ports.clear(); starts.clear() }
    private fun emit(finding: NetworkFinding, now: Long) {
        val previous = cooldown[finding]
        if (previous == null || now - previous >= 60_000) {
            cooldown[finding] = now
            onFinding(finding)
        }
    }
}
