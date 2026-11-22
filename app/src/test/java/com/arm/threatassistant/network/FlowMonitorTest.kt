package com.arm.threatassistant.network

import org.junit.Assert.*
import org.junit.Test

class FlowMonitorTest {
    @Test fun fanoutIsDistinctBoundedAndDebounced() {
        var now = 0L
        val findings = mutableListOf<NetworkFinding>()
        val monitor = FlowMonitor(null, { now }, findings::add)
        repeat(20) { monitor.finish(monitor.open("tcp", "192.0.2.1", 443)) }
        assertTrue(findings.isEmpty())
        repeat(10) { monitor.finish(monitor.open("tcp", "192.0.2.1", 1000 + it)) }
        assertEquals(listOf(NetworkFinding.PORT_FANOUT), findings)
        now = 60_001
        repeat(10) { monitor.finish(monitor.open("tcp", "192.0.2.1", 2000 + it)) }
        assertEquals(2, findings.size)
    }
    @Test fun fanoutSeparatesHostsProtocolsAndExpiredPorts() {
        var now = 0L
        val findings = mutableListOf<NetworkFinding>()
        val m = FlowMonitor(null, { now }, findings::add)
        repeat(9) { m.open("tcp", "192.0.2.1", it + 1) }
        m.open("udp", "192.0.2.1", 10)
        m.open("tcp", "192.0.2.2", 10)
        now = 60_000
        m.open("tcp", "192.0.2.1", 10)
        assertTrue(findings.isEmpty())
    }
    @Test fun connectionRateExpiresAndDeduplicates() {
        var now = 0L
        val findings = mutableListOf<NetworkFinding>()
        val m = FlowMonitor(null, { now }, findings::add)
        repeat(99) { m.open("tcp", "192.0.2.1", 443) }
        assertTrue(findings.isEmpty())
        now = 10_000
        m.open("tcp", "192.0.2.1", 443)
        assertTrue(findings.isEmpty())
        repeat(101) { m.open("tcp", "192.0.2.1", 443) }
        assertEquals(listOf(NetworkFinding.CONNECTION_BURST), findings)
    }
    @Test fun byteAccountingSurvivesIdleAndFinishesExactlyOnce() {
        var now = 0L
        val summaries = mutableListOf<FlowSummary>()
        val m = FlowMonitor(null, { now }, onSummary = summaries::add)
        val id = m.open("tcp", "192.0.2.1", 443)
        m.transfer(id, true, 100)
        now = 120_000
        m.expire()
        m.transfer(id, false, 250)
        m.finish(id); m.finish(id); m.close()
        assertEquals(1, summaries.size)
        assertEquals(100L, summaries[0].sent)
        assertEquals(250L, summaries[0].received)
        assertEquals(120L, summaries[0].durationSeconds)
        assertEquals(0, m.activeCount())
    }
    @Test fun memoryIsBoundedUnderTenThousandFlows() {
        val m = FlowMonitor(null)
        repeat(10_000) { m.open("tcp", "192.0.${it / 256}.${it % 256}", 443) }
        assertEquals(512, m.activeCount())
        m.close()
        assertEquals(10_000L, m.completed)
    }
    @Test fun udpRateUsesElapsedTimeNotStreamReadCount() {
        var now = 0L
        val findings = mutableListOf<NetworkFinding>()
        val m = FlowMonitor(null, { now }, findings::add)
        val tcp = m.open("tcp", "192.0.2.1", 443)
        repeat(2000) { m.transfer(tcp, true, 1) }
        val udp = m.open("udp", "192.0.2.1", 443)
        repeat(1000) { m.transfer(udp, true, 1, true) }
        assertTrue(findings.isEmpty())
        now = 1000
        m.transfer(udp, false, 1, true)
        assertEquals(listOf(NetworkFinding.UDP_BURST), findings)
    }
}
