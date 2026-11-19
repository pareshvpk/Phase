package com.arm.threatassistant.llm

import org.junit.Assert.assertEquals
import org.junit.Test

class CpuCoresTest {

    @Test
    fun countsCoresAboveTheSlowestCluster() {
        val vivo = listOf(1804800L, 1804800, 1804800, 1804800, 2208000, 2208000, 2208000, 2208000)
        assertEquals(4, CpuCores.bigCoreCount(vivo, 8))
    }

    @Test
    fun threeClustersCountMiddleAndPrime() {
        val freqs = listOf(1800000L, 1800000, 1800000, 2400000, 2400000, 2400000, 2400000, 3200000)
        assertEquals(5, CpuCores.bigCoreCount(freqs, 8))
    }

    @Test
    fun singleClusterUsesAllCoresClamped() {
        assertEquals(6, CpuCores.bigCoreCount(List(8) { 2000000L }, 8))
        assertEquals(4, CpuCores.bigCoreCount(List(4) { 2000000L }, 4))
    }

    @Test
    fun unreadableFallsBackToHalf() {
        assertEquals(4, CpuCores.bigCoreCount(emptyList(), 8))
        assertEquals(2, CpuCores.bigCoreCount(emptyList(), 2))
    }
}
