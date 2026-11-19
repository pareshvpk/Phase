package com.arm.threatassistant.llm

import java.io.File

/** Counts the phone's big (performance) CPU cores from cpufreq max frequencies. */
object CpuCores {

    /** Fallback when cpufreq is unreadable: half the cores, at least 2, at most 4. */
    fun bigCoreCount(): Int {
        val freqs = (0 until Runtime.getRuntime().availableProcessors()).mapNotNull { cpu ->
            runCatching {
                File("/sys/devices/system/cpu/cpu$cpu/cpufreq/cpuinfo_max_freq").readText().trim().toLong()
            }.getOrNull()
        }
        return bigCoreCount(freqs, Runtime.getRuntime().availableProcessors())
    }

    /**
     * Cores whose max frequency is above the slowest cluster's. Phones with one
     * cluster use all cores. Result is clamped to 2..6 threads.
     */
    internal fun bigCoreCount(maxFreqsKhz: List<Long>, available: Int): Int {
        if (maxFreqsKhz.isEmpty()) return (available / 2).coerceIn(2, 4)
        val slowest = maxFreqsKhz.min()
        val big = maxFreqsKhz.count { it > slowest }
        val count = if (big == 0) maxFreqsKhz.size else big
        return count.coerceIn(2, 6)
    }
}
