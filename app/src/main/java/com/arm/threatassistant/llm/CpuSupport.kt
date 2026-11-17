package com.arm.threatassistant.llm

import android.content.Context
import java.io.File

/**
 * Whether the on-device Llama model can run on this CPU.
 *
 * The stock `executorch-android` AAR uses Armv8.1 LSE atomics and crashes with
 * SIGILL on Armv8.0 cores. Llama is supported only when every core listed in
 * `/proc/cpuinfo` advertises the `atomics` feature.
 *
 * [isSupported(cpuinfo)] is pure so it can be unit-tested with sample cpuinfo
 * text; nothing in ExecuTorch is touched before this check.
 */
object CpuSupport {

    private const val CPUINFO_PATH = "/proc/cpuinfo"
    private const val ATOMICS_FEATURE = "atomics"

    /** True only when every block that has a `Features` line contains `atomics`. */
    fun isSupported(cpuinfo: String): Boolean {
        val text = cpuinfo.replace("\r\n", "\n")
        val blocks = text.split("\n\n")
        if (blocks.isEmpty()) return false
        var foundFeatures = false
        for (block in blocks) {
            val featuresLine = block.lines().firstOrNull { line ->
                line.trimStart().startsWith("Features")
            }
            if (featuresLine == null) continue
            foundFeatures = true
            val features = featuresLine.substringAfter("Features").trim().removePrefix(":").trim().split(Regex("\\s+"))
            if (!features.contains(ATOMICS_FEATURE)) return false
        }
        return foundFeatures
    }

    /** Reads `/proc/cpuinfo` on the device and answers whether Llama is supported. */
    fun isSupported(context: Context): Boolean =
        runCatching { File(CPUINFO_PATH).readText() }
            .map { isSupported(it) }
            .getOrDefault(false)
}
