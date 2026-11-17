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

    /** True only when every core block has a `Features` line containing `atomics`. */
    fun isSupported(cpuinfo: String): Boolean {
        val blocks = cpuinfo.split("\n\n")
        if (blocks.isEmpty()) return false
        var anyCore = false
        for (block in blocks) {
            val featuresLine = block.lines().firstOrNull { line ->
                line.trimStart().startsWith("Features")
            } ?: return false
            val features = featuresLine.substringAfter("Features").trim().removePrefix(":").trim().split(Regex("\\s+"))
            if (!features.contains(ATOMICS_FEATURE)) return false
            anyCore = true
        }
        return anyCore
    }

    /** Reads `/proc/cpuinfo` on the device and answers whether Llama is supported. */
    fun isSupported(context: Context): Boolean =
        runCatching { File(CPUINFO_PATH).readText() }
            .map { isSupported(it) }
            .getOrDefault(false)
}
