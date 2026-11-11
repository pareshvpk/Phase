package com.arm.threatassistant.domain.model

/**
 * Outcome of an analysis run.
 *
 * [verdict] is nullable because Phase 1 performs a placeholder action and does
 * not produce a real threat verdict. When the detection engine is implemented,
 * [verdict] will be populated from [ThreatVerdict].
 */
data class AnalysisResult(
    val input: AnalysisInput,
    val status: AnalysisStatus,
    val verdict: ThreatVerdict?,
    val message: String?,
    val timestampMillis: Long = System.currentTimeMillis()
)
