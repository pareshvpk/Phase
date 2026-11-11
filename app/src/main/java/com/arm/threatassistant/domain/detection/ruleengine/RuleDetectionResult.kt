package com.arm.threatassistant.domain.detection.ruleengine

/**
 * Aggregated output of [FastRuleEngine].
 *
 * Contains every detected [DetectionSignal] for an input. The result does NOT
 * contain a security verdict; verdict determination is the responsibility of
 * the RiskPolicyEngine.
 *
 * Properties:
 * - [signals] — all detected signals, ordered by rule category then rule id.
 * - [signalCount] — total number of detected signals.
 * - [categoriesDetected] — distinct categories that produced at least one signal.
 * - [detectorId] — identifier of the detector that produced this result.
 * - [detectorVersion] — version of the detector code.
 */
data class RuleDetectionResult(
    val signals: List<DetectionSignal>,
    val detectorId: String,
    val detectorVersion: String
) {
    val signalCount: Int get() = signals.size

    val categoriesDetected: Set<RuleCategory> get() = signals.map { it.category }.toSet()

    fun hasSignals(): Boolean = signals.isNotEmpty()
}
