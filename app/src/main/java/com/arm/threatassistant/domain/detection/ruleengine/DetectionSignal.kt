package com.arm.threatassistant.domain.detection.ruleengine

/**
 * A single structured detection signal produced by [FastRuleEngine].
 *
 * A signal records that one specific rule matched one specific span of input
 * text. Multiple signals may be produced for one message; the engine never
 * stops at the first match.
 *
 * Properties:
 * - [signalId] — unique identifier within a single analysis run.
 * - [category] — the [RuleCategory] this signal belongs to.
 * - [ruleId] — the stable identifier of the rule that matched.
 * - [description] — human-readable explanation of what was detected.
 * - [matchedText] — the excerpt of input text that triggered the match
 *   (safe to display; original input is preserved elsewhere).
 * - [severity] — how strongly this signal indicates a potential scam.
 * - [detectorId] — stable identifier of the detector that produced it.
 * - [detectorVersion] — version of the detector code.
 */
data class DetectionSignal(
    val signalId: String,
    val category: RuleCategory,
    val ruleId: String,
    val description: String,
    val matchedText: String,
    val severity: DetectionSeverity,
    val detectorId: String,
    val detectorVersion: String
)
