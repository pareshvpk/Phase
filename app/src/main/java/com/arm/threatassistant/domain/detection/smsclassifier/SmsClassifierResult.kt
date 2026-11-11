package com.arm.threatassistant.domain.detection.smsclassifier

/**
 * Result of a single [SmsSpecialistClassifier] inference run.
 *
 * This is an evidence-producing result only. It does NOT determine the final
 * threat verdict; that remains with the future RiskPolicyEngine.
 *
 * Properties:
 * - [status] — whether inference succeeded, why it did not, or whether input
 *   was unsupported.
 * - [predictedLabel] — "SAFE" or "THREAT" when [status] is [AVAILABLE]; null
 *   otherwise.
 * - [threatScore] — calibrated or uncalibrated probability in [0.0, 1.0] when
 *   [status] is [AVAILABLE]; null otherwise. Higher means more threat-like.
 * - [isCalibrated] — whether [threatScore] has been calibrated against held-out
 *   validation data.
 * - [modelVersion] — version string of the model artifact used.
 * - [detectorId] — stable identifier of this detector ("SmsSpecialistClassifier").
 * - [detectorVersion] — version of the detector code.
 * - [contributingFeatures] — top contributing n-grams when available, for
 *   explainability; null or empty when not applicable.
 * - [errorMessage] — human-readable error description when [status] is [ERROR]
 *   or [UNAVAILABLE]; null otherwise.
 */
data class SmsClassifierResult(
    val status: SmsClassifierStatus,
    val predictedLabel: String?,
    val threatScore: Double?,
    val isCalibrated: Boolean,
    val modelVersion: String?,
    val detectorId: String,
    val detectorVersion: String,
    val contributingFeatures: List<ContributingFeature>?,
    val errorMessage: String?
) {
    val isAvailable: Boolean get() = status == SmsClassifierStatus.AVAILABLE
    val isThreat: Boolean get() = predictedLabel == "THREAT"
    val isSafe: Boolean get() = predictedLabel == "SAFE"
}
