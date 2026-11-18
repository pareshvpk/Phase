package com.arm.threatassistant.domain.detection.riskpolicy

import com.arm.threatassistant.domain.detection.ruleengine.RuleDetectionResult
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierResult
import com.arm.threatassistant.domain.detection.urldetection.UrlDetectionResult
import com.arm.threatassistant.domain.detection.urldetection.UrlDetectionSeverity
import com.arm.threatassistant.domain.model.AnalysisStatus

/**
 * Authoritative threat verdict produced by [RiskPolicyEngine].
 */
enum class ThreatVerdictLevel {
    /** No meaningful evidence of a threat. */
    SAFE,
    /** Some concerning indicators but not sufficient for HIGH_RISK. */
    SUSPICIOUS,
    /** Multiple high-severity indicators or strong classifier confidence. */
    HIGH_RISK,
    /** Not enough information to make a determination. */
    INSUFFICIENT_EVIDENCE
}

/**
 * Weighting applied to each category of detection evidence.
 */
internal data class EvidenceWeights(
    /** Weight per HIGH severity rule signal. */
    val ruleHighSeverity: Double = 0.25,
    /** Weight per MEDIUM severity rule signal. */
    val ruleMediumSeverity: Double = 0.12,
    /** Weight per LOW severity rule signal. */
    val ruleLowSeverity: Double = 0.05,
    /** Weight applied to the classifier threat score (0.0-1.0). */
    val classifierThreatScore: Double = 0.40,
    /** Weight per HIGH severity URL signal. */
    val urlHighSeverity: Double = 0.20,
    /** Weight per MEDIUM severity URL signal. */
    val urlMediumSeverity: Double = 0.10,
    /** Weight per LOW severity URL signal. */
    val urlLowSeverity: Double = 0.05,
    /** Maximum total risk score before clamping. */
    val maxScore: Double = 1.0
)

/**
 * Thresholds for verdict determination.
 */
internal data class VerdictThresholds(
    /** Score at or above this is HIGH_RISK. */
    val highRisk: Double = 0.65,
    /** Score at or above this (but below highRisk) is SUSPICIOUS. */
    val suspicious: Double = 0.30,
    /** Below this is SAFE (if any evidence exists). */
    val safe: Double = 0.05,
    /** Minimum classifier threat score for the classifier to influence the verdict. */
    val classifierMinConfidence: Double = 0.60,
    /** Minimum number of rule signals required for any verdict above INSUFFICIENT_EVIDENCE. */
    val minRuleSignals: Int = 1
)

/**
 * Detailed breakdown of how the verdict was computed.
 */
data class RiskAssessment(
    val verdict: ThreatVerdictLevel,
    val riskScore: Double,
    val evidenceSummary: List<String>,
    val ruleContribution: Double,
    val classifierContribution: Double,
    val urlContribution: Double,
    val ruleSignalCount: Int,
    val classifierThreatScore: Double?,
    val urlSignalCount: Int,
    val inputStatus: AnalysisStatus
)

/**
 * RiskPolicyEngine — the authoritative decision-making component.
 *
 * Combines rule detection evidence, SMS classifier score, and URL specialist
 * evidence into a deterministic threat verdict.
 *
 * Design principles:
 *   - No single keyword or signal is sufficient proof of fraud.
 *   - Classifier confidence must exceed a minimum threshold to influence the verdict.
 *   - Conflicting evidence is resolved conservatively (lean toward SUSPICIOUS).
 *   - Every verdict is accompanied by an explainable evidence summary.
 *   - Decisions are deterministic and reproducible.
 *   - The LLM never overrides this engine.
 */
object RiskPolicyEngine {

    internal const val DETECTOR_ID = "RiskPolicyEngine"
    internal const val DETECTOR_VERSION = "1.0.0"

    private val weights = EvidenceWeights()
    private val thresholds = VerdictThresholds()

    /**
     * The classifier confidence the engine requires before the classifier may
     * influence a verdict. Exposed so callers (e.g. the SMS alert policy) reuse
     * the same threshold instead of inventing a new number.
     */
    internal val classifierMinConfidence: Double
        get() = thresholds.classifierMinConfidence

    /**
     * Produces a [ThreatVerdictLevel] and [RiskAssessment] from all available
     * detection evidence.
     */
    fun assess(
        ruleResult: RuleDetectionResult?,
        classifierResult: SmsClassifierResult?,
        urlResult: UrlDetectionResult?,
        inputStatus: AnalysisStatus
    ): RiskAssessment {

        val ruleContribution = computeRuleContribution(ruleResult)
        val classifierContribution = computeClassifierContribution(classifierResult)
        val urlContribution = computeUrlContribution(urlResult)

        val rawScore = ruleContribution + classifierContribution + urlContribution
        val riskScore = rawScore.coerceIn(0.0, weights.maxScore)
        val ruleSignalCount = ruleResult?.signalCount ?: 0
        val urlSignalCount = urlResult?.signalCount ?: 0
        val ruleHighSeverityCount = ruleResult?.signals?.count {
            it.severity == com.arm.threatassistant.domain.detection.ruleengine.DetectionSeverity.HIGH
        } ?: 0
        val urlHighSeverityCount = urlResult?.signals?.count {
            it.severity == UrlDetectionSeverity.HIGH
        } ?: 0
        val classifierScore = classifierResult?.threatScore

        val evidenceSummary = buildEvidenceSummary(
            ruleResult, classifierResult, urlResult,
            ruleContribution, classifierContribution, urlContribution
        )

        val verdict = determineVerdict(
            riskScore = riskScore,
            ruleSignalCount = ruleSignalCount,
            ruleHighSeverityCount = ruleHighSeverityCount,
            classifierScore = classifierScore,
            urlSignalCount = urlSignalCount,
            urlHighSeverityCount = urlHighSeverityCount,
            inputStatus = inputStatus
        )

        return RiskAssessment(
            verdict = verdict,
            riskScore = riskScore,
            evidenceSummary = evidenceSummary,
            ruleContribution = ruleContribution,
            classifierContribution = classifierContribution,
            urlContribution = urlContribution,
            ruleSignalCount = ruleSignalCount,
            classifierThreatScore = classifierScore,
            urlSignalCount = urlSignalCount,
            inputStatus = inputStatus
        )
    }

    // -----------------------------------------------------------------------
    // Contribution computation
    // -----------------------------------------------------------------------

    private fun computeRuleContribution(result: RuleDetectionResult?): Double {
        if (result == null || result.signals.isEmpty()) return 0.0

        var score = 0.0
        for (signal in result.signals) {
            score += when (signal.severity) {
                com.arm.threatassistant.domain.detection.ruleengine.DetectionSeverity.HIGH -> weights.ruleHighSeverity
                com.arm.threatassistant.domain.detection.ruleengine.DetectionSeverity.MEDIUM -> weights.ruleMediumSeverity
                com.arm.threatassistant.domain.detection.ruleengine.DetectionSeverity.LOW -> weights.ruleLowSeverity
            }
        }
        return score
    }

    private fun computeClassifierContribution(result: SmsClassifierResult?): Double {
        // Only count the classifier if it produced a confident result.
        val score = result?.threatScore ?: return 0.0
        if (score < thresholds.classifierMinConfidence) return 0.0
        return score * weights.classifierThreatScore
    }

    private fun computeUrlContribution(result: UrlDetectionResult?): Double {
        if (result == null || result.signals.isEmpty()) return 0.0

        var score = 0.0
        for (signal in result.signals) {
            score += when (signal.severity) {
                UrlDetectionSeverity.HIGH -> weights.urlHighSeverity
                UrlDetectionSeverity.MEDIUM -> weights.urlMediumSeverity
                UrlDetectionSeverity.LOW -> weights.urlLowSeverity
            }
        }
        return score
    }

    // -----------------------------------------------------------------------
    // Verdict determination
    // -----------------------------------------------------------------------

    private fun determineVerdict(
        riskScore: Double,
        ruleSignalCount: Int,
        ruleHighSeverityCount: Int,
        classifierScore: Double?,
        urlSignalCount: Int,
        urlHighSeverityCount: Int,
        inputStatus: AnalysisStatus
    ): ThreatVerdictLevel {

        val classifierConfident = classifierScore != null &&
            classifierScore >= thresholds.classifierMinConfidence

        // No evidence at all → INSUFFICIENT_EVIDENCE. A low-confidence
        // classifier score does not count as evidence.
        val hasAnyEvidence = ruleSignalCount > 0 || urlSignalCount > 0 || classifierConfident
        if (!hasAnyEvidence) {
            return ThreatVerdictLevel.INSUFFICIENT_EVIDENCE
        }

        // Input could not be analyzed (error/status issue).
        if (inputStatus == AnalysisStatus.ERROR) {
            return ThreatVerdictLevel.INSUFFICIENT_EVIDENCE
        }

        // HIGH_RISK: high aggregate score, or strong multi-signal evidence.
        if (riskScore >= thresholds.highRisk) {
            return ThreatVerdictLevel.HIGH_RISK
        }

        // HIGH_RISK: multiple high-severity rule signals even if aggregate
        // score is moderate (conservative: multiple coercion rules = serious).
        // Only HIGH severity signals count; several LOW/MEDIUM signals do not.
        if (ruleHighSeverityCount >= 3) {
            return ThreatVerdictLevel.HIGH_RISK
        }

        // SUSPICIOUS: moderate aggregate score, or any single high-severity
        // rule/URL signal, or confident classifier prediction.
        if (riskScore >= thresholds.suspicious) {
            return ThreatVerdictLevel.SUSPICIOUS
        }

        if (ruleHighSeverityCount >= 1 || urlHighSeverityCount >= 1) {
            return ThreatVerdictLevel.SUSPICIOUS
        }

        if (classifierConfident) {
            return ThreatVerdictLevel.SUSPICIOUS
        }

        // SAFE: some evidence exists but below all risk thresholds.
        if (riskScore >= thresholds.safe) {
            return ThreatVerdictLevel.SAFE
        }

        return ThreatVerdictLevel.SAFE
    }

    // -----------------------------------------------------------------------
    // Evidence summary
    // -----------------------------------------------------------------------

    private fun buildEvidenceSummary(
        ruleResult: RuleDetectionResult?,
        classifierResult: SmsClassifierResult?,
        urlResult: UrlDetectionResult?,
        ruleContribution: Double,
        classifierContribution: Double,
        urlContribution: Double
    ): List<String> {
        val summary = mutableListOf<String>()

        if (ruleResult != null && ruleResult.signals.isNotEmpty()) {
            val highCount = ruleResult.signals.count {
                it.severity == com.arm.threatassistant.domain.detection.ruleengine.DetectionSeverity.HIGH
            }
            val mediumCount = ruleResult.signals.count {
                it.severity == com.arm.threatassistant.domain.detection.ruleengine.DetectionSeverity.MEDIUM
            }
            summary.add(
                "Rule engine: ${ruleResult.signalCount} signal(s) " +
                    "(HIGH: $highCount, MEDIUM: $mediumCount), " +
                    "contribution: ${"%.2f".format(ruleContribution)}"
            )
            // List top rule categories.
            val categories = ruleResult.categoriesDetected
            if (categories.isNotEmpty()) {
                summary.add("  Rule categories: ${categories.joinToString { it.name }}")
            }
        }

        if (classifierResult != null && classifierResult.status == com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierStatus.AVAILABLE) {
            summary.add(
                "SMS classifier: ${classifierResult.predictedLabel} " +
                    "(score: ${"%.3f".format(classifierResult.threatScore ?: 0.0)}), " +
                    "contribution: ${"%.2f".format(classifierContribution)}"
            )
        } else if (classifierResult != null) {
            summary.add(
                "SMS classifier: ${classifierResult.status} " +
                    "(${classifierResult.errorMessage ?: "no detail"}), " +
                    "no threat contribution."
            )
        }

        if (urlResult != null && urlResult.signals.isNotEmpty()) {
            val highCount = urlResult.signals.count { it.severity == UrlDetectionSeverity.HIGH }
            val mediumCount = urlResult.signals.count { it.severity == UrlDetectionSeverity.MEDIUM }
            summary.add(
                "URL specialist: ${urlResult.signalCount} signal(s) " +
                    "(HIGH: $highCount, MEDIUM: $mediumCount), " +
                    "contribution: ${"%.2f".format(urlContribution)}"
            )
        }

        if (summary.isEmpty()) {
            summary.add("No detection signals found.")
        }

        return summary
    }

    private fun Double.coerceIn(minimum: Double, maximum: Double): Double =
        if (this < minimum) minimum else if (this > maximum) maximum else this
}
