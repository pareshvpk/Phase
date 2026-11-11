package com.arm.threatassistant.domain.detection.riskpolicy

import com.arm.threatassistant.domain.detection.ruleengine.*
import com.arm.threatassistant.domain.detection.smsclassifier.*
import com.arm.threatassistant.domain.detection.urldetection.*
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.AnalysisStatus
import org.junit.Assert.*
import org.junit.Test

class RiskPolicyEngineTest {

    private val engine = RiskPolicyEngine

    private val ruleEmpty = RuleDetectionResult(
        signals = emptyList(),
        detectorId = "FastRuleEngine",
        detectorVersion = "1.0.0"
    )

    private val ruleHighSignal = RuleDetectionResult(
        signals = listOf(
            DetectionSignal(
                signalId = "s1",
                category = RuleCategory.URGENCY_AND_COERCION,
                ruleId = "urg_001",
                description = "Immediate action required",
                matchedText = "immediate action required",
                severity = DetectionSeverity.HIGH,
                detectorId = "FastRuleEngine",
                detectorVersion = "1.0.0"
            )
        ),
        detectorId = "FastRuleEngine",
        detectorVersion = "1.0.0"
    )

    private val ruleMultipleHigh = RuleDetectionResult(
        signals = listOf(
            DetectionSignal("s1", RuleCategory.URGENCY_AND_COERCION, "urg_001", "d", "m",
                DetectionSeverity.HIGH, "FastRuleEngine", "1.0.0"),
            DetectionSignal("s2", RuleCategory.CREDENTIAL_REQUEST, "cred_003", "d", "m",
                DetectionSeverity.HIGH, "FastRuleEngine", "1.0.0"),
            DetectionSignal("s3", RuleCategory.PAYMENT_DEMAND, "pay_001", "d", "m",
                DetectionSeverity.HIGH, "FastRuleEngine", "1.0.0")
        ),
        detectorId = "FastRuleEngine",
        detectorVersion = "1.0.0"
    )

    private val classifierAvailable = SmsClassifierResult(
        status = SmsClassifierStatus.AVAILABLE,
        predictedLabel = "THREAT",
        threatScore = 0.85,
        isCalibrated = false,
        modelVersion = "1.0.0",
        detectorId = "SmsSpecialistClassifier",
        detectorVersion = "1.0.0",
        contributingFeatures = emptyList(),
        errorMessage = null
    )

    private val classifierLowScore = SmsClassifierResult(
        status = SmsClassifierStatus.AVAILABLE,
        predictedLabel = "SAFE",
        threatScore = 0.30,
        isCalibrated = false,
        modelVersion = "1.0.0",
        detectorId = "SmsSpecialistClassifier",
        detectorVersion = "1.0.0",
        contributingFeatures = emptyList(),
        errorMessage = null
    )

    private val classifierUnavailable = SmsClassifierResult(
        status = SmsClassifierStatus.UNAVAILABLE,
        predictedLabel = null,
        threatScore = null,
        isCalibrated = false,
        modelVersion = null,
        detectorId = "SmsSpecialistClassifier",
        detectorVersion = "1.0.0",
        contributingFeatures = null,
        errorMessage = "Model not found"
    )

    private val urlHighSignal = UrlDetectionResult(
        urls = emptyList(),
        signals = listOf(
            UrlDetectionSignal("s1", UrlDetectionCategory.IP_BASED_URL, UrlDetectionSeverity.HIGH,
                "desc", "http://1.2.3.4", "1.2.3.4", "UrlSpecialistDetector", "1.0.0")
        ),
        detectorId = "UrlSpecialistDetector",
        detectorVersion = "1.0.0"
    )

    private fun ruleOnlyResult(severity: DetectionSeverity): RuleDetectionResult {
        return RuleDetectionResult(
            signals = listOf(
                DetectionSignal("s1", RuleCategory.URGENCY_AND_COERCION, "urg_001", "d", "m",
                    severity, "FastRuleEngine", "1.0.0")
            ),
            detectorId = "FastRuleEngine",
            detectorVersion = "1.0.0"
        )
    }

    @Test
    fun noEvidenceReturnsInsufficientEvidence() {
        val assessment = engine.assess(ruleEmpty, null, null, AnalysisStatus.COMPLETED)
        assertEquals(ThreatVerdictLevel.INSUFFICIENT_EVIDENCE, assessment.verdict)
    }

    @Test
    fun errorStatusReturnsInsufficientEvidence() {
        val assessment = engine.assess(ruleHighSignal, classifierAvailable, urlHighSignal, AnalysisStatus.ERROR)
        assertEquals(ThreatVerdictLevel.INSUFFICIENT_EVIDENCE, assessment.verdict)
    }

    @Test
    fun singleMediumRuleSignalIsSafe() {
        val assessment = engine.assess(ruleOnlyResult(DetectionSeverity.MEDIUM), null, null, AnalysisStatus.COMPLETED)
        assertEquals(ThreatVerdictLevel.SAFE, assessment.verdict)
    }

    @Test
    fun singleHighRuleSignalIsSuspicious() {
        val assessment = engine.assess(ruleHighSignal, null, null, AnalysisStatus.COMPLETED)
        assertEquals(ThreatVerdictLevel.SUSPICIOUS, assessment.verdict)
    }

    @Test
    fun multipleHighRuleSignalsIsHighRisk() {
        val assessment = engine.assess(ruleMultipleHigh, null, null, AnalysisStatus.COMPLETED)
        assertEquals(ThreatVerdictLevel.HIGH_RISK, assessment.verdict)
    }

    @Test
    fun highClassifierScoreIsSuspicious() {
        val assessment = engine.assess(ruleEmpty, classifierAvailable, null, AnalysisStatus.COMPLETED)
        assertEquals(ThreatVerdictLevel.SUSPICIOUS, assessment.verdict)
    }

    @Test
    fun lowClassifierScoreDoesNotInfluenceVerdict() {
        val assessment = engine.assess(ruleEmpty, classifierLowScore, null, AnalysisStatus.COMPLETED)
        assertEquals(ThreatVerdictLevel.INSUFFICIENT_EVIDENCE, assessment.verdict)
    }

    @Test
    fun unavailableClassifierNeverProducesSafe() {
        val assessment = engine.assess(ruleEmpty, classifierUnavailable, null, AnalysisStatus.COMPLETED)
        assertNotEquals(ThreatVerdictLevel.SAFE, assessment.verdict)
    }

    @Test
    fun urlHighSignalIsSuspicious() {
        val assessment = engine.assess(ruleEmpty, null, urlHighSignal, AnalysisStatus.COMPLETED)
        assertEquals(ThreatVerdictLevel.SUSPICIOUS, assessment.verdict)
    }

    @Test
    fun combinedEvidenceIsHighRisk() {
        val assessment = engine.assess(ruleHighSignal, classifierAvailable, urlHighSignal, AnalysisStatus.COMPLETED)
        assertEquals(ThreatVerdictLevel.HIGH_RISK, assessment.verdict)
    }

    @Test
    fun assessmentContainsEvidenceSummary() {
        val assessment = engine.assess(ruleHighSignal, classifierAvailable, null, AnalysisStatus.COMPLETED)
        assertFalse(assessment.evidenceSummary.isEmpty())
        assertTrue(assessment.evidenceSummary.any { it.contains("Rule engine") })
        assertTrue(assessment.evidenceSummary.any { it.contains("SMS classifier") })
    }

    @Test
    fun riskScoreIsInRange() {
        val assessment = engine.assess(ruleMultipleHigh, classifierAvailable, urlHighSignal, AnalysisStatus.COMPLETED)
        assertTrue(assessment.riskScore >= 0.0 && assessment.riskScore <= 1.0)
    }

    @Test
    fun deterministicSameInputSameResult() {
        val a = engine.assess(ruleHighSignal, classifierAvailable, null, AnalysisStatus.COMPLETED)
        val b = engine.assess(ruleHighSignal, classifierAvailable, null, AnalysisStatus.COMPLETED)
        assertEquals(a.verdict, b.verdict)
        assertEquals(a.riskScore, b.riskScore, 0.0001)
    }

    @Test
    fun nullInputsAreHandledGracefully() {
        // Should not throw
        val assessment = engine.assess(null, null, null, AnalysisStatus.COMPLETED)
        assertEquals(ThreatVerdictLevel.INSUFFICIENT_EVIDENCE, assessment.verdict)
    }
}
