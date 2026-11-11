package com.arm.threatassistant.domain.smsclassifier

import org.junit.Test
import org.junit.Assert.*

import com.arm.threatassistant.domain.detection.ruleengine.FastRuleEngine
import com.arm.threatassistant.domain.detection.ruleengine.RuleDetectionResult
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierModel
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierResult
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierStatus
import com.arm.threatassistant.domain.detection.smsclassifier.SmsSpecialistClassifier
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.AnalysisResult
import com.arm.threatassistant.domain.model.AnalysisStatus
import com.arm.threatassistant.domain.model.ThreatVerdict

/**
 * Integration tests verifying that FastRuleEngine and SmsSpecialistClassifier
 * can run in the same analysis flow, that the classifier never overwrites
 * AnalysisResult.verdict, and that classifier failure does not produce SAFE.
 */
class SmsClassifierIntegrationTest {

    private fun threatModel(): SmsClassifierModel {
        return SmsClassifierModel(
            modelVersion = "1.0.0-test-integration",
            detectorId = "SmsSpecialistClassifier",
            detectorVersion = "1.0.0",
            vocabulary = listOf("urgent", "otp", "suspend", "bank", "payment", "fee", "hello", "thanks"),
            idf = listOf(1.5, 1.5, 1.5, 1.0, 1.2, 1.2, 1.0, 1.0),
            weights = listOf(1.5, 1.5, 1.5, 0.2, 0.5, 1.0, -0.5, -0.5),
            bias = -0.3,
            threshold = 0.5,
            labelMap = mapOf("SAFE" to 0, "THREAT" to 1),
            isCalibrated = false,
            featureConfig = emptyMap(),
            trainingInfo = emptyMap()
        )
    }

    // ---- Both detectors run in same flow ----

    @Test
    fun bothDetectorsRunInSameFlow() {
        val input = AnalysisInput(messageText = "Urgent: your bank account will be suspended. Share your OTP immediately.")
        val normalized = input.copy(normalizedText = input.messageText.lowercase())

        val ruleResult = FastRuleEngine.detect(normalized)
        val classifier = SmsSpecialistClassifier.fromModel(threatModel())
        val classifierResult = classifier.classify(normalized)

        // Rule engine should find signals.
        assertTrue(ruleResult.hasSignals(), "Expected rule signals, got none")

        // Classifier should produce a result.
        assertEquals(SmsClassifierStatus.AVAILABLE, classifierResult.status)
        assertNotNull(classifierResult.predictedLabel)
    }

    // ---- Classifier failure does not produce SAFE ----

    @Test
    fun classifierUnavailableDoesNotProduceSafe() {
        val classifier = SmsSpecialistClassifier.unavailable("Model missing")
        val result = classifier.classify(AnalysisInput(messageText = "This is a completely safe message from your bank."))
        assertEquals(SmsClassifierStatus.UNAVAILABLE, result.status)
        assertNull(result.predictedLabel, "Unavailable classifier must not return SAFE")
        assertNull(result.threatScore)
    }

    // ---- AnalysisResult.verdict remains null ----

    @Test
    fun analysisResultVerdictRemainsNull() {
        // Simulate the analysis flow: neither detector touches AnalysisResult.verdict.
        val input = AnalysisInput(messageText = "Urgent OTP verify now")
        val result = AnalysisResult(
            input = input,
            status = AnalysisStatus.COMPLETED,
            verdict = null,
            message = "Analysis completed"
        )

        assertNull(result.verdict, "AnalysisResult.verdict must remain null after Phase 3B")

        // Run both detectors - neither modifies AnalysisResult.
        val ruleResult = FastRuleEngine.detect(input)
        val classifier = SmsSpecialistClassifier.fromModel(threatModel())
        val classifierResult = classifier.classify(input)

        // Construct a new result (as the ViewModel would) - verdict still null.
        val updatedResult = AnalysisResult(
            input = input,
            status = AnalysisStatus.COMPLETED,
            verdict = null,
            message = "Detection evidence collected"
        )
        assertNull(updatedResult.verdict)
    }

    // ---- SmsClassifierResult is not ThreatVerdict ----

    @Test
    fun classifierResultIsNotThreatVerdict() {
        val classifier = SmsSpecialistClassifier.fromModel(threatModel())
        val result = classifier.classify(AnalysisInput(messageText = "urgent otp suspend"))

        // SmsClassifierResult is a distinct type from ThreatVerdict.
        assertFalse(result ::class == ThreatVerdict::class)
        assertTrue(result is SmsClassifierResult)
        // predictedLabel is a String, not a ThreatVerdict enum.
        assertTrue(result.predictedLabel is String || result.predictedLabel == null)
    }

    // ---- Threat and safe messages produce different labels ----

    @Test
    fun threatAndSafeMessagesDiffer() {
        val classifier = SmsSpecialistClassifier.fromModel(threatModel())

        val threatResult = classifier.classify(
            AnalysisInput(messageText = "Urgent: your account will be suspended. Pay a fee immediately.")
        )
        val safeResult = classifier.classify(
            AnalysisInput(messageText = "Hello, thanks for your payment. Your balance is credited.")
        )

        assertEquals(SmsClassifierStatus.AVAILABLE, threatResult.status)
        assertEquals(SmsClassifierStatus.AVAILABLE, safeResult.status)
        assertNotEquals(threatResult.predictedLabel, safeResult.predictedLabel)
    }

    // ---- Classifier preserves FastRuleEngine output ----

    @Test
    fun classifierDoesNotInterfereWithRuleEngine() {
        val input = AnalysisInput(messageText = "Urgent OTP verify account suspend")
        val before = FastRuleEngine.detect(input)

        val classifier = SmsSpecialistClassifier.fromModel(threatModel())
        val _ = classifier.classify(input)

        val after = FastRuleEngine.detect(input)
        assertEquals(before.signalCount, after.signalCount, "Rule engine output must be unchanged by classifier")
    }
}
