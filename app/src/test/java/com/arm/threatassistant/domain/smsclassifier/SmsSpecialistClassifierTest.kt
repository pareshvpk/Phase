package com.arm.threatassistant.domain.smsclassifier

import org.junit.Test
import org.junit.Assert.*

import com.arm.threatassistant.domain.detection.smsclassifier.ContributingFeature
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierModel
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierResult
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierStatus
import com.arm.threatassistant.domain.detection.smsclassifier.SmsSpecialistClassifier
import com.arm.threatassistant.domain.model.AnalysisInput

/**
 * Unit tests for SmsSpecialistClassifier.
 *
 * Tests use synthetically constructed models (not the asset) so they run
 * without Android Context. The test models are clearly development fixtures.
 */
class SmsSpecialistClassifierTest {

    // ---- Helper: build a threat-leaning model ----

    private fun threatModel(): SmsClassifierModel {
        // Words "urgent", "otp", "suspend" have strong positive weights (threat).
        // Words "hello", "thanks" have negative weights (safe).
        return SmsClassifierModel(
            modelVersion = "1.0.0-test-threat",
            detectorId = "SmsSpecialistClassifier",
            detectorVersion = "1.0.0",
            vocabulary = listOf("urgent", "otp", "suspend", "hello", "thanks"),
            idf = listOf(1.5, 1.5, 1.5, 1.0, 1.0),
            weights = listOf(2.0, 2.0, 2.0, -1.0, -1.0),
            bias = -0.5,
            threshold = 0.5,
            labelMap = mapOf("SAFE" to 0, "THREAT" to 1),
            isCalibrated = false,
            featureConfig = emptyMap(),
            trainingInfo = emptyMap()
        )
    }

    // ---- Helper: build a safe-leaning model ----

    private fun safeModel(): SmsClassifierModel {
        return SmsClassifierModel(
            modelVersion = "1.0.0-test-safe",
            detectorId = "SmsSpecialistClassifier",
            detectorVersion = "1.0.0",
            vocabulary = listOf("urgent", "otp", "suspend", "hello", "thanks"),
            idf = listOf(1.5, 1.5, 1.5, 1.0, 1.0),
            weights = listOf(2.0, 2.0, 2.0, -1.0, -1.0),
            bias = 2.0, // high bias pushes toward SAFE
            threshold = 0.5,
            labelMap = mapOf("SAFE" to 0, "THREAT" to 1),
            isCalibrated = false,
            featureConfig = emptyMap(),
            trainingInfo = emptyMap()
        )
    }

    // ---- Classifier construction ----

    @Test
    fun fromModelCreatesAvailableClassifier() {
        val model = threatModel()
        val classifier = SmsSpecialistClassifier.fromModel(model)
        val result = classifier.classify(AnalysisInput(messageText = "urgent otp verify now"))
        assertEquals(SmsClassifierStatus.AVAILABLE, result.status)
        assertNotNull(result.predictedLabel)
        assertNotNull(result.threatScore)
    }

    @Test
    fun unavailableClassifierNeverReturnsSafe() {
        val classifier = SmsSpecialistClassifier.unavailable("No model asset found")
        val result = classifier.classify(AnalysisInput(messageText = "This looks completely safe"))
        assertEquals(SmsClassifierStatus.UNAVAILABLE, result.status)
        assertNull(result.predictedLabel) // must NOT be SAFE
        assertNull(result.threatScore)
        assertNotNull(result.errorMessage)
    }

    // ---- Known scam messages ----

    @Test
    fun urgentOtpMessageIsClassifiedAsThreat() {
        val classifier = SmsSpecialistClassifier.fromModel(threatModel())
        val result = classifier.classify(AnalysisInput(messageText = "Urgent: share your OTP immediately to avoid account suspension."))
        assertEquals(SmsClassifierStatus.AVAILABLE, result.status)
        assertEquals("THREAT", result.predictedLabel)
        assertTrue(result.threatScore ?: 0.0 >= 0.5)
    }

    @Test
    fun otpRequestIsClassifiedAsThreat() {
        val classifier = SmsSpecialistClassifier.fromModel(threatModel())
        val result = classifier.classify(AnalysisInput(messageText = "Please send your OTP to verify your identity."))
        assertEquals(SmsClassifierStatus.AVAILABLE, result.status)
        assertEquals("THREAT", result.predictedLabel)
    }

    @Test
    fun accountSuspensionScamIsClassifiedAsThreat() {
        val classifier = SmsSpecialistClassifier.fromModel(threatModel())
        val result = classifier.classify(AnalysisInput(messageText = "Your account will be suspended unless you act now."))
        assertEquals(SmsClassifierStatus.AVAILABLE, result.status)
        assertEquals("THREAT", result.predictedLabel)
    }

    // ---- Legitimate messages ----

    @Test
    fun legitimateMessageCanBeClassifiedAsSafe() {
        val classifier = SmsSpecialistClassifier.fromModel(threatModel())
        val result = classifier.classify(AnalysisInput(messageText = "Hello, thanks for meeting me yesterday."))
        assertEquals(SmsClassifierStatus.AVAILABLE, result.status)
        // With this model, "hello" and "thanks" have negative weights; no threat words.
        // Bias is -0.5, so score will be negative => SAFE.
        assertEquals("SAFE", result.predictedLabel)
    }

    // ---- URL-containing messages ----

    @Test
    fun urlContainingScamIsClassifiedAsThreat() {
        val classifier = SmsSpecialistClassifier.fromModel(threatModel())
        val result = classifier.classify(
            AnalysisInput(messageText = "Urgent: click http://fake-bank.example.in to verify your OTP now.")
        )
        assertEquals(SmsClassifierStatus.AVAILABLE, result.status)
        assertEquals("THREAT", result.predictedLabel)
    }

    // ---- Model missing / corrupted ----

    @Test
    fun missingModelProducesUnavailableNotSafe() {
        val classifier = SmsSpecialistClassifier.unavailable("Model asset not found")
        val result = classifier.classify(AnalysisInput(messageText = "Any text at all"))
        assertEquals(SmsClassifierStatus.UNAVAILABLE, result.status)
        assertNull(result.predictedLabel)
    }

    @Test
    fun corruptedModelProducesUnavailable() {
        val classifier = SmsSpecialistClassifier.unavailable("Failed to parse model JSON: malformed")
        val result = classifier.classify(AnalysisInput(messageText = "Urgent OTP verify"))
        assertEquals(SmsClassifierStatus.UNAVAILABLE, result.status)
        assertNull(result.predictedLabel)
        assertNotNull(result.errorMessage)
    }

    // ---- Probability range ----

    @Test
    fun threatScoreIsInZeroToOneRange() {
        val classifier = SmsSpecialistClassifier.fromModel(threatModel())
        val result = classifier.classify(AnalysisInput(messageText = "urgent otp suspend"))
        assertTrue(result.status == SmsClassifierStatus.AVAILABLE)
        val score = result.threatScore ?: -1.0
        assertTrue(score >= 0.0 && score <= 1.0, "Score $score out of range [0,1]")
    }

    // ---- Deterministic repeated predictions ----

    @Test
    fun repeatedPredictionsAreDeterministic() {
        val classifier = SmsSpecialistClassifier.fromModel(threatModel())
        val text = "Urgent OTP verification required for account suspend immediately."
        val r1 = classifier.classify(AnalysisInput(messageText = text))
        val r2 = classifier.classify(AnalysisInput(messageText = text))
        val r3 = classifier.classify(AnalysisInput(messageText = text))
        assertEquals(r1.threatScore, r2.threatScore)
        assertEquals(r2.threatScore, r3.threatScore)
        assertEquals(r1.predictedLabel, r2.predictedLabel)
        assertEquals(r2.predictedLabel, r3.predictedLabel)
    }

    // ---- Empty / unsupported input ----

    @Test
    fun emptyInputIsUnsupportedInput() {
        val classifier = SmsSpecialistClassifier.fromModel(threatModel())
        val result = classifier.classify(AnalysisInput(messageText = ""))
        assertEquals(SmsClassifierStatus.UNSUPPORTED_INPUT, result.status)
        assertNull(result.predictedLabel)
    }

    @Test
    fun whitespaceOnlyInputIsUnsupportedInput() {
        val classifier = SmsSpecialistClassifier.fromModel(threatModel())
        val result = classifier.classify(AnalysisInput(messageText = "   \n\t  "))
        assertEquals(SmsClassifierStatus.UNSUPPORTED_INPUT, result.status)
        assertNull(result.predictedLabel)
    }

    // ---- Result metadata ----

    @Test
    fun resultHasDetectorMetadata() {
        val classifier = SmsSpecialistClassifier.fromModel(threatModel())
        val result = classifier.classify(AnalysisInput(messageText = "urgent otp"))
        assertEquals("SmsSpecialistClassifier", result.detectorId)
        assertEquals("1.0.0", result.detectorVersion)
        assertEquals("1.0.0-test-threat", result.modelVersion)
        assertFalse(result.isCalibrated)
    }

    // ---- Contributing features ----

    @Test
    fun contributingFeaturesPresent() {
        val classifier = SmsSpecialistClassifier.fromModel(threatModel())
        val result = classifier.classify(AnalysisInput(messageText = "urgent otp verify now"))
        assertTrue(result.status == SmsClassifierStatus.AVAILABLE)
        val features = result.contributingFeatures
        assertNotNull(features)
        assertTrue(features.isNotEmpty())
        // At least one feature should have positive contribution (pushing toward THREAT).
        assertTrue(features.any { it.contribution > 0 }, "Expected positive contribution, got $features")
    }
}