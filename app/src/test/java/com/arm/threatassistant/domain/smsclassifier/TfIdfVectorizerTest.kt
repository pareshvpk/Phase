package com.arm.threatassistant.domain.smsclassifier

import org.junit.Test
import org.junit.Assert.*

import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierModel
import com.arm.threatassistant.domain.detection.smsclassifier.TfIdfVectorizer
import kotlin.math.sqrt

/**
 * Unit tests for TfIdfVectorizer.
 *
 * Verifies vocabulary lookup, unknown-token handling, IDF weighting,
 * feature ordering, L2 normalization, and deterministic output.
 */
class TfIdfVectorizerTest {

    private fun testModel(): SmsClassifierModel {
        return SmsClassifierModel(
            modelVersion = "1.0.0-test",
            detectorId = "SmsSpecialistClassifier",
            detectorVersion = "1.0.0",
            vocabulary = listOf("urgent", "otp", "safe", "hello", "urgent otp"),
            idf = listOf(1.5, 2.0, 1.0, 0.5, 1.2),
            weights = listOf(0.5, -0.3, 0.1, -0.2, 0.8),
            bias = 0.0,
            threshold = 0.5,
            labelMap = mapOf("SAFE" to 0, "THREAT" to 1),
            isCalibrated = false,
            featureConfig = emptyMap(),
            trainingInfo = emptyMap()
        )
    }

    // ---- Vocabulary lookup ----

    @Test
    fun vectorizeMapsTermsToVocabularyIndices() {
        val model = testModel()
        val vector = TfIdfVectorizer.vectorize(listOf("urgent", "otp", "urgent"), model)

        // "urgent" appears twice, idf=1.5 => tfidf = 2 * 1.5 = 3.0
        // "otp" appears once, idf=2.0 => tfidf = 1 * 2.0 = 2.0
        // L2 norm = sqrt(9 + 4) = sqrt(13)
        val norm = sqrt(13.0)
        assertEquals(3.0 / norm, vector[0], 1e-6)
        assertEquals(2.0 / norm, vector[1], 1e-6)
        assertEquals(0.0, vector[2], 1e-6) // "safe" not present
        assertEquals(0.0, vector[3], 1e-6) // "hello" not present
        assertEquals(0.0, vector[4], 1e-6) // bigram not present
    }

    // ---- Unknown tokens ----

    @Test
    fun vectorizeIgnoresOutOfVocabularyTokens() {
        val model = testModel()
        val vector = TfIdfVectorizer.vectorize(listOf("urgent", "unknownword", "xyz"), model)

        // Only "urgent" contributes; unknown words are skipped.
        assertEquals(1.5 / 1.5, vector[0], 1e-6) // tf=1, idf=1.5, norm=1.5 => 1.0
        assertEquals(0.0, vector[1], 1e-6)
        assertEquals(0.0, vector[2], 1e-6)
        assertEquals(0.0, vector[3], 1e-6)
        assertEquals(0.0, vector[4], 1e-6)
    }

    // ---- IDF calculation parity ----

    @Test
    fun vectorizeAppliesIdfWeights() {
        val model = testModel()
        // "safe" has idf=1.0, "urgent" has idf=1.5. Same count should produce
        // different TF-IDF values proportional to IDF.
        val v1 = TfIdfVectorizer.vectorize(listOf("safe"), model)
        val v2 = TfIdfVectorizer.vectorize(listOf("urgent"), model)
        assertEquals(1.0, v1[2], 1e-6)  // tf=1 * idf=1.0, norm=1.0 => 1.0
        assertEquals(1.0, v2[0], 1e-6)  // tf=1 * idf=1.5, norm=1.5 => 1.0
    }

    // ---- Feature ordering ----

    @Test
    fun vectorizeOutputIsAlignedWithVocabulary() {
        val model = testModel()
        val vector = TfIdfVectorizer.vectorize(listOf("hello"), model)
        // "hello" is at index 3.
        assertEquals(0.0, vector[0], 1e-6)
        assertEquals(0.0, vector[1], 1e-6)
        assertEquals(0.0, vector[2], 1e-6)
        assertEquals(1.0, vector[3], 1e-6) // tf=1 * idf=0.5, norm=0.5 => 1.0
        assertEquals(0.0, vector[4], 1e-6)
    }

    // ---- Deterministic output ----

    @Test
    fun vectorizeIsDeterministic() {
        val model = testModel()
        val terms = listOf("urgent", "otp", "safe", "urgent", "otp", "urgent")
        val v1 = TfIdfVectorizer.vectorize(terms, model)
        val v2 = TfIdfVectorizer.vectorize(terms, model)
        assertContentEquals(v1, v2)
    }

    // ---- Empty input ----

    @Test
    fun vectorizeEmptyTermsReturnsZeroVector() {
        val model = testModel()
        val vector = TfIdfVectorizer.vectorize(emptyList(), model)
        assertEquals(model.vocabulary.size, vector.size)
        for (v in vector) {
            assertEquals(0.0, v, 1e-6)
        }
    }

    // ---- Bigrams ----

    @Test
    fun vectorizeHandlesBigrams() {
        val model = testModel()
        val vector = TfIdfVectorizer.vectorize(listOf("urgent", "otp", "urgent otp"), model)
        // "urgent otp" bigram at index 4, idf=1.2, tf=1 => tfidf=1.2
        // "urgent" at index 0, idf=1.5, tf=1 => tfidf=1.5
        // "otp" at index 1, idf=2.0, tf=1 => tfidf=2.0
        // norm = sqrt(1.5^2 + 2.0^2 + 1.2^2) = sqrt(2.25 + 4 + 1.44) = sqrt(7.69)
        val norm = sqrt(7.69)
        assertEquals(1.5 / norm, vector[0], 1e-6)
        assertEquals(2.0 / norm, vector[1], 1e-6)
        assertEquals(1.2 / norm, vector[4], 1e-6)
    }
}
