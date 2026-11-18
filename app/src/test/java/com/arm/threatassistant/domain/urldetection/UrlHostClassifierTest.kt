package com.arm.threatassistant.domain.detection.urldetection

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The shipped host model must normalise hosts and score them in Kotlin
 * exactly as the Python trainer did (tools/url_classifier/train_host_model.py).
 * Expected probabilities come from src/test/resources/host_model_parity.json.
 */
class UrlHostClassifierTest {

    private val model: UrlHostModel by lazy {
        UrlHostModel.parse(File("src/main/assets/url_host_model.json").readText(Charsets.UTF_8))
    }

    private data class ParityEntry(
        val url: String,
        val host: String,
        val probability: Double
    )

    private val parity: List<ParityEntry> by lazy {
        val json = org.json.JSONObject(
            File("src/test/resources/host_model_parity.json").readText(Charsets.UTF_8)
        )
        val entries = json.getJSONArray("entries")
        (0 until entries.length()).map { i ->
            val entry = entries.getJSONObject(i)
            ParityEntry(
                url = entry.getString("url"),
                host = entry.getString("host"),
                probability = entry.getDouble("probability")
            )
        }
    }

    @Test
    fun parityFileHasFortyEntries() {
        assertEquals(40, parity.size)
    }

    @Test
    fun normalizeHostMatchesPythonForEveryParityEntry() {
        for (entry in parity) {
            assertEquals(entry.url, entry.host, UrlHostClassifier.normalizeHost(entry.url))
        }
    }

    @Test
    fun probabilityMatchesPythonForEveryParityEntry() {
        for (entry in parity) {
            val host = UrlHostClassifier.normalizeHost(entry.url)
            assertNotNull("no host for ${entry.url}", host)
            val actual = UrlHostClassifier.probability(model, host!!)
            assertEquals("probability mismatch for ${entry.url}", entry.probability, actual, 1e-4)
        }
    }

    @Test
    fun normalisationFollowsPythonSteps() {
        assertEquals("example.com", UrlHostClassifier.normalizeHost("https://WWW.Example.COM:8080/x"))
        assertEquals("host", UrlHostClassifier.normalizeHost("user@host"))
        assertEquals("example.com", UrlHostClassifier.normalizeHost("http://example.com."))
        assertEquals("example.com", UrlHostClassifier.normalizeHost("example.com."))
        assertEquals("x.com", UrlHostClassifier.normalizeHost("www.x.com"))
        assertEquals("x.com", UrlHostClassifier.normalizeHost("https://www.x.com/path?q=1"))
        assertEquals("example.com", UrlHostClassifier.normalizeHost("  example.com  "))
        assertNull(UrlHostClassifier.normalizeHost(""))
        assertNull(UrlHostClassifier.normalizeHost("     "))
    }

    @Test
    fun knownPhishingHostIsFlagged() {
        assertTrue(UrlHostClassifier.isPhishing(model, "sbi-kyc-update.xyz"))
        assertTrue(UrlHostClassifier.probability(model, "sbi-kyc-update.xyz") >= model.threshold)
    }

    @Test
    fun knownBenignHostsAreNotFlagged() {
        for (host in listOf("sbi.co.in", "google.com", "amazon.in", "hdfcbank.com")) {
            val probability = UrlHostClassifier.probability(model, host)
            assertFalse(
                "$host should stay below the threshold (p=$probability)",
                UrlHostClassifier.isPhishing(model, host)
            )
        }
    }

    @Test
    fun shippedModelIsTheTrainedOneNotAFixture() {
        assertTrue("vocabulary too small: ${model.vocabulary.size}", model.vocabulary.size >= 5_000)
        assertEquals("UrlHostClassifier", model.detectorId)
    }
}
