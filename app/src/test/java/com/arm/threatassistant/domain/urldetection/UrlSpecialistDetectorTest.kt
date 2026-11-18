package com.arm.threatassistant.domain.detection.urldetection

import com.arm.threatassistant.domain.model.AnalysisInput
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class UrlSpecialistDetectorTest {

    private val detector = UrlSpecialistDetector

    private fun input(text: String): AnalysisInput = AnalysisInput(messageText = text)

    @Test
    fun ipBasedUrlIsDetected() {
        val result = detector.detect(input("Visit http://192.168.1.1/login now"))
        assertTrue(result.hasSignals)
        assertTrue(result.signals.any { it.category == UrlDetectionCategory.IP_BASED_URL })
        assertTrue(result.signals.any { it.severity == UrlDetectionSeverity.HIGH })
    }

    @Test
    fun urlShortenerIsDetected() {
        val result = detector.detect(input("Click https://bit.ly/3xYzAbc"))
        assertTrue(result.signals.any { it.category == UrlDetectionCategory.URL_SHORTENER })
    }

    @Test
    fun suspiciousTldIsDetected() {
        val result = detector.detect(input("Visit http://example.xyz"))
        assertTrue(result.signals.any { it.category == UrlDetectionCategory.SUSPICIOUS_TLD })
    }

    @Test
    fun homographAttackIsDetected() {
        // Mixed Latin + Cyrillic in domain
        val result = detector.detect(input("Visit http://paypa\u0431.com"))
        assertTrue(result.signals.any { it.category == UrlDetectionCategory.HOMOGRAPH_ATTACK })
    }

    @Test
    fun unusualPortIsDetected() {
        val result = detector.detect(input("Visit http://example.com:8080/"))
        assertTrue(result.signals.any { it.category == UrlDetectionCategory.UNUSUAL_PORT })
    }

    @Test
    fun encodedCharactersAreDetected() {
        val result = detector.detect(input("Visit http://example.com/%2Fadmin"))
        assertTrue(result.signals.any { it.category == UrlDetectionCategory.ENCODED_CHARACTERS })
    }

    @Test
    fun misleadingStructureWithAtSign() {
        val result = detector.detect(input("Visit http://user@paypal.com.evil.com/"))
        assertTrue(result.signals.any { it.category == UrlDetectionCategory.MISLEADING_STRUCTURE })
    }

    @Test
    fun suspiciousDomainKeywordsAreDetected() {
        val result = detector.detect(input("Visit http://secure-account-verify.com"))
        assertTrue(result.signals.any { it.category == UrlDetectionCategory.SUSPICIOUS_DOMAIN })
    }

    @Test
    fun legitimateUrlProducesNoSignals() {
        val result = detector.detect(input("Visit https://www.google.com"))
        assertFalse(result.hasSignals)
    }

    @Test
    fun emptyInputProducesNoSignals() {
        val result = detector.detect(input(""))
        assertFalse(result.hasSignals)
        assertTrue(result.urls.isEmpty())
    }

    @Test
    fun noUrlsProducesNoSignals() {
        val result = detector.detect(input("Just some plain text with no links"))
        assertFalse(result.hasSignals)
        assertTrue(result.urls.isEmpty())
    }

    @Test
    fun multipleSignalsCanFireForOneUrl() {
        val result = detector.detect(input("Click http://192.168.1.1:8080/login"))
        assertTrue(result.signalCount >= 2)
    }

    @Test
    fun mlHostModelAddsPhishingSignalOnlyWhenProvided() {
        val model = UrlHostModel.parse(
            File("src/main/assets/url_host_model.json").readText(Charsets.UTF_8)
        )
        val phishingInput = input("Visit http://sbi-kyc-update.xyz/login now")

        val withModel = detector.detect(phishingInput, model)
        val mlSignals = withModel.signals.filter {
            it.category == UrlDetectionCategory.ML_PHISHING_HOST
        }
        assertEquals(1, mlSignals.size)
        assertEquals(UrlDetectionSeverity.MEDIUM, mlSignals[0].severity)
        assertEquals(
            "Machine-learning model: this web address looks like a phishing site.",
            mlSignals[0].description
        )
        assertEquals("sbi-kyc-update.xyz", mlSignals[0].matchedComponent)

        val withoutModel = detector.detect(phishingInput)
        assertFalse(
            withoutModel.signals.any { it.category == UrlDetectionCategory.ML_PHISHING_HOST }
        )
        assertEquals(
            withoutModel.signals.map { it.category },
            withModel.signals
                .map { it.category }
                .filter { it != UrlDetectionCategory.ML_PHISHING_HOST }
        )

        val benignInput = input("Visit https://www.google.com")
        val benignWithModel = detector.detect(benignInput, model)
        assertFalse(
            benignWithModel.signals.any { it.category == UrlDetectionCategory.ML_PHISHING_HOST }
        )
        assertEquals(
            detector.detect(benignInput).signals.map { it.category },
            benignWithModel.signals.map { it.category }
        )
    }

    @Test
    fun resultHasDetectorMetadata() {
        val result = detector.detect(input("http://bit.ly/x"))
        assertEquals("UrlSpecialistDetector", result.detectorId)
        assertEquals("1.0.0", result.detectorVersion)
    }
}
