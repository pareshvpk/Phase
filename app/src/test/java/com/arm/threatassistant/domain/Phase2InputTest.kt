package com.arm.threatassistant.domain

import org.junit.Test
import org.junit.Assert.*

import com.arm.threatassistant.domain.adapters.ManualInputAdapter
import com.arm.threatassistant.domain.adapters.ProcessTextAdapter
import com.arm.threatassistant.domain.adapters.ShareSheetAdapter
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.InputSource
import com.arm.threatassistant.domain.normalization.InputNormalizer

/**
 * Unit tests for Phase 2 input ingestion and normalization.
 *
 * These tests exercise pure Kotlin/Java logic only and do not require the
 * Android framework. Intent-based adapter paths (ShareSheetAdapter,
 * ProcessTextAdapter) are exercised through their shared [adapt] method;
 * Intent extraction is covered by the manifest intent filters and the
 * MainActivity wiring.
 */
class Phase2InputTest {

    private val adapter = ManualInputAdapter()

    @Test
    fun manualAdapterRejectsEmptyInput() {
        assertNull(adapter.adapt(""))
        assertNull(adapter.adapt(null ?: ""))
    }

    @Test
    fun manualAdapterRejectsWhitespaceOnlyInput() {
        assertNull(adapter.adapt("   "))
        assertNull(adapter.adapt("\n\t\r "))
    }

    @Test
    fun manualAdapterAcceptsNormalSmsText() {
        val input = adapter.adapt("Free money! Click here now.")
        assertNotNull(input)
        assertEquals("Free money! Click here now.", input!!.messageText)
        assertEquals(InputSource.MANUAL, input.source)
    }

    @Test
    fun manualAdapterAppliesLengthLimit() {
        val longText = "a".repeat(10000)
        val input = adapter.adapt(longText)
        assertNotNull(input)
        assertTrue(input!!.messageText.length <= 5000)
        assertEquals("true", input.processingMetadata["truncated"])
    }

    @Test
    fun normalizerPreservesOriginalInput() {
        val original = "Café ☃"
        val input = AnalysisInput(messageText = original)
        val result = InputNormalizer.normalize(input)
        assertEquals(original, result.messageText)
    }

    @Test
    fun normalizerProducesNfcNormalizedText() {
        // "e" + combining acute accent (U+0301) should compose to é (U+00E9) under NFC.
        val decomposed = "e\u0301"
        val result = InputNormalizer.normalize(decomposed)
        assertEquals("\u00E9", result.normalizedText)
    }

    @Test
    fun normalizerExtractsMultipleUrls() {
        val text = "Visit https://example.com and http://sub.example.org/path?q=1 or www.example.net."
        val result = InputNormalizer.normalize(text)
        assertTrue(result.extractedUrls.size >= 2, "Expected multiple URLs, got ${result.extractedUrls}")
        assertTrue(result.extractedUrls.any { it.startsWith("https://example.com") })
        assertTrue(result.extractedHosts.any { it == "example.com" })
    }

    @Test
    fun normalizerHandlesMalformedUrlsWithoutCrashing() {
        val text = "Check http://not-a-valid..host and http://[ipv6 and weird://scheme"
        // Should not throw.
        val result = InputNormalizer.normalize(text)
        assertNotNull(result.normalizedText)
    }

    @Test
    fun normalizerExtractsHostnamesSeparately() {
        val text = "https://example.com/page"
        val result = InputNormalizer.normalize(text)
        assertTrue(result.extractedHosts.contains("example.com"))
    }

    @Test
    fun normalizerExtractsPhoneNumbers() {
        val text = "Call +1-234-567-7890 or (234) 567-7890."
        val result = InputNormalizer.normalize(text)
        assertTrue(result.extractedPhones.isNotEmpty(), "Expected phone extraction, got $result")
    }

    @Test
    fun normalizerDetectsZeroWidthCharacters() {
        val text = "Hello\u200BWorld" // zero-width space between
        val result = InputNormalizer.normalize(text)
        assertTrue(result.warnings.any { it.contains("Zero-width") }, "Expected zero-width warning, got $result")
        // Character must not be silently removed.
        assertTrue(result.normalizedText.contains("\u200B"))
    }

    @Test
    fun normalizerHandlesMixedLatinCyrillic() {
        val text = "Hello Привет Hello" // mixed script
        val result = InputNormalizer.normalize(text)
        assertNotNull(result.normalizedText)
        assertTrue(result.normalizedText.contains("Привет"))
    }

    @Test
    fun normalizerHandlesExtremelyLongMessages() {
        val longText = "x".repeat(200_000)
        val result = InputNormalizer.normalize(longText)
        assertEquals(longText, result.normalizedText)
        assertTrue(result.warnings.any { it.contains("exceeds") })
    }

    @Test
    fun normalizerDoesNotTruncateUtf8Sequences() {
        // A string longer than any limit built of multi-byte characters must remain whole.
        val text = "☃".repeat(10_000)
        val result = InputNormalizer.normalize(text)
        assertEquals(text, result.normalizedText)
    }

    @Test
    fun normalizerClassifiesNothingAndMakesNoNetworkCalls() {
        val text = "https://example.com suspicious content"
        val result = InputNormalizer.normalize(text)
        // No verdict / classification fields exist on the result.
        assertNotNull(result.normalizedText)
        assertFalse(result.warnings.any { it.contains("safe") || it.contains("malicious") })
    }

    @Test
    fun shareSheetAdapterAdaptRejectsBlank() {
        assertNull(ShareSheetAdapter().adapt(""))
        assertNull(ShareSheetAdapter().adapt("  "))
    }

    @Test
    fun shareSheetAdapterAdaptAcceptsText() {
        val input = ShareSheetAdapter().adapt("shared message https://example.com")
        assertNotNull(input)
        assertEquals(InputSource.SHARE_SHEET, input!!.source)
        assertTrue(input.extractedUrls.isNotEmpty() || input.messageText.contains("https://example.com"))
    }

    @Test
    fun processTextAdapterAdaptRejectsBlank() {
        assertNull(ProcessTextAdapter().adapt(""))
        assertNull(ProcessTextAdapter().adapt("\t"))
    }

    @Test
    fun processTextAdapterAdaptAcceptsText() {
        val input = ProcessTextAdapter().adapt("selected text")
        assertNotNull(input)
        assertEquals(InputSource.PROCESS_TEXT, input!!.source)
        assertEquals("selected text", input.messageText)
    }

    @Test
    fun analysisInputDefaultsPreservePhase1Behaviour() {
        // Existing constructor signature remains compatible.
        val input = AnalysisInput(messageText = "hello")
        assertEquals("hello", input.messageText)
        assertNull(input.normalizedText)
        assertEquals(InputSource.MANUAL, input.source)
        assertTrue(input.extractedUrls.isEmpty())
        assertTrue(input.normalizationWarnings.isEmpty())
    }
}
