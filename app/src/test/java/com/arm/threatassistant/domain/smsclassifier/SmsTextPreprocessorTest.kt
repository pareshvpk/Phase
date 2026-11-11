package com.arm.threatassistant.domain.smsclassifier

import org.junit.Test
import org.junit.Assert.*

import com.arm.threatassistant.domain.detection.smsclassifier.SmsTextPreprocessor

/**
 * Unit tests for SmsTextPreprocessor.
 *
 * These tests exercise pure Kotlin logic only — no Android framework required.
 * They verify NFC normalization, lowercasing, tokenization, n-gram generation,
 * and edge cases (empty input, URLs, phones, Hinglish, long messages).
 */
class SmsTextPreprocessorTest {

    // ---- Unicode normalization ----

    @Test
    fun preprocessAppliesNfcNormalization() {
        // "e" + combining acute accent (U+0301) should compose to é (U+00E9).
        val terms = SmsTextPreprocessor.preprocess("e\u0301")
        assertTrue(terms.any { it.contains("\u00E9") }, "Expected NFC-composed é, got $terms")
    }

    // ---- Lowercase handling ----

    @Test
    fun preprocessLowercases() {
        val terms = SmsTextPreprocessor.preprocess("URGENT Action Required")
        assertTrue(terms.any { it == "urgent" }, "Expected 'urgent', got $terms")
        assertFalse(terms.any { it == "URGENT" }, "Should not retain uppercase, got $terms")
    }

    // ---- Tokenization ----

    @Test
    fun preprocessTokenizesOnNonAlphanumeric() {
        val terms = SmsTextPreprocessor.preprocess("Hello, world! Test-123.")
        assertTrue(terms.contains("hello"), "Expected 'hello', got $terms")
        assertTrue(terms.contains("world"), "Expected 'world', got $terms")
        assertTrue(terms.contains("test"), "Expected 'test', got $terms")
        assertTrue(terms.contains("123"), "Expected '123', got $terms")
    }

    @Test
    fun preprocessDropsSingleCharacterTokens() {
        // "a b c" should produce no tokens (all length < 2).
        val terms = SmsTextPreprocessor.preprocess("a b c")
        assertTrue(terms.isEmpty(), "Expected no tokens for single-char input, got $terms")
    }

    // ---- N-grams ----

    @Test
    fun preprocessProducesUnigramsAndBigrams() {
        val terms = SmsTextPreprocessor.preprocess("share your otp")
        assertTrue(terms.contains("share"), "Expected unigram 'share', got $terms")
        assertTrue(terms.contains("your"), "Expected unigram 'your', got $terms")
        assertTrue(terms.contains("otp"), "Expected unigram 'otp', got $terms")
        assertTrue(terms.contains("share your"), "Expected bigram 'share your', got $terms")
        assertTrue(terms.contains("your otp"), "Expected bigram 'your otp', got $terms")
    }

    @Test
    fun preprocessSingleWordProducesOnlyUnigram() {
        val terms = SmsTextPreprocessor.preprocess("urgent")
        assertEquals(listOf("urgent"), terms, "Expected only 'urgent', got $terms")
    }

    // ---- Empty input ----

    @Test
    fun preprocessEmptyInputReturnsEmpty() {
        assertTrue(SmsTextPreprocessor.preprocess("").isEmpty())
        assertTrue(SmsTextPreprocessor.preprocess("   ").isEmpty())
        assertTrue(SmsTextPreprocessor.preprocess("\n\t\r ").isEmpty())
    }

    // ---- URLs and phone numbers ----

    @Test
    fun preprocessHandlesUrls() {
        val terms = SmsTextPreprocessor.preprocess("Click https://example.com now")
        assertTrue(terms.contains("click"), "Expected 'click', got $terms")
        assertTrue(terms.contains("example"), "Expected 'example', got $terms")
        assertTrue(terms.contains("com"), "Expected 'com', got $terms")
        assertTrue(terms.contains("now"), "Expected 'now', got $terms")
    }

    @Test
    fun preprocessHandlesPhoneNumbers() {
        val terms = SmsTextPreprocessor.preprocess("Call +1-234-567-7890 now")
        assertTrue(terms.contains("call"), "Expected 'call', got $terms")
        assertTrue(terms.contains("234"), "Expected '234', got $terms")
        assertTrue(terms.contains("567"), "Expected '567', got $terms")
        assertTrue(terms.contains("7890"), "Expected '7890', got $terms")
    }

    // ---- Hinglish and mixed Unicode ----

    @Test
    fun preprocessHandlesHinglish() {
        // Hinglish: English + Devanagari. Devanagari characters are alphanumeric
        // in Unicode, so they form tokens.
        val terms = SmsTextPreprocessor.preprocess("Your account \u092E\u0930\u094D\u092A\u093E\u0924 will be blocked")
        assertTrue(terms.any { it == "your" || it == "account" || it == "will" || it == "be" || it == "blocked" },
            "Expected English tokens, got $terms")
        // Devanagari word "bank" (\u092E\u0930\u094D\u092A\u093E\u0924) should be a token.
        assertTrue(terms.any { it.contains("\u092E") }, "Expected Devanagari token, got $terms")
    }

    // ---- Long messages ----

    @Test
    fun preprocessHandlesLongMessageWithoutCrash() {
        val longText = "urgent otp verify account suspend ".repeat(5000)
        val terms = SmsTextPreprocessor.preprocess(longText)
        assertTrue(terms.isNotEmpty(), "Expected tokens for long message")
        assertTrue(terms.contains("urgent"), "Expected 'urgent' in long message, got $terms")
    }

    // ---- termFrequencies ----

    @Test
    fun termFrequenciesCountsCorrectly() {
        val freqs = SmsTextPreprocessor.termFrequencies(listOf("a", "b", "a", "c", "a", "b"))
        assertEquals(3, freqs["a"])
        assertEquals(2, freqs["b"])
        assertEquals(1, freqs["c"])
    }

    @Test
    fun termFrequenciesEmptyReturnsEmptyMap() {
        assertTrue(SmsTextPreprocessor.termFrequencies(emptyList()).isEmpty())
    }
}
