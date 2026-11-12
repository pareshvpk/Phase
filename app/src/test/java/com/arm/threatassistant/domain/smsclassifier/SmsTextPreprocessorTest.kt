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
        assertTrue("Expected NFC-composed é, got $terms", terms.any { it.contains("\u00E9") })
    }

    // ---- Lowercase handling ----

    @Test
    fun preprocessLowercases() {
        val terms = SmsTextPreprocessor.preprocess("URGENT Action Required")
        assertTrue("Expected 'urgent', got $terms", terms.any { it == "urgent" })
        assertFalse("Should not retain uppercase, got $terms", terms.any { it == "URGENT" })
    }

    // ---- Tokenization ----

    @Test
    fun preprocessTokenizesOnNonAlphanumeric() {
        val terms = SmsTextPreprocessor.preprocess("Hello, world! Test-123.")
        assertTrue("Expected 'hello', got $terms", terms.contains("hello"))
        assertTrue("Expected 'world', got $terms", terms.contains("world"))
        assertTrue("Expected 'test', got $terms", terms.contains("test"))
        assertTrue("Expected '123', got $terms", terms.contains("123"))
    }

    @Test
    fun preprocessDropsSingleCharacterTokens() {
        // "a b c" should produce no tokens (all length < 2).
        val terms = SmsTextPreprocessor.preprocess("a b c")
        assertTrue("Expected no tokens for single-char input, got $terms", terms.isEmpty())
    }

    // ---- N-grams ----

    @Test
    fun preprocessProducesUnigramsAndBigrams() {
        val terms = SmsTextPreprocessor.preprocess("share your otp")
        assertTrue("Expected unigram 'share', got $terms", terms.contains("share"))
        assertTrue("Expected unigram 'your', got $terms", terms.contains("your"))
        assertTrue("Expected unigram 'otp', got $terms", terms.contains("otp"))
        assertTrue("Expected bigram 'share your', got $terms", terms.contains("share your"))
        assertTrue("Expected bigram 'your otp', got $terms", terms.contains("your otp"))
    }

    @Test
    fun preprocessSingleWordProducesOnlyUnigram() {
        val terms = SmsTextPreprocessor.preprocess("urgent")
        assertEquals("Expected only 'urgent', got $terms", listOf("urgent"), terms)
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
        assertTrue("Expected 'click', got $terms", terms.contains("click"))
        assertTrue("Expected 'example', got $terms", terms.contains("example"))
        assertTrue("Expected 'com', got $terms", terms.contains("com"))
        assertTrue("Expected 'now', got $terms", terms.contains("now"))
    }

    @Test
    fun preprocessHandlesPhoneNumbers() {
        val terms = SmsTextPreprocessor.preprocess("Call +1-234-567-7890 now")
        assertTrue("Expected 'call', got $terms", terms.contains("call"))
        assertTrue("Expected '234', got $terms", terms.contains("234"))
        assertTrue("Expected '567', got $terms", terms.contains("567"))
        assertTrue("Expected '7890', got $terms", terms.contains("7890"))
    }

    // ---- Hinglish and mixed Unicode ----

    @Test
    fun preprocessHandlesHinglish() {
        // Hinglish: English + Devanagari. Devanagari characters are alphanumeric
        // in Unicode, so they form tokens.
        val terms = SmsTextPreprocessor.preprocess("Your account \u092E\u0930\u094D\u092A\u093E\u0924 will be blocked")
        assertTrue("Expected English tokens, got $terms", terms.any { it == "your" || it == "account" || it == "will" || it == "be" || it == "blocked" })
        // Devanagari word "bank" (\u092E\u0930\u094D\u092A\u093E\u0924) should be a token.
        assertTrue("Expected Devanagari token, got $terms", terms.any { it.contains("\u092E") })
    }

    // ---- Long messages ----

    @Test
    fun preprocessHandlesLongMessageWithoutCrash() {
        val longText = "urgent otp verify account suspend ".repeat(5000)
        val terms = SmsTextPreprocessor.preprocess(longText)
        assertTrue("Expected tokens for long message", terms.isNotEmpty())
        assertTrue("Expected 'urgent' in long message, got $terms", terms.contains("urgent"))
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
