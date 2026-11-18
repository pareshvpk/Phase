package com.arm.threatassistant.presentation.result

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class RiskHighlighterTest {

    @Test
    fun matchesCaseInsensitively() {
        val message = "Your ACCOUNT will be blocked today"

        val spans = RiskHighlighter.spans(message, listOf("account will be blocked"))

        assertEquals(listOf(HighlightSpan(5, 28)), spans)
    }

    @Test
    fun everyOccurrenceIsHighlighted() {
        val message = "code code code"

        val spans = RiskHighlighter.spans(message, listOf("code"))

        assertEquals(
            listOf(HighlightSpan(0, 4), HighlightSpan(5, 9), HighlightSpan(10, 14)),
            spans
        )
    }

    @Test
    fun overlappingSpansAreMerged() {
        val message = "your account blocked today"

        val spans = RiskHighlighter.spans(
            message,
            listOf("account blocked", "blocked today")
        )

        assertEquals(listOf(HighlightSpan(5, 26)), spans)
    }

    @Test
    fun adjacentSpansAreMerged() {
        val message = "wiretransfer now"

        val spans = RiskHighlighter.spans(message, listOf("wire", "transfer"))

        assertEquals(listOf(HighlightSpan(0, 12)), spans)
    }

    @Test
    fun spansAreSortedAndUseOriginalIndices() {
        val message = "block the account, then verify the otp"

        val spans = RiskHighlighter.spans(message, listOf("verify the otp", "block the account"))

        assertEquals(
            listOf(
                HighlightSpan(0, 17),
                HighlightSpan(24, 38)
            ),
            spans
        )
    }

    @Test
    fun whitespaceDifferencesStillMatch() {
        val message = "please   send the\ncode now"
        val phrase = "please send the code"

        val spans = RiskHighlighter.spans(message, listOf(phrase))

        assertEquals(listOf(HighlightSpan(0, 22)), spans)
    }

    @Test
    fun phraseNotFoundIsSkipped() {
        val spans = RiskHighlighter.spans(
            "nothing suspicious here",
            listOf("wire transfer immediately")
        )

        assertTrue(spans.isEmpty())
    }

    @Test
    fun emptyAndTinyInputsProduceNoSpans() {
        assertTrue(RiskHighlighter.spans("", listOf("otp")).isEmpty())
        assertTrue(RiskHighlighter.spans("share the otp now", emptyList()).isEmpty())
        assertTrue(RiskHighlighter.spans("share the otp now", listOf("  ", "ab", "ot")).isEmpty())
    }

    @Test
    fun hindiTextIsHighlighted() {
        val message = "आपका खाता तुरंत ब्लॉक हो जाएगा"
        val phrase = "खाता तुरंत"
        val start = message.indexOf(phrase)
        assertTrue(start >= 0)

        val spans = RiskHighlighter.spans(message, listOf(phrase))

        assertEquals(listOf(HighlightSpan(start, start + phrase.length)), spans)
    }

    @Test
    fun hindiPhraseWithDifferentWhitespaceStillMatches() {
        val message = "आपका   खाता तुरंत ब्लॉक हो जाएगा"
        val phrase = "खाता तुरंत"
        val start = message.indexOf(phrase)
        assertTrue(start >= 0)

        val spans = RiskHighlighter.spans(message, listOf(phrase))

        assertEquals(listOf(HighlightSpan(start, start + phrase.length)), spans)
    }

    @Test
    fun spanCountIsCapped() {
        val message = List(40) { "risk" }.joinToString(" ")

        val spans = RiskHighlighter.spans(message, listOf("risk"))

        assertEquals(RiskHighlighter.MAX_SPANS, spans.size)
        assertEquals(HighlightSpan(0, 4), spans.first())
    }
}
