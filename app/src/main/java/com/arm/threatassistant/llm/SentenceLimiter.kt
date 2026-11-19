package com.arm.threatassistant.llm

/**
 * Counts complete sentences in streamed model output so generation can stop
 * early once the requested number of sentences is reached.
 *
 * Pure Kotlin with no Android dependencies so it can be unit-tested on the JVM.
 * A sentence ends at `.`, `!`, `?` or `।` followed by whitespace or the end of
 * the text. Dots inside numbers ("2.5", "Rs.500") are not sentence ends.
 */
object SentenceLimiter {

    private const val DEFAULT_MAX_SENTENCES = 2

    fun reached(text: String, maxSentences: Int = DEFAULT_MAX_SENTENCES): Boolean {
        if (maxSentences <= 0) return true
        var count = 0
        for (i in text.indices) {
            val c = text[i]
            if (c != '.' && c != '!' && c != '?' && c != '।') continue
            val atEnd = i + 1 == text.length
            if (!atEnd && !text[i + 1].isWhitespace()) continue
            if (c == '.' && isNumberDot(text, i)) continue
            count += 1
            if (count >= maxSentences) return true
        }
        return false
    }

    /**
     * True for the dot in a decimal or currency amount such as "2.5" or
     * "Rs.500": the character right after the dot is a digit and the dot is not
     * itself the end of a sentence.
     */
    private fun isNumberDot(text: String, index: Int): Boolean {
        val next = text.getOrNull(index + 1) ?: return false
        return next.isDigit()
    }
}
