package com.arm.threatassistant.domain.detection.smsclassifier

import java.text.Normalizer

/**
 * Text preprocessing for the SMS specialist classifier.
 *
 * The pipeline must match the Python training pipeline exactly:
 * 1. Unicode NFC normalization
 * 2. Lowercasing
 * 3. Tokenization on Unicode letter/number boundaries (tokens of length >= 2)
 * 4. Word n-grams (unigrams + bigrams)
 *
 * Tokenization is Unicode-aware: any character that is a letter or a number in
 * *any* script is part of a token. An ASCII-only tokenizer would silently drop
 * Devanagari (and other non-Latin) words, which would break Hinglish and
 * regional-language messages — both the token itself and the bigrams built
 * from it.
 *
 * All processing is deterministic and pure Kotlin — no Android framework
 * dependencies, no network, no external libraries.
 */
object SmsTextPreprocessor {

    // Minimum token length — single-character tokens are dropped to match
    // sklearn's default token pattern behaviour (\b\w\w+\b).
    private const val MIN_TOKEN_LENGTH = 2

    // N-gram range: unigrams and bigrams only.
    private const val NGRAM_MIN = 1
    private const val NGRAM_MAX = 2

    // Token characters: Unicode letters and numbers. Everything else
    // (punctuation, whitespace, symbols, invisible/zero-width characters) is a
    // delimiter.
    private val TOKEN_BOUNDARY = Regex("[^\\p{L}\\p{N}]+")

    /**
     * Preprocesses [text] into a list of n-gram terms suitable for TF-IDF
     * vectorization.
     *
     * Steps:
     *  - NFC normalize for consistent Unicode representation.
     *  - Lowercase for case-insensitive matching.
     *  - Split on any non-letter/non-number sequence; drop noise tokens.
     *  - Emit unigrams and bigrams (joined by a single space).
     *
     * The original input text is never modified by this method.
     */
    fun preprocess(text: String): List<String> {
        if (text.isBlank()) {
            return emptyList()
        }

        // 1. NFC normalization + 2. Lowercasing
        val normalized = Normalizer.normalize(text, Normalizer.Form.NFC).lowercase()

        // 3. Tokenization: split on any non-letter/non-number sequence.
        val rawTokens = normalized.split(TOKEN_BOUNDARY)
        val tokens = rawTokens.filter { isUsableToken(it) }

        if (tokens.isEmpty()) {
            return emptyList()
        }

        // 4. Word n-grams (unigrams + bigrams).
        val ngrams = mutableListOf<String>()
        ngrams.addAll(tokens)

        if (NGRAM_MAX >= 2 && tokens.size >= 2) {
            for (i in 0 until tokens.size - 1) {
                ngrams.add("${tokens[i]} ${tokens[i + 1]}")
            }
        }

        return ngrams
    }

    /**
     * Decides whether a raw token is worth keeping.
     *
     * Tokens of two or more characters are always kept. A single-character
     * token is dropped as noise when it is ASCII ("a", "b", "1"), but kept
     * when it is a non-ASCII letter or digit: in several scripts a single
     * character carries meaning on its own (e.g. "é", "ॐ", "१"), and dropping
     * it would lose the NFC-normalized form of the text.
     */
    private fun isUsableToken(token: String): Boolean {
        if (token.length >= MIN_TOKEN_LENGTH) {
            return true
        }
        if (token.length != 1) {
            return false
        }
        val c = token[0]
        return c.code > 127 && (c.isLetter() || c.isDigit())
    }

    /**
     * Counts the frequency of each term in [terms].
     */
    fun termFrequencies(terms: List<String>): Map<String, Int> {
        val counts = mutableMapOf<String, Int>()
        for (term in terms) {
            counts[term] = (counts[term] ?: 0) + 1
        }
        return counts
    }
}
