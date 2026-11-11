package com.arm.threatassistant.domain.detection.smsclassifier

import java.text.Normalizer

/**
 * Text preprocessing for the SMS specialist classifier.
 *
 * The pipeline must match the Python training pipeline exactly:
 * 1. Unicode NFC normalization
 * 2. Lowercasing
 * 3. Tokenization on non-alphanumeric boundaries (tokens of length >= 2)
 * 4. Word n-grams (unigrams + bigrams)
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

    /**
     * Preprocesses [text] into a list of n-gram terms suitable for TF-IDF
     * vectorization.
     *
     * Steps:
     *  - NFC normalize for consistent Unicode representation.
     *  - Lowercase for case-insensitive matching.
     *  - Split on non-alphanumeric sequences; drop short tokens.
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

        // 3. Tokenization: split on any non-alphanumeric sequence.
        val rawTokens = normalized.split(Regex("[^a-zA-Z0-9]+"))
        val tokens = rawTokens.filter { it.length >= MIN_TOKEN_LENGTH }

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
