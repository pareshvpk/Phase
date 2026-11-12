package com.arm.threatassistant.domain.detection.smsclassifier

import kotlin.math.sqrt

/**
 * TF-IDF vectorizer for inference only.
 *
 * Transforms a list of preprocessed n-gram terms into a fixed-length TF-IDF
 * vector using the model's vocabulary and pre-computed IDF values. Terms not
 * in the vocabulary are ignored (out-of-vocabulary handling), unless a simple
 * morphological variant of the term is in the vocabulary (see
 * [resolveIndex]).
 *
 * The math must match the Python training pipeline exactly:
 *  - TF = raw term frequency (count of term in document)
 *  - IDF = pre-computed from training (smooth IDF: log((n_docs + 1) / (df + 1)) + 1)
 *  - TF-IDF = TF * IDF
 *  - L2 normalization of the resulting vector
 */
object TfIdfVectorizer {

    // Suffixes stripped to recover a dictionary form of an out-of-vocabulary
    // term. Ordered from most to least specific.
    private val STEM_SUFFIXES = listOf("ies", "ing", "ed", "es", "s")

    // Minimum length of a term / of its stem for stemming to be attempted.
    // Short words are too ambiguous to fold safely ("fees" -> "fee" is fine,
    // but "gas" -> "ga" is not).
    private const val MIN_STEM_LENGTH = 4

    /**
     * Transforms [terms] into an L2-normalized TF-IDF vector aligned with
     * [model]'s vocabulary.
     *
     * Returns a DoubleArray of size model.vocabulary.size, where each position
     * corresponds to the vocabulary entry at the same index. Out-of-vocabulary
     * terms contribute nothing.
     */
    fun vectorize(terms: List<String>, model: SmsClassifierModel): DoubleArray {
        val vocabSize = model.vocabulary.size
        val vector = DoubleArray(vocabSize)

        if (terms.isEmpty() || vocabSize == 0) {
            return vector
        }

        // Raw term frequencies.
        val tf = SmsTextPreprocessor.termFrequencies(terms)

        // Build index map: term -> position in vocabulary.
        val vocabIndex = model.vocabularyIndex

        // Compute TF-IDF values.
        for ((term, count) in tf) {
            val idx = resolveIndex(term, vocabIndex) ?: continue
            val idf = model.idf[idx]
            vector[idx] += count.toDouble() * idf
        }

        // L2 normalization.
        var squaredSum = 0.0
        for (value in vector) {
            squaredSum += value * value
        }
        val norm = sqrt(squaredSum)
        if (norm > 0.0) {
            for (i in vector.indices) {
                vector[i] /= norm
            }
        }

        return vector
    }

    /**
     * Resolves [term] to a vocabulary index.
     *
     * An exact match always wins. Only when the term is out of vocabulary are
     * simple morphological variants tried (e.g. "suspended" -> "suspend"), so
     * that inflected forms still activate the trained feature without
     * changing the behaviour of terms the model already knows.
     */
    private fun resolveIndex(term: String, vocabIndex: Map<String, Int>): Int? {
        vocabIndex[term]?.let { return it }
        for (variant in stemVariants(term)) {
            vocabIndex[variant]?.let { return it }
        }
        return null
    }

    /**
     * Returns candidate dictionary forms of [term], most specific first.
     *
     * Only single words are stemmed; n-grams are matched exactly.
     */
    private fun stemVariants(term: String): List<String> {
        if (term.length < MIN_STEM_LENGTH + 1 || term.contains(' ')) {
            return emptyList()
        }
        val variants = mutableListOf<String>()
        for (suffix in STEM_SUFFIXES) {
            if (!term.endsWith(suffix)) {
                continue
            }
            val stem = term.dropLast(suffix.length)
            if (stem.length < MIN_STEM_LENGTH) {
                continue
            }
            variants.add(if (suffix == "ies") "${stem}y" else stem)
        }
        return variants
    }
}
