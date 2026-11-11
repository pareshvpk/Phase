package com.arm.threatassistant.domain.detection.smsclassifier

import kotlin.math.sqrt

/**
 * TF-IDF vectorizer for inference only.
 *
 * Transforms a list of preprocessed n-gram terms into a fixed-length TF-IDF
 * vector using the model's vocabulary and pre-computed IDF values. Terms not
 * in the vocabulary are ignored (out-of-vocabulary handling).
 *
 * The math must match the Python training pipeline exactly:
 *  - TF = raw term frequency (count of term in document)
 *  - IDF = pre-computed from training (smooth IDF: log((n_docs + 1) / (df + 1)) + 1)
 *  - TF-IDF = TF * IDF
 *  - L2 normalization of the resulting vector
 */
object TfIdfVectorizer {

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
        var squaredSum = 0.0
        for ((term, count) in tf) {
            val idx = vocabIndex[term] ?: continue
            val idf = model.idf[idx]
            val tfidf = count.toDouble() * idf
            vector[idx] = tfidf
            squaredSum += tfidf * tfidf
        }

        // L2 normalization.
        val norm = sqrt(squaredSum)
        if (norm > 0.0) {
            for (i in vector.indices) {
                vector[i] /= norm
            }
        }

        return vector
    }
}
