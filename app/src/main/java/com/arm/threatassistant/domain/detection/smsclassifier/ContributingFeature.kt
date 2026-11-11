package com.arm.threatassistant.domain.detection.smsclassifier

/**
 * A single feature that contributed to the classifier's prediction.
 *
 * [term] is the n-gram term. [tfidfValue] is its TF-IDF weight in the input
 * vector. [weight] is the model's learned weight for that term. [contribution]
 * is weight * tfidfValue — the signed push this feature exerted on the
 * log-odds score.
 */
data class ContributingFeature(
    val term: String,
    val tfidfValue: Double,
    val weight: Double,
    val contribution: Double
)
