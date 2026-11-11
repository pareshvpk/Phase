package com.arm.threatassistant.domain.detection.smsclassifier

/**
 * In-memory representation of a trained SMS specialist classifier model.
 *
 * Loaded from a JSON asset at runtime. All fields are required for inference
 * and are validated on load.
 *
 * Properties:
 * - [modelVersion] — version string of the model artifact.
 * - [detectorId] — stable detector identifier ("SmsSpecialistClassifier").
 * - [detectorVersion] — version of the detector code that produced this model.
 * - [vocabulary] — ordered list of n-gram terms; index position is the
 *   feature position in the TF-IDF vector.
 * - [idf] — pre-computed IDF value per vocabulary term, aligned by index.
 * - [weights] — learned logistic regression weight per vocabulary term,
 *   aligned by index.
 * - [bias] — learned intercept.
 * - [threshold] — decision threshold on the predicted probability.
 * - [labelMap] — mapping from label string to integer index.
 * - [isCalibrated] — whether probabilities were calibrated on validation data.
 * - [featureConfig] — preprocessing and vectorization configuration used
 *   during training, for reproducibility.
 * - [trainingInfo] — provenance metadata (dataset, sample counts, etc.).
 */
data class SmsClassifierModel(
    val modelVersion: String,
    val detectorId: String,
    val detectorVersion: String,
    val vocabulary: List<String>,
    val idf: List<Double>,
    val weights: List<Double>,
    val bias: Double,
    val threshold: Double,
    val labelMap: Map<String, Int>,
    val isCalibrated: Boolean,
    val featureConfig: Map<String, Any>,
    val trainingInfo: Map<String, Any>
) {
    /** Lazily built term -> index map for O(1) vocabulary lookup. */
    private var _vocabularyIndex: Map<String, Int>? = null
    val vocabularyIndex: Map<String, Int>
        get() {
            if (_vocabularyIndex == null) {
                _vocabularyIndex = vocabulary.withIndex().associateBy({ it.value }, { it.index })
            }
            return _vocabularyIndex!!
        }

    /**
     * Validates that the model is internally consistent. Throws
     * [IllegalArgumentException] if any check fails.
     */
    fun validate() {
        require(modelVersion.isNotBlank()) { "modelVersion must not be blank" }
        require(detectorId.isNotBlank()) { "detectorId must not be blank" }
        require(detectorVersion.isNotBlank()) { "detectorVersion must not be blank" }
        require(vocabulary.isNotEmpty()) { "vocabulary must not be empty" }
        require(idf.size == vocabulary.size) {
            "idf size (${idf.size}) must match vocabulary size (${vocabulary.size})"
        }
        require(weights.size == vocabulary.size) {
            "weights size (${weights.size}) must match vocabulary size (${vocabulary.size})"
        }
        require(threshold >= 0.0 && threshold <= 1.0) {
            "threshold must be in [0.0, 1.0], got $threshold"
        }
        require(labelMap.containsKey("SAFE")) { "labelMap must contain 'SAFE'" }
        require(labelMap.containsKey("THREAT")) { "labelMap must contain 'THREAT'" }
    }
}
