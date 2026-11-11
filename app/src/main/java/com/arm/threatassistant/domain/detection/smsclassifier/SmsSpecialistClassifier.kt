package com.arm.threatassistant.domain.detection.smsclassifier

import kotlin.math.exp

/**
 * SMS Specialist Classifier — logistic regression inference with TF-IDF features.
 *
 * This is a pure-Kotlin, CPU-only, fully offline detector. It loads a trained
 * model artifact (JSON) and produces a [SmsClassifierResult] for a given
 * [AnalysisInput].
 *
 * Design:
 *  - Logistic regression with TF-IDF features (word unigrams + bigrams).
 *  - Sigmoid output mapped to [0.0, 1.0] threat probability.
 *  - Deterministic inference — same input always produces same output.
 *  - No network, no LLM, no ExecuTorch, no ONNX, no external dependencies.
 *
 * Evidence only: this classifier does NOT produce a final threat verdict.
 * The [AnalysisResult.verdict] field must never be set by this class.
 */
class SmsSpecialistClassifier private constructor(
    private val model: SmsClassifierModel?,
    private val modelLoadError: String?
) {

    /**
     * Creates a classifier from a loaded model. If [model] is null, the
     * classifier reports [SmsClassifierStatus.UNAVAILABLE] with the given
     * [modelLoadError].
     */
    private constructor(model: SmsClassifierModel?) : this(model, null)

    /**
     * Creates a classifier in an unavailable state (model missing/corrupt).
     */
    private constructor(modelLoadError: String) : this(null, modelLoadError)

    companion object {
        internal const val DETECTOR_ID = "SmsSpecialistClassifier"
        internal const val DETECTOR_VERSION = "1.0.0"

        /** Creates an unavailable classifier without requiring a Context. */
        fun unavailable(reason: String): SmsSpecialistClassifier {
            return SmsSpecialistClassifier(reason)
        }

        /** Loads a model from an asset and creates a classifier (static factory). */
        @JvmStatic
        fun fromAssets(context: android.content.Context, assetName: String): SmsSpecialistClassifier {
            return try {
                val model = SmsClassifierModelLoader.loadFromAssets(context, assetName)
                SmsSpecialistClassifier(model)
            } catch (e: Exception) {
                SmsSpecialistClassifier("Failed to load model from asset '$assetName': ${e.message}")
            }
        }

        /** Creates a classifier directly from a [SmsClassifierModel] (static factory). */
        @JvmStatic
        fun fromModel(model: SmsClassifierModel): SmsSpecialistClassifier {
            return SmsSpecialistClassifier(model)
        }
    }

    /**
     * Classifies [input] and returns a [SmsClassifierResult].
     *
     * Never returns SAFE merely because inference failed — failures are
     * reported as [SmsClassifierStatus.ERROR] or [UNAVAILABLE] with a null
     * predicted label.
     */
    fun classify(input: com.arm.threatassistant.domain.model.AnalysisInput): SmsClassifierResult {
        val text = input.normalizedText ?: input.messageText

        // Unsupported input: blank text cannot be meaningfully classified.
        if (text.isBlank()) {
            return SmsClassifierResult(
                status = SmsClassifierStatus.UNSUPPORTED_INPUT,
                predictedLabel = null,
                threatScore = null,
                isCalibrated = model?.isCalibrated ?: false,
                modelVersion = model?.modelVersion,
                detectorId = DETECTOR_ID,
                detectorVersion = DETECTOR_VERSION,
                contributingFeatures = null,
                errorMessage = "Input text is blank; classifier cannot evaluate unsupported input."
            )
        }

        // Model unavailable: never interpret as SAFE.
        if (model == null) {
            return SmsClassifierResult(
                status = SmsClassifierStatus.UNAVAILABLE,
                predictedLabel = null,
                threatScore = null,
                isCalibrated = false,
                modelVersion = null,
                detectorId = DETECTOR_ID,
                detectorVersion = DETECTOR_VERSION,
                contributingFeatures = null,
                errorMessage = modelLoadError ?: "No model loaded."
            )
        }
        val m = model!!

        return try {
            runInference(text, m)
        } catch (e: Exception) {
            SmsClassifierResult(
                status = SmsClassifierStatus.ERROR,
                predictedLabel = null,
                threatScore = null,
                isCalibrated = m.isCalibrated,
                modelVersion = m.modelVersion,
                detectorId = DETECTOR_ID,
                detectorVersion = DETECTOR_VERSION,
                contributingFeatures = null,
                errorMessage = "Inference failed: ${e.message}"
            )
        }
    }

    private fun runInference(text: String, m: SmsClassifierModel): SmsClassifierResult {
        // Preprocess: NFC, lowercase, tokenize, n-grams.
        val terms = SmsTextPreprocessor.preprocess(text)

        // Empty after preprocessing (e.g., only punctuation or single chars).
        if (terms.isEmpty()) {
            return SmsClassifierResult(
                status = SmsClassifierStatus.UNSUPPORTED_INPUT,
                predictedLabel = null,
                threatScore = null,
                isCalibrated = m.isCalibrated,
                modelVersion = m.modelVersion,
                detectorId = DETECTOR_ID,
                detectorVersion = DETECTOR_VERSION,
                contributingFeatures = null,
                errorMessage = "Input produced no usable tokens after preprocessing."
            )
        }

        // Vectorize: TF-IDF against model vocabulary.
        val vector = TfIdfVectorizer.vectorize(terms, m)

        // Logistic regression: score = w · x + b; probability = sigmoid(score).
        var score = m.bias
        for (i in vector.indices) {
            score += vector[i] * m.weights[i]
        }
        val probability = sigmoid(score)

        val label = if (probability >= m.threshold) "THREAT" else "SAFE"

        // Top contributing features (by absolute contribution) for explainability.
        val contributions = mutableListOf<ContributingFeature>()
        for (i in vector.indices) {
            val tfidf = vector[i]
            if (tfidf != 0.0) {
                val weight = m.weights[i]
                val contribution = weight * tfidf
                contributions.add(
                    ContributingFeature(
                        term = m.vocabulary[i],
                        tfidfValue = tfidf,
                        weight = weight,
                        contribution = contribution
                    )
                )
            }
        }
        contributions.sortByDescending { Math.abs(it.contribution) }
        val topFeatures = contributions.take(10)

        return SmsClassifierResult(
            status = SmsClassifierStatus.AVAILABLE,
            predictedLabel = label,
            threatScore = probability,
            isCalibrated = m.isCalibrated,
            modelVersion = m.modelVersion,
            detectorId = DETECTOR_ID,
            detectorVersion = DETECTOR_VERSION,
            contributingFeatures = topFeatures,
            errorMessage = null
        )
    }

    private fun sigmoid(x: Double): Double {
        return 1.0 / (1.0 + exp(-x))
    }
}
