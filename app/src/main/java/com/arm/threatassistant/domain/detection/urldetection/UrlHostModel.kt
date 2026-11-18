package com.arm.threatassistant.domain.detection.urldetection

import android.content.Context
import java.io.IOException
import kotlin.math.exp
import kotlin.math.sqrt

/**
 * In-memory representation of the shipped phishing-URL host model
 * (`url_host_model.json`, detector id `UrlHostClassifier`).
 *
 * Character n-gram TF-IDF + logistic regression over the normalised host only.
 * Parsed from JSON with org.json exactly like
 * [com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierModel] /
 * [com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierModelLoader]:
 * unknown keys (`dataset`, `metrics`, ...) are ignored, required keys are
 * validated on load.
 *
 * Properties:
 * - [modelVersion] — version string of the model artifact.
 * - [detectorId] — stable detector identifier ("UrlHostClassifier").
 * - [ngramMin] / [ngramMax] — inclusive character n-gram length range.
 * - [vocabulary] — ordered n-gram terms; index position is the feature
 *   position in the TF-IDF vector.
 * - [idf] — pre-computed IDF value per vocabulary term, aligned by index.
 * - [weights] — learned logistic regression weight per vocabulary term.
 * - [bias] — learned intercept.
 * - [threshold] — decision threshold on the predicted probability.
 */
data class UrlHostModel(
    val modelVersion: String,
    val detectorId: String,
    val ngramMin: Int,
    val ngramMax: Int,
    val vocabulary: List<String>,
    val idf: List<Double>,
    val weights: List<Double>,
    val bias: Double,
    val threshold: Double
) {

    /**
     * Lazily built term -> index map. Built once per model instance and
     * reused by every [UrlHostClassifier.probability] call.
     */
    val vocabularyIndex: HashMap<String, Int> by lazy {
        val index = HashMap<String, Int>(vocabulary.size * 2)
        for (i in vocabulary.indices) {
            index[vocabulary[i]] = i
        }
        index
    }

    /**
     * Validates that the model is internally consistent. Throws
     * [IllegalArgumentException] if any check fails.
     */
    fun validate() {
        require(modelVersion.isNotBlank()) { "modelVersion must not be blank" }
        require(detectorId.isNotBlank()) { "detectorId must not be blank" }
        require(ngramMin >= 1) { "ngramMin must be >= 1" }
        require(ngramMax >= ngramMin) { "ngramMax must be >= ngramMin" }
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
    }

    companion object {

        /**
         * Loads a model from [assetName] in the app's assets directory.
         */
        @Throws(IOException::class, IllegalArgumentException::class)
        fun fromAssets(context: Context, assetName: String): UrlHostModel {
            val inputStream = context.assets.open(assetName)
            try {
                val json = inputStream.bufferedReader().readText()
                return parse(json)
            } finally {
                inputStream.close()
            }
        }

        /**
         * Parses a model from a JSON string; unknown keys are ignored.
         */
        @Throws(IllegalArgumentException::class)
        fun parse(json: String): UrlHostModel {
            val obj = org.json.JSONObject(json)

            val modelVersion = requiredString(obj, "model_version")
            val detectorId = requiredString(obj, "detector_id")
            val ngramMin = obj.getInt("ngram_min")
            val ngramMax = obj.getInt("ngram_max")
            val vocabulary = requiredStringList(obj, "vocabulary")
            val idf = requiredDoubleList(obj, "idf")
            val weights = requiredDoubleList(obj, "weights")
            val bias = obj.getDouble("bias")
            val threshold = obj.getDouble("threshold")

            val model = UrlHostModel(
                modelVersion = modelVersion,
                detectorId = detectorId,
                ngramMin = ngramMin,
                ngramMax = ngramMax,
                vocabulary = vocabulary,
                idf = idf,
                weights = weights,
                bias = bias,
                threshold = threshold
            )

            model.validate()
            return model
        }

        private fun requiredString(obj: org.json.JSONObject, key: String): String {
            if (!obj.has(key) || obj.isNull(key)) {
                throw IllegalArgumentException("Missing $key")
            }
            val value = obj.getString(key)
            if (value.isBlank()) {
                throw IllegalArgumentException("Missing $key")
            }
            return value
        }

        private fun requiredStringList(obj: org.json.JSONObject, key: String): List<String> {
            if (!obj.has(key) || obj.isNull(key)) {
                throw IllegalArgumentException("Missing or invalid $key")
            }
            val arr = obj.getJSONArray(key)
            val list = ArrayList<String>(arr.length())
            for (i in 0 until arr.length()) {
                list.add(arr.getString(i))
            }
            if (list.isEmpty()) {
                throw IllegalArgumentException("Missing or invalid $key")
            }
            return list
        }

        private fun requiredDoubleList(obj: org.json.JSONObject, key: String): List<Double> {
            if (!obj.has(key) || obj.isNull(key)) {
                throw IllegalArgumentException("Missing or invalid $key")
            }
            val arr = obj.getJSONArray(key)
            val list = ArrayList<Double>(arr.length())
            for (i in 0 until arr.length()) {
                list.add(arr.getDouble(i))
            }
            return list
        }
    }
}

/**
 * Offline phishing-URL host scorer.
 *
 * Reproduces `tools/url_classifier/train_host_model.py` exactly:
 *
 * 1. Lowercase and strip surrounding whitespace; prepend `http://` when the
 *    string has no `://` prefix.
 * 2. `netloc` = substring up to the first `/`, `?` or `#`. Drop userinfo
 *    (everything up to and including the last `@`), drop `:port` (bracketed
 *    IPv6 literals keep their brackets and content), then remove one trailing
 *    `.` from the host.
 * 3. Remove one leading `www.` (only if still leading after step 2).
 * 4. Text fed to the n-grammer = `"^" + host + "$"`.
 * 5. Features = every character n-gram of length [UrlHostModel.ngramMin] to
 *    [UrlHostModel.ngramMax], counted once per occurrence (raw TF).
 * 6. TF-IDF = TF * stored IDF, row L2-normalised.
 * 7. `p = sigmoid(w . x + bias)`; phishing when `p >= threshold`.
 */
object UrlHostClassifier {

    /**
     * Normalises a raw URL string to the host the model was trained on.
     * Returns `null` when no host can be extracted.
     */
    fun normalizeHost(url: String): String? {
        var s = url.trim().lowercase()
        if (s.isEmpty()) return null
        if (!s.contains("://")) {
            s = "http://$s"
        }
        val rest = s.substringAfter("://")

        // netloc ends at the first path/query/fragment separator
        var end = rest.length
        for (ch in charArrayOf('/', '?', '#')) {
            val i = rest.indexOf(ch)
            if (i in 0 until end) {
                end = i
            }
        }
        var netloc = rest.substring(0, end)

        // drop userinfo: everything up to the LAST "@" (passwords may contain "@")
        val at = netloc.lastIndexOf('@')
        if (at >= 0) {
            netloc = netloc.substring(at + 1)
        }

        // drop ":port"; keep bracketed IPv6 literals intact
        var host: String
        if (netloc.startsWith("[")) {
            val close = netloc.indexOf(']')
            host = if (close != -1) netloc.substring(0, close + 1) else netloc
            val tail = if (close != -1) netloc.substring(close + 1) else ""
            val isPort = tail.startsWith(":") && tail.length > 1 &&
                tail.substring(1).all { it in '0'..'9' }
            when {
                isPort -> Unit
                tail.isNotEmpty() && !tail.startsWith(":") -> host = host + tail
            }
        } else {
            host = netloc.substringBefore(":")
        }

        // single trailing dot (FQDN root label)
        if (host.endsWith(".")) {
            host = host.substring(0, host.length - 1)
        }
        // single leading "www."
        if (host.startsWith("www.")) {
            host = host.substring(4)
        }
        return host.ifEmpty { null }
    }

    /**
     * Probability that [host] is a phishing host, matching the Python trainer.
     * The vocabulary index is built once per [UrlHostModel] and reused.
     */
    fun probability(model: UrlHostModel, host: String): Double {
        val text = "^" + host + "$"
        val index = model.vocabularyIndex

        // raw TF of every character n-gram of length ngramMin..ngramMax
        val tf = HashMap<String, Int>()
        val n = text.length
        for (k in model.ngramMin..model.ngramMax) {
            if (k > n) break
            for (i in 0..(n - k)) {
                val gram = text.substring(i, i + k)
                tf[gram] = (tf[gram] ?: 0) + 1
            }
        }

        // TF * IDF for in-vocabulary terms only, squared-summed for L2
        val indices = IntArray(tf.size)
        val values = DoubleArray(tf.size)
        var used = 0
        var sq = 0.0
        for ((gram, count) in tf) {
            val i = index[gram] ?: continue
            val v = count * model.idf[i]
            indices[used] = i
            values[used] = v
            used++
            sq += v * v
        }

        // L2-normalise the row, then sigmoid(w . x + b)
        val norm = sqrt(sq)
        var dot = 0.0
        for (j in 0 until used) {
            val v = if (norm > 0.0) values[j] / norm else values[j]
            dot += v * model.weights[indices[j]]
        }
        return sigmoid(dot + model.bias)
    }

    /** True when [host] scores at or above the model's stored threshold. */
    fun isPhishing(model: UrlHostModel, host: String): Boolean {
        return probability(model, host) >= model.threshold
    }

    private fun sigmoid(z: Double): Double {
        val clipped = z.coerceIn(-500.0, 500.0)
        return 1.0 / (1.0 + exp(-clipped))
    }
}
