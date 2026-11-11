package com.arm.threatassistant.domain.detection.smsclassifier

import android.content.Context
import java.io.IOException

/**
 * Loads and parses a [SmsClassifierModel] from a JSON asset file.
 *
 * Uses only org.json (bundled with the Android SDK) — no additional Gradle
 * dependencies. Validates the model on load; invalid or corrupted assets
 * result in a clear [IllegalArgumentException] or [IOException] that callers
 * should treat as [SmsClassifierStatus.UNAVAILABLE].
 */
object SmsClassifierModelLoader {

    private const val MODEL_VERSION_KEY = "model_version"
    private const val DETECTOR_ID_KEY = "detector_id"
    private const val DETECTOR_VERSION_KEY = "detector_version"
    private const val VOCABULARY_KEY = "vocabulary"
    private const val IDF_KEY = "idf"
    private const val WEIGHTS_KEY = "weights"
    private const val BIAS_KEY = "bias"
    private const val THRESHOLD_KEY = "threshold"
    private const val LABEL_MAP_KEY = "label_map"
    private const val IS_CALIBRATED_KEY = "is_calibrated"
    private const val FEATURE_CONFIG_KEY = "feature_config"
    private const val TRAINING_INFO_KEY = "training_info"

    /**
     * Loads a model from [assetName] in the app's assets directory.
     */
    @Throws(IOException::class, IllegalArgumentException::class)
    fun loadFromAssets(context: Context, assetName: String): SmsClassifierModel {
        val inputStream = context.assets.open(assetName)
        try {
            val json = inputStream.bufferedReader().readText()
            return parse(json)
        } finally {
            inputStream.close()
        }
    }

    /**
     * Parses a model from a JSON string.
     */
    @Throws(IllegalArgumentException::class)
    fun parse(json: String): SmsClassifierModel {
        val obj = org.json.JSONObject(json)

        val modelVersion = optString(obj, MODEL_VERSION_KEY) { "Missing model_version" }
        val detectorId = optString(obj, DETECTOR_ID_KEY) { "Missing detector_id" }
        val detectorVersion = optString(obj, DETECTOR_VERSION_KEY) { "Missing detector_version" }

        val vocabulary = optStringList(obj, VOCABULARY_KEY) { "Missing or invalid vocabulary" }
        val idf = optDoubleList(obj, IDF_KEY) { "Missing or invalid idf" }
        val weights = optDoubleList(obj, WEIGHTS_KEY) { "Missing or invalid weights" }

        val bias = optDouble(obj, BIAS_KEY) { "Missing or invalid bias" }
        val threshold = optDouble(obj, THRESHOLD_KEY) { "Missing or invalid threshold" }

        val labelMap = optLabelMap(obj) { "Missing or invalid label_map" }
        val isCalibrated = optBoolean(obj, IS_CALIBRATED_KEY, false)
        val featureConfig = optObjectMap(obj, FEATURE_CONFIG_KEY, emptyMap())
        val trainingInfo = optObjectMap(obj, TRAINING_INFO_KEY, emptyMap())

        val model = SmsClassifierModel(
            modelVersion = modelVersion,
            detectorId = detectorId,
            detectorVersion = detectorVersion,
            vocabulary = vocabulary,
            idf = idf,
            weights = weights,
            bias = bias,
            threshold = threshold,
            labelMap = labelMap,
            isCalibrated = isCalibrated,
            featureConfig = featureConfig,
            trainingInfo = trainingInfo
        )

        model.validate()
        return model
    }

    // ---- Helpers ----

    private fun optString(
        obj: org.json.JSONObject,
        key: String,
        error: () -> String
    ): String {
        if (!obj.has(key) || obj.isNull(key)) {
            throw IllegalArgumentException(error.invoke())
        }
        val value = obj.getString(key)
        if (value.isBlank()) {
            throw IllegalArgumentException(error.invoke())
        }
        return value
    }

    private fun optStringList(
        obj: org.json.JSONObject,
        key: String,
        error: () -> String
    ): List<String> {
        if (!obj.has(key) || obj.isNull(key)) {
            throw IllegalArgumentException(error.invoke())
        }
        val arr = obj.getJSONArray(key)
        val list = mutableListOf<String>()
        for (i in 0 until arr.length()) {
            list.add(arr.getString(i))
        }
        if (list.isEmpty()) {
            throw IllegalArgumentException(error.invoke())
        }
        return list
    }

    private fun optDoubleList(
        obj: org.json.JSONObject,
        key: String,
        error: () -> String
    ): List<Double> {
        if (!obj.has(key) || obj.isNull(key)) {
            throw IllegalArgumentException(error.invoke())
        }
        val arr = obj.getJSONArray(key)
        val list = mutableListOf<Double>()
        for (i in 0 until arr.length()) {
            list.add(arr.getDouble(i))
        }
        return list
    }

    private fun optDouble(
        obj: org.json.JSONObject,
        key: String,
        error: () -> String
    ): Double {
        if (!obj.has(key) || obj.isNull(key)) {
            throw IllegalArgumentException(error.invoke())
        }
        return obj.getDouble(key)
    }

    private fun optBoolean(
        obj: org.json.JSONObject,
        key: String,
        default: Boolean
    ): Boolean {
        return if (obj.has(key) && !obj.isNull(key)) obj.getBoolean(key) else default
    }

    private fun optLabelMap(
        obj: org.json.JSONObject,
        error: () -> String
    ): Map<String, Int> {
        if (!obj.has(LABEL_MAP_KEY) || obj.isNull(LABEL_MAP_KEY)) {
            throw IllegalArgumentException(error.invoke())
        }
        val arr = obj.getJSONArray(LABEL_MAP_KEY)
        val map = mutableMapOf<String, Int>()
        for (i in 0 until arr.length()) {
            val entry = arr.getJSONArray(i)
            map[entry.getString(0)] = entry.getInt(1)
        }
        return map
    }

    private fun optObjectMap(
        obj: org.json.JSONObject,
        key: String,
        default: Map<String, Any>
    ): Map<String, Any> {
        if (!obj.has(key) || obj.isNull(key)) {
            return default
        }
        val inner = obj.getJSONObject(key)
        val map = mutableMapOf<String, Any>()
        val keys = inner.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            map[k] = jsonValue(inner.get(k))
        }
        return map
    }

    private fun jsonValue(value: Any): Any {
        return when (value) {
            is org.json.JSONObject -> {
                val inner = value as org.json.JSONObject
                val map = mutableMapOf<String, Any>()
                val keys = inner.keys()
                while (keys.hasNext()) {
                    val k = keys.next()
                    map[k] = jsonValue(inner.get(k))
                }
                map
            }
            is org.json.JSONArray -> {
                val arr = value as org.json.JSONArray
                val list = mutableListOf<Any>()
                for (i in 0 until arr.length()) {
                    list.add(jsonValue(arr.get(i)))
                }
                list
            }
            else -> value
        }
    }
}
