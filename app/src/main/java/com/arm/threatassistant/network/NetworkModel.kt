package com.arm.threatassistant.network

import org.json.JSONObject
import kotlin.math.exp
import kotlin.math.ln1p
import kotlin.math.max

/** Same double-precision inference and mean imputation as the Python monitor. */
class NetworkModel(json: String) {
    private val raw = JSONObject(json)
    private fun strings(key: String) = raw.getJSONArray(key).let { a -> List(a.length()) { a.getString(it) } }
    private fun vector(key: String) = raw.getJSONArray(key).let { a -> DoubleArray(a.length()) { a.getDouble(it) } }
    private fun matrix(key: String) = raw.getJSONArray(key).let { a -> Array(a.length()) { i ->
        a.getJSONArray(i).let { row -> DoubleArray(row.length()) { row.getDouble(it) } }
    } }
    private val features = strings("feature_names")
    private val base = strings("base_features")
    private val logs = strings("log1p_columns").toSet()
    private val classes = strings("classes")
    private val mean = vector("mean")
    private val std = vector("std")
    private val w1 = matrix("W1")
    private val b1 = vector("b1")
    private val w2 = matrix("W2")
    private val b2 = vector("b2")

    init {
        require(features.size == mean.size && std.size == mean.size && w1.size == mean.size)
        require(w1.all { it.size == b1.size } && w2.size == b1.size)
        require(w2.all { it.size == classes.size } && b2.size == classes.size)
        require(std.all { it.isFinite() && it > 0 })
    }

    data class Estimate(val label: String, val score: Double, val imputed: List<String>)

    fun predict(values: Map<String, Any>): Estimate {
        val x = DoubleArray(features.size) { i ->
            val name = features[i].substringBefore('=')
            val value = values[name]
            if (value == null) 0.0 else {
                val numeric = if ('=' in features[i]) {
                    if (value.toString() == features[i].substringAfter('=')) 1.0 else 0.0
                } else {
                    val n = (value as Number).toDouble()
                    require(n.isFinite())
                    if (name in logs) ln1p(max(n, 0.0)) else n
                }
                (numeric - mean[i]) / std[i]
            }
        }
        val hidden = DoubleArray(b1.size) { j -> max(0.0, b1[j] + x.indices.sumOf { i -> x[i] * w1[i][j] }) }
        val logits = DoubleArray(b2.size) { j -> b2[j] + hidden.indices.sumOf { i -> hidden[i] * w2[i][j] } }
        val best = logits.indices.maxBy { logits[it] }
        val total = logits.sumOf { exp(it - logits[best]) }
        return Estimate(classes[best], 1.0 / total, base.filterNot(values::containsKey))
    }
}
