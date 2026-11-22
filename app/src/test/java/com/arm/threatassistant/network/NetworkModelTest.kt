package com.arm.threatassistant.network

import org.json.JSONArray
import org.junit.Assert.*
import org.junit.Test
import java.io.File

class NetworkModelTest {
    @Test fun kotlinMatchesPythonForObservedAndImputedFeatures() {
        val model = NetworkModel(File("src/main/assets/nids_model.json").readText())
        val fixtures = JSONArray(javaClass.classLoader!!.getResource("network_model_parity.json")!!.readText())
        repeat(fixtures.length()) { i ->
            val fixture = fixtures.getJSONObject(i)
            val json = fixture.getJSONObject("values")
            val values = json.keys().asSequence().associateWith { json.get(it) }
            val result = model.predict(values)
            assertEquals(fixture.getString("label"), result.label)
            assertEquals(fixture.getDouble("score"), result.score, 1e-10)
            assertEquals(fixture.getInt("imputed"), result.imputed.size)
        }
    }
}
