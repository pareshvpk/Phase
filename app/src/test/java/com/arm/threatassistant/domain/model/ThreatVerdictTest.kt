package com.arm.threatassistant.domain.model

import org.junit.Test
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue

import com.arm.threatassistant.presentation.viewmodel.ThreatAnalysisUiState
import com.arm.threatassistant.presentation.viewmodel.ThreatAnalysisViewModel

/**
 * Unit tests for the Phase 1 domain models.
 *
 * These tests verify the model definitions only. No detection or risk
 * calculation is exercised at this stage.
 */
class ThreatVerdictTest {

    @Test
    fun threatVerdictDeclaresAllFutureCategories() {
        val values = ThreatVerdict.values().map { it.name }.toSet()
        assertNotNull(values)
        assertTrue(values.contains("SAFE_UNVERIFIED"))
        assertTrue(values.contains("SUSPICIOUS"))
        assertTrue(values.contains("HIGH_RISK"))
        assertTrue(values.contains("INCONCLUSIVE"))
        assertTrue(values.contains("UNSUPPORTED_INPUT"))
        assertEquals(5, values.size)
    }

    @Test
    fun analysisStatusDeclaresLifecycleStates() {
        val values = AnalysisStatus.values().map { it.name }.toSet()
        assertTrue(values.contains("IDLE"))
        assertTrue(values.contains("ANALYZING"))
        assertTrue(values.contains("COMPLETED"))
        assertTrue(values.contains("ERROR"))
        assertEquals(4, values.size)
    }

    @Test
    fun analysisInputHoldsMessageText() {
        val input = AnalysisInput(messageText = "Free money! Click here now.")
        assertEquals("Free money! Click here now.", input.messageText)
    }

    @Test
    fun analysisResultDefaultsTimestamp() {
        val input = AnalysisInput(messageText = "hello")
        val result = AnalysisResult(
            input = input,
            status = AnalysisStatus.IDLE,
            verdict = null,
            message = null
        )
        assertEquals(input, result.input)
        assertEquals(AnalysisStatus.IDLE, result.status)
        assertNull(result.verdict)
        assertTrue(result.timestampMillis > 0)
    }

    @Test
    fun uiStateStartsIdle() {
        val state = ThreatAnalysisViewModel().uiState.value
        assertEquals(AnalysisStatus.IDLE, state.status)
        assertEquals("", state.inputText)
        assertNull(state.errorMessage)
        assertNull(state.resultMessage)
        assertFalse(state.inputText.isNotBlank())
    }
}
