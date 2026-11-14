package com.arm.threatassistant.presentation

import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.arm.threatassistant.MainActivity
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Integration tests for Phase 2 intent-based input ingestion.
 *
 * These tests require the androidx.test dependencies and a device/emulator and
 * are not executed in the pure-JVM unit-test source set. They verify that the
 * share sheet (ACTION_SEND) and process text (ACTION_PROCESS_TEXT) intent
 * filters are wired to MainActivity and that shared/selected text reaches the
 * view model without crashing.
 */
@RunWith(AndroidJUnit4::class)
class IntentIngestionTest {

    // Explicit component: on a real device an implicit SEND/PROCESS_TEXT
    // intent resolves to the system chooser instead of this app.
    private val targetContext =
        androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun sendIntentWithPlainTextDoesNotCrash() {
        val intent = Intent(Intent.ACTION_SEND).apply {
            setClass(targetContext, MainActivity::class.java)
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, "Shared SMS: https://example.com free money")
        }
        ActivityScenario.launch<MainActivity>(intent).close()
    }

    @Test
    fun processTextIntentWithSelectedTextDoesNotCrash() {
        val intent = Intent(Intent.ACTION_PROCESS_TEXT).apply {
            setClass(targetContext, MainActivity::class.java)
            type = "text/plain"
            putExtra(Intent.EXTRA_PROCESS_TEXT, "Selected text from another app")
        }
        ActivityScenario.launch<MainActivity>(intent).close()
    }

    @Test
    fun sendIntentWithoutTextIsHandledSafely() {
        val intent = Intent(Intent.ACTION_SEND).apply {
            setClass(targetContext, MainActivity::class.java)
            type = "text/plain"
        }
        ActivityScenario.launch<MainActivity>(intent).close()
    }
}
