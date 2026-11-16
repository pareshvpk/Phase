package com.arm.threatassistant

import android.app.Application
import com.arm.threatassistant.llm.LlmInstallState

/**
 * Process entry point. Kicks off the one-time extraction of the bundled model
 * so the explanation button is ready shortly after launch.
 */
class ThreatAssistantApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        LlmInstallState.ensureStarted(this)
    }
}
