package com.arm.threatassistant

import android.app.Application
import com.arm.threatassistant.domain.ThreatAnalyzer
import com.arm.threatassistant.llm.LlmInstallState

/**
 * Process entry point. Kicks off the one-time extraction of the bundled model
 * so the explanation button is ready shortly after launch, and warms the SMS
 * classifier in the background so the first check is not slow.
 */
class ThreatAssistantApplication : Application() {

    override fun onCreate() {
        super.onCreate()
        LlmInstallState.ensureStarted(this)
        Thread({ ThreatAnalyzer.preload(this) }, "arm-preload").apply {
            isDaemon = true
            priority = Thread.MIN_PRIORITY
        }.start()
    }
}
