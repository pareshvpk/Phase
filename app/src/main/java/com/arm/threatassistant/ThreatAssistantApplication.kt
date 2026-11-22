package com.arm.threatassistant

import android.app.Application
import android.content.ComponentCallbacks2
import com.arm.threatassistant.domain.ThreatAnalyzer
import com.arm.threatassistant.llm.LlmExplainerProvider
import com.arm.threatassistant.llm.LlmInstallState
import com.arm.threatassistant.presentation.settings.AppSettings
import com.arm.threatassistant.presentation.settings.explanationLanguageName
import com.arm.threatassistant.sms.MmsWatcher
import java.util.Locale

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
        LlmExplainerProvider.warmUp(this, currentExplanationLanguageName())
        MmsWatcher.schedule(this)
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= ComponentCallbacks2.TRIM_MEMORY_RUNNING_CRITICAL ||
            level == ComponentCallbacks2.TRIM_MEMORY_COMPLETE
        ) {
            LlmExplainerProvider.release()
        }
    }

    /** Same language-name derivation the explanation prompt uses. */
    private fun currentExplanationLanguageName(): String =
        AppSettings.get(this).state.value.language
            .explanationLanguageName(Locale.getDefault().language)
}
