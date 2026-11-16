package com.arm.threatassistant

import android.content.Intent
import android.content.res.Configuration
import android.os.Bundle
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.arm.threatassistant.domain.adapters.ProcessTextAdapter
import com.arm.threatassistant.domain.adapters.ShareSheetAdapter
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.InputSource
import com.arm.threatassistant.presentation.screens.ThreatAssistantScreen
import com.arm.threatassistant.presentation.settings.AppSettings
import com.arm.threatassistant.presentation.settings.resolveDarkTheme
import com.arm.threatassistant.presentation.theme.ThreatAssistantTheme

class MainActivity : AppCompatActivity() {

    companion object {
        /** Marks an ACTION_SEND intent that originated from an SMS alert. */
        const val EXTRA_FROM_SMS_ALERT = "com.arm.threatassistant.extra.FROM_SMS_ALERT"
    }

    private var ingestedInput by mutableStateOf<IngestedInput?>(null)
    private var ingestRequestId = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        val settings = AppSettings.get(this)
        super.onCreate(savedInstanceState)

        val systemDark = (resources.configuration.uiMode and
            Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
        val darkTheme = resolveDarkTheme(settings.state.value.theme, systemDark)
        val transparent = android.graphics.Color.TRANSPARENT
        enableEdgeToEdge(
            statusBarStyle = if (darkTheme) {
                SystemBarStyle.dark(transparent)
            } else {
                SystemBarStyle.light(transparent, transparent)
            },
            navigationBarStyle = if (darkTheme) {
                SystemBarStyle.dark(transparent)
            } else {
                SystemBarStyle.light(transparent, transparent)
            }
        )

        // Cold start: ingest the launching intent exactly once. On configuration
        // changes the ViewModel survives, so re-ingesting would be redundant.
        if (savedInstanceState == null) {
            handleIntent(intent)
        }

        setContent {
            val settingsState by settings.state.collectAsState()
            val dark = resolveDarkTheme(
                theme = settingsState.theme,
                systemInDarkTheme = isSystemInDarkTheme()
            )
            ThreatAssistantTheme(darkTheme = dark) {
                val pending = ingestedInput
                ThreatAssistantScreen(
                    ingestedInput = pending?.input,
                    ingestRequestId = pending?.requestId ?: 0L
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(intent: Intent?) {
        if (intent == null) return

        val adapted = when (intent.action) {
            Intent.ACTION_SEND -> ShareSheetAdapter().adaptFromIntent(intent)
                ?.let { input ->
                    if (intent.getBooleanExtra(EXTRA_FROM_SMS_ALERT, false)) {
                        input.copy(source = InputSource.SMS)
                    } else {
                        input
                    }
                }
            Intent.ACTION_PROCESS_TEXT -> ProcessTextAdapter().adaptFromIntent(intent)
            else -> null
        } ?: return

        ingestRequestId += 1
        ingestedInput = IngestedInput(adapted, ingestRequestId)
    }
}

/**
 * Intent-sourced input plus a monotonically increasing request id. The id lets
 * the UI treat repeated shares of identical text as distinct ingestion events.
 */
private data class IngestedInput(
    val input: AnalysisInput,
    val requestId: Long
)
