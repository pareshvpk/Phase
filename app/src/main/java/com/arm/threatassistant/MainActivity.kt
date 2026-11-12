package com.arm.threatassistant

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import com.arm.threatassistant.domain.adapters.ProcessTextAdapter
import com.arm.threatassistant.domain.adapters.ShareSheetAdapter
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.presentation.screens.ThreatAssistantScreen
import com.arm.threatassistant.presentation.theme.ThreatAssistantTheme

class MainActivity : ComponentActivity() {

    private var ingestedInput by mutableStateOf<IngestedInput?>(null)
    private var ingestRequestId = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Cold start: ingest the launching intent exactly once. On configuration
        // changes the ViewModel survives, so re-ingesting would be redundant.
        if (savedInstanceState == null) {
            handleIntent(intent)
        }

        setContent {
            ThreatAssistantTheme {
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
