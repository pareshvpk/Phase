package com.arm.threatassistant

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import com.arm.threatassistant.domain.adapters.ProcessTextAdapter
import com.arm.threatassistant.domain.adapters.ShareSheetAdapter
import com.arm.threatassistant.presentation.screens.ThreatAssistantScreen
import com.arm.threatassistant.presentation.theme.ThreatAssistantTheme

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val intent = intent
        val action = intent.action

        val ingestedInput = when (action) {
            Intent.ACTION_SEND -> ShareSheetAdapter().adaptFromIntent(intent)
            Intent.ACTION_PROCESS_TEXT -> ProcessTextAdapter().adaptFromIntent(intent)
            else -> null
        }

        setContent {
            ThreatAssistantTheme {
                ThreatAssistantScreen(
                    ingestedInput = ingestedInput
                )
            }
        }
    }
}
