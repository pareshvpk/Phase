package com.arm.threatassistant.presentation.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.Spacer
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel

/**
 * Displays recommended actions based on the threat verdict.
 */
@Composable
fun RecommendedActionsSection(
    verdict: ThreatVerdictLevel?,
    modifier: Modifier = Modifier
) {
    if (verdict == null) return

    val actions = recommendedActions(verdict)
    if (actions.isEmpty()) return

    Card(
        modifier = modifier.fillMaxWidth().padding(vertical = 8.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = stringResource(R.string.section_recommended_actions),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(8.dp))
            Column(modifier = Modifier.fillMaxWidth()) {
                actions.forEach { action ->
                    Text(
                        text = "\u2022 $action",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                }
            }
        }
    }
}

private fun recommendedActions(verdict: ThreatVerdictLevel): List<String> {
    return when (verdict) {
        ThreatVerdictLevel.SAFE -> listOf(
            "Message appears safe. No action required.",
            "Exercise normal caution with unexpected links or requests."
        )
        ThreatVerdictLevel.SUSPICIOUS -> listOf(
            "Do not click any links in this message.",
            "Do not reply with personal information, OTPs, or passwords.",
            "Verify the sender through an official channel.",
            "Consider reporting the message to your carrier."
        )
        ThreatVerdictLevel.HIGH_RISK -> listOf(
            "DO NOT click any links or respond to this message.",
            "DO NOT share OTPs, passwords, or banking details.",
            "Block the sender immediately.",
            "Report the message as spam/phishing to your carrier.",
            "If you already shared credentials, change your passwords and contact your bank."
        )
        ThreatVerdictLevel.INSUFFICIENT_EVIDENCE -> listOf(
            "Insufficient evidence for a determination.",
            "Exercise caution with unexpected messages.",
            "Do not share sensitive information unless you initiated the contact."
        )
    }
}
