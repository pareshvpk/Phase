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
 * Displays the authoritative threat verdict from [RiskPolicyEngine].
 */
@Composable
fun RiskVerdictSection(
    assessment: com.arm.threatassistant.domain.detection.riskpolicy.RiskAssessment?,
    modifier: Modifier = Modifier
) {
    if (assessment == null) return

    val containerColor = when (assessment.verdict) {
        ThreatVerdictLevel.SAFE -> MaterialTheme.colorScheme.surfaceContainer
        ThreatVerdictLevel.SUSPICIOUS -> MaterialTheme.colorScheme.surfaceContainer
        ThreatVerdictLevel.HIGH_RISK -> MaterialTheme.colorScheme.errorContainer
        ThreatVerdictLevel.INSUFFICIENT_EVIDENCE -> MaterialTheme.colorScheme.surfaceContainerHigh
    }

    Card(
        modifier = modifier.fillMaxWidth().padding(vertical = 8.dp),
        colors = CardDefaults.cardColors(
            containerColor = containerColor
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = stringResource(R.string.section_threat_verdict),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(8.dp))
            val verdictTextColor = when (assessment.verdict) {
                ThreatVerdictLevel.SAFE -> MaterialTheme.colorScheme.onSurface
                ThreatVerdictLevel.SUSPICIOUS -> MaterialTheme.colorScheme.onSurface
                ThreatVerdictLevel.HIGH_RISK -> MaterialTheme.colorScheme.onErrorContainer
                ThreatVerdictLevel.INSUFFICIENT_EVIDENCE -> MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
            }
            Text(
                text = assessment.verdict.name,
                style = MaterialTheme.typography.headlineSmall,
                color = verdictTextColor
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = "Risk score: ${"%.2f".format(assessment.riskScore)}",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.8f)
            )
        }
    }
}
