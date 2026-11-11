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
import com.arm.threatassistant.domain.detection.riskpolicy.RiskAssessment

/**
 * Displays the evidence summary explaining how the verdict was reached.
 */
@Composable
fun EvidenceSection(
    assessment: RiskAssessment?,
    modifier: Modifier = Modifier
) {
    if (assessment == null || assessment.evidenceSummary.isEmpty()) return

    Card(
        modifier = modifier.fillMaxWidth().padding(vertical = 8.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = stringResource(R.string.section_evidence),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(8.dp))
            Column(modifier = Modifier.fillMaxWidth()) {
                assessment.evidenceSummary.forEach { line ->
                    Text(
                        text = line,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                }
            }
        }
    }
}
