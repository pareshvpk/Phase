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
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.arm.threatassistant.domain.model.AnalysisStatus
import com.arm.threatassistant.R

@Composable
fun ResultArea(
    status: AnalysisStatus,
    resultMessage: String?,
    modifier: Modifier = Modifier
) {
    val resultContentDescription = stringResource(R.string.content_description_result_area)
    Card(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
            .semantics { contentDescription = resultContentDescription },
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = stringResource(R.string.result_placeholder_title),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(8.dp))
            when (status) {
                AnalysisStatus.IDLE -> {
                    Text(
                        text = "Enter a message and press Analyze.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                    )
                }
                AnalysisStatus.ANALYZING -> {
                    Text(
                        text = stringResource(R.string.status_analyzing),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
                AnalysisStatus.COMPLETED -> {
                    Text(
                        text = resultMessage ?: "",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
                AnalysisStatus.ERROR -> {
                    Text(
                        text = resultMessage ?: "",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}
