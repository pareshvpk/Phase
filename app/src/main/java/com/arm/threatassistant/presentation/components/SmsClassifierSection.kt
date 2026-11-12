package com.arm.threatassistant.presentation.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.detection.smsclassifier.ContributingFeature
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierResult
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierStatus
import java.util.Locale

/**
 * Displays SMS Specialist Classifier output for development and testing.
 *
 * This component shows classifier evidence only — status, predicted label,
 * threat score, model version, and any error. It does NOT display an
 * authoritative security verdict. The final verdict belongs to the
 * RiskPolicyEngine (Phase 5).
 */
@Composable
fun SmsClassifierSection(
    result: SmsClassifierResult?,
    modifier: Modifier = Modifier
) {
    if (result == null) {
        return
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        colors = CardDefaults.cardColors(
            containerColor = when (result.status) {
                SmsClassifierStatus.ERROR -> MaterialTheme.colorScheme.errorContainer
                SmsClassifierStatus.UNAVAILABLE -> MaterialTheme.colorScheme.surfaceContainerHigh
                else -> MaterialTheme.colorScheme.surfaceContainerHigh
            }
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = stringResource(R.string.section_sms_classifier_title),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(8.dp))

            // Status row
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
            ) {
                Text(
                    text = "Status:",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                    modifier = Modifier.weight(0.3f)
                )
                Text(
                    text = result.status.name,
                    style = MaterialTheme.typography.bodySmall,
                    color = statusColor(result.status)
                )
            }
            Spacer(modifier = Modifier.height(8.dp))

            when (result.status) {
                SmsClassifierStatus.AVAILABLE -> {
                    // Predicted label
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Prediction:",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                            modifier = Modifier.weight(0.3f)
                        )
                        Text(
                            text = result.predictedLabel ?: "—",
                            style = MaterialTheme.typography.bodySmall,
                            color = if (result.predictedLabel == "THREAT") {
                                MaterialTheme.colorScheme.error
                            } else {
                                MaterialTheme.colorScheme.primary
                            }
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))

                    // Threat score
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Threat score:",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                            modifier = Modifier.weight(0.3f)
                        )
                        Text(
                            text = String.format(
                                Locale.US,
                                "%.1f%%",
                                (result.threatScore ?: 0.0) * 100.0
                            ),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))

                    // Model version
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Model version:",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f),
                            modifier = Modifier.weight(0.3f)
                        )
                        Text(
                            text = result.modelVersion ?: "—",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))

                    // Calibration note
                    if (!result.isCalibrated) {
                        Text(
                            text = stringResource(R.string.sms_classifier_uncalibrated_note),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f),
                            maxLines = 2
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                    }

                    // Top contributing features
                    result.contributingFeatures?.let { features ->
                        if (features.isNotEmpty()) {
                            Text(
                                text = stringResource(R.string.sms_classifier_contributing_features),
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Spacer(modifier = Modifier.height(4.dp))
                            Column(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(start = 8.dp)
                            ) {
                                features.forEach { feature ->
                                    Text(
                                        text = "${feature.term} (${feature.contribution * 100.0 / 1.0}%)",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                                    )
                                }
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                        }
                    }
                }

                SmsClassifierStatus.UNAVAILABLE -> {
                    Text(
                        text = result.errorMessage ?: stringResource(R.string.sms_classifier_unavailable),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                    )
                }

                SmsClassifierStatus.ERROR -> {
                    Text(
                        text = result.errorMessage ?: stringResource(R.string.sms_classifier_error),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.error
                    )
                }

                SmsClassifierStatus.UNSUPPORTED_INPUT -> {
                    Text(
                        text = result.errorMessage ?: stringResource(R.string.sms_classifier_unsupported_input),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                    )
                }
            }
        }
    }
}

@Composable
private fun statusColor(status: SmsClassifierStatus): androidx.compose.ui.graphics.Color {
    return when (status) {
        SmsClassifierStatus.AVAILABLE -> MaterialTheme.colorScheme.primary
        SmsClassifierStatus.UNAVAILABLE -> MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
        SmsClassifierStatus.ERROR -> MaterialTheme.colorScheme.error
        SmsClassifierStatus.UNSUPPORTED_INPUT -> MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
    }
}
