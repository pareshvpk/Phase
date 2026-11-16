package com.arm.threatassistant.presentation.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.arm.threatassistant.R
import com.arm.threatassistant.llm.LlmInstallStatus
import com.arm.threatassistant.presentation.theme.ArmTheme
import com.arm.threatassistant.presentation.viewmodel.ExplanationState
import kotlin.math.roundToInt

/**
 * Optional explanation of the verdict.
 *
 * In English the on-device model is offered behind a quiet tonal button. In
 * Hindi and Tamil the model is not used; a fixed local paragraph built from the
 * same reason strings is shown instead.
 *
 * The bundled model is prepared in the background. While it is being installed
 * a small progress card replaces the button; if preparation fails the section
 * explains why and offers a retry.
 */
@Composable
fun LlmExplanationSection(
    state: ExplanationState,
    installState: LlmInstallStatus,
    isEnglish: Boolean,
    offlineText: String,
    onExplain: () -> Unit,
    onRetryInstall: () -> Unit,
    modifier: Modifier = Modifier
) {
    if (!isEnglish) {
        if (offlineText.isNotBlank()) {
            ExplanationCard(
                text = offlineText,
                modifier = modifier
            )
        }
        return
    }

    when (installState) {
        LlmInstallStatus.NotBundled -> {
            if (state is ExplanationState.Done) {
                ExplanationCard(text = state.text, modifier = modifier)
            }
        }

        is LlmInstallStatus.Installing -> {
            if (state is ExplanationState.Done) {
                ExplanationCard(text = state.text, modifier = modifier)
            } else {
                PreparingCard(progress = installState.progress, modifier = modifier)
            }
        }

        LlmInstallStatus.Ready -> {
            ExplanationContent(
                state = state,
                showButtonWhenHidden = true,
                onExplain = onExplain,
                modifier = modifier
            )
        }

        is LlmInstallStatus.Failed -> {
            if (state is ExplanationState.Done) {
                ExplanationCard(text = state.text, modifier = modifier)
            } else {
                InstallFailedCard(
                    message = installState.message,
                    onRetry = onRetryInstall,
                    modifier = modifier
                )
            }
        }
    }
}

@Composable
private fun ExplanationContent(
    state: ExplanationState,
    showButtonWhenHidden: Boolean,
    onExplain: () -> Unit,
    modifier: Modifier = Modifier
) {
    when (state) {
        ExplanationState.Hidden -> {
            if (showButtonWhenHidden) {
                ExplainButton(onExplain = onExplain, modifier = modifier)
            }
        }

        ExplanationState.Ready -> ExplainButton(onExplain = onExplain, modifier = modifier)

        is ExplanationState.Generating -> {
            Card(
                modifier = modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(
                    containerColor = ArmTheme.colors.cardSurface
                )
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(16.dp),
                            strokeWidth = 2.dp
                        )
                        Spacer(modifier = Modifier.width(8.dp))
                        Text(
                            text = stringResource(R.string.llm_generating),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    if (state.text.isNotBlank()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = state.text,
                            style = MaterialTheme.typography.bodyLarge,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            }
        }

        is ExplanationState.Done -> {
            ExplanationCard(text = state.text, modifier = modifier)
        }

        is ExplanationState.Failed -> {
            Card(
                modifier = modifier.fillMaxWidth(),
                shape = RoundedCornerShape(24.dp),
                colors = CardDefaults.cardColors(
                    containerColor = ArmTheme.colors.cardSurface
                )
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text(
                        text = stringResource(R.string.llm_unavailable),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    FilledTonalButton(onClick = onExplain) {
                        Text(text = stringResource(R.string.llm_try_again))
                    }
                }
            }
        }
    }
}

@Composable
private fun ExplainButton(
    onExplain: () -> Unit,
    modifier: Modifier = Modifier
) {
    FilledTonalButton(
        onClick = onExplain,
        modifier = modifier.fillMaxWidth()
    ) {
        Text(text = stringResource(R.string.llm_explain_button))
    }
}

@Composable
private fun PreparingCard(
    progress: Float,
    modifier: Modifier = Modifier
) {
    val percent = (progress.coerceIn(0f, 1f) * 100f).roundToInt()
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = ArmTheme.colors.cardSurface
        )
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Text(
                text = stringResource(R.string.llm_preparing, percent),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Spacer(modifier = Modifier.height(8.dp))
            LinearProgressIndicator(
                progress = { progress.coerceIn(0f, 1f) },
                modifier = Modifier.fillMaxWidth()
            )
        }
    }
}

@Composable
private fun InstallFailedCard(
    message: String,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = ArmTheme.colors.cardSurface
        )
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Text(
                text = stringResource(R.string.llm_install_failed, message),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(8.dp))
            FilledTonalButton(onClick = onRetry) {
                Text(text = stringResource(R.string.llm_retry))
            }
        }
    }
}

@Composable
private fun ExplanationCard(
    text: String,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = ArmTheme.colors.cardSurface
        )
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Text(
                text = text,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = stringResource(R.string.llm_explanation_caption),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
