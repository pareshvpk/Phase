package com.arm.threatassistant.presentation.screens

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.relocation.bringIntoViewRequester
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.AnalysisStatus
import com.arm.threatassistant.llm.LlmInstallState
import com.arm.threatassistant.presentation.components.ActionsCard
import com.arm.threatassistant.presentation.components.CheckMessageButton
import com.arm.threatassistant.presentation.components.LlmExplanationSection
import com.arm.threatassistant.presentation.components.MessageInput
import com.arm.threatassistant.presentation.components.ReasonCard
import com.arm.threatassistant.presentation.components.ShieldHero
import com.arm.threatassistant.presentation.components.VerdictCard
import com.arm.threatassistant.presentation.result.ReasonId
import com.arm.threatassistant.presentation.result.ReasonMapper
import com.arm.threatassistant.presentation.result.labelRes
import com.arm.threatassistant.presentation.settings.AppLanguage
import com.arm.threatassistant.presentation.settings.AppSettings
import com.arm.threatassistant.presentation.viewmodel.ThreatAnalysisUiState
import com.arm.threatassistant.presentation.viewmodel.ThreatAnalysisViewModel
import kotlinx.coroutines.delay

/**
 * Home tab: check a message and read a plain-language verdict.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun CheckScreen(
    modifier: Modifier = Modifier,
    viewModel: ThreatAnalysisViewModel = viewModel(),
    ingestedInput: AnalysisInput? = null,
    ingestRequestId: Long = 0L
) {
    val context = LocalContext.current
    val configuration = LocalConfiguration.current
    val state: ThreatAnalysisUiState by viewModel.uiState.collectAsState()
    val settingsState by AppSettings.get(context).state.collectAsState()
    val llmInstallState by LlmInstallState.state.collectAsState()

    val deviceLanguage = configuration.locales[0].language
    val isEnglish = when (settingsState.language) {
        AppLanguage.ENGLISH -> true
        AppLanguage.HINDI, AppLanguage.TAMIL -> false
        AppLanguage.SYSTEM -> deviceLanguage != "hi" && deviceLanguage != "ta"
    }

    val reasons = remember(
        state.ruleDetectionResult,
        state.urlDetectionResult,
        state.smsClassifierResult
    ) {
        ReasonMapper.map(
            ruleResult = state.ruleDetectionResult,
            urlResult = state.urlDetectionResult,
            classifierResult = state.smsClassifierResult
        )
    }
    val offlineExplanation = remember(reasons) {
        buildOfflineExplanation(context, reasons)
    }

    val bringIntoViewRequester = remember { BringIntoViewRequester() }
    LaunchedEffect(state.riskAssessment) {
        if (state.riskAssessment != null) {
            delay(120)
            runCatching { bringIntoViewRequester.bringIntoView() }
        }
    }

    LaunchedEffect(ingestRequestId) {
        if (ingestedInput != null) {
            viewModel.onIngestedInput(context, ingestedInput)
        }
    }

    val result = state.riskAssessment
    val isIdle = state.status == AnalysisStatus.IDLE

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        item {
            Column {
                Text(
                    text = stringResource(R.string.app_name),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = stringResource(R.string.app_tagline),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        if (result == null && isIdle) {
            item {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    ShieldHero()
                    Spacer(modifier = Modifier.size(16.dp))
                    Text(
                        text = stringResource(R.string.check_title),
                        style = MaterialTheme.typography.headlineMedium,
                        color = MaterialTheme.colorScheme.onBackground,
                        textAlign = TextAlign.Center
                    )
                    Spacer(modifier = Modifier.size(8.dp))
                    Text(
                        text = stringResource(R.string.check_subtitle),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center
                    )
                }
            }
        }

        item {
            MessageInput(
                value = state.inputText,
                onValueChange = { viewModel.onMessageChanged(context, it) },
                onPaste = { viewModel.onMessageChanged(context, it) },
                errorMessage = state.errorMessage
            )
        }

        item {
            CheckMessageButton(
                onClick = { viewModel.onAnalyze(context) },
                enabled = state.status != AnalysisStatus.ANALYZING
            )
        }

        if (state.status == AnalysisStatus.ANALYZING) {
            item {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = stringResource(R.string.status_analyzing),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        if (result != null) {
            item {
                VerdictCard(
                    verdict = result.verdict,
                    modifier = Modifier.bringIntoViewRequester(bringIntoViewRequester)
                )
            }

            if (reasons.isNotEmpty()) {
                item { ReasonCard(reasons = reasons) }
            }

            item { ActionsCard(verdict = result.verdict) }

            item {
                LlmExplanationSection(
                    state = state.explanation,
                    installState = llmInstallState,
                    isEnglish = isEnglish,
                    offlineText = offlineExplanation,
                    onExplain = { viewModel.onExplain(context) },
                    onRetryInstall = { LlmInstallState.retry(context) }
                )
            }

            item {
                TextButton(
                    onClick = { viewModel.onMessageChanged(context, "") },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(text = stringResource(R.string.check_another))
                }
            }
        }
    }
}

private fun buildOfflineExplanation(
    context: android.content.Context,
    reasons: List<ReasonId>
): String {
    if (reasons.isEmpty()) return ""
    val separator = context.getString(R.string.offline_explanation_separator)
    val joined = reasons.joinToString(separator) { context.getString(it.labelRes) }
    return context.getString(R.string.offline_explanation_template, joined)
}
