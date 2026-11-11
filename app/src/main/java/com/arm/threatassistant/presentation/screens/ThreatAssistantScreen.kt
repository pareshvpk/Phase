package com.arm.threatassistant.presentation.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.InputSource
import com.arm.threatassistant.presentation.components.AppInfoSection
import com.arm.threatassistant.presentation.components.AnalyzeButton
import com.arm.threatassistant.presentation.components.EvidenceSection
import com.arm.threatassistant.presentation.components.ExtractedEntitiesSection
import com.arm.threatassistant.presentation.components.MessageInput
import com.arm.threatassistant.presentation.components.NormalizationWarningsSection
import com.arm.threatassistant.presentation.components.NormalizedInputPreview
import com.arm.threatassistant.presentation.components.RecommendedActionsSection
import com.arm.threatassistant.presentation.components.ResultArea
import com.arm.threatassistant.presentation.components.RiskVerdictSection
import com.arm.threatassistant.presentation.components.RuleDetectionSection
import com.arm.threatassistant.presentation.components.SmsClassifierSection
import com.arm.threatassistant.presentation.components.UrlDetectionSection
import com.arm.threatassistant.presentation.viewmodel.ThreatAnalysisViewModel
import com.arm.threatassistant.presentation.viewmodel.ThreatAnalysisUiState
import androidx.lifecycle.viewmodel.compose.viewModel

/**
 * Settings and privacy screen.
 *
 * Displays privacy architecture, permissions, and data handling information.
 * No user data is collected, stored, or transmitted.
 */
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier.fillMaxSize().padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        TopAppBar(
            title = { Text(text = stringResource(R.string.settings_title)) },
            colors = TopAppBarDefaults.mediumTopAppBarColors(
                containerColor = MaterialTheme.colorScheme.primary
            ),
            navigationIcon = {
                IconButton(onClick = onBack) {
                    Text(text = "\u2190")
                }
            }
        )

        Spacer(modifier = Modifier.height(8.dp))

        Text(
            text = stringResource(R.string.settings_privacy_title),
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface
        )

        Spacer(modifier = Modifier.height(8.dp))

        val privacyLines = listOf(
            stringResource(R.string.privacy_no_network),
            stringResource(R.string.privacy_no_sms_permission),
            stringResource(R.string.privacy_no_analytics),
            stringResource(R.string.privacy_local_processing),
            stringResource(R.string.privacy_no_url_auto_open),
            stringResource(R.string.privacy_original_preserved)
        )

        LazyColumn(
            modifier = Modifier.fillMaxWidth(),
            contentPadding = androidx.compose.foundation.layout.PaddingValues(horizontal = 16.dp)
        ) {
            items(privacyLines, key = { it }) { line ->
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(text = "\u26A1", style = MaterialTheme.typography.bodyMedium)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = line,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceContainer
            )
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = stringResource(R.string.settings_permissions_title),
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = stringResource(R.string.settings_permissions_body),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.8f)
                )
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Text(
            text = stringResource(R.string.settings_app_version),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
        )
    }
}

/**
 * Main screen with settings navigation.
 *
 * Wraps the original MainScreen content and adds a settings button to the
 * top app bar. When settings is open, only the settings screen is shown.
 */
@Composable
fun ThreatAssistantScreen(
    viewModel: ThreatAnalysisViewModel = viewModel(),
    ingestedInput: AnalysisInput? = null
) {
    var showSettings by remember { mutableStateOf(false) }

    if (showSettings) {
        SettingsScreen(
            onBack = { showSettings = false }
        )
        return
    }

    MainScreenContent(
        viewModel = viewModel,
        ingestedInput = ingestedInput,
        onSettingsClick = { showSettings = true }
    )
}

@Composable
private fun MainScreenContent(
    viewModel: ThreatAnalysisViewModel,
    ingestedInput: AnalysisInput?,
    onSettingsClick: () -> Unit
) {
    val context = LocalContext.current
    val state: ThreatAnalysisUiState by viewModel.uiState.collectAsState()

    // Ingest intent-sourced input (share sheet / process text) once when it arrives.
    LaunchedEffect(ingestedInput) {
        if (ingestedInput != null) {
            viewModel.onIngestedInput(context, ingestedInput)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = stringResource(R.string.app_name),
                        style = MaterialTheme.typography.titleLarge
                    )
                },
                colors = TopAppBarDefaults.mediumTopAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primary
                ),
                actions = {
                    IconButton(onClick = onSettingsClick) {
                        Text(text = "\u2699")
                    }
                }
            )
        }
    ) { paddingValues ->
        BoxWithConstraints(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(rememberScrollState())
        ) {
            val contentWidth = with(LocalDensity.current) {
                constraints.maxWidth.coerceAtMost((640 * density).toInt()).dp
            }

            Column(
                modifier = Modifier.width(contentWidth),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                MessageInput(
                    value = state.inputText,
                    onValueChange = { viewModel.onMessageChanged(it) },
                    errorMessage = state.errorMessage
                )

                AnalyzeButton(
                    onClick = { viewModel.onAnalyze(context) },
                    enabled = true
                )

                state.errorMessage?.let { error ->
                    Text(
                        text = error,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }

                ResultArea(
                    status = state.status,
                    resultMessage = state.resultMessage
                )

                NormalizedInputPreview(
                    normalizedText = state.normalizedText
                )

                ExtractedEntitiesSection(
                    urls = state.extractedUrls,
                    phones = state.extractedPhones
                )

                NormalizationWarningsSection(
                    warnings = state.normalizationWarnings
                )

                RuleDetectionSection(
                    result = state.ruleDetectionResult
                )

                UrlDetectionSection(
                    result = state.urlDetectionResult
                )

                SmsClassifierSection(
                    result = state.smsClassifierResult
                )

                RiskVerdictSection(
                    assessment = state.riskAssessment
                )

                EvidenceSection(
                    assessment = state.riskAssessment
                )

                RecommendedActionsSection(
                    verdict = state.riskAssessment?.verdict
                )

                when (state.inputSource) {
                    InputSource.SHARE_SHEET,
                    InputSource.PROCESS_TEXT -> {
                        Text(
                            text = stringResource(R.string.info_input_source),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                        )
                    }
                    InputSource.MANUAL -> {}
                }

                Spacer(modifier = Modifier.height(24.dp))
                AppInfoSection()
            }
        }
    }
}
