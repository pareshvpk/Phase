package com.arm.threatassistant.presentation.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.collectAsState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.AnalysisStatus
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
import com.arm.threatassistant.presentation.components.SmsProtectionCard
import com.arm.threatassistant.presentation.components.UrlDetectionSection
import com.arm.threatassistant.presentation.viewmodel.ThreatAnalysisViewModel
import com.arm.threatassistant.presentation.viewmodel.ThreatAnalysisUiState
import androidx.lifecycle.viewmodel.compose.viewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MainScreen(
    viewModel: ThreatAnalysisViewModel = viewModel(),
    ingestedInput: AnalysisInput? = null
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
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primary,
                    titleContentColor = MaterialTheme.colorScheme.onPrimary,
                    actionIconContentColor = MaterialTheme.colorScheme.onPrimary,
                    navigationIconContentColor = MaterialTheme.colorScheme.onPrimary
                )
            )
        }
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(rememberScrollState()),
            contentAlignment = Alignment.TopCenter
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .widthIn(max = 640.dp)
                    .padding(horizontal = 16.dp),
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

                SmsProtectionCard()

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
                    InputSource.SHARE_SHEET, InputSource.PROCESS_TEXT -> {
                        Text(
                            text = stringResource(R.string.info_input_source),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                        )
                    }
                    InputSource.SMS -> {
                        Text(
                            text = stringResource(R.string.info_input_source_sms),
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
