package com.arm.threatassistant.presentation.viewmodel

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.arm.threatassistant.domain.ThreatAnalyzer
import com.arm.threatassistant.domain.adapters.InputAdapter
import com.arm.threatassistant.domain.adapters.ManualInputAdapter
import com.arm.threatassistant.domain.detection.riskpolicy.RiskAssessment
import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import com.arm.threatassistant.domain.detection.ruleengine.RuleDetectionResult
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierResult
import com.arm.threatassistant.domain.detection.urldetection.UrlDetectionResult
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.AnalysisStatus
import com.arm.threatassistant.domain.model.InputSource
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * View model for the main threat-analysis screen.
 *
 * Manual text is validated by [ManualInputAdapter], then handed to the shared
 * [ThreatAnalyzer], which runs the full offline pipeline (normalization, rule
 * detection, URL detection, SMS classification and risk policy) on a
 * background thread. Intent-sourced input follows the same path.
 */
class ThreatAnalysisViewModel : ViewModel() {

    companion object {
        /** Placeholder result text shown when analysis cannot proceed. */
        internal const val NOT_IMPLEMENTED_MESSAGE =
            "Threat detection is not yet implemented. Input has been ingested and " +
            "normalized; detection will be delivered in a later phase."
    }

    private val adapter: InputAdapter = ManualInputAdapter()

    private val _uiState = MutableStateFlow(ThreatAnalysisUiState())
    val uiState: StateFlow<ThreatAnalysisUiState> = _uiState.asStateFlow()

    fun onMessageChanged(text: String) {
        _uiState.update {
            it.copy(
                inputText = text,
                status = AnalysisStatus.IDLE,
                errorMessage = null,
                resultMessage = null,
                normalizedText = null,
                extractedUrls = emptyList(),
                extractedPhones = emptyList(),
                normalizationWarnings = emptyList(),
                ruleDetectionResult = null,
                smsClassifierResult = null,
                urlDetectionResult = null,
                riskAssessment = null
            )
        }
    }

    fun onAnalyze(context: Context) {
        val text = _uiState.value.inputText

        val adapted = adapter.adapt(text)
        if (adapted == null) {
            _uiState.update {
                it.copy(
                    status = AnalysisStatus.IDLE,
                    errorMessage = "Please enter a message to analyze.",
                    resultMessage = null,
                    ruleDetectionResult = null,
                    smsClassifierResult = null,
                    urlDetectionResult = null,
                    riskAssessment = null
                )
            }
            return
        }

        ingest(context, adapted)
    }

    /**
     * Ingests input that arrived via an Android intent (share sheet or process
     * text). The caller has already adapted the intent into an [AnalysisInput]
     * with the correct [InputSource]; this method normalizes it and updates the
     * UI state. No threat verdict is produced.
     */
    fun onIngestedInput(context: Context, input: AnalysisInput) {
        if (input.messageText.isBlank()) {
            _uiState.update {
                it.copy(
                    inputText = "",
                    status = AnalysisStatus.IDLE,
                    errorMessage = "Shared content contained no usable text.",
                    resultMessage = null,
                    ruleDetectionResult = null,
                    smsClassifierResult = null,
                    urlDetectionResult = null,
                    riskAssessment = null
                )
            }
            return
        }

        // Populate the input field immediately so the shared text is visible,
        // then run the same analysis pipeline used for manual input.
        _uiState.update {
            it.copy(
                inputText = input.messageText,
                errorMessage = null,
                status = AnalysisStatus.ANALYZING,
                resultMessage = null,
                normalizedText = null,
                extractedUrls = emptyList(),
                extractedPhones = emptyList(),
                normalizationWarnings = emptyList(),
                ruleDetectionResult = null,
                smsClassifierResult = null,
                urlDetectionResult = null,
                riskAssessment = null
            )
        }
        ingest(context, input)
    }

    private fun ingest(context: Context, input: AnalysisInput) {
        // The complete offline pipeline runs off the main thread. The shared
        // ThreatAnalyzer loads and caches the classifier model exactly once.
        viewModelScope.launch(Dispatchers.Default) {
            val analysis = ThreatAnalyzer.analyze(context, input.messageText, input.source)
            val normalized = analysis.normalizedInput

            val resultMessage = buildResultMessage(
                analysis.riskAssessment,
                analysis.classifierResult
            )

            _uiState.update {
                it.copy(
                    status = AnalysisStatus.COMPLETED,
                    errorMessage = null,
                    resultMessage = resultMessage,
                    normalizedText = normalized.normalizedText,
                    extractedUrls = normalized.extractedUrls,
                    extractedPhones = normalized.extractedPhones,
                    normalizationWarnings = normalized.normalizationWarnings,
                    inputSource = normalized.source,
                    ruleDetectionResult = analysis.ruleDetectionResult,
                    smsClassifierResult = analysis.classifierResult,
                    urlDetectionResult = analysis.urlDetectionResult,
                    riskAssessment = analysis.riskAssessment
                )
            }
        }
    }

    private fun buildResultMessage(assessment: RiskAssessment, classifierResult: SmsClassifierResult?): String {
        val sb = StringBuilder()
        sb.append("Verdict: ${assessment.verdict} (risk score: ${"%.2f".format(assessment.riskScore)})\n")
        sb.append("Evidence:\n")
        for (line in assessment.evidenceSummary) {
            sb.append("  • $line\n")
        }
        if (classifierResult?.contributingFeatures?.isNotEmpty() == true) {
            sb.append("Top contributing features:\n")
            for (f in classifierResult.contributingFeatures!!.take(5)) {
                sb.append("    - ${f.term}: contribution ${"%.3f".format(f.contribution)}\n")
            }
        }
        sb.append("Recommended actions:\n")
        sb.append(recommendedActions(assessment.verdict).joinToString("\n") { "  • $it" })
        return sb.toString()
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
}

data class ThreatAnalysisUiState(
    val inputText: String = "",
    val normalizedText: String? = null,
    val status: AnalysisStatus = AnalysisStatus.IDLE,
    val resultMessage: String? = null,
    val errorMessage: String? = null,
    val extractedUrls: List<String> = emptyList(),
    val extractedPhones: List<String> = emptyList(),
    val normalizationWarnings: List<String> = emptyList(),
    val inputSource: InputSource = InputSource.MANUAL,
    val ruleDetectionResult: RuleDetectionResult? = null,
    val smsClassifierResult: SmsClassifierResult? = null,
    val urlDetectionResult: UrlDetectionResult? = null,
    val riskAssessment: RiskAssessment? = null
)
