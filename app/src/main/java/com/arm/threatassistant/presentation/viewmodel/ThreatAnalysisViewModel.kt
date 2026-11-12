package com.arm.threatassistant.presentation.viewmodel

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.arm.threatassistant.domain.adapters.InputAdapter
import com.arm.threatassistant.domain.adapters.ManualInputAdapter
import com.arm.threatassistant.domain.detection.ruleengine.FastRuleEngine
import com.arm.threatassistant.domain.detection.ruleengine.RuleDetectionResult
import com.arm.threatassistant.domain.detection.riskpolicy.RiskAssessment
import com.arm.threatassistant.domain.detection.riskpolicy.RiskPolicyEngine
import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierResult
import com.arm.threatassistant.domain.detection.smsclassifier.SmsSpecialistClassifier
import com.arm.threatassistant.domain.detection.urldetection.UrlDetectionResult
import com.arm.threatassistant.domain.detection.urldetection.UrlSpecialistDetector
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.AnalysisStatus
import com.arm.threatassistant.domain.model.InputSource
import com.arm.threatassistant.domain.normalization.InputNormalizer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

/**
 * View model for the main threat-analysis screen.
 *
 * Phase 2 connects the real input ingestion and normalization flow:
 * manual text is validated by [ManualInputAdapter], then normalized by
 * [InputNormalizer]. Phase 3A adds deterministic rule detection via
 * [FastRuleEngine]; detected signals are exposed in the UI state for
 * development/testing. No authoritative security verdict is produced here;
 * verdict determination remains with the RiskPolicyEngine (Phase 5).
 */
class ThreatAnalysisViewModel : ViewModel() {

    companion object {
        /** Placeholder result text shown when analysis cannot proceed. */
        internal const val NOT_IMPLEMENTED_MESSAGE =
            "Threat detection is not yet implemented. Input has been ingested and " +
            "normalized; detection will be delivered in a later phase."
    }

    private val adapter: InputAdapter = ManualInputAdapter()

    /** SMS specialist classifier — lazily initialized on first analysis. */
    private var smsClassifier: SmsSpecialistClassifier? = null

    /** Risk policy engine — authoritative verdict component. */
    private val riskEngine = RiskPolicyEngine

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
        val normalized = InputNormalizer.normalize(input)

        // Phase 3A: run deterministic rule detection on the normalized input.
        val detectionResult = FastRuleEngine.detect(normalized)

        // Phase 3: run URL specialist detection on the normalized input.
        val urlDetectionResult = UrlSpecialistDetector.detect(normalized)

        // Phase 3B: run SMS specialist classifier on the normalized input.
        // Everything below runs off the main thread on Dispatchers.Default,
        // including model loading (asset I/O) and inference.
        viewModelScope.launch(Dispatchers.Default) {
            val classifier = getOrCreateClassifier(context)
            val classifierResult = classifier.classify(normalized)

            // Phase 4: run risk policy engine to produce the authoritative verdict.
            val assessment = riskEngine.assess(
                ruleResult = detectionResult,
                classifierResult = classifierResult,
                urlResult = urlDetectionResult,
                inputStatus = AnalysisStatus.COMPLETED
            )

            val resultMessage = buildResultMessage(assessment, classifierResult)

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
                    ruleDetectionResult = detectionResult,
                    smsClassifierResult = classifierResult,
                    urlDetectionResult = urlDetectionResult,
                    riskAssessment = assessment
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

    /**
     * Lazily creates and caches the SMS specialist classifier. The model is
     * loaded from assets once and reused for the lifetime of the ViewModel.
     * If the model asset is missing or corrupt, the classifier reports
     * [SmsClassifierStatus.UNAVAILABLE] rather than crashing.
     */
    private fun getOrCreateClassifier(context: Context): SmsSpecialistClassifier {
        if (smsClassifier == null) {
            smsClassifier = SmsSpecialistClassifier.fromAssets(
                context,
                "sms_classifier_model_test_fixture.json"
            )
        }
        return smsClassifier!!
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
