package com.arm.threatassistant.presentation.viewmodel

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.ThreatAnalyzer
import com.arm.threatassistant.domain.ThreatAnalysisResult
import com.arm.threatassistant.domain.adapters.InputAdapter
import com.arm.threatassistant.domain.adapters.ManualInputAdapter
import com.arm.threatassistant.domain.detection.riskpolicy.RiskAssessment
import com.arm.threatassistant.domain.detection.ruleengine.RuleDetectionResult
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierResult
import com.arm.threatassistant.domain.detection.urldetection.UrlDetectionResult
import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.AnalysisStatus
import com.arm.threatassistant.llm.AdviceGuard
import com.arm.threatassistant.llm.ExplanationPromptBuilder
import com.arm.threatassistant.llm.LlmExplainerProvider
import com.arm.threatassistant.presentation.result.OfflineExplanation
import com.arm.threatassistant.presentation.result.ReasonMapper
import com.arm.threatassistant.presentation.settings.AppLanguage
import com.arm.threatassistant.presentation.settings.AppSettings
import com.arm.threatassistant.presentation.settings.AppSettingsState
import com.arm.threatassistant.presentation.settings.explanationLanguageName
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.Locale

/**
 * State of the optional on-device Llama explanation. The explanation is always
 * derived from the authoritative detection verdict and never changes it.
 */
sealed interface ExplanationState {
    data object Hidden : ExplanationState
    data object Ready : ExplanationState
    data class Generating(val text: String) : ExplanationState
    data class Done(val text: String) : ExplanationState
    data class Failed(val message: String) : ExplanationState
}

/**
 * View model for the message-checking screen.
 *
 * Manual text is validated by [ManualInputAdapter], then handed to the shared
 * [ThreatAnalyzer], which runs the full offline pipeline (normalization, rule
 * detection, URL detection, SMS classification and risk policy) on a
 * background thread. Intent-sourced input follows the same path.
 */
class ThreatAnalysisViewModel : ViewModel() {

    private val adapter: InputAdapter = ManualInputAdapter()

    private val _uiState = MutableStateFlow(ThreatAnalysisUiState())
    val uiState: StateFlow<ThreatAnalysisUiState> = _uiState.asStateFlow()

    private var explanationJob: Job? = null

    fun onMessageChanged(context: Context, text: String) {
        stopExplanation(context)
        _uiState.update {
            it.copy(
                inputText = text,
                status = AnalysisStatus.IDLE,
                errorMessage = null,
                normalizedText = null,
                ruleDetectionResult = null,
                smsClassifierResult = null,
                urlDetectionResult = null,
                riskAssessment = null,
                highlightPhrases = emptyList(),
                explanation = explanationAvailability(context)
            )
        }
    }

    fun onAnalyze(context: Context) {
        val text = _uiState.value.inputText

        stopExplanation(context)

        val adapted = adapter.adapt(text)
        if (adapted == null) {
            _uiState.update {
                it.copy(
                    status = AnalysisStatus.IDLE,
                    errorMessage = context.getString(R.string.error_empty_input),
                    ruleDetectionResult = null,
                    smsClassifierResult = null,
                    urlDetectionResult = null,
                    riskAssessment = null,
                    highlightPhrases = emptyList(),
                    explanation = explanationAvailability(context)
                )
            }
            return
        }

        ingest(context, adapted)
    }

    /**
     * Ingests input that arrived via an Android intent (share sheet or process
     * text). The caller has already adapted the intent into an [AnalysisInput];
     * this method populates the input field and runs the analysis pipeline.
     */
    fun onIngestedInput(context: Context, input: AnalysisInput) {
        stopExplanation(context)

        if (input.messageText.isBlank()) {
            _uiState.update {
                it.copy(
                    inputText = "",
                    status = AnalysisStatus.IDLE,
                    errorMessage = context.getString(R.string.error_shared_empty),
                    ruleDetectionResult = null,
                    smsClassifierResult = null,
                    urlDetectionResult = null,
                    riskAssessment = null,
                    highlightPhrases = emptyList(),
                    explanation = explanationAvailability(context)
                )
            }
            return
        }

        _uiState.update {
            it.copy(
                inputText = input.messageText,
                errorMessage = null,
                status = AnalysisStatus.ANALYZING,
                normalizedText = null,
                ruleDetectionResult = null,
                smsClassifierResult = null,
                urlDetectionResult = null,
                riskAssessment = null,
                highlightPhrases = emptyList(),
                explanation = explanationAvailability(context)
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

            _uiState.update {
                it.copy(
                    status = AnalysisStatus.COMPLETED,
                    errorMessage = null,
                    normalizedText = normalized.normalizedText,
                    ruleDetectionResult = analysis.ruleDetectionResult,
                    smsClassifierResult = analysis.classifierResult,
                    urlDetectionResult = analysis.urlDetectionResult,
                    riskAssessment = analysis.riskAssessment,
                    highlightPhrases = highlightPhrases(analysis),
                    explanation = explanationAvailability(context)
                )
            }
        }
    }

    private fun highlightPhrases(analysis: ThreatAnalysisResult): List<String> {
        val rulePhrases = analysis.ruleDetectionResult.signals
            .mapNotNull { signal -> signal.matchedText.takeIf { text -> text.isNotBlank() } }
        val urlPhrases = analysis.urlDetectionResult.signals
            .mapNotNull { signal -> signal.matchedUrl.takeIf { url -> url.isNotBlank() } }
        return (rulePhrases + urlPhrases).distinct()
    }

    /**
     * Generates a plain-language explanation for the current verdict. The
     * explanation is advisory only; it never changes the verdict. When [auto] is
     * true the call is a no-op unless auto-explain is enabled for this verdict.
     */
    fun onExplain(context: Context) {
        startExplanation(context, auto = false)
    }

    /** Starts an automatic explanation when the settings and verdict allow it. */
    fun startAutoExplanation(context: Context) {
        startExplanation(context, auto = true)
    }

    /** Cancels any in-flight generation and stops the native module. */
    fun cancelExplanation(context: Context) {
        stopExplanation(context)
    }

    private fun startExplanation(context: Context, auto: Boolean) {
        val current = _uiState.value
        val assessment = current.riskAssessment ?: return
        if (auto && !shouldAutoExplain(assessment.verdict, AppSettings.get(context).state.value)) return

        val explainer = LlmExplainerProvider.get(context.applicationContext) ?: run {
            _uiState.update { it.copy(explanation = ExplanationState.Hidden) }
            return
        }

        val messageText = current.normalizedText ?: current.inputText
        val language = AppSettings.get(context).state.value.language
        val languageName = language.explanationLanguageName(Locale.getDefault().language)
        // Split so the long system prefix stays in the KV cache between messages.
        val prefix = ExplanationPromptBuilder.prefix(languageName)
        val tail = ExplanationPromptBuilder.tail(
            verdictLabel = assessment.verdict.name,
            evidence = assessment.evidenceSummary,
            messageText = messageText,
            languageName = languageName
        )

        val fallbackErrorMessage = context.getString(R.string.error_explanation_failed)
        val fallback = OfflineExplanation.build(
            context,
            ReasonMapper.map(
                ruleResult = current.ruleDetectionResult,
                urlResult = current.urlDetectionResult,
                classifierResult = current.smsClassifierResult
            )
        )
        val safeSteps = OfflineExplanation.safeStepsFor(context, assessment.verdict)

        stopExplanation(context)
        _uiState.update { it.copy(explanation = ExplanationState.Generating("")) }

        explanationJob = viewModelScope.launch {
            try {
                val text = explainer.explain(prefix, tail) { token ->
                    _uiState.update { state ->
                        val generating = state.explanation as? ExplanationState.Generating
                        if (generating == null) {
                            state
                        } else {
                            state.copy(
                                explanation = ExplanationState.Generating(generating.text + token)
                            )
                        }
                    }
                }
                val guarded = AdviceGuard.guard(
                    text = text,
                    verdict = assessment.verdict,
                    languageTag = languageTag(context),
                    fallback = fallback,
                    safeSteps = safeSteps
                )
                _uiState.update { it.copy(explanation = ExplanationState.Done(guarded)) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (t: Throwable) {
                val message = t.message?.takeIf { it.isNotBlank() }
                    ?: fallbackErrorMessage
                _uiState.update { it.copy(explanation = ExplanationState.Failed(message)) }
            }
        }
    }

    private fun shouldAutoExplain(verdict: ThreatVerdictLevel, settings: AppSettingsState): Boolean {
        if (!settings.explainAutomatically) return false
        return when (verdict) {
            ThreatVerdictLevel.HIGH_RISK, ThreatVerdictLevel.SUSPICIOUS -> true
            // No scam signal: nothing to explain, so do not run Llama.
            ThreatVerdictLevel.INSUFFICIENT_EVIDENCE, ThreatVerdictLevel.SAFE -> false
        }
    }

    private fun languageTag(context: Context): String {
        val language = AppSettings.get(context).state.value.language
        return when (language) {
            AppLanguage.HINDI -> "hi"
            AppLanguage.TAMIL -> "ta"
            AppLanguage.ENGLISH -> "en"
            AppLanguage.SYSTEM -> {
                val locales = context.resources.configuration.locales
                val tag = if (locales.size() > 0) locales.get(0).language else null
                tag?.lowercase() ?: "en"
            }
        }
    }

    private fun explanationAvailability(context: Context): ExplanationState =
        if (LlmExplainerProvider.get(context.applicationContext) != null) {
            ExplanationState.Ready
        } else {
            ExplanationState.Hidden
        }

    private fun stopExplanation(context: Context) {
        explanationJob?.cancel()
        explanationJob = null
        LlmExplainerProvider.get(context.applicationContext)?.stop()
    }
}

data class ThreatAnalysisUiState(
    val inputText: String = "",
    val normalizedText: String? = null,
    val status: AnalysisStatus = AnalysisStatus.IDLE,
    val errorMessage: String? = null,
    val ruleDetectionResult: RuleDetectionResult? = null,
    val smsClassifierResult: SmsClassifierResult? = null,
    val urlDetectionResult: UrlDetectionResult? = null,
    val riskAssessment: RiskAssessment? = null,
    val highlightPhrases: List<String> = emptyList(),
    val explanation: ExplanationState = ExplanationState.Hidden
)
