package com.arm.threatassistant.domain

import android.content.Context
import com.arm.threatassistant.domain.detection.riskpolicy.RiskAssessment
import com.arm.threatassistant.domain.detection.riskpolicy.RiskPolicyEngine
import com.arm.threatassistant.domain.detection.ruleengine.FastRuleEngine
import com.arm.threatassistant.domain.detection.ruleengine.RuleDetectionResult
import com.arm.threatassistant.domain.detection.smsclassifier.SmsClassifierResult
import com.arm.threatassistant.domain.detection.smsclassifier.SmsSpecialistClassifier
import com.arm.threatassistant.domain.detection.urldetection.UrlDetectionResult
import com.arm.threatassistant.domain.detection.urldetection.UrlSpecialistDetector
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.AnalysisStatus
import com.arm.threatassistant.domain.model.InputSource
import com.arm.threatassistant.domain.normalization.InputNormalizer

/**
 * Complete result of the on-device analysis pipeline.
 *
 * [normalizedInput] preserves the original message and adds the normalized
 * representation and extracted entities. [riskAssessment] holds the
 * authoritative verdict produced by [RiskPolicyEngine].
 */
data class ThreatAnalysisResult(
    val normalizedInput: AnalysisInput,
    val ruleDetectionResult: RuleDetectionResult,
    val urlDetectionResult: UrlDetectionResult,
    val classifierResult: SmsClassifierResult,
    val riskAssessment: RiskAssessment
)

/**
 * Reusable, process-wide entry point for the offline threat-analysis pipeline:
 * InputNormalizer -> FastRuleEngine -> UrlSpecialistDetector ->
 * SmsSpecialistClassifier -> RiskPolicyEngine.
 *
 * The classifier model is loaded from assets once, lazily, and shared by every
 * caller (UI and SMS receiver). Loading is guarded by a synchronized block so
 * concurrent analyses cannot load or replace the model more than once.
 *
 * No network access, no message persistence and no message-content logging.
 */
object ThreatAnalyzer {

    internal const val CLASSIFIER_ASSET = "sms_classifier_model.json"

    @Volatile
    private var classifier: SmsSpecialistClassifier? = null

    /**
     * Runs the full analysis pipeline synchronously. Callers that are on the
     * main thread should dispatch to a background thread first.
     */
    fun analyze(context: Context, text: String, source: InputSource): ThreatAnalysisResult {
        val input = AnalysisInput(messageText = text, source = source)
        val normalized = InputNormalizer.normalize(input)

        val ruleResult = FastRuleEngine.detect(normalized)
        val urlResult = UrlSpecialistDetector.detect(normalized)
        val classifierResult = getOrCreateClassifier(context).classify(normalized)
        val assessment = RiskPolicyEngine.assess(
            ruleResult = ruleResult,
            classifierResult = classifierResult,
            urlResult = urlResult,
            inputStatus = AnalysisStatus.COMPLETED
        )

        return ThreatAnalysisResult(
            normalizedInput = normalized,
            ruleDetectionResult = ruleResult,
            urlDetectionResult = urlResult,
            classifierResult = classifierResult,
            riskAssessment = assessment
        )
    }

    private fun getOrCreateClassifier(context: Context): SmsSpecialistClassifier {
        val existing = classifier
        if (existing != null) {
            return existing
        }
        return synchronized(this) {
            classifier ?: SmsSpecialistClassifier.fromAssets(
                context.applicationContext,
                CLASSIFIER_ASSET
            ).also { classifier = it }
        }
    }
}
