package com.arm.threatassistant.sms

import android.content.Context
import android.util.Log
import com.arm.threatassistant.domain.ThreatAnalyzer
import com.arm.threatassistant.domain.detection.ruleengine.DetectionSeverity
import com.arm.threatassistant.domain.detection.riskpolicy.RiskPolicyEngine
import com.arm.threatassistant.domain.model.InputSource
import com.arm.threatassistant.presentation.result.ReasonMapper
import java.util.UUID

/**
 * Shared per-message pipeline for incoming SMS and MMS text.
 *
 * Message text is never logged: the ARMSMS lines only carry verdicts and
 * counts. OTP, transaction and credential messages are skipped before
 * analysis. Flagged text is kept in app-private same-day storage for the Today
 * tab and is deleted at local midnight.
 */
object SmsThreatProcessor {

    private const val TAG = "ARMSMS"

    fun process(
        context: Context,
        sender: String,
        body: String,
        messageId: String? = null,
        isActive: () -> Boolean = { true }
    ) {
        if (SensitiveSmsFilter.shouldSkip(body)) {
            Log.i(TAG, "sms_skipped sensitive")
            return
        }
        val analysis = ThreatAnalyzer.analyze(context, body, InputSource.SMS)
        val verdict = analysis.riskAssessment.verdict
        val hasHighSeverityRule = analysis.ruleDetectionResult.signals.any {
            it.severity == DetectionSeverity.HIGH
        }
        val classifierResult = analysis.classifierResult
        val classifierSaysScam = classifierResult.isThreat &&
            (classifierResult.threatScore ?: 0.0) >=
            RiskPolicyEngine.classifierMinConfidence
        if (SmsAlertPolicy.shouldAlert(
                verdict = verdict,
                sender = sender,
                hasHighSeverityRule = hasHighSeverityRule,
                classifierSaysScam = classifierSaysScam
            )
        ) {
            Log.i(TAG, "sms_alert verdict=$verdict")
            val reasons = ReasonMapper.map(
                ruleResult = analysis.ruleDetectionResult,
                urlResult = analysis.urlDetectionResult,
                classifierResult = analysis.classifierResult
            )
            if (!isActive()) return
            TodayAlertsStore.add(
                context,
                TodayAlert(
                    id = messageId ?: UUID.randomUUID().toString(),
                    sender = sender,
                    body = body,
                    verdict = verdict,
                    receivedAtMillis = System.currentTimeMillis(),
                    reasonIds = reasons.map { it.stableId }
                )
            )
            if (!isActive()) return
            SmsAlertNotifier.notify(context, sender, verdict, body, messageId?.hashCode())
        } else {
            Log.i(TAG, "sms_no_alert verdict=$verdict")
        }
    }
}
