package com.arm.threatassistant.sms

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import com.arm.threatassistant.domain.ThreatAnalyzer
import com.arm.threatassistant.domain.detection.ruleengine.DetectionSeverity
import com.arm.threatassistant.domain.detection.riskpolicy.RiskPolicyEngine
import com.arm.threatassistant.domain.model.InputSource
import com.arm.threatassistant.presentation.result.ReasonMapper
import java.util.UUID
import java.util.concurrent.Executors

/**
 * Opt-in receiver for android.provider.Telephony.SMS_RECEIVED.
 *
 * Exits immediately unless the user enabled SMS protection. Multipart bodies
 * are joined per originating address, then analyzed off the main thread via
 * [ThreatAnalyzer]. Analysis is fully on-device and message text is never
 * logged. OTP, transaction and credential messages are skipped before
 * analysis.
 *
 * Flagged (scam or suspicious) message text is kept in app-private storage
 * only until the end of the local day so it can appear in the Today list, and
 * is then deleted. Safe messages are never stored.
 */
class IncomingSmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        if (!SmsProtectionPreferences.isEnabled(context)) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) return

        val bySender = messages
            .groupBy { it.originatingAddress.orEmpty() }
            .mapValues { (_, parts) ->
                parts.joinToString(separator = "") { it.displayMessageBody.orEmpty() }
            }
            .filterValues { it.isNotBlank() }

        if (bySender.isEmpty()) return

        val pendingResult = goAsync()
        executor.execute {
            try {
                for ((sender, body) in bySender) {
                    if (SensitiveSmsFilter.shouldSkip(body)) continue
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
                        val reasons = ReasonMapper.map(
                            ruleResult = analysis.ruleDetectionResult,
                            urlResult = analysis.urlDetectionResult,
                            classifierResult = analysis.classifierResult
                        )
                        TodayAlertsStore.add(
                            context,
                            TodayAlert(
                                id = UUID.randomUUID().toString(),
                                sender = sender,
                                body = body,
                                verdict = verdict,
                                receivedAtMillis = System.currentTimeMillis(),
                                reasonIds = reasons.map { it.stableId }
                            )
                        )
                        SmsAlertNotifier.notify(context, sender, verdict, body)
                    }
                }
            } finally {
                pendingResult.finish()
            }
        }
    }

    private companion object {
        val executor = Executors.newSingleThreadExecutor()
    }
}
