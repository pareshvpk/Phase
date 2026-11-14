package com.arm.threatassistant.sms

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import com.arm.threatassistant.domain.ThreatAnalyzer
import com.arm.threatassistant.domain.model.InputSource
import java.util.concurrent.Executors

/**
 * Opt-in receiver for android.provider.Telephony.SMS_RECEIVED.
 *
 * Exits immediately unless the user enabled SMS protection. Multipart bodies
 * are joined per originating address, then analyzed off the main thread via
 * [ThreatAnalyzer]. Analysis is fully on-device; message text is neither
 * stored nor logged. OTP, transaction and credential messages are skipped
 * before analysis.
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
                    if (SmsAlertPolicy.shouldAlert(verdict)) {
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
