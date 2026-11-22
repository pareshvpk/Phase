package com.arm.threatassistant.sms

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import java.util.concurrent.Executors

/**
 * Opt-in receiver for android.provider.Telephony.SMS_RECEIVED.
 *
 * Exits immediately unless the user enabled SMS protection. Multipart bodies
 * are joined per originating address, then analyzed off the main thread by
 * [SmsThreatProcessor]. Analysis is fully on-device and message text is never
 * logged (the ARMSMS log lines only carry counts and verdicts). OTP,
 * transaction and credential messages are skipped before analysis.
 *
 * Flagged (scam or suspicious) message text is kept in app-private storage
 * only until the end of the local day so it can appear in the Today list, and
 * is then deleted. Safe messages are never stored.
 */
class IncomingSmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        if (!SmsProtectionPreferences.isEnabled(context)) {
            Log.i(TAG, "sms_received protection=off")
            return
        }

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) return

        val bySender = messages
            .groupBy { it.originatingAddress.orEmpty() }
            .mapValues { (_, parts) ->
                parts.joinToString(separator = "") { it.displayMessageBody.orEmpty() }
            }
            .filterValues { it.isNotBlank() }

        if (bySender.isEmpty()) return
        Log.i(TAG, "sms_received senders=${bySender.size}")

        val pendingResult = goAsync()
        executor.execute {
            try {
                for ((sender, body) in bySender) {
                    if (!SmsProtectionPreferences.isEnabled(context)) break
                    SmsThreatProcessor.process(context, sender, body) { SmsProtectionPreferences.isEnabled(context) }
                }
            } catch (_: Exception) {
                Log.e(TAG, "sms_analysis_failed")
            } finally {
                pendingResult.finish()
            }
        }
    }

    private companion object {
        const val TAG = "ARMSMS"
        val executor = Executors.newSingleThreadExecutor()
    }
}
