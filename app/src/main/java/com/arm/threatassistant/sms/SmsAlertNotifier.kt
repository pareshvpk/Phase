package com.arm.threatassistant.sms

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import com.arm.threatassistant.MainActivity
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import java.util.concurrent.atomic.AtomicInteger

/**
 * Posts high-importance alerts for suspicious or high-risk incoming SMS.
 *
 * The notification never contains the message body. Tapping it opens
 * [MainActivity] with the message text so it is shown and analyzed again.
 */
internal object SmsAlertNotifier {

    const val CHANNEL_ID = "sms_threat_alerts"

    @Volatile
    private var channelCreated = false

    private val requestCodeCounter = AtomicInteger(0)

    fun notify(
        context: Context,
        sender: String?,
        verdict: ThreatVerdictLevel,
        messageText: String
    ) {
        ensureChannel(context)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }

        val notificationManager = NotificationManagerCompat.from(context)
        if (!notificationManager.areNotificationsEnabled()) {
            return
        }

        val displaySender = sender?.takeIf { it.isNotBlank() }
            ?: context.getString(R.string.sms_alert_unknown_sender)

        val contentIntent = Intent(context, MainActivity::class.java).apply {
            action = Intent.ACTION_SEND
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, messageText)
            putExtra(MainActivity.EXTRA_FROM_SMS_ALERT, true)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        }

        val notificationId = nextRequestCode()

        val pendingIntent = PendingIntent.getActivity(
            context,
            notificationId,
            contentIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_warning_sms)
            .setContentTitle(context.getString(R.string.sms_alert_title, displaySender))
            .setContentText(context.getString(R.string.sms_alert_text, verdict.name))
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText(context.getString(R.string.sms_alert_text, verdict.name))
            )
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()

        try {
            notificationManager.notify(notificationId, notification)
        } catch (_: SecurityException) {
            // Notification permission was revoked between the check and notify.
        }
    }

    private fun ensureChannel(context: Context) {
        if (channelCreated) return
        synchronized(this) {
            if (channelCreated) return
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                val channel = NotificationChannel(
                    CHANNEL_ID,
                    context.getString(R.string.sms_alert_channel_name),
                    NotificationManager.IMPORTANCE_HIGH
                ).apply {
                    description = context.getString(R.string.sms_alert_channel_description)
                }
                context.getSystemService(NotificationManager::class.java)
                    ?.createNotificationChannel(channel)
            }
            channelCreated = true
        }
    }

    private fun nextRequestCode(): Int {
        val timePart = (System.currentTimeMillis() and 0x00FFFFFF).toInt()
        val counterPart = requestCodeCounter.incrementAndGet() and 0xFF
        return (timePart shl 8) or counterPart
    }
}
