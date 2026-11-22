package com.arm.threatassistant.sms

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log

/**
 * Listens for the MMS push notification.
 *
 * The MMS is not downloaded yet at this point, so this only ensures the
 * content-trigger job is scheduled. The job fires when the messages app writes
 * the message to content://mms.
 */
class IncomingMmsReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.WAP_PUSH_RECEIVED_ACTION) return
        if (intent.type != MMS_MIME_TYPE) return
        Log.i(TAG, "mms_push_received")
        MmsWatcher.schedule(context)
    }

    private companion object {
        const val TAG = "ARMSMS"
        const val MMS_MIME_TYPE = "application/vnd.wap.mms-message"
    }
}
