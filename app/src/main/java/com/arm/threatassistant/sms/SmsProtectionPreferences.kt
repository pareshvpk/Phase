package com.arm.threatassistant.sms

import android.content.Context

/**
 * Persists the user's opt-in choice for incoming-SMS protection.
 *
 * Only this single boolean is stored here. Flagged message text is kept
 * separately in app-private same-day storage for the Today tab.
 */
object SmsProtectionPreferences {

    private const val PREFS_NAME = "sms_protection"
    const val KEY_ENABLED = "sms_protection_enabled"

    fun isEnabled(context: Context): Boolean {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_ENABLED, false)
    }

    fun setEnabled(context: Context, enabled: Boolean) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit()
            .putBoolean(KEY_ENABLED, enabled)
            .apply()
    }
}
