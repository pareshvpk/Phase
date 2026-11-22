package com.arm.threatassistant.presentation.onboarding

import android.content.Context
import android.content.Intent

/** Shares the settings file, but owns only the introduction flag. */
object OnboardingPrefs {
    private const val PREFS_NAME = "app_settings"
    private const val KEY_DONE = "onboarding_done"

    fun isDone(context: Context): Boolean =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .getBoolean(KEY_DONE, false)

    fun markDone(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_DONE, true).apply()
    }

    fun reset(context: Context) {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            .edit().remove(KEY_DONE).apply()
    }
}

/** Even an empty share must reach the checker without an introduction gate. */
internal fun shouldShowOnboarding(done: Boolean, action: String?): Boolean =
    !done && action != Intent.ACTION_SEND && action != Intent.ACTION_PROCESS_TEXT
