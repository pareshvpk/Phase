package com.arm.threatassistant.presentation.settings

import android.content.Context
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

/**
 * App language options. [SYSTEM] follows the device locale; the other choices map
 * directly to an Android language tag used for the per-app locale.
 */
enum class AppLanguage(val languageTag: String) {
    SYSTEM(""),
    ENGLISH("en"),
    HINDI("hi"),
    TAMIL("ta");

    companion object {
        fun fromStorageValue(value: String?): AppLanguage =
            entries.firstOrNull { it.name == value } ?: SYSTEM
    }
}

/**
 * Theme options. [SYSTEM] follows the device dark-mode setting.
 */
enum class AppTheme(val storageValue: String) {
    SYSTEM("system"),
    LIGHT("light"),
    DARK("dark");

    companion object {
        fun fromStorageValue(value: String?): AppTheme =
            entries.firstOrNull { it.storageValue == value } ?: SYSTEM
    }
}

/**
 * Immutable snapshot of the user's app settings.
 */
data class AppSettingsState(
    val language: AppLanguage = AppLanguage.SYSTEM,
    val theme: AppTheme = AppTheme.SYSTEM,
    /** Auto-run a simple explanation for likely scams when the model is ready. */
    val explainAutomatically: Boolean = true,
    /**
     * Use the on-device model for Hindi/Tamil explanations (experimental).
     * Shown only when the app language is Hindi or Tamil.
     */
    val explanationsInLocalLanguage: Boolean = false
)

/**
 * Resolves whether dark colours should be used. Pure so it can be unit-tested.
 */
fun resolveDarkTheme(theme: AppTheme, systemInDarkTheme: Boolean): Boolean = when (theme) {
    AppTheme.SYSTEM -> systemInDarkTheme
    AppTheme.LIGHT -> false
    AppTheme.DARK -> true
}

/**
 * Name passed to the explanation prompt. For [AppLanguage.SYSTEM] the language
 * explanation is English unless the device locale is Hindi or Tamil.
 */
fun AppLanguage.explanationLanguageName(deviceLanguageTag: String?): String = when (this) {
    AppLanguage.ENGLISH -> "English"
    AppLanguage.HINDI -> "Hindi"
    AppLanguage.TAMIL -> "Tamil"
    AppLanguage.SYSTEM -> when (deviceLanguageTag) {
        "hi" -> "Hindi"
        "ta" -> "Tamil"
        else -> "English"
    }
}

/**
 * Persists the language and theme choices in SharedPreferences and exposes them
 * as a [StateFlow] so the UI updates immediately.
 *
 * The per-app locale is applied through [AppCompatDelegate] and, on API 33+, the
 * system persists it. On older API levels appcompat persists it automatically
 * via the `autoStoreLocales` metadata declared in the manifest.
 */
class AppSettings private constructor(context: Context) {

    private val preferences = context.applicationContext
        .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val _state = MutableStateFlow(load())
    val state: StateFlow<AppSettingsState> = _state.asStateFlow()

    init {
        AppCompatDelegate.setDefaultNightMode(load().theme.toNightMode())
    }

    fun setLanguage(language: AppLanguage) {
        preferences.edit().putString(KEY_LANGUAGE, language.name).apply()
        _state.update { it.copy(language = language) }
        applyLocale(language)
    }

    fun setTheme(theme: AppTheme) {
        preferences.edit().putString(KEY_THEME, theme.storageValue).apply()
        _state.update { it.copy(theme = theme) }
        AppCompatDelegate.setDefaultNightMode(theme.toNightMode())
    }

    fun setExplainAutomatically(enabled: Boolean) {
        preferences.edit().putBoolean(KEY_AUTO_EXPLAIN, enabled).apply()
        _state.update { it.copy(explainAutomatically = enabled) }
    }

    fun setExplanationsInLocalLanguage(enabled: Boolean) {
        preferences.edit().putBoolean(KEY_LOCAL_LANGUAGE_EXPLANATIONS, enabled).apply()
        _state.update { it.copy(explanationsInLocalLanguage = enabled) }
    }

    private fun load(): AppSettingsState = AppSettingsState(
        language = AppLanguage.fromStorageValue(preferences.getString(KEY_LANGUAGE, null)),
        theme = AppTheme.fromStorageValue(preferences.getString(KEY_THEME, null)),
        explainAutomatically = preferences.getBoolean(KEY_AUTO_EXPLAIN, true),
        explanationsInLocalLanguage = preferences.getBoolean(KEY_LOCAL_LANGUAGE_EXPLANATIONS, false)
    )

    companion object {
        private const val PREFS_NAME = "app_settings"
        private const val KEY_LANGUAGE = "app_language"
        private const val KEY_THEME = "app_theme"
        private const val KEY_AUTO_EXPLAIN = "explain_automatically"
        private const val KEY_LOCAL_LANGUAGE_EXPLANATIONS = "explanations_in_local_language"

        @Volatile
        private var instance: AppSettings? = null

        fun get(context: Context): AppSettings = instance ?: synchronized(this) {
            instance ?: AppSettings(context).also { instance = it }
        }
    }
}

private fun AppTheme.toNightMode(): Int = when (this) {
    AppTheme.SYSTEM -> AppCompatDelegate.MODE_NIGHT_FOLLOW_SYSTEM
    AppTheme.LIGHT -> AppCompatDelegate.MODE_NIGHT_NO
    AppTheme.DARK -> AppCompatDelegate.MODE_NIGHT_YES
}

private fun applyLocale(language: AppLanguage) {
    val locales = if (language == AppLanguage.SYSTEM) {
        LocaleListCompat.getEmptyLocaleList()
    } else {
        LocaleListCompat.forLanguageTags(language.languageTag)
    }
    AppCompatDelegate.setApplicationLocales(locales)
}
