package com.arm.threatassistant.presentation.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.arm.threatassistant.BuildConfig
import com.arm.threatassistant.R
import com.arm.threatassistant.presentation.settings.AppLanguage
import com.arm.threatassistant.presentation.settings.AppSettings
import com.arm.threatassistant.presentation.settings.AppTheme
import com.arm.threatassistant.presentation.theme.ArmTheme

/**
 * Settings tab: language, appearance, explanations, privacy and introduction.
 */
@Composable
fun SettingsScreen(modifier: Modifier = Modifier, onShowIntroduction: () -> Unit = {}) {
    val context = LocalContext.current
    val settings = AppSettings.get(context)
    val settingsState by settings.state.collectAsState()
    var showPrivacy by rememberSaveable { mutableStateOf(false) }

    if (showPrivacy) {
        AlertDialog(
            onDismissRequest = { showPrivacy = false },
            title = { Text(stringResource(R.string.settings_privacy_title)) },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    Text(stringResource(R.string.onboarding_privacy_body))
                    Text(stringResource(R.string.privacy_model_download))
                    Text(stringResource(R.string.privacy_protection_control))
                }
            },
            confirmButton = {
                TextButton(onClick = { showPrivacy = false }) {
                    Text(stringResource(R.string.privacy_close))
                }
            }
        )
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = stringResource(R.string.settings_title),
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onBackground
        )

        SettingsGroup(title = stringResource(R.string.settings_language_title)) {
            AppLanguage.entries.forEach { language ->
                SettingsRadioRow(
                    label = stringResource(language.labelRes),
                    selected = settingsState.language == language,
                    onClick = { settings.setLanguage(language) }
                )
            }
        }

        SettingsGroup(title = stringResource(R.string.settings_theme_title)) {
            AppTheme.entries.forEach { theme ->
                SettingsRadioRow(
                    label = stringResource(theme.labelRes),
                    selected = settingsState.theme == theme,
                    onClick = { settings.setTheme(theme) }
                )
            }
        }

        SettingsGroup(title = stringResource(R.string.settings_explanations_title)) {
            SettingsSwitchRow(
                label = stringResource(R.string.settings_auto_explain_title),
                summary = stringResource(R.string.settings_auto_explain_summary),
                selected = settingsState.explainAutomatically,
                onClick = { settings.setExplainAutomatically(!settingsState.explainAutomatically) }
            )
            if (settingsState.language == AppLanguage.HINDI ||
                settingsState.language == AppLanguage.TAMIL
            ) {
                SettingsSwitchRow(
                    label = stringResource(R.string.settings_local_language_explanations_title),
                    summary = stringResource(R.string.settings_local_language_explanations_summary),
                    selected = settingsState.explanationsInLocalLanguage,
                    onClick = {
                        settings.setExplanationsInLocalLanguage(!settingsState.explanationsInLocalLanguage)
                    }
                )
            }
        }

        SettingsGroup(title = stringResource(R.string.settings_about_title)) {
            TextButton(onClick = { showPrivacy = true }) {
                Text(stringResource(R.string.settings_privacy_title))
            }
            TextButton(onClick = onShowIntroduction) {
                Text(stringResource(R.string.settings_show_introduction))
            }
            Text(
                text = stringResource(
                    R.string.settings_version_format,
                    BuildConfig.VERSION_NAME
                ),
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
        }
    }
}

@Composable
private fun SettingsGroup(
    title: String,
    content: @Composable () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = ArmTheme.colors.cardSurface
        )
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            content()
        }
    }
}

@Composable
private fun SettingsRadioRow(
    label: String,
    selected: Boolean,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RadioButton(selected = selected, onClick = onClick)
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface
        )
    }
}

private val AppLanguage.labelRes: Int
    get() = when (this) {
        AppLanguage.SYSTEM -> R.string.settings_language_system
        AppLanguage.ENGLISH -> R.string.settings_language_english
        AppLanguage.HINDI -> R.string.settings_language_hindi
        AppLanguage.TAMIL -> R.string.settings_language_tamil
    }

private val AppTheme.labelRes: Int
    get() = when (this) {
        AppTheme.SYSTEM -> R.string.settings_theme_system
        AppTheme.LIGHT -> R.string.settings_theme_light
        AppTheme.DARK -> R.string.settings_theme_dark
    }

@Composable
private fun SettingsSwitchRow(
    label: String,
    summary: String,
    selected: Boolean,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column {
            Text(
                text = label,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = summary,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
        Spacer(modifier = Modifier.width(8.dp))
        Switch(checked = selected, onCheckedChange = { onClick() })
    }
}
