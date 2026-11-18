package com.arm.threatassistant.presentation.screens

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.apps.AppRiskFinding
import com.arm.threatassistant.domain.apps.AppRiskLevel
import com.arm.threatassistant.domain.apps.AppScanResult
import com.arm.threatassistant.presentation.theme.ArmTheme
import com.arm.threatassistant.presentation.viewmodel.AppsScanState
import com.arm.threatassistant.presentation.viewmodel.AppsViewModel

/**
 * Apps tab: an on-device scan of installed apps for behaviour that is typical
 * of banking trojans and remote-access scams. Everything is read and judged
 * locally; the footer states that promise in plain words.
 */
@Composable
fun AppsScreen(
    modifier: Modifier = Modifier,
    viewModel: AppsViewModel
) {
    val context = LocalContext.current
    val state by viewModel.uiState.collectAsState()

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.apps_title),
                        style = MaterialTheme.typography.headlineSmall,
                        color = MaterialTheme.colorScheme.onBackground
                    )
                    Text(
                        text = stringResource(R.string.apps_subtitle),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (state is AppsScanState.Results) {
                    TextButton(onClick = { viewModel.scan() }) {
                        Text(text = stringResource(R.string.apps_scan_button))
                    }
                }
            }
        }

        when (val current = state) {
            AppsScanState.Idle -> item {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Button(onClick = { viewModel.scan() }) {
                        Text(text = stringResource(R.string.apps_scan_button))
                    }
                }
            }

            AppsScanState.Scanning -> item {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 24.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    CircularProgressIndicator()
                    Spacer(modifier = Modifier.size(16.dp))
                    Text(
                        text = stringResource(R.string.apps_scanning),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            is AppsScanState.Results -> {
                val attention = current.results.filter { it.level != AppRiskLevel.SAFE }
                val safeCount = current.results.size - attention.size

                item {
                    Text(
                        text = if (attention.isEmpty()) {
                            stringResource(R.string.apps_no_risky)
                        } else {
                            stringResource(R.string.apps_need_attention, attention.size)
                        },
                        style = MaterialTheme.typography.titleMedium,
                        color = if (attention.isEmpty()) {
                            ArmTheme.colors.onSafeContainer
                        } else {
                            MaterialTheme.colorScheme.onBackground
                        }
                    )
                }

                items(attention, key = { result -> result.app.packageName }) { result ->
                    AppRiskCard(
                        result = result,
                        onOpenSettings = {
                            val intent = Intent(
                                Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                Uri.parse("package:${result.app.packageName}")
                            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            runCatching { context.startActivity(intent) }
                        },
                        onUninstall = {
                            val intent = Intent(
                                Intent.ACTION_DELETE,
                                Uri.parse("package:${result.app.packageName}")
                            ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            runCatching { context.startActivity(intent) }
                        }
                    )
                }

                if (safeCount > 0) {
                    item {
                        Text(
                            text = stringResource(R.string.apps_look_fine, safeCount),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }

        item {
            Text(
                text = stringResource(R.string.apps_footer),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun AppRiskCard(
    result: AppScanResult,
    onOpenSettings: () -> Unit,
    onUninstall: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = ArmTheme.colors.cardSurface)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = result.app.label,
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f)
                )
                Spacer(modifier = Modifier.width(8.dp))
                AppRiskLevelChip(level = result.level)
            }

            Spacer(modifier = Modifier.size(10.dp))

            result.findings.forEach { finding ->
                Text(
                    text = stringResource(finding.labelRes),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = 4.dp)
                )
            }

            Spacer(modifier = Modifier.size(8.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = onOpenSettings) {
                    Text(text = stringResource(R.string.apps_action_settings))
                }
                OutlinedButton(onClick = onUninstall) {
                    Text(text = stringResource(R.string.apps_action_uninstall))
                }
            }
        }
    }
}

@Composable
private fun AppRiskLevelChip(level: AppRiskLevel) {
    val colors = ArmTheme.colors
    val style = when (level) {
        AppRiskLevel.DANGEROUS -> AppLevelStyle(
            container = colors.dangerContainer,
            content = colors.onDangerContainer,
            labelRes = R.string.apps_level_dangerous
        )

        AppRiskLevel.REVIEW -> AppLevelStyle(
            container = colors.suspiciousContainer,
            content = colors.onSuspiciousContainer,
            labelRes = R.string.apps_level_review
        )

        AppRiskLevel.SAFE -> AppLevelStyle(
            container = colors.safeContainer,
            content = colors.onSafeContainer,
            labelRes = R.string.apps_no_risky
        )
    }

    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(style.container)
            .padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            text = stringResource(style.labelRes),
            style = MaterialTheme.typography.labelMedium,
            color = style.content
        )
    }
}

private data class AppLevelStyle(
    val container: Color,
    val content: Color,
    val labelRes: Int
)

private val AppRiskFinding.labelRes: Int
    get() = when (this) {
        AppRiskFinding.SIDELOADED -> R.string.apps_finding_sideloaded
        AppRiskFinding.READS_SMS -> R.string.apps_finding_reads_sms
        AppRiskFinding.ACCESSIBILITY_CONTROL -> R.string.apps_finding_accessibility
        AppRiskFinding.SCREEN_OVERLAY -> R.string.apps_finding_overlay
        AppRiskFinding.DEVICE_ADMIN -> R.string.apps_finding_device_admin
        AppRiskFinding.HIDDEN_ICON -> R.string.apps_finding_hidden_icon
        AppRiskFinding.INSTALLS_APPS -> R.string.apps_finding_installs_apps
        AppRiskFinding.READS_NOTIFICATIONS -> R.string.apps_finding_reads_notifications
        AppRiskFinding.SMS_PLUS_ACCESSIBILITY -> R.string.apps_finding_sms_accessibility
        AppRiskFinding.REMOTE_CONTROL_COMBO -> R.string.apps_finding_remote_control
    }
