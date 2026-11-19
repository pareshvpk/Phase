package com.arm.threatassistant.presentation.screens

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.text.format.DateFormat
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import com.arm.threatassistant.presentation.components.ShieldHero
import com.arm.threatassistant.presentation.result.ReasonId
import com.arm.threatassistant.presentation.result.labelRes
import com.arm.threatassistant.presentation.theme.ArmTheme
import com.arm.threatassistant.sms.SmsProtectionPreferences
import com.arm.threatassistant.sms.TodayAlert
import com.arm.threatassistant.sms.TodayAlertsLogic
import com.arm.threatassistant.sms.TodayAlertsStore
import kotlinx.coroutines.delay
import java.time.ZoneId
import java.util.Date

/**
 * Today tab: scam and suspicious messages received today, in local time.
 *
 * The list clears itself at local midnight. Tapping a card opens the regular
 * Check screen with the message re-ingested from SMS so the full verdict,
 * reasons and next steps are shown.
 */
@Composable
fun TodayScreen(
    modifier: Modifier = Modifier,
    onOpenAlert: (TodayAlert) -> Unit = {},
    onOpenProtection: () -> Unit = {}
) {
    val context = LocalContext.current
    val alerts by TodayAlertsStore.alerts.collectAsState()
    var protectionOn by remember { mutableStateOf(isProtectionOn(context)) }
    var showClearDialog by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        protectionOn = isProtectionOn(context)
        TodayAlertsStore.getToday(context)
        while (true) {
            val remaining = TodayAlertsLogic.millisUntilNextMidnight(
                nowMillis = System.currentTimeMillis(),
                zone = ZoneId.systemDefault()
            )
            delay(remaining.coerceAtLeast(1_000L))
            TodayAlertsStore.getToday(context)
        }
    }

    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        protectionOn = isProtectionOn(context)
        TodayAlertsStore.getToday(context)
    }

    if (showClearDialog) {
        AlertDialog(
            onDismissRequest = { showClearDialog = false },
            title = { Text(text = stringResource(R.string.today_clear_all_confirm_title)) },
            text = {
                Text(
                    text = pluralStringResource(
                        R.plurals.today_clear_all_confirm_message,
                        alerts.size,
                        alerts.size
                    )
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showClearDialog = false
                        TodayAlertsStore.clear(context)
                    }
                ) {
                    Text(text = stringResource(R.string.today_delete))
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearDialog = false }) {
                    Text(text = stringResource(R.string.today_cancel))
                }
            }
        )
    }

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
                        text = stringResource(R.string.today_title),
                        style = MaterialTheme.typography.headlineSmall,
                        color = MaterialTheme.colorScheme.onBackground
                    )
                    Text(
                        text = stringResource(R.string.today_subtitle),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                if (protectionOn && alerts.isNotEmpty()) {
                    TextButton(onClick = { showClearDialog = true }) {
                        Text(text = stringResource(R.string.today_clear_all))
                    }
                }
            }
        }

        when {
            !protectionOn -> item {
                TodayMessageState(
                    title = stringResource(R.string.today_protection_off_title),
                    subtitle = null,
                    action = {
                        Button(onClick = onOpenProtection) {
                            Text(text = stringResource(R.string.today_protection_off_button))
                        }
                    }
                )
            }

            alerts.isEmpty() -> item {
                TodayMessageState(
                    title = stringResource(R.string.today_empty_title),
                    subtitle = stringResource(R.string.today_empty_subtitle),
                    action = null
                )
            }

            else -> items(alerts, key = { it.id }) { alert ->
                TodayAlertCard(
                    alert = alert,
                    onOpen = { onOpenAlert(alert) },
                    onDelete = { TodayAlertsStore.remove(context, alert.id) }
                )
            }
        }
    }
}

@Composable
private fun TodayMessageState(
    title: String,
    subtitle: String?,
    action: (@Composable () -> Unit)?
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        ShieldHero(size = 96.dp)
        Spacer(modifier = Modifier.size(16.dp))
        Text(
            text = title,
            style = MaterialTheme.typography.titleLarge,
            color = MaterialTheme.colorScheme.onBackground,
            textAlign = TextAlign.Center
        )
        if (subtitle != null) {
            Spacer(modifier = Modifier.size(4.dp))
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center
            )
        }
        if (action != null) {
            Spacer(modifier = Modifier.size(16.dp))
            action()
        }
    }
}

@Composable
private fun TodayAlertCard(
    alert: TodayAlert,
    onOpen: () -> Unit,
    onDelete: () -> Unit
) {
    val context = LocalContext.current
    val timeText = remember(alert.receivedAtMillis) {
        DateFormat.getTimeFormat(context).format(Date(alert.receivedAtMillis))
    }
    val sender = alert.sender.takeIf { it.isNotBlank() }
        ?: stringResource(R.string.sms_alert_unknown_sender)
    val reason = remember(alert.reasonIds) {
        alert.reasonIds.firstNotNullOfOrNull { ReasonId.fromId(it) }
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onOpen),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = ArmTheme.colors.cardSurface)
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.Top
        ) {
            Column(modifier = Modifier.weight(1f)) {
                TodayVerdictChip(verdict = alert.verdict)
                Spacer(modifier = Modifier.size(8.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = sender,
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurface,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = timeText,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Spacer(modifier = Modifier.size(4.dp))
                Text(
                    text = alert.body,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                if (reason != null) {
                    Spacer(modifier = Modifier.size(6.dp))
                    Text(
                        text = stringResource(reason.labelRes),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
            IconButton(onClick = onDelete) {
                Icon(
                    imageVector = Icons.Filled.Delete,
                    contentDescription = stringResource(R.string.today_delete_content_description),
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun TodayVerdictChip(verdict: ThreatVerdictLevel) {
    val colors = ArmTheme.colors
    val style = when (verdict) {
        ThreatVerdictLevel.HIGH_RISK -> TodayChipStyle(
            container = colors.dangerContainer,
            content = colors.onDangerContainer,
            iconRes = R.drawable.ic_verdict_danger,
            labelRes = R.string.verdict_high_risk_title
        )

        ThreatVerdictLevel.INSUFFICIENT_EVIDENCE -> TodayChipStyle(
            container = colors.safeContainer,
            content = colors.onSafeContainer,
            iconRes = R.drawable.ic_verdict_safe,
            labelRes = R.string.verdict_unclear_title
        )

        ThreatVerdictLevel.SUSPICIOUS -> TodayChipStyle(
            container = colors.suspiciousContainer,
            content = colors.onSuspiciousContainer,
            iconRes = R.drawable.ic_verdict_warning,
            labelRes = R.string.verdict_suspicious_title
        )

        ThreatVerdictLevel.SAFE -> TodayChipStyle(
            container = colors.safeContainer,
            content = colors.onSafeContainer,
            iconRes = R.drawable.ic_verdict_safe,
            labelRes = R.string.verdict_safe_title
        )
    }

    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(50))
            .background(style.container)
            .padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            painter = painterResource(style.iconRes),
            contentDescription = null,
            tint = style.content,
            modifier = Modifier.size(14.dp)
        )
        Spacer(modifier = Modifier.width(4.dp))
        Text(
            text = stringResource(style.labelRes),
            style = MaterialTheme.typography.labelMedium,
            color = style.content
        )
    }
}

private data class TodayChipStyle(
    val container: Color,
    val content: Color,
    val iconRes: Int,
    val labelRes: Int
)

private fun isProtectionOn(context: Context): Boolean =
    SmsProtectionPreferences.isEnabled(context) &&
        ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.RECEIVE_SMS
        ) == PackageManager.PERMISSION_GRANTED
