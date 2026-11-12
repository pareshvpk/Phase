package com.arm.threatassistant.presentation.components

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.arm.threatassistant.R
import com.arm.threatassistant.sms.SmsProtectionPreferences

/**
 * Opt-in card for incoming-SMS protection.
 *
 * Enabling requests RECEIVE_SMS (and POST_NOTIFICATIONS on API 33+). The
 * preference is only stored when RECEIVE_SMS is granted, so the receiver can
 * never be enabled without the required permission.
 */
@Composable
fun SmsProtectionCard(modifier: Modifier = Modifier) {
    val context = LocalContext.current

    fun hasReceiveSmsPermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            context,
            Manifest.permission.RECEIVE_SMS
        ) == PackageManager.PERMISSION_GRANTED
    }

    var enabled by remember {
        mutableStateOf(SmsProtectionPreferences.isEnabled(context) && hasReceiveSmsPermission())
    }
    var permissionDenied by remember { mutableStateOf(false) }

    // Keep the stored opt-in consistent with the actual permission state.
    LaunchedEffect(Unit) {
        if (!hasReceiveSmsPermission() && SmsProtectionPreferences.isEnabled(context)) {
            SmsProtectionPreferences.setEnabled(context, false)
        }
    }

    val permissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        val granted = grants[Manifest.permission.RECEIVE_SMS] == true
        enabled = granted
        permissionDenied = !granted
        SmsProtectionPreferences.setEnabled(context, granted)
    }

    fun requestPermissions() {
        val permissions = buildList {
            add(Manifest.permission.RECEIVE_SMS)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        permissionLauncher.launch(permissions.toTypedArray())
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainer
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = stringResource(R.string.sms_protection_title),
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = stringResource(R.string.sms_protection_description),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)
                    )
                }
                Spacer(modifier = Modifier.width(12.dp))
                Switch(
                    checked = enabled,
                    onCheckedChange = { checked ->
                        if (checked) {
                            requestPermissions()
                        } else {
                            enabled = false
                            permissionDenied = false
                            SmsProtectionPreferences.setEnabled(context, false)
                        }
                    }
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = stringResource(
                    when {
                        permissionDenied -> R.string.sms_protection_permission_denied
                        enabled -> R.string.sms_protection_enabled
                        else -> R.string.sms_protection_disabled
                    }
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
            )
        }
    }
}
