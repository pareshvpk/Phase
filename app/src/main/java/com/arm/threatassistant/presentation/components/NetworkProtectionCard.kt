package com.arm.threatassistant.presentation.components

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.arm.threatassistant.R
import com.arm.threatassistant.network.*

@Composable
fun NetworkProtectionCard() {
    val context = LocalContext.current
    val state by NetworkState.state.collectAsState()
    var denied by remember { mutableStateOf(false) }
    var consent by remember { mutableStateOf(false) }
    fun start() {
        try { ContextCompat.startForegroundService(context, Intent(context, NetworkVpnService::class.java)) }
        catch (_: RuntimeException) { NetworkState.update { it.copy(failed = true, starting = false) } }
    }
    val vpn = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) start() else denied = true
    }
    fun prepare() {
        try {
            val intent = VpnService.prepare(context)
            if (intent == null) start() else vpn.launch(intent)
        } catch (_: RuntimeException) { denied = true }
    }
    val notifications = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { prepare() }
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.network_title), style = MaterialTheme.typography.titleMedium)
            Text(stringResource(R.string.network_description))
            Text(stringResource(when {
                Build.VERSION.SDK_INT < 29 -> R.string.network_unsupported
                state.starting -> R.string.network_starting
                state.running -> R.string.network_running
                state.failed -> R.string.network_failed
                denied -> R.string.network_denied
                else -> R.string.network_stopped
            }))
            if (state.running || state.starting) {
                OutlinedButton(onClick = { context.startService(Intent(context, NetworkVpnService::class.java).setAction(NetworkVpnService.STOP)) }) {
                    Text(stringResource(R.string.network_stop))
                }
            } else {
                Button(onClick = { denied = false; consent = true }, enabled = Build.VERSION.SDK_INT >= 29) {
                    Text(stringResource(R.string.network_start))
                }
            }
            if (state.packets > 0) Text(stringResource(R.string.network_stats,
                state.packets, state.sent / 1024, state.received / 1024, state.active, state.completed))
            state.findings.forEach { finding ->
                Text(stringResource(when (finding) {
                    NetworkFinding.PORT_FANOUT -> R.string.network_fanout
                    NetworkFinding.CONNECTION_BURST -> R.string.network_connections
                    NetworkFinding.UDP_BURST -> R.string.network_udp_burst
                }), style = MaterialTheme.typography.bodyMedium)
            }
            state.estimate?.let { estimate ->
                Text(stringResource(R.string.network_estimate, estimate.label, estimate.imputed.size),
                    style = MaterialTheme.typography.bodySmall)
            }
            if (state.findings.isNotEmpty() || state.estimate != null) {
                TextButton(onClick = { NetworkState.clear() }) { Text(stringResource(R.string.network_clear)) }
            }
            Text(stringResource(R.string.network_limits), style = MaterialTheme.typography.bodySmall)
        }
    }
    if (consent) AlertDialog(onDismissRequest = { consent = false },
        title = { Text(stringResource(R.string.network_title)) },
        text = { Text(stringResource(R.string.network_consent)) },
        confirmButton = { TextButton(onClick = {
            consent = false
            if (Build.VERSION.SDK_INT >= 33) notifications.launch(Manifest.permission.POST_NOTIFICATIONS) else prepare()
        }) { Text(stringResource(R.string.network_start)) } },
        dismissButton = { TextButton(onClick = { consent = false }) { Text(stringResource(android.R.string.cancel)) } })
}
