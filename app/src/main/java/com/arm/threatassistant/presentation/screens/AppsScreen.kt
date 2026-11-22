package com.arm.threatassistant.presentation.screens

import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.widget.Toast
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.apps.ReviewPriority
import com.arm.threatassistant.domain.apps.AccessChange
import com.arm.threatassistant.presentation.viewmodel.AppsState
import com.arm.threatassistant.presentation.viewmodel.AppsViewModel

@Composable
fun AppsScreen(onBack: () -> Unit, model: AppsViewModel = viewModel()) {
    BackHandler(onBack = onBack)
    val state by model.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val openSettings: (Intent) -> Unit = { intent ->
        try {
            context.startActivity(intent)
        } catch (_: android.content.ActivityNotFoundException) {
            Toast.makeText(context, R.string.apps_settings_failed, Toast.LENGTH_SHORT).show()
        } catch (_: SecurityException) {
            Toast.makeText(context, R.string.apps_settings_failed, Toast.LENGTH_SHORT).show()
        }
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            TextButton(onClick = onBack) { Text(stringResource(R.string.apps_back)) }
            Text(stringResource(R.string.apps_review_title), style = MaterialTheme.typography.headlineSmall)
            Text(stringResource(R.string.apps_scope))
            Text(stringResource(R.string.apps_history_scope))
            Button(onClick = model::refresh, enabled = state != AppsState.Loading) {
                Text(stringResource(R.string.apps_scan))
            }
        }
        when (val current = state) {
            AppsState.Idle -> Unit
            AppsState.Cleared -> item { Text(stringResource(R.string.apps_cleared)) }
            AppsState.Loading -> item { CircularProgressIndicator() }
            AppsState.Unavailable -> item {
                Text(stringResource(R.string.apps_operation_failed))
            }
            is AppsState.Ready -> {
                val snapshot = current.snapshot
                if (snapshot.firstScan) item { Text(stringResource(R.string.apps_first_scan)) }
                else if (snapshot.changes.isEmpty()) item { Text(stringResource(R.string.apps_no_change)) }
                if (snapshot.entries.isEmpty()) item { Text(stringResource(R.string.apps_empty)) }
                items(snapshot.entries, key = { it.id }) { entry ->
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(entry.label, style = MaterialTheme.typography.titleMedium)
                            Text(entry.id, style = MaterialTheme.typography.bodySmall)
                            val access = entry.access
                            for (change in snapshot.changes[entry.id].orEmpty()) {
                                val message = when (change) {
                                    AccessChange.NEWLY_VISIBLE -> R.string.apps_new_visible
                                    AccessChange.SCREEN -> R.string.apps_new_screen
                                    AccessChange.GESTURES -> R.string.apps_new_gestures
                                    AccessChange.SMS -> R.string.apps_new_sms
                                }
                                Text(stringResource(message), style = MaterialTheme.typography.labelLarge)
                            }
                            if (access.systemApp) Text(stringResource(R.string.apps_system))
                            if (access.priority() == ReviewPriority.REVIEW) Text(stringResource(R.string.apps_combination))
                            if (access.readsScreen) Text(stringResource(R.string.apps_screen))
                            if (access.performsGestures) Text(stringResource(R.string.apps_gestures))
                            if (access.smsGranted == true) Text(stringResource(R.string.apps_sms))
                            if (access.smsGranted == null) Text(stringResource(R.string.apps_unknown))
                            TextButton(onClick = {
                                openSettings(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                                    Uri.fromParts("package", entry.id, null)))
                            }) { Text(stringResource(R.string.apps_details)) }
                        }
                    }
                }
            }
        }
        item {
            Text(stringResource(R.string.apps_remediation))
            OutlinedButton(onClick = { openSettings(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS)) }) {
                Text(stringResource(R.string.apps_access_settings))
            }
            TextButton(onClick = model::clearHistory, enabled = state != AppsState.Loading) {
                Text(stringResource(R.string.apps_reset))
            }
        }
    }
}
