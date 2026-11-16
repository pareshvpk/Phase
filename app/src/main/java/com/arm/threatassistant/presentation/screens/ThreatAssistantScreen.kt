package com.arm.threatassistant.presentation.screens

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.viewmodel.compose.viewModel
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.model.AnalysisInput
import com.arm.threatassistant.domain.model.InputSource
import com.arm.threatassistant.presentation.viewmodel.ThreatAnalysisViewModel
import com.arm.threatassistant.sms.TodayAlertsLogic
import com.arm.threatassistant.sms.TodayAlertsStore
import kotlinx.coroutines.delay
import java.time.ZoneId

private enum class Destination(
    val labelRes: Int,
    val icon: ImageVector
) {
    CHECK(R.string.nav_check, Icons.Filled.Search),
    TODAY(R.string.nav_today, Icons.Filled.Notifications),
    PROTECTION(R.string.nav_protection, Icons.Filled.Lock),
    SETTINGS(R.string.nav_settings, Icons.Filled.Settings)
}

/**
 * Root app shell: four bottom-navigation destinations and simple state-based
 * navigation. System back from Today, Protection or Settings returns to Check.
 */
@Composable
fun ThreatAssistantScreen(
    ingestedInput: AnalysisInput? = null,
    ingestRequestId: Long = 0L,
    viewModel: ThreatAnalysisViewModel = viewModel()
) {
    val context = LocalContext.current
    val todayAlerts by TodayAlertsStore.alerts.collectAsState()
    var destination by rememberSaveable { mutableStateOf(Destination.CHECK) }

    LaunchedEffect(ingestRequestId) {
        if (ingestRequestId > 0L) {
            destination = Destination.CHECK
        }
    }

    // Keep the tab badge current, including after local midnight.
    LaunchedEffect(Unit) {
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
        TodayAlertsStore.getToday(context)
    }

    BackHandler(enabled = destination != Destination.CHECK) {
        destination = Destination.CHECK
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        bottomBar = {
            NavigationBar(
                containerColor = MaterialTheme.colorScheme.surfaceContainer
            ) {
                Destination.entries.forEach { item ->
                    NavigationBarItem(
                        selected = destination == item,
                        onClick = { destination = item },
                        icon = {
                            if (item == Destination.TODAY) {
                                BadgedBox(
                                    badge = {
                                        val count = todayAlerts.size
                                        if (count > 0) {
                                            Badge(
                                                containerColor = MaterialTheme.colorScheme.error
                                            ) {
                                                Text(
                                                    text = if (count > 99) {
                                                        stringResource(R.string.today_badge_overflow)
                                                    } else {
                                                        count.toString()
                                                    }
                                                )
                                            }
                                        }
                                    }
                                ) {
                                    Icon(
                                        imageVector = item.icon,
                                        contentDescription = null
                                    )
                                }
                            } else {
                                Icon(
                                    imageVector = item.icon,
                                    contentDescription = null
                                )
                            }
                        },
                        label = { Text(text = stringResource(item.labelRes)) },
                        alwaysShowLabel = true
                    )
                }
            }
        }
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
        ) {
            when (destination) {
                Destination.CHECK -> CheckScreen(
                    viewModel = viewModel,
                    ingestedInput = ingestedInput,
                    ingestRequestId = ingestRequestId
                )
                Destination.TODAY -> TodayScreen(
                    onOpenAlert = { alert ->
                        viewModel.onIngestedInput(
                            context,
                            AnalysisInput(
                                messageText = alert.body,
                                source = InputSource.SMS
                            )
                        )
                        destination = Destination.CHECK
                    },
                    onOpenProtection = { destination = Destination.PROTECTION }
                )
                Destination.PROTECTION -> ProtectionScreen()
                Destination.SETTINGS -> SettingsScreen()
            }
        }
    }
}
