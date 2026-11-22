package com.arm.threatassistant.presentation.onboarding

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.arm.threatassistant.R

/** Introduction only: protection and Android permissions remain explicit opt-ins. */
@Composable
fun OnboardingScreen(onFinish: (openProtection: Boolean) -> Unit) {
    var page by rememberSaveable { mutableIntStateOf(0) }
    val title = when (page) {
        0 -> R.string.onboarding_check_title
        1 -> R.string.onboarding_privacy_title
        else -> R.string.onboarding_protection_title
    }
    val body = when (page) {
        0 -> R.string.onboarding_check_body
        1 -> R.string.onboarding_privacy_body
        else -> R.string.onboarding_protection_body
    }
    val icon = when (page) {
        0 -> Icons.Filled.Search
        1 -> Icons.Filled.Lock
        else -> Icons.Filled.Notifications
    }

    BackHandler {
        if (page > 0) page-- else onFinish(false)
    }

    Scaffold(containerColor = MaterialTheme.colorScheme.background) { padding ->
        Box(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentAlignment = Alignment.Center
        ) {
            Column(
                modifier = Modifier.widthIn(max = 560.dp).fillMaxWidth()
                    .verticalScroll(rememberScrollState()).padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(24.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = stringResource(R.string.onboarding_step, page + 1, 3),
                        style = MaterialTheme.typography.labelLarge
                    )
                    TextButton(onClick = { onFinish(false) }) {
                        Text(stringResource(R.string.onboarding_skip))
                    }
                }
                Icon(
                    imageVector = icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(72.dp)
                )
                Text(
                    text = stringResource(title),
                    style = MaterialTheme.typography.headlineMedium,
                    textAlign = TextAlign.Center
                )
                Text(
                    text = stringResource(body),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center
                )
                Button(
                    onClick = { if (page < 2) page++ else onFinish(true) },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(stringResource(if (page < 2) R.string.onboarding_next else R.string.onboarding_set_up))
                }
                if (page == 2) {
                    TextButton(onClick = { onFinish(false) }) {
                        Text(stringResource(R.string.onboarding_not_now))
                    }
                }
                if (page > 0) {
                    TextButton(onClick = { page-- }) {
                        Text(stringResource(R.string.onboarding_back))
                    }
                }
            }
        }
    }
}
