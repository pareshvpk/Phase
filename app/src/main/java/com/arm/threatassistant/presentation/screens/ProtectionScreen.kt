package com.arm.threatassistant.presentation.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Info
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.network.NetworkFinding
import com.arm.threatassistant.domain.network.NetworkRiskLevel
import com.arm.threatassistant.domain.network.NetworkRiskScorer
import com.arm.threatassistant.domain.network.NetworkSnapshot
import com.arm.threatassistant.network.NetworkSnapshotCollector
import com.arm.threatassistant.presentation.components.ShieldHero
import com.arm.threatassistant.presentation.components.SmsProtectionCard
import com.arm.threatassistant.presentation.theme.ArmTheme
import kotlinx.coroutines.launch

/** Incoming-SMS protection and the offline privacy promise. */
@Composable
fun ProtectionScreen(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Spacer(modifier = Modifier.size(8.dp))
        ShieldHero(size = 80.dp)
        Text(
            text = stringResource(R.string.protection_title),
            style = MaterialTheme.typography.headlineSmall,
            color = MaterialTheme.colorScheme.onBackground
        )
        Text(
            text = stringResource(R.string.protection_subtitle),
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center
        )

        SmsProtectionCard()

        NetworkCheckCard()

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(24.dp),
            colors = CardDefaults.cardColors(
                containerColor = ArmTheme.colors.cardSurface
            )
        ) {
            Row(
                modifier = Modifier.padding(20.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = Icons.Filled.Lock,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    text = stringResource(R.string.privacy_offline_card),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }
        }
    }
}

/**
 * On-device network safety check: reads the current network once (off the main
 * thread), scores it with the offline rules and shows one plain line plus one
 * advice line per finding. Nothing is sent anywhere.
 */
@Composable
private fun NetworkCheckCard(modifier: Modifier = Modifier) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val colors = ArmTheme.colors

    var checking by remember { mutableStateOf(false) }
    var snapshot by remember { mutableStateOf<NetworkSnapshot?>(null) }

    val scored = snapshot?.let { current -> NetworkRiskScorer.score(current) }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = colors.cardSurface)
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    imageVector = Icons.Filled.Info,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(24.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Text(
                    text = stringResource(R.string.network_check_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
            }

            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.network_check_hint),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = {
                    if (!checking) {
                        checking = true
                        scope.launch {
                            snapshot = runCatching {
                                NetworkSnapshotCollector.collect(context)
                            }.getOrNull()
                            checking = false
                        }
                    }
                },
                enabled = !checking
            ) {
                Text(text = stringResource(R.string.network_check_button))
            }

            if (checking) {
                Spacer(modifier = Modifier.height(12.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        strokeWidth = 2.dp
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = stringResource(R.string.network_check_running),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }

            scored?.let { (level, findings) ->
                val levelColor: Color = when (level) {
                    NetworkRiskLevel.OK -> colors.onSafeContainer
                    NetworkRiskLevel.CAUTION -> colors.onSuspiciousContainer
                    NetworkRiskLevel.RISKY -> colors.onDangerContainer
                }

                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = stringResource(level.labelRes),
                    style = MaterialTheme.typography.titleSmall,
                    color = levelColor
                )

                if (findings.isEmpty()) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = stringResource(R.string.network_check_no_findings),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }

                findings.forEach { finding ->
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = stringResource(finding.noteRes),
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                    Spacer(modifier = Modifier.height(2.dp))
                    Text(
                        text = stringResource(finding.adviceRes),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

private val NetworkRiskLevel.labelRes: Int
    get() = when (this) {
        NetworkRiskLevel.OK -> R.string.network_level_ok
        NetworkRiskLevel.CAUTION -> R.string.network_level_caution
        NetworkRiskLevel.RISKY -> R.string.network_level_risky
    }

private val NetworkFinding.noteRes: Int
    get() = when (this) {
        NetworkFinding.OPEN_WIFI -> R.string.network_finding_open_wifi
        NetworkFinding.WEP_WIFI -> R.string.network_finding_wep_wifi
        NetworkFinding.CAPTIVE_PORTAL -> R.string.network_finding_captive_portal
        NetworkFinding.NOT_VALIDATED -> R.string.network_finding_not_validated
        NetworkFinding.PUBLIC_DNS_HIJACK_RISK -> R.string.network_finding_public_dns
        NetworkFinding.NO_PRIVATE_DNS_ON_OPEN_WIFI -> R.string.network_finding_no_private_dns
        NetworkFinding.USB_DEBUGGING_ON -> R.string.network_finding_usb_debugging
        NetworkFinding.DEVELOPER_OPTIONS_ON -> R.string.network_finding_developer_options
        NetworkFinding.VPN_ACTIVE_UNKNOWN -> R.string.network_finding_vpn
    }

private val NetworkFinding.adviceRes: Int
    get() = when (this) {
        NetworkFinding.OPEN_WIFI -> R.string.network_advice_open_wifi
        NetworkFinding.WEP_WIFI -> R.string.network_advice_wep_wifi
        NetworkFinding.CAPTIVE_PORTAL -> R.string.network_advice_captive_portal
        NetworkFinding.NOT_VALIDATED -> R.string.network_advice_not_validated
        NetworkFinding.PUBLIC_DNS_HIJACK_RISK -> R.string.network_advice_public_dns
        NetworkFinding.NO_PRIVATE_DNS_ON_OPEN_WIFI -> R.string.network_advice_no_private_dns
        NetworkFinding.USB_DEBUGGING_ON -> R.string.network_advice_usb_debugging
        NetworkFinding.DEVELOPER_OPTIONS_ON -> R.string.network_advice_developer_options
        NetworkFinding.VPN_ACTIVE_UNKNOWN -> R.string.network_advice_vpn
    }
