package com.arm.threatassistant.presentation.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import com.arm.threatassistant.presentation.theme.ArmTheme

/** Up to three practical next steps for the verdict. */
@Composable
fun ActionsCard(
    verdict: ThreatVerdictLevel,
    modifier: Modifier = Modifier
) {
    val actionRes = when (verdict) {
        ThreatVerdictLevel.SAFE -> listOf(R.string.action_safe_1)
        ThreatVerdictLevel.SUSPICIOUS -> listOf(
            R.string.action_suspicious_1,
            R.string.action_suspicious_2,
            R.string.action_suspicious_3
        )
        ThreatVerdictLevel.HIGH_RISK -> listOf(
            R.string.action_high_risk_1,
            R.string.action_high_risk_2,
            R.string.action_high_risk_3
        )
        ThreatVerdictLevel.INSUFFICIENT_EVIDENCE -> listOf(
            R.string.action_insufficient_1,
            R.string.action_insufficient_2
        )
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(
            containerColor = ArmTheme.colors.cardSurface
        )
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(
                text = stringResource(R.string.what_to_do),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            actionRes.forEach { res ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.CheckCircle,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = stringResource(res),
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
    }
}
