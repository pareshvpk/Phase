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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import com.arm.threatassistant.presentation.theme.ArmTheme
import com.arm.threatassistant.presentation.result.OfflineExplanation
import com.arm.threatassistant.presentation.result.ReasonId

/** Up to three practical next steps for the verdict. */
@Composable
fun ActionsCard(
    verdict: ThreatVerdictLevel,
    modifier: Modifier = Modifier,
    reasons: List<ReasonId> = emptyList()
) {
    val count = when (verdict) {
        ThreatVerdictLevel.SAFE -> 1
        ThreatVerdictLevel.INSUFFICIENT_EVIDENCE -> 2
        else -> 3
    }
    val actions = OfflineExplanation.safeStepsFor(LocalContext.current, verdict, reasons).take(count)

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
            actions.forEach { action ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        imageVector = Icons.Filled.CheckCircle,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = action,
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface
                    )
                }
            }
        }
    }
}
