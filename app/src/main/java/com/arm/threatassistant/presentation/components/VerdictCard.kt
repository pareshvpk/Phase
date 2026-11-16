package com.arm.threatassistant.presentation.components

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.detection.riskpolicy.ThreatVerdictLevel
import com.arm.threatassistant.presentation.theme.ArmTheme

/**
 * Large, tinted verdict card. Every verdict pairs colour with an icon and a
 * text label, so colour is never the only signal.
 */
@Composable
fun VerdictCard(
    verdict: ThreatVerdictLevel,
    modifier: Modifier = Modifier
) {
    val colors = ArmTheme.colors
    val style = when (verdict) {
        ThreatVerdictLevel.SAFE -> VerdictStyle(
            container = colors.safeContainer,
            onContainer = colors.onSafeContainer,
            iconRes = R.drawable.ic_verdict_safe,
            titleRes = R.string.verdict_safe_title,
            subtitleRes = R.string.verdict_safe_subtitle
        )
        ThreatVerdictLevel.SUSPICIOUS,
        ThreatVerdictLevel.INSUFFICIENT_EVIDENCE -> VerdictStyle(
            container = colors.suspiciousContainer,
            onContainer = colors.onSuspiciousContainer,
            iconRes = R.drawable.ic_verdict_warning,
            titleRes = R.string.verdict_suspicious_title,
            subtitleRes = R.string.verdict_suspicious_subtitle
        )
        ThreatVerdictLevel.HIGH_RISK -> VerdictStyle(
            container = colors.dangerContainer,
            onContainer = colors.onDangerContainer,
            iconRes = R.drawable.ic_verdict_danger,
            titleRes = R.string.verdict_high_risk_title,
            subtitleRes = R.string.verdict_high_risk_subtitle
        )
    }

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = RoundedCornerShape(28.dp),
        colors = CardDefaults.cardColors(containerColor = style.container)
    ) {
        Row(
            modifier = Modifier.padding(20.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                painter = painterResource(style.iconRes),
                contentDescription = null,
                tint = style.onContainer,
                modifier = Modifier.size(40.dp)
            )
            Spacer(modifier = Modifier.width(16.dp))
            Column {
                Text(
                    text = stringResource(style.titleRes),
                    style = MaterialTheme.typography.headlineSmall,
                    color = style.onContainer
                )
                Text(
                    text = stringResource(style.subtitleRes),
                    style = MaterialTheme.typography.bodyLarge,
                    color = style.onContainer.copy(alpha = 0.9f)
                )
            }
        }
    }
}

private data class VerdictStyle(
    val container: Color,
    val onContainer: Color,
    val iconRes: Int,
    val titleRes: Int,
    val subtitleRes: Int
)
