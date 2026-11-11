package com.arm.threatassistant.presentation.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
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
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.arm.threatassistant.R
import com.arm.threatassistant.domain.detection.ruleengine.DetectionSeverity
import com.arm.threatassistant.domain.detection.ruleengine.DetectionSignal
import com.arm.threatassistant.domain.detection.ruleengine.RuleDetectionResult

/**
 * Displays rule detection signals from [FastRuleEngine] for development and
 * testing purposes.
 *
 * This component does NOT display an authoritative security verdict. It lists
 * the individual detection signals with their category, severity, and matched
 * text excerpt so reviewers can see which rules fired and why.
 */
@Composable
fun RuleDetectionSection(
    result: RuleDetectionResult?,
    modifier: Modifier = Modifier
) {
    if (result == null || result.signals.isEmpty()) {
        return
    }

    Card(
        modifier = modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp)
            .semantics { contentDescription = stringResource(R.string.content_description_rule_detection) },
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHigh
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = stringResource(R.string.section_rule_detection_title),
                style = MaterialTheme.typography.labelLarge,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = "${result.signals.size} detection signal(s) found",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(12.dp))

            result.signals.forEach { signal ->
                DetectionSignalRow(signal = signal)
                Spacer(modifier = Modifier.height(8.dp))
            }
        }
    }
}

@Composable
private fun DetectionSignalRow(signal: DetectionSignal) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
    ) {
        // Severity chip
        val (chipColor, chipText) = when (signal.severity) {
            DetectionSeverity.LOW -> {
                Color(0xFFE3F2FD) to "LOW"
            }
            DetectionSeverity.MEDIUM -> {
                Color(0xFFFFECB3) to "MEDIUM"
            }
            DetectionSeverity.HIGH -> {
                Color(0xFFFFEBEE) to "HIGH"
            }
        }
        Box(
            modifier = Modifier
                .width(64.dp)
                .height(24.dp)
                .background(chipColor),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = chipText,
                style = MaterialTheme.typography.labelSmall,
                color = Color(0xFF000000)
            )
        }
        Spacer(modifier = Modifier.width(8.dp))

        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = signal.description,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = "Rule: ${signal.ruleId}  |  Category: ${signal.category.name}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
            )
            Text(
                text = "Matched: \"${signal.matchedText}\"",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f),
                maxLines = 2,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}
