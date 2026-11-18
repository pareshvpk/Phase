package com.arm.threatassistant.presentation.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.arm.threatassistant.R
import com.arm.threatassistant.presentation.result.HighlightSpan
import com.arm.threatassistant.presentation.theme.ArmTheme

@Composable
fun HighlightedMessageCard(
    message: String,
    spans: List<HighlightSpan>,
    modifier: Modifier = Modifier
) {
    if (message.isBlank() || spans.isEmpty()) return

    val colorScheme = MaterialTheme.colorScheme
    val annotated = remember(message, spans, colorScheme) {
        annotatedMessage(message, spans, colorScheme.errorContainer, colorScheme.onErrorContainer)
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
                text = stringResource(R.string.result_highlight_title),
                style = MaterialTheme.typography.titleMedium,
                color = MaterialTheme.colorScheme.onSurface
            )
            Text(
                text = annotated,
                style = MaterialTheme.typography.bodyLarge,
                color = MaterialTheme.colorScheme.onSurface,
                maxLines = 12,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

private fun annotatedMessage(
    message: String,
    spans: List<HighlightSpan>,
    background: Color,
    onBackground: Color
): AnnotatedString = buildAnnotatedString {
    append(message)
    for (span in spans) {
        val start = span.start.coerceIn(0, message.length)
        val end = span.end.coerceIn(start, message.length)
        if (end <= start) continue
        addStyle(
            SpanStyle(
                background = background,
                color = onBackground,
                fontWeight = FontWeight.SemiBold
            ),
            start,
            end
        )
    }
}
