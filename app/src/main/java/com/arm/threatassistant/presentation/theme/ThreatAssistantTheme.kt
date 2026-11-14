package com.arm.threatassistant.presentation.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

/**
 * Semantic colours used by the verdict card, one per threat verdict level.
 */
object VerdictColors {
    val Safe = Color(0xFF34C77B)
    val Suspicious = Color(0xFFF5A524)
    val Danger = Color(0xFFF0524F)
    val Unknown = Color(0xFF8B95A7)
}

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF7AA7FF),
    onPrimary = Color(0xFF06122B),
    background = Color(0xFF0B0F17),
    onBackground = Color(0xFFE9ECF2),
    surface = Color(0xFF0B0F17),
    onSurface = Color(0xFFE9ECF2),
    surfaceContainer = Color(0xFF151B27),
    surfaceContainerHigh = Color(0xFF1C2433),
    onSurfaceVariant = Color(0xFF9AA4B5),
    outline = Color(0xFF2A3345),
    outlineVariant = Color(0xFF222A3A),
    error = Color(0xFFFF8A80),
    onError = Color(0xFF3B0906)
)

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF2F5BEA),
    onPrimary = Color(0xFFFFFFFF),
    background = Color(0xFFF6F7FB),
    onBackground = Color(0xFF10151F),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF10151F),
    surfaceContainer = Color(0xFFFFFFFF),
    surfaceContainerHigh = Color(0xFFEEF1F7),
    onSurfaceVariant = Color(0xFF5B6475),
    outline = Color(0xFFD5DAE5),
    outlineVariant = Color(0xFFE6E9F0),
    error = Color(0xFFB3261E),
    onError = Color(0xFFFFFFFF)
)

private val AppShapes = Shapes(
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(20.dp),
    large = RoundedCornerShape(28.dp)
)

@Composable
fun ThreatAssistantTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    MaterialTheme(
        colorScheme = colorScheme,
        shapes = AppShapes,
        content = content
    )
}
