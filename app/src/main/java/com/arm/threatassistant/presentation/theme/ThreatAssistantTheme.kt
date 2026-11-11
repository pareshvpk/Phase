package com.arm.threatassistant.presentation.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF8AB4F8),
    onPrimary = Color(0xFF000000),
    primaryContainer = Color(0xFF2A3B5C),
    onPrimaryContainer = Color(0xFFE8EAED),
    secondary = Color(0xFFCC8CFF),
    onSecondary = Color(0xFF000000),
    secondaryContainer = Color(0xFF3A1B5C),
    onSecondaryContainer = Color(0xFFF3E8FF),
    tertiary = Color(0xFF8ED1FC),
    onTertiary = Color(0xFF000000),
    surface = Color(0xFF0B0E14),
    onSurface = Color(0xFFE8EAED),
    surfaceContainer = Color(0xFF131824),
    background = Color(0xFF0B0E14),
    onBackground = Color(0xFFE8EAED),
    error = Color(0xFFFF8A80),
    onError = Color(0xFF000000)
)

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF1A237E),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFE8EAF6),
    onPrimaryContainer = Color(0xFF1A237E),
    secondary = Color(0xFF303F9F),
    onSecondary = Color(0xFFFFFFFF),
    surface = Color(0xFFFFFFFF),
    onSurface = Color(0xFF000000),
    background = Color(0xFFFFFFFF),
    onBackground = Color(0xFF000000),
    error = Color(0xFFB3261E),
    onError = Color(0xFFFFFFFF)
)

@Composable
fun ThreatAssistantTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    MaterialTheme(
        colorScheme = colorScheme,
        content = content
    )
}
