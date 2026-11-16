package com.arm.threatassistant.presentation.theme

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/**
 * Verdict and brand colours that Material 3 does not model directly.
 *
 * Verdict colours are deliberately separate from the error role: a form
 * validation error must never look like a scam warning. Every container colour
 * is paired with an on-container colour that meets WCAG AA contrast.
 */
@Immutable
data class ArmExtendedColors(
    val safe: Color,
    val safeContainer: Color,
    val onSafeContainer: Color,
    val suspicious: Color,
    val suspiciousContainer: Color,
    val onSuspiciousContainer: Color,
    val danger: Color,
    val dangerContainer: Color,
    val onDangerContainer: Color,
    val cardSurface: Color,
    val gradientStart: Color,
    val gradientEnd: Color,
    val onGradient: Color
)

private val LightExtendedColors = ArmExtendedColors(
    safe = Color(0xFF146C43),
    safeContainer = Color(0xFFDCF5E4),
    onSafeContainer = Color(0xFF073B1E),
    suspicious = Color(0xFF8A5A00),
    suspiciousContainer = Color(0xFFFFF0C9),
    onSuspiciousContainer = Color(0xFF3F2A00),
    danger = Color(0xFFB3261E),
    dangerContainer = Color(0xFFFFDAD6),
    onDangerContainer = Color(0xFF410002),
    cardSurface = Color(0xFFFFFFFF),
    gradientStart = Color(0xFF8A1C62),
    gradientEnd = Color(0xFFC72A87),
    onGradient = Color(0xFFFFFFFF)
)

private val DarkExtendedColors = ArmExtendedColors(
    safe = Color(0xFF7BD79A),
    safeContainer = Color(0xFF0B3D22),
    onSafeContainer = Color(0xFFB9F2CB),
    suspicious = Color(0xFFFFC24D),
    suspiciousContainer = Color(0xFF4A3400),
    onSuspiciousContainer = Color(0xFFFFE08A),
    danger = Color(0xFFFFB4AB),
    dangerContainer = Color(0xFF5E1216),
    onDangerContainer = Color(0xFFFFDAD6),
    cardSurface = Color(0xFF21161D),
    gradientStart = Color(0xFF7C1C57),
    gradientEnd = Color(0xFFA82C7C),
    onGradient = Color(0xFFFFF7FB)
)

val LocalArmExtendedColors = staticCompositionLocalOf { LightExtendedColors }

/** Access point for the brand and verdict tokens. */
object ArmTheme {
    val colors: ArmExtendedColors
        @Composable get() = LocalArmExtendedColors.current
}

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF8A1C62),
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFFFFD8EC),
    onPrimaryContainer = Color(0xFF3B0026),
    secondary = Color(0xFF66516E),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFF0DCEC),
    onSecondaryContainer = Color(0xFF241A2A),
    background = Color(0xFFFFF7FB),
    onBackground = Color(0xFF211A1E),
    surface = Color(0xFFFFFBFE),
    onSurface = Color(0xFF211A1E),
    surfaceVariant = Color(0xFFF9E8F2),
    onSurfaceVariant = Color(0xFF52434B),
    outline = Color(0xFF84707A),
    outlineVariant = Color(0xFFD6C1CC),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFFDF1F7),
    surfaceContainer = Color(0xFFF9E8F2),
    surfaceContainerHigh = Color(0xFFF3DDEA),
    surfaceContainerHighest = Color(0xFFEDD2E2),
    error = Color(0xFFB3261E),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFFFDAD6),
    onErrorContainer = Color(0xFF410002)
)

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFFFFAFD6),
    onPrimary = Color(0xFF57103A),
    primaryContainer = Color(0xFF7C1C57),
    onPrimaryContainer = Color(0xFFFFD8EC),
    secondary = Color(0xFFD8C0DF),
    onSecondary = Color(0xFF3B2A42),
    secondaryContainer = Color(0xFF523F5B),
    onSecondaryContainer = Color(0xFFF0DCEC),
    background = Color(0xFF191016),
    onBackground = Color(0xFFF2DEE8),
    surface = Color(0xFF191016),
    onSurface = Color(0xFFF2DEE8),
    surfaceVariant = Color(0xFF523F5B),
    onSurfaceVariant = Color(0xFFD4BFC9),
    outline = Color(0xFF9D8994),
    outlineVariant = Color(0xFF52434C),
    surfaceContainerLowest = Color(0xFF130B10),
    surfaceContainerLow = Color(0xFF21161D),
    surfaceContainer = Color(0xFF261A22),
    surfaceContainerHigh = Color(0xFF31222C),
    surfaceContainerHighest = Color(0xFF3D2B36),
    error = Color(0xFFFFB4AB),
    onError = Color(0xFF690005),
    errorContainer = Color(0xFF93000A),
    onErrorContainer = Color(0xFFFFDAD6)
)

private val AppShapes = Shapes(
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(24.dp),
    large = RoundedCornerShape(28.dp)
)

private val AppTypography = Typography().let { base ->
    base.copy(
        headlineMedium = base.headlineMedium.copy(fontWeight = FontWeight.SemiBold),
        headlineSmall = base.headlineSmall.copy(fontWeight = FontWeight.SemiBold),
        titleLarge = base.titleLarge.copy(fontWeight = FontWeight.SemiBold),
        titleMedium = base.titleMedium.copy(fontWeight = FontWeight.SemiBold),
        titleSmall = base.titleSmall.copy(fontWeight = FontWeight.SemiBold)
    )
}

@Composable
fun ThreatAssistantTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    content: @Composable () -> Unit
) {
    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme
    val extendedColors = if (darkTheme) DarkExtendedColors else LightExtendedColors
    androidx.compose.runtime.CompositionLocalProvider(
        LocalArmExtendedColors provides extendedColors
    ) {
        MaterialTheme(
            colorScheme = colorScheme,
            shapes = AppShapes,
            typography = AppTypography,
            content = content
        )
    }
}
