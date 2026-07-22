package com.strike48.pickcrux.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private val SageDarkColors = darkColorScheme(
    primary = PickColors.Brand,
    onPrimary = PickColors.OnBrand,
    primaryContainer = PickColors.Brand,
    onPrimaryContainer = PickColors.OnBrand,
    secondary = PickColors.Brand,
    onSecondary = PickColors.OnBrand,
    background = PickColors.Background,
    onBackground = PickColors.Text,
    surface = PickColors.Surface,
    onSurface = PickColors.Text,
    surfaceVariant = PickColors.Surface,
    onSurfaceVariant = PickColors.Muted,
    error = PickColors.Error,
    onError = PickColors.OnBrand,
    outline = PickColors.Hairline,
    outlineVariant = PickColors.RowSeparator,
)

// Material 3 shape scale per the spec: control 12dp, card/row 16dp.
private val PickShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(16.dp),
    extraLarge = RoundedCornerShape(24.dp),
)

private val PickTypography = Typography().run {
    copy(
        headlineSmall = headlineSmall.copy(color = PickColors.Text),
        titleLarge = titleLarge.copy(color = PickColors.Text),
        titleMedium = titleMedium.copy(color = PickColors.Text),
        titleSmall = titleSmall.copy(color = PickColors.Text),
        bodyLarge = bodyLarge.copy(color = PickColors.Text),
        bodyMedium = bodyMedium.copy(color = PickColors.Text),
        bodySmall = bodySmall.copy(color = PickColors.Text),
        labelLarge = labelLarge.copy(color = PickColors.Text),
    )
}

/** Bold 20sp wordmark style with tight letter-spacing per the spec. */
val WordmarkStyle = TextStyle(
    fontFamily = FontFamily.SansSerif,
    fontWeight = FontWeight.Bold,
    fontSize = 20.sp,
    letterSpacing = (-0.2).sp,
    color = PickColors.Text,
)

@Composable
fun PickTheme(content: @Composable () -> Unit) {
    // Always dark — the shell is a fixed sage-dark experience.
    @Suppress("UNUSED_VARIABLE")
    val dark = isSystemInDarkTheme()
    MaterialTheme(
        colorScheme = SageDarkColors,
        shapes = PickShapes,
        typography = PickTypography,
        content = content,
    )
}
