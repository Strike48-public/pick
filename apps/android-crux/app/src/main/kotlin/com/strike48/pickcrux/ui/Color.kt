package com.strike48.pickcrux.ui

import androidx.compose.ui.graphics.Color

/**
 * "Sage dark" palette — the single source of truth is
 * docs/superpowers/specs/2026-07-22-crux-shell-design.md (mirrors the Dioxus
 * Easy Mode --em-* tokens). Do NOT use default Material purple.
 */
object PickColors {
    val Brand = Color(0xFF9CBFAE) // sage (primary)
    val BrandPressed = Color(0xFF7FA894) // deeper sage
    val OnBrand = Color(0xFF17201B) // dark ink on sage fills

    val Background = Color(0xFF1C1C1C) // neutral near-black page bg
    val Surface = Color(0xFF242B27) // sage-tinted elevated surface

    val Text = Color(0xFFE9EEEB) // primary text / headings
    val Muted = Color(0x99E9EEEB) // rgba(233,238,235,0.6)
    val SubtleFill = Color(0x14E9EEEB) // rgba(233,238,235,0.08)
    val FaintWash = Color(0x08E9EEEB) // rgba(233,238,235,0.03)

    val Hairline = Color(0x1FE9EEEB) // rgba(233,238,235,0.12)
    val StrongBorder = Color(0x38E9EEEB) // rgba(233,238,235,0.22)
    val RowSeparator = Color(0x14E9EEEB) // rgba(233,238,235,0.08)

    val Error = Color(0xFFD99A9A)

    // Tool-call status badges
    val StatusSuccess = Color(0xFF8FC4AB)
    val StatusError = Color(0xFFD99A9A)
    val StatusWarning = Color(0xFFD9B07C)
}
