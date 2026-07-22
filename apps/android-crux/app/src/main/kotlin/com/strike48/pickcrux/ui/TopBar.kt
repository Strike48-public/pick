package com.strike48.pickcrux.ui

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.DateRange
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp

@Composable
fun TopBar(
    connected: Boolean,
    onNewChat: () -> Unit,
    onHistory: () -> Unit,
    onReports: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(PickColors.Background)
            // Clear the system status bar so the badge/wordmark aren't drawn under the clock.
            .statusBarsPadding()
            .padding(start = 20.dp, end = 12.dp, top = 4.dp, bottom = 12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            BrandBadge(connected = connected)
            Spacer(Modifier.width(10.dp))
            Text(text = "Pick", style = WordmarkStyle)
            Spacer(Modifier.weight(1f))
            IconAction(Icons.Filled.Add, "New chat", onNewChat)
            IconAction(Icons.Filled.DateRange, "History", onHistory)
            IconAction(Icons.AutoMirrored.Filled.List, "Reports", onReports)
        }
    }
}

@Composable
private fun IconAction(icon: ImageVector, description: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .size(40.dp)
            .clip(CircleShape)
            .clickable(onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = icon,
            contentDescription = description,
            tint = PickColors.Text,
            modifier = Modifier.size(20.dp),
        )
    }
}

/**
 * 30x30 sage rounded-square badge with the "S" stroke glyph from the spec.
 *
 * `connected` drives a small connection-status dot in the bottom-right corner:
 * green when connected, muted otherwise. This replaces the old "Connected"
 * text line under the wordmark.
 */
@Composable
fun BrandBadge(sizeDp: Int = 30, connected: Boolean = false) {
    val dotColor = if (connected) PickColors.StatusSuccess else PickColors.Muted
    val ringColor = PickColors.Background
    Box(
        modifier = Modifier
            .size(sizeDp.dp)
            .clip(RoundedCornerShape(9.dp))
            .background(PickColors.Brand),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(modifier = Modifier.size((sizeDp * 0.9f).dp)) {
            // Path authored in a 32x32 viewBox; scale to canvas.
            val s = size.minDimension / 32f
            fun x(v: Float) = v * s
            val path = Path().apply {
                // M23 9 C23 6 19 5 16 5 C12 5 9 7 9 10 C9 16 23 14 23 21 C23 25 19 27 15 27 C11 27 8 25 8 22
                moveTo(x(23f), x(9f))
                cubicTo(x(23f), x(6f), x(19f), x(5f), x(16f), x(5f))
                cubicTo(x(12f), x(5f), x(9f), x(7f), x(9f), x(10f))
                cubicTo(x(9f), x(16f), x(23f), x(14f), x(23f), x(21f))
                cubicTo(x(23f), x(25f), x(19f), x(27f), x(15f), x(27f))
                cubicTo(x(11f), x(27f), x(8f), x(25f), x(8f), x(22f))
            }
            drawPath(
                path = path,
                color = PickColors.OnBrand,
                style = Stroke(width = 3.2f * s, cap = StrokeCap.Round, join = StrokeJoin.Round),
            )
        }
        // Status dot, aligned to the badge's bottom-right corner. A ring in the
        // page background keeps it legible against the sage fill.
        Canvas(
            modifier = Modifier
                .align(Alignment.BottomEnd)
                .size((sizeDp * 0.3f).dp),
        ) {
            val r = size.minDimension / 2f
            drawCircle(color = ringColor, radius = r)
            drawCircle(color = dotColor, radius = r * 0.72f)
        }
    }
}
