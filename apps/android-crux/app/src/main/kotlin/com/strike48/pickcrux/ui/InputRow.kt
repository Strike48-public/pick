package com.strike48.pickcrux.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.unit.dp

@Composable
fun InputRow(onSend: (String) -> Unit) {
    var text by remember { mutableStateOf("") }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(PickColors.Background)
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedTextField(
            value = text,
            onValueChange = { text = it },
            placeholder = { Text("Message", color = PickColors.Muted) },
            singleLine = true,
            shape = RoundedCornerShape(12.dp),
            colors = OutlinedTextFieldDefaults.colors(
                focusedTextColor = PickColors.Text,
                unfocusedTextColor = PickColors.Text,
                focusedContainerColor = PickColors.SubtleFill,
                unfocusedContainerColor = PickColors.SubtleFill,
                cursorColor = PickColors.Brand,
                focusedBorderColor = PickColors.StrongBorder,
                unfocusedBorderColor = PickColors.Hairline,
            ),
            modifier = Modifier.weight(1f),
        )
        SendPill(
            enabled = text.isNotBlank(),
            onClick = {
                val t = text.trim()
                if (t.isNotEmpty()) {
                    onSend(t)
                    text = ""
                }
            },
        )
    }
}

@Composable
private fun SendPill(enabled: Boolean, onClick: () -> Unit) {
    // Circular sage icon button (matches the iOS up-arrow send): dark glyph on
    // sage, sized to align with the input field height.
    Box(
        modifier = Modifier
            .size(44.dp)
            .clip(CircleShape)
            .background(if (enabled) PickColors.Brand else PickColors.Brand.copy(alpha = 0.5f))
            .clickable(enabled = enabled, onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Icon(
            imageVector = Icons.AutoMirrored.Filled.Send,
            contentDescription = "Send",
            tint = PickColors.OnBrand,
        )
    }
}
