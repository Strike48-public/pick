package com.strike48.pickcrux.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.strike48.pick.shared.MessageKind
import com.strike48.pick.shared.MessageView
import com.strike48.pick.shared.ToolCallView
import com.strike48.pick.shared.ToolStatus

@Composable
fun MessageRow(message: MessageView) {
    when (message.kind) {
        MessageKind.USER -> UserBubble(message.markdown)
        MessageKind.AGENTTEXT -> MarkdownText(
            blocks = message.blocks,
            modifier = Modifier.fillMaxWidth(),
        )
        MessageKind.TOOLCALL -> {
            val tool = message.tool
            if (tool != null) {
                ToolCallRow(tool)
            } else {
                Text(message.markdown, color = PickColors.Muted, fontSize = 14.sp)
            }
        }
    }
}

@Composable
private fun UserBubble(text: String) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = androidx.compose.foundation.layout.Arrangement.End) {
        Box(
            modifier = Modifier
                .widthIn(max = 300.dp)
                .clip(RoundedCornerShape(16.dp))
                .background(PickColors.Brand)
                .padding(horizontal = 12.dp, vertical = 8.dp),
        ) {
            Text(text = text, color = PickColors.OnBrand, fontSize = 15.sp)
        }
    }
}

@Composable
fun ToolCallRow(tool: ToolCallView) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(PickColors.Surface)
            .border(1.dp, PickColors.Hairline, RoundedCornerShape(16.dp))
            .padding(horizontal = 14.dp, vertical = 12.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = tool.name,
                fontFamily = FontFamily.Monospace,
                fontSize = 14.sp,
                color = PickColors.Text,
                modifier = Modifier.weight(1f),
            )
            Spacer(Modifier.width(8.dp))
            StatusBadge(tool.status)
        }
    }
}

@Composable
fun StatusBadge(status: ToolStatus) {
    val (label, color) = when (status) {
        ToolStatus.RUNNING -> "running" to PickColors.StatusWarning
        ToolStatus.SUCCESS -> "success" to PickColors.StatusSuccess
        ToolStatus.ERROR -> "error" to PickColors.StatusError
    }
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(999.dp))
            .background(color.copy(alpha = 0.18f))
            .padding(horizontal = 10.dp, vertical = 3.dp),
    ) {
        Text(text = label, color = color, fontSize = 12.sp, fontWeight = FontWeight.Medium)
    }
}
