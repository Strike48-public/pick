package com.strike48.pickcrux.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.strike48.pick.shared.MessageKind
import com.strike48.pick.shared.MessagePartView
import com.strike48.pick.shared.MessageView
import com.strike48.pick.shared.ToolCallView
import com.strike48.pick.shared.ToolStatus

@Composable
fun MessageRow(message: MessageView) {
    when (message.kind) {
        MessageKind.USER -> UserBubble(message.markdown)
        // Render the ordered parts (text/thinking/tool) so an agent message
        // reads exactly as it does in the Dioxus app. Falls back to the legacy
        // flattened markdown when a message carries no parts.
        MessageKind.AGENTTEXT -> AgentMessage(message)
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
private fun AgentMessage(message: MessageView) {
    if (message.parts.isEmpty()) {
        MarkdownText(blocks = message.blocks, modifier = Modifier.fillMaxWidth())
        return
    }
    Column(
        modifier = Modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        message.parts.forEach { part ->
            when (part) {
                is MessagePartView.Text -> MarkdownText(
                    blocks = part.blocks,
                    modifier = Modifier.fillMaxWidth(),
                )
                is MessagePartView.Thinking -> ThinkingBlock(part.text)
                is MessagePartView.Tool -> ToolCallRow(part.tool)
            }
        }
    }
}

@Composable
private fun ThinkingBlock(text: String) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(PickColors.SubtleFill)
            .padding(horizontal = 12.dp, vertical = 8.dp),
    ) {
        Column {
            Text(
                text = "Thinking",
                color = PickColors.Muted,
                fontSize = 11.sp,
                fontWeight = FontWeight.Medium,
            )
            Spacer(Modifier.width(0.dp))
            Text(text = text, color = PickColors.Muted, fontSize = 13.sp)
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
    val hasDetail = !tool.arguments.isNullOrEmpty() ||
        !tool.result.isNullOrEmpty() ||
        !tool.error.isNullOrEmpty()
    var expanded by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(PickColors.Surface)
            .border(1.dp, PickColors.Hairline, RoundedCornerShape(16.dp))
            .then(if (hasDetail) Modifier.clickable { expanded = !expanded } else Modifier)
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            if (hasDetail) {
                Text(
                    text = if (expanded) "▼" else "▶",
                    fontSize = 10.sp,
                    color = PickColors.Muted,
                    modifier = Modifier.padding(end = 6.dp),
                )
            }
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
        if (expanded) {
            tool.arguments?.takeIf { it.isNotEmpty() }
                ?.let { ToolDetail("Arguments", it, PickColors.Muted) }
            tool.result?.takeIf { it.isNotEmpty() }
                ?.let { ToolDetail("Result", it, PickColors.Text) }
            tool.error?.takeIf { it.isNotEmpty() }
                ?.let { ToolDetail("Error", it, PickColors.StatusError) }
        }
    }
}

@Composable
private fun ToolDetail(title: String, body: String, color: Color) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Text(title, color = PickColors.Muted, fontSize = 11.sp, fontWeight = FontWeight.Medium)
        Text(body, color = color, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
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
