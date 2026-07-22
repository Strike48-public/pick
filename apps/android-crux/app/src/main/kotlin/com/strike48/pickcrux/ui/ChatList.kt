package com.strike48.pickcrux.ui

import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.strike48.pick.shared.DocRef
import com.strike48.pick.shared.MessageView
import com.strike48.pick.shared.QuickActionView
import com.strike48.pick.shared.ToolCallView

/** Scrolling message list with an animated agent-activity status line. */
@Composable
fun ChatList(
    messages: List<MessageView>,
    toolCalls: List<ToolCallView>,
    activityActive: Boolean,
    activityLabel: String,
    modifier: Modifier = Modifier,
) {
    val listState = rememberLazyListState()

    // How much content is on screen; grows as the scan streams in.
    val streamSize = messages.size + toolCalls.size + (if (activityActive) 1 else 0)

    // Whether the user has scrolled up to read history. When they're at (or
    // near) the bottom we auto-follow new content; if they scroll up we stop,
    // and re-follow once they scroll back down.
    val atBottom by remember {
        derivedStateOf {
            val last = listState.layoutInfo.visibleItemsInfo.lastOrNull()?.index ?: 0
            last >= listState.layoutInfo.totalItemsCount - 2
        }
    }

    // Auto-scroll to the newest content as it streams, unless the user scrolled
    // up (atBottom == false). They override simply by scrolling.
    LaunchedEffect(streamSize) {
        if (streamSize > 0 && atBottom) {
            listState.animateScrollToItem((streamSize - 1).coerceAtLeast(0))
        }
    }

    LazyColumn(
        state = listState,
        modifier = modifier.fillMaxWidth(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        items(messages) { msg -> MessageRow(msg) }
        if (toolCalls.isNotEmpty()) {
            item {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "Running tools",
                        color = PickColors.Muted,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Medium,
                    )
                    toolCalls.forEach { ToolCallRow(it) }
                }
            }
        }
        // Animated agent-activity status line (no spinner) while the agent works.
        if (activityActive) {
            item { TypingIndicator(label = activityLabel) }
        }
    }
}

/**
 * AI-chat style "agent is working" status line: three pulsing dots + a label
 * ("Thinking...", "Running tools...", ...). Replaces the spinner.
 */
@Composable
fun TypingIndicator(label: String) {
    val transition = rememberInfiniteTransition(label = "typing")
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            repeat(3) { i ->
                val alpha by transition.animateFloat(
                    initialValue = 0.3f,
                    targetValue = 1f,
                    animationSpec = infiniteRepeatable(
                        animation = tween(600, delayMillis = i * 200),
                        repeatMode = RepeatMode.Reverse,
                    ),
                    label = "dot$i",
                )
                Box(
                    modifier = Modifier
                        .size(6.dp)
                        .graphicsLayer { this.alpha = alpha }
                        .background(PickColors.Brand, CircleShape),
                )
            }
        }
        if (label.isNotEmpty()) {
            Text(text = label, color = PickColors.Muted, fontSize = 14.sp)
        }
    }
}

/**
 * Contextual "Next Steps" chips shown below the message list after a successful
 * tool call. Tapping a chip fires a follow-up `SendMessage(chip.message)`. The
 * chips are computed in Rust (middleware quick-action registry); the shell just
 * renders label + fires the message.
 */
@Composable
fun NextStepsRow(actions: List<QuickActionView>, onSend: (String) -> Unit) {
    if (actions.isEmpty()) return
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Text(
            text = "Next Steps",
            color = PickColors.Muted,
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium,
        )
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            actions.forEach { action ->
                Box(
                    modifier = Modifier
                        .clip(RoundedCornerShape(999.dp))
                        .background(PickColors.SubtleFill)
                        .border(1.dp, PickColors.Brand.copy(alpha = 0.4f), RoundedCornerShape(999.dp))
                        .clickable { onSend(action.message) }
                        .padding(horizontal = 14.dp, vertical = 8.dp),
                ) {
                    Text(
                        text = action.label,
                        color = PickColors.Text,
                        fontSize = 14.sp,
                        fontWeight = FontWeight.Medium,
                    )
                }
            }
        }
    }
}

/** Conversation-scoped document strip pinned above the input row. */
@Composable
fun ConversationDocStrip(docs: List<DocRef>, onOpen: (String) -> Unit) {
    if (docs.isEmpty()) return
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(max = 220.dp)
            .background(PickColors.FaintWash)
            .border(1.dp, PickColors.Hairline)
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Text(
            text = "Documents",
            color = PickColors.Muted,
            fontSize = 12.sp,
            fontWeight = FontWeight.Medium,
            modifier = Modifier.padding(bottom = 4.dp),
        )
        docs.forEach { doc ->
            Text(
                text = doc.title,
                color = PickColors.Text,
                fontSize = 14.sp,
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onOpen(doc.id) }
                    .padding(vertical = 8.dp),
            )
        }
    }
}
