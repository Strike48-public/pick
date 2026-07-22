package com.strike48.pickcrux.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.strike48.pick.shared.DocRef
import com.strike48.pick.shared.MessageView
import com.strike48.pick.shared.ToolCallView

/** Scrolling message list with a live running-tools strip while scanning. */
@Composable
fun ChatList(
    messages: List<MessageView>,
    toolCalls: List<ToolCallView>,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
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
