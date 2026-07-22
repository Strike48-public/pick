package com.strike48.pickcrux.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.KeyboardArrowLeft
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.strike48.pick.shared.ConversationRef
import com.strike48.pick.shared.DocRef
import com.strike48.pick.shared.DocView
import com.strike48.pick.shared.NoticeKind
import com.strike48.pick.shared.NoticeView

/** History overlay: list of conversations. Tap a row -> SelectConversation. */
@Composable
fun HistorySheet(
    history: List<ConversationRef>,
    onSelect: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    FullScreenOverlay {
        OverlayHeader(title = "History", onClose = onDismiss)
        if (history.isEmpty()) {
            EmptyState("No conversations yet")
        } else {
            LazyColumn(modifier = Modifier.fillMaxWidth()) {
                items(history) { conv ->
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onSelect(conv.id) }
                            .padding(horizontal = 16.dp, vertical = 14.dp),
                    ) {
                        Text(conv.title, color = PickColors.Text, fontSize = 16.sp)
                        Spacer(Modifier.height(2.dp))
                        Text(conv.relativeTime, color = PickColors.Muted, fontSize = 13.sp)
                    }
                    RowSeparator()
                }
            }
        }
    }
}

/** Reports/Documents overlay: list of all documents. Tap -> OpenDocument. */
@Composable
fun DocumentsList(
    documents: List<DocRef>,
    onOpen: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    FullScreenOverlay {
        OverlayHeader(title = "Reports", onClose = onDismiss)
        if (documents.isEmpty()) {
            EmptyState("No documents yet")
        } else {
            LazyColumn(modifier = Modifier.fillMaxWidth()) {
                items(documents) { doc ->
                    Text(
                        text = doc.title,
                        color = PickColors.Text,
                        fontSize = 16.sp,
                        modifier = Modifier
                            .fillMaxWidth()
                            .clickable { onOpen(doc.id) }
                            .padding(horizontal = 16.dp, vertical = 16.dp),
                    )
                    RowSeparator()
                }
            }
        }
    }
}

/** Full-screen document viewer with chevron back + share. */
@Composable
fun DocViewer(
    doc: DocView,
    onClose: () -> Unit,
    onCreateShareLink: (String) -> Unit,
    onShare: (String) -> Unit,
) {
    FullScreenOverlay {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 4.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(RoundedCornerShape(999.dp))
                    .clickable(onClick = onClose),
                contentAlignment = Alignment.Center,
            ) {
                Icon(
                    imageVector = Icons.AutoMirrored.Filled.KeyboardArrowLeft,
                    contentDescription = "Close",
                    tint = PickColors.Text,
                    modifier = Modifier.size(28.dp),
                )
            }
            Text(
                text = doc.title,
                color = PickColors.Text,
                fontWeight = FontWeight.SemiBold,
                fontSize = 18.sp,
                modifier = Modifier.weight(1f).padding(horizontal = 4.dp),
            )
            val shareUrl = doc.shareUrl
            if (shareUrl != null) {
                GhostPill("Share") { onShare(shareUrl) }
            } else {
                GhostPill("Create link") { onCreateShareLink(doc.id) }
            }
        }
        RowSeparator()
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
        ) {
            MarkdownText(doc.blocks)
        }
    }
}

@Composable
fun SignInView(onRetry: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        BrandBadge(sizeDp = 48)
        Spacer(Modifier.height(20.dp))
        Text(
            text = "Sign in to connect to Strike48",
            color = PickColors.Text,
            fontWeight = FontWeight.SemiBold,
            fontSize = 20.sp,
        )
        Spacer(Modifier.height(8.dp))
        Text(
            text = "Authenticate to register this connector and start scanning.",
            color = PickColors.Muted,
            fontSize = 14.sp,
        )
        Spacer(Modifier.height(24.dp))
        SagePillButton(text = "Sign in", onClick = onRetry)
    }
}

@Composable
fun ErrorCard(message: String, onDismiss: () -> Unit) {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(PickColors.Surface)
            .border(1.dp, PickColors.Error.copy(alpha = 0.4f), RoundedCornerShape(16.dp))
            .padding(16.dp),
    ) {
        Column(Modifier.fillMaxWidth()) {
            Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "Error",
                    color = PickColors.Error,
                    fontWeight = FontWeight.Bold,
                    fontSize = 15.sp,
                    modifier = Modifier.weight(1f),
                )
                Text(
                    text = "Dismiss",
                    color = PickColors.Muted,
                    fontSize = 14.sp,
                    modifier = Modifier.clickable(onClick = onDismiss).padding(4.dp),
                )
            }
            Spacer(Modifier.height(6.dp))
            Text(text = message, color = PickColors.Text, fontSize = 14.sp)
        }
    }
}

/**
 * Inline notice surfaced when the agent backend errored (token/rate-limit
 * exhaustion or a generic upstream failure) instead of producing a reply.
 * Distinct from [ErrorCard]: it carries a specific title/detail built from
 * `tokenUsageStats` and, when present, a tappable "Open Studio" link that opens
 * the Studio session via an ACTION_VIEW intent.
 */
@Composable
fun NoticeCard(notice: NoticeView, onOpenStudio: (String) -> Unit) {
    // Token-limit warns (amber); a generic upstream blip uses the error accent.
    val accent = when (notice.kind) {
        NoticeKind.TOKENLIMIT -> PickColors.StatusWarning
        else -> PickColors.Error
    }
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp, vertical = 8.dp)
            .clip(RoundedCornerShape(16.dp))
            .background(PickColors.Surface)
            .border(1.dp, accent.copy(alpha = 0.4f), RoundedCornerShape(16.dp))
            .padding(16.dp),
    ) {
        Column(Modifier.fillMaxWidth()) {
            Text(
                text = notice.title,
                color = accent,
                fontWeight = FontWeight.SemiBold,
                fontSize = 15.sp,
            )
            Spacer(Modifier.height(6.dp))
            Text(text = notice.detail, color = PickColors.Text, fontSize = 14.sp)
            notice.studioUrl?.let { url ->
                Spacer(Modifier.height(8.dp))
                Text(
                    text = "Open Studio",
                    color = PickColors.Brand,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 14.sp,
                    modifier = Modifier.clickable { onOpenStudio(url) }.padding(vertical = 2.dp),
                )
            }
        }
    }
}

// --- shared overlay primitives ---

@Composable
private fun FullScreenOverlay(content: @Composable androidx.compose.foundation.layout.ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(PickColors.Background),
        content = content,
    )
}

@Composable
private fun OverlayHeader(title: String, onClose: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 4.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(
            modifier = Modifier
                .size(40.dp)
                .clip(RoundedCornerShape(999.dp))
                .clickable(onClick = onClose),
            contentAlignment = Alignment.Center,
        ) {
            Icon(
                imageVector = Icons.AutoMirrored.Filled.KeyboardArrowLeft,
                contentDescription = "Close",
                tint = PickColors.Text,
                modifier = Modifier.size(28.dp),
            )
        }
        Text(
            text = title,
            color = PickColors.Text,
            fontWeight = FontWeight.SemiBold,
            fontSize = 18.sp,
        )
    }
    RowSeparator()
}

@Composable
private fun RowSeparator() {
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(1.dp)
            .background(PickColors.RowSeparator),
    )
}

@Composable
private fun GhostPill(text: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(999.dp))
            .background(PickColors.SubtleFill)
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 8.dp),
    ) {
        Text(text = text, color = PickColors.Text, fontSize = 14.sp, fontWeight = FontWeight.Medium)
    }
}

@Composable
private fun EmptyState(text: String) {
    Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
        Text(text = text, color = PickColors.Muted, fontSize = 14.sp)
    }
}
