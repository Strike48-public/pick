package com.strike48.pickcrux.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.DateRange
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.strike48.pick.shared.ConversationRef

/**
 * Contents of the platform-native navigation drawer (rendered inside a
 * ModalNavigationDrawer's ModalDrawerSheet). Holds the primary destinations
 * plus a live list of recent chats, with Log out pinned at the bottom.
 */
@Composable
fun DrawerContents(
    recentChats: List<ConversationRef>,
    onNewChat: () -> Unit,
    onOpenReports: () -> Unit,
    onOpenSettings: () -> Unit,
    onSelectChat: (String) -> Unit,
    onLogout: () -> Unit,
) {
    ModalDrawerSheet(drawerContainerColor = PickColors.Surface) {
        Column(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier.padding(start = 20.dp, top = 20.dp, bottom = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                BrandBadge(connected = false)
                Spacer(Modifier.width(10.dp))
                Text(text = "Pick", style = WordmarkStyle)
            }
            RowSeparator()

            DrawerItem(Icons.Filled.Add, "New chat", onNewChat)
            DrawerItem(Icons.AutoMirrored.Filled.List, "Reports", onOpenReports)
            DrawerItem(Icons.Filled.Settings, "Settings", onOpenSettings)

            RowSeparator()
            Text(
                text = "Recent chats",
                color = PickColors.Muted,
                fontSize = 12.sp,
                fontWeight = FontWeight.Medium,
                modifier = Modifier.padding(start = 20.dp, top = 12.dp, bottom = 4.dp),
            )
            if (recentChats.isEmpty()) {
                Text(
                    text = "No conversations yet",
                    color = PickColors.Muted,
                    fontSize = 14.sp,
                    modifier = Modifier.padding(start = 20.dp, top = 4.dp, bottom = 8.dp),
                )
            } else {
                LazyColumn(modifier = Modifier.fillMaxWidth().weight(1f)) {
                    items(recentChats) { conv ->
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { onSelectChat(conv.id) }
                                .padding(horizontal = 20.dp, vertical = 10.dp),
                        ) {
                            Text(
                                text = conv.title.ifBlank { "Untitled chat" },
                                color = PickColors.Text,
                                fontSize = 15.sp,
                                maxLines = 1,
                            )
                            if (conv.relativeTime.isNotBlank()) {
                                Text(
                                    text = conv.relativeTime,
                                    color = PickColors.Muted,
                                    fontSize = 12.sp,
                                )
                            }
                        }
                    }
                }
            }

            RowSeparator()
            DrawerItem(Icons.AutoMirrored.Filled.List, "Log out", onLogout, tint = PickColors.Error)
            Spacer(Modifier.height(12.dp))
        }
    }
}

@Composable
private fun DrawerItem(
    icon: ImageVector,
    label: String,
    onClick: () -> Unit,
    tint: androidx.compose.ui.graphics.Color = PickColors.Text,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 20.dp, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Icon(imageVector = icon, contentDescription = label, tint = tint, modifier = Modifier.size(22.dp))
        Text(text = label, color = tint, fontSize = 16.sp)
    }
}

/**
 * Full-screen Settings surface: feature-flag toggles. Telemetry is opt-out
 * (on by default); flipping it takes effect immediately (the core closes /
 * reopens the Sentry client) and is persisted by the shell.
 */
@Composable
fun SettingsScreen(
    telemetryEnabled: Boolean,
    onTelemetryChange: (Boolean) -> Unit,
    onClose: () -> Unit,
) {
    FullScreenOverlay {
        OverlayHeader(title = "Settings", onClose = onClose)
        Column(modifier = Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 8.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f).padding(end = 12.dp)) {
                    Text(text = "Usage analytics", color = PickColors.Text, fontSize = 16.sp)
                    Text(
                        text = "Share anonymous usage + crash data to help improve Pick. " +
                            "No scan results, targets, or personal data are sent.",
                        color = PickColors.Muted,
                        fontSize = 13.sp,
                    )
                }
                Switch(
                    checked = telemetryEnabled,
                    onCheckedChange = onTelemetryChange,
                    colors = SwitchDefaults.colors(
                        checkedThumbColor = PickColors.OnBrand,
                        checkedTrackColor = PickColors.Brand,
                    ),
                )
            }
        }
    }
}
