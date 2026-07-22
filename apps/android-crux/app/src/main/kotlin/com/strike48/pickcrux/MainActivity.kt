package com.strike48.pickcrux

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.strike48.pick.shared.Event
import com.strike48.pick.shared.Screen
import com.strike48.pick.shared.ViewModel
import com.strike48.pickcrux.ui.ChatList
import com.strike48.pickcrux.ui.ConversationDocStrip
import com.strike48.pickcrux.ui.DocViewer
import com.strike48.pickcrux.ui.DocumentsList
import com.strike48.pickcrux.ui.ErrorCard
import com.strike48.pickcrux.ui.HistorySheet
import com.strike48.pickcrux.ui.InputRow
import com.strike48.pickcrux.ui.PickColors
import com.strike48.pickcrux.ui.PickTheme
import com.strike48.pickcrux.ui.ScanCard
import com.strike48.pickcrux.ui.SignInView
import com.strike48.pickcrux.ui.TopBar

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Placeholder api_url/token: real Matrix/OAuth wiring is a later task.
        // Network calls may error into ViewModel.error, which the UI renders.
        val core = NativeCore.create(
            apiUrl = "https://plg.strike48.test",
            token = "placeholder-token",
        )

        setContent {
            PickTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = PickColors.Background) {
                    PickApp(core)
                }
            }
        }
    }
}

@Composable
fun PickApp(core: NativeCore) {
    var model by remember { mutableStateOf(core.view()) }
    // Local overlay state the core does not track (which top-bar list is open).
    var showHistory by remember { mutableStateOf(false) }
    var showReports by remember { mutableStateOf(false) }
    val context = LocalContext.current

    fun send(event: Event) {
        model = core.update(event)
    }

    // Document viewer takes the whole screen when a doc is open.
    val openDoc = model.openDocument
    if (openDoc != null) {
        DocViewer(
            doc = openDoc,
            onClose = { send(Event.CloseDocument) },
            onCreateShareLink = { send(Event.CreateShareLink(it)) },
            onShare = { url ->
                val intent = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, url)
                }
                context.startActivity(Intent.createChooser(intent, "Share"))
            },
        )
        return
    }

    if (showHistory) {
        HistorySheet(
            history = model.history,
            onSelect = { showHistory = false; send(Event.SelectConversation(it)) },
            onDismiss = { showHistory = false; send(Event.CloseHistory) },
        )
        return
    }

    if (showReports) {
        DocumentsList(
            documents = model.allDocuments,
            onOpen = { showReports = false; send(Event.OpenDocument(it)) },
            onDismiss = { showReports = false },
        )
        return
    }

    Column(modifier = Modifier.fillMaxSize()) {
        TopBar(
            connectionLabel = model.connection.label,
            onNewChat = { send(Event.NewChat) },
            onHistory = { send(Event.OpenHistory); showHistory = true },
            onReports = { showReports = true },
        )

        model.error?.let { err ->
            ErrorCard(message = err, onDismiss = { send(Event.DismissError) })
        }

        when {
            model.needsSignIn || model.screen == Screen.NEEDSSIGNIN -> {
                Box(modifier = Modifier.fillMaxSize()) {
                    SignInView(onRetry = { send(Event.RetrySignIn) })
                }
            }
            model.showScanCard -> {
                ScanCard(
                    scanInProgress = model.scanInProgress,
                    onStartScan = { send(Event.StartScan) },
                )
                if (model.messages.isNotEmpty() || model.toolCalls.isNotEmpty()) {
                    ChatList(
                        messages = model.messages,
                        toolCalls = model.toolCalls,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
            else -> {
                ChatList(
                    messages = model.messages,
                    toolCalls = model.toolCalls,
                    modifier = Modifier.weight(1f),
                )
                ConversationDocStrip(
                    docs = model.conversationDocs,
                    onOpen = { send(Event.OpenDocument(it)) },
                )
                InputRow(onSend = { send(Event.SendMessage(it)) })
            }
        }
    }
}
