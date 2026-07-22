package com.strike48.pickcrux

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import com.strike48.pick.shared.AgentActivity
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
import com.strike48.pickcrux.ui.NoticeCard
import com.strike48.pickcrux.ui.PickColors
import com.strike48.pickcrux.ui.PickTheme
import com.strike48.pickcrux.ui.ScanCard
import com.strike48.pickcrux.ui.SignInView
import com.strike48.pickcrux.ui.TopBar

/**
 * Native OAuth constants. The shell opens a browser / Custom Tab to the Matrix
 * `/auth/login` endpoint; Matrix runs the Keycloak SSO login and redirects back
 * to [REDIRECT_URI], which [OAuthCallbackActivity] intercepts. The captured
 * token is a workspace-scoped Studio session token (`__st`) — the only credential
 * that carries workspace scope and can see the pentest agent.
 */
object Oauth {
    const val API_BASE = "https://plg.strike48.test"
    const val REDIRECT_URI = "com.strike48.pentest://oauth/callback"

    /** `https://<host>/auth/login?redirect=<url-encoded REDIRECT_URI>`. */
    fun loginUrl(): String {
        val redirect = Uri.encode(REDIRECT_URI)
        return "$API_BASE/auth/login?redirect=$redirect"
    }
}

class MainActivity : ComponentActivity() {
    companion object {
        private const val TAG = "PickCruxMain"
    }

    private lateinit var core: NativeCore

    // Drives which screen shows: no token yet -> SignInView. Flipped to true once
    // OAuth delivers a token and the core adopts it via pick_set_token.
    private var signedIn by mutableStateOf(false)

    // Bumped after setToken so the composable re-reads core.view().
    private var refreshTick by mutableStateOf(0)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        core = NativeCore.create(
            apiUrl = Oauth.API_BASE,
            token = "", // no token yet: SignIn screen gates the shell until OAuth
        )

        setContent {
            PickTheme {
                androidx.compose.material3.Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = PickColors.Background,
                ) {
                    PickApp(
                        core = core,
                        signedIn = signedIn,
                        refreshTick = refreshTick,
                        onSignIn = { launchOauth() },
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        // Adopt any token captured by OAuthCallbackActivity (may have arrived
        // while we were backgrounded during the browser flow).
        OAuthTokenHolder.setListener { token -> adoptToken(token) }
    }

    override fun onPause() {
        super.onPause()
        OAuthTokenHolder.clearListener()
    }

    // A relaunch via FLAG_ACTIVITY_SINGLE_TOP lands here too.
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
    }

    private fun adoptToken(token: String) {
        Log.i(TAG, "Adopting OAuth token (len=${token.length}) into core")
        core.setToken(token)
        signedIn = true
        refreshTick++ // force the composable to re-read core.view()
    }

    /** Open a Custom Tab (falls back to ACTION_VIEW) at the Matrix login URL. */
    private fun launchOauth() {
        val url = Oauth.loginUrl()
        Log.i(TAG, "Launching OAuth login: $url")
        val uri = Uri.parse(url)
        try {
            // Custom Tabs via reflection-free intent: a plain VIEW intent with the
            // Custom Tabs extras works on any browser and needs no extra dependency.
            val intent = Intent(Intent.ACTION_VIEW, uri).apply {
                putExtra("android.support.customtabs.extra.SESSION", null as Bundle?)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            startActivity(intent)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to launch browser: ${e.message}")
            startActivity(Intent(Intent.ACTION_VIEW, uri))
        }
    }
}

@Composable
fun PickApp(
    core: NativeCore,
    signedIn: Boolean,
    refreshTick: Int,
    onSignIn: () -> Unit,
) {
    // Re-read the view whenever the sign-in state or refresh tick changes.
    var model by remember(signedIn, refreshTick) { mutableStateOf(core.view()) }
    // Local overlay state the core does not track (which top-bar list is open).
    var showHistory by remember { mutableStateOf(false) }
    var showReports by remember { mutableStateOf(false) }
    val context = LocalContext.current

    // Streaming: the core pushes a view update (on the main thread) whenever an
    // async effect resolves. Re-render as the scan streams in — no polling.
    DisposableEffect(core) {
        core.onViewChanged = { model = it }
        onDispose { core.onViewChanged = null }
    }

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
            connectionLabel = if (signedIn) model.connection.label else "Sign in to connect",
            onNewChat = { send(Event.NewChat) },
            onHistory = { send(Event.OpenHistory); showHistory = true },
            onReports = { send(Event.OpenDocuments); showReports = true },
        )

        model.error?.let { err ->
            ErrorCard(message = err, onDismiss = { send(Event.DismissError) })
        }

        // Surfaced when the agent backend errored (token limit or a generic
        // upstream failure) instead of ending the scan silently.
        model.notice?.let { notice ->
            NoticeCard(
                notice = notice,
                onOpenStudio = { url ->
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                },
            )
        }

        when {
            // No native OAuth token yet -> gate the shell behind Sign In.
            !signedIn || model.needsSignIn || model.screen == Screen.NEEDSSIGNIN -> {
                Box(modifier = Modifier.fillMaxSize()) {
                    SignInView(onRetry = onSignIn)
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
                        activityActive = model.agentActivity != AgentActivity.IDLE,
                        activityLabel = model.activityLabel,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
            else -> {
                ChatList(
                    messages = model.messages,
                    toolCalls = model.toolCalls,
                    activityActive = model.agentActivity != AgentActivity.IDLE,
                    activityLabel = model.activityLabel,
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
