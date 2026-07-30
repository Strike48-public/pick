//! Agent chat panel component.
//!
//! Right-side slide-out panel for conversing with Matrix AI agents.
//! Supports rich rendering: tool calls, markdown, thinking blocks.
//! Drag-to-resize on the left edge (mirroring the sidebar pattern).

mod agent_selector;
mod constants;
mod history;
mod input;
mod messages;
mod next_steps;
mod render;

use dioxus::prelude::*;
use pentest_core::matrix::{
    apply_event, build_error_notice, subscribe_conversation, AgentInfo, AgentStatus, ApplyOutcome,
    ChatClient, ChatMessage, ChatNotice, ChatNoticeKind, ConnectionState, ConversationInfo,
    ConversationStreamEvent, MatrixChatClient, UpdateAgentInput,
};
use pentest_core::terminal::TerminalLine;
use std::collections::HashMap;
use std::sync::Arc;

use super::button::{Button, ButtonSize, ButtonVariant};
use agent_selector::ChatHeader;
pub use agent_selector::{ChatHeaderActions, ChatHeaderCtx};
use constants::*;
use history::HistoryDropdown;
use input::ChatInput;
use messages::MessageList;
pub use render::format_relative_time;
use render::{CHART_PROCESSOR_JS, UTILS_JS};

/// Resolve the dev TLS-insecure flag the same way the rest of the app does
/// (`liveview_connector::token_refresh::build_http_client` and
/// `pentest_core::matrix::insecure_tls`): BUILD-time `option_env!` first — the
/// only source that reaches the mobile apps, which have no runtime environment —
/// then the RUNTIME env for desktop/dev/headless.
fn subscription_insecure_tls() -> bool {
    let truthy = |v: &str| v == "true" || v == "1";
    option_env!("MATRIX_TLS_INSECURE")
        .or(option_env!("MATRIX_INSECURE"))
        .map(truthy)
        .filter(|&b| b)
        .unwrap_or_else(|| {
            std::env::var("MATRIX_TLS_INSECURE")
                .or_else(|_| std::env::var("MATRIX_INSECURE"))
                .map(|v| truthy(&v))
                .unwrap_or(false)
        })
}

/// Human-readable label for a non-terminal agent status, mirroring the labels
/// the old poller surfaced so the "Thinking..." semantics are preserved.
fn status_label(status: AgentStatus) -> &'static str {
    match status {
        AgentStatus::Processing => "Thinking...",
        AgentStatus::Streaming => "Responding...",
        AgentStatus::ExecutingTools => "Running tools...",
        AgentStatus::AwaitingConsent => "Awaiting approval...",
        AgentStatus::AwaitingClientTools => "Running client tools...",
        _ => "Thinking...",
    }
}

/// Merge server-truth messages with any local-only (`local-*`) messages the user
/// has sent that the backend has not echoed yet, so a (re)connect catch-up never
/// drops the in-flight user turn. Server messages win by id; unechoed locals are
/// prepended.
fn merge_server_messages(messages: &mut Signal<Vec<ChatMessage>>, server: Vec<ChatMessage>) {
    let locals: Vec<ChatMessage> = messages
        .peek()
        .iter()
        .filter(|m| m.id.starts_with("local-"))
        .cloned()
        .collect();
    let mut merged = server;
    for lm in locals {
        let echoed = merged
            .iter()
            .any(|s| s.sender_type == "USER" && s.text == lm.text);
        if !echoed {
            merged.insert(0, lm);
        }
    }
    messages.set(merged);
}

/// One HTTP `get_conversation` to seed history and the initial thinking state
/// before the live subscription takes over (also used for reconnect catch-up).
async fn seed_from_conversation(
    client: &MatrixChatClient,
    cid: &str,
    messages: &mut Signal<Vec<ChatMessage>>,
    agent_thinking: &mut Signal<bool>,
    agent_status_text: &mut Signal<String>,
    error_msg: &mut Signal<Option<String>>,
) {
    match client.get_conversation(cid).await {
        Ok(state) => {
            merge_server_messages(messages, state.messages);
            if state.agent_status.is_terminal() {
                agent_thinking.set(false);
                agent_status_text.set(String::new());
            } else {
                agent_thinking.set(true);
                agent_status_text.set(status_label(state.agent_status).to_string());
            }
            // Surface a durable mid-stream failure: a turn that died with the
            // agent server reporting IDLE (not ERROR) still carries
            // `metadata.stream_error`. Without this a crashed turn opens clean.
            if let Some(err) = state.stream_error {
                error_msg.set(Some(err));
            }
        }
        Err(e) => tracing::warn!("[chat] seed get_conversation failed: {e}"),
    }
}

/// Fold an [`ApplyOutcome`] into the thinking/status/error signals. Called for
/// every streamed event. On a terminal status it clears the thinking state and,
/// if a validation round-trip is in flight, parses the Validator's verdicts.
#[allow(clippy::too_many_arguments)]
async fn apply_outcome(
    outcome: ApplyOutcome,
    client: &MatrixChatClient,
    agent_thinking: &mut Signal<bool>,
    agent_status_text: &mut Signal<String>,
    error_msg: &mut Signal<Option<String>>,
    chat_notice: &mut Signal<Option<ChatNotice>>,
    pending_validator_apply: &mut Signal<Option<usize>>,
    messages: &mut Signal<Vec<ChatMessage>>,
    conversation_id: &str,
) {
    // The streamed error reason (AgentStatusEvent.error) is now available
    // directly — surface it. Polling never saw this.
    if let Some(err) = outcome.error.clone() {
        error_msg.set(Some(err));
    }

    let Some(status) = outcome.status else {
        return;
    };

    if status == AgentStatus::Error {
        // Richer notice (token/rate-limit classification) via the Studio usage
        // stats query, same as the old poller surfaced.
        let notice = build_error_notice(client).await;
        chat_notice.set(Some(notice));
    }

    if status.is_terminal() {
        agent_thinking.set(false);
        agent_status_text.set(String::new());

        // Validator round-trip: the turn is done, so parse its reply and apply
        // the verdicts to the evidence graph (previously done after polling).
        let pending = *pending_validator_apply.peek();
        if let Some(pending_count) = pending {
            pending_validator_apply.set(None);
            // The terminal AgentStatusEvent can arrive BEFORE the final
            // Message event carrying the Validator's verdict reply. Fetch the
            // authoritative conversation first (the old poller parsed only
            // after a post-terminal get_conversation), so the reply is present.
            if let Ok(state) = client.get_conversation(conversation_id).await {
                merge_server_messages(messages, state.messages);
            }
            let mut em = *error_msg;
            apply_validator_reply(&messages.peek(), pending_count, &mut em);
        }
    } else {
        agent_thinking.set(true);
        agent_status_text.set(status_label(status).to_string());
    }
}

/// Parse the Validator Agent's latest reply and apply its verdicts to the
/// evidence graph.
///
/// Called after the validation conversation finishes polling. Finds the newest
/// non-USER message, extracts the fenced verdict JSON, and hands it to
/// [`crate::session::apply_validator_verdicts`]. The outcome is surfaced through
/// `error_msg` so the operator never silently proceeds:
///
/// * unparseable reply -> error (the Validator went off-script);
/// * verdicts applied but nodes still pending -> warning that Generate Report
///   will refuse until they are adjudicated;
/// * everything adjudicated -> `error_msg` is cleared.
///
/// Kept as a free function (rather than a closure) so the glue stays readable
/// and does not capture the component's signal soup. The behaviour it composes
/// is covered by the `parse_validator_verdicts` tests in `pentest-core` and the
/// `apply_validator_verdicts` tests in `crate::session`.
fn apply_validator_reply(
    messages: &[ChatMessage],
    pending_count: usize,
    error_msg: &mut Signal<Option<String>>,
) {
    let Some(reply) = messages
        .iter()
        .rev()
        .find(|m| m.sender_type != "USER" && !m.text.is_empty())
    else {
        error_msg.set(Some(
            "The Validator produced no reply. Try validating again, or check the \
             conversation for an error."
                .to_string(),
        ));
        return;
    };

    let verdicts = match pentest_core::orchestrator::parse_validator_verdicts(&reply.text) {
        Ok(v) => v,
        Err(e) => {
            error_msg.set(Some(format!(
                "Could not read the Validator's verdicts ({e}). The report gate will refuse \
                 until every finding is adjudicated — ask the Validator to re-emit its JSON \
                 verdict block, or validate again."
            )));
            return;
        }
    };

    let report = crate::session::apply_validator_verdicts(&verdicts);

    // Surface unmatched verdict IDs - these indicate the Validator hallucinated
    // or mistyped node IDs that don't exist in the evidence graph.
    if !report.unmatched_verdict_ids.is_empty() {
        tracing::warn!(
            unmatched = report.unmatched_verdict_ids.len(),
            "validator emitted verdicts for node ids not in the graph"
        );
        error_msg.set(Some(format!(
            "Warning: Validator issued verdicts for {} non-existent node ID(s). \
             This indicates the Validator hallucinated IDs. Validated {}/{} findings; \
             {} still pending. Ask the Validator to re-emit verdicts using only the \
             node IDs from the manifest, or validate again.",
            report.unmatched_verdict_ids.len(),
            report.applied,
            pending_count,
            report.still_pending_ids.len()
        )));
        return;
    }

    if report.is_fully_adjudicated() {
        // All clear — Generate Report will now succeed.
        error_msg.set(None);
    } else {
        let still = report.still_pending_ids.len();
        error_msg.set(Some(format!(
            "Validated {} of {} finding(s); {} still pending. Generate Report will refuse \
             until the Validator adjudicates the rest.",
            report.applied, pending_count, still
        )));
    }
}

/// Props for the ChatPanel component.
#[derive(Props, Clone, PartialEq)]
pub struct ChatPanelProps {
    /// Whether the panel is visible.
    pub visible: bool,
    /// Matrix API URL (e.g. "http://localhost:4000").
    pub api_url: String,
    /// Auth token for Matrix GraphQL calls.
    pub auth_token: String,
    /// Tenant/realm name (e.g. "non-prod") used when auto-creating the agent
    /// so connector tool patterns resolve correctly.
    pub tenant_id: String,
    /// Callback to close the panel.
    pub on_close: EventHandler<()>,
    /// Shared mailbox: caller writes Some("message") to auto-send, chat panel consumes it.
    #[props(default)]
    pub send_mailbox: Option<Signal<Option<String>>>,
    /// When true, renders as an inline full-page view instead of a slide-out overlay.
    /// Set by BOTH the easy-mode shell and the expert full-page Chat page, so it
    /// controls layout only — use `easy_mode` for lay-friendly copy/behavior.
    #[props(default)]
    pub full_page: bool,
    /// True only in the easy-mode shell. Drives lay-friendly empty-state copy
    /// (the "Scan My Network" greeting) and hides the expert suggested-action
    /// chips. Distinct from `full_page`, which the expert full-page chat also
    /// sets — conflating them leaked easy-mode copy into the expert shell.
    #[props(default)]
    pub easy_mode: bool,
    /// Mailbox to open a specific conversation by ID (set by sidebar recent conversations).
    #[props(default)]
    pub open_conversation_id: Option<Signal<Option<String>>>,
    /// Output signal: writes the selected agent ID whenever it changes (for Easy Mode documents list).
    #[props(default)]
    pub selected_agent_out: Option<Signal<Option<String>>>,
    /// Output signal: true when a conversation is active (has messages). Easy
    /// Mode uses this to hide the Scan card once a chat has started.
    #[props(default)]
    pub conversation_active_out: Option<Signal<bool>>,
    /// Output signal: the active conversation's ID (None until one starts).
    /// Easy Mode uses this to show a documents strip scoped to THIS conversation.
    #[props(default)]
    pub conversation_id_out: Option<Signal<Option<String>>>,
    /// Callback to emit chat-level auth events (ChatReady, ChatAuthDead).
    #[props(default)]
    pub on_chat_event: EventHandler<crate::auth_flow::AuthEvent>,
}

#[component]
pub fn ChatPanel(props: ChatPanelProps) -> Element {
    // -----------------------------------------------------------------------
    // Signals
    // -----------------------------------------------------------------------

    // Agents list
    let mut agents = use_signal(Vec::<AgentInfo>::new);
    let mut selected_agent = use_signal(|| None::<AgentInfo>);
    let mut agents_loaded = use_signal(|| false);

    // Track whether we've already kicked off a fetch
    let mut fetch_started = use_signal(|| false);

    // Conversation state
    let mut conversation_id = use_signal(|| None::<String>);
    let mut messages = use_signal(Vec::<ChatMessage>::new);

    // Mirror "conversation active" (has messages) to the optional out-signal so
    // Easy Mode can hide the Scan card once a chat has started.
    if let Some(mut out) = props.conversation_active_out {
        use_effect(move || {
            let active = !messages.read().is_empty();
            if *out.peek() != active {
                out.set(active);
            }
        });
    }
    // Mirror the active conversation ID so Easy Mode can scope its documents
    // strip to the current conversation.
    if let Some(mut out) = props.conversation_id_out {
        use_effect(move || {
            let cid = conversation_id.read().clone();
            if *out.peek() != cid {
                out.set(cid);
            }
        });
    }
    let mut is_sending = use_signal(|| false);
    let mut agent_thinking = use_signal(|| false);
    let mut agent_status_text = use_signal(String::new);
    let mut error_msg = use_signal(|| None::<String>);
    // Subtle inline notice driven by the stream applier — distinct from
    // `error_msg` (which renders the loud red banner for call-failures). Used for
    // things like "Token limit reached" where we want a softer, link-bearing
    // message.
    let mut chat_notice = use_signal(|| None::<ChatNotice>);

    // Live subscription plumbing (replaces the old 800ms HTTP poll).
    // `connection_state` mirrors the transport's watch channel so the header can
    // show a "Reconnecting..." chip / "Retry" button. `retry_tick` is bumped by
    // the Retry button to force the subscription effect to respawn. When the
    // active conversation is a Validator round-trip, `pending_validator_apply`
    // holds the pending-node count so the terminal-status handler knows to parse
    // and apply the Validator's verdicts (previously done right after polling).
    let connection_state = use_signal(|| ConnectionState::Connecting);
    let mut retry_tick = use_signal(|| 0u32);
    let mut pending_validator_apply = use_signal(|| None::<usize>);

    // Per-agent conversation tracking
    let mut agent_conversations: Signal<HashMap<String, String>> = use_signal(HashMap::new);
    let mut conversation_list: Signal<Vec<ConversationInfo>> = use_signal(Vec::new);
    let mut show_history: Signal<bool> = use_signal(|| false);
    let mut history_loading: Signal<bool> = use_signal(|| false);

    // Tool call expand/collapse state
    let expanded_tools = use_signal(Vec::<String>::new);

    // Auto-scroll state
    let mut user_scrolled_up = use_signal(|| false);

    // Resize state
    let mut panel_width = use_signal(|| CHAT_DEFAULT_WIDTH);
    let mut is_resizing = use_signal(|| false);

    // Close animation state
    let mut closing = use_signal(|| false);

    // Context signal for sharing chat header actions with AppLayout (full-page mode).
    // AppLayout provides this via use_context_provider; ChatPanel writes when full_page.
    let mut chat_header_ctx: Signal<Option<ChatHeaderCtx>> = use_context();

    // Count consecutive auth failures so a stale restored token forces a fresh
    // sign-in (via the easy-mode overlay) rather than retrying the dead token
    // forever.
    let auth_fail_count = use_signal(|| 0u32);

    // Reset closing when panel becomes visible again
    if props.visible && closing() {
        closing.set(false);
    }

    let api_url = props.api_url.clone();
    let auth_token = props.auth_token.clone();

    // -----------------------------------------------------------------------
    // Auth token resolution — prefer session store (set by connector), then prop
    // -----------------------------------------------------------------------

    // Bumped whenever we write the session token out-of-band (browser OAuth
    // success). The session store is a process-global RwLock, not a signal, so
    // without this the render never re-reads it after sign-in and stays stuck on
    // the "complete sign-in in the browser" state until an unrelated re-render.
    // Reading it here makes `effective_token` reactive to that write.
    let token_tick = use_signal(|| 0u32);

    let effective_token = {
        let _ = token_tick(); // subscribe: re-resolve the token when it changes
        let session_token = crate::session::get_auth_token();
        if !session_token.is_empty() {
            session_token
        } else {
            auth_token.clone()
        }
    };

    // Shared base client — created once, reuses the reqwest connection pool.
    // Avoids repeated Client::builder() calls (which can fail on Windows).
    let base_client = use_hook({
        let api_url = api_url.clone();
        move || Arc::new(MatrixChatClient::new(api_url))
    });

    // Build client helper — reads session store at call time for freshest token.
    // Uses the current api_url prop (not the one captured in use_hook) so that
    // requests hit the right host even when the URL arrives after first mount.
    let make_client = {
        let base_client = base_client.clone();
        let effective_token = effective_token.clone();
        let api_url = api_url.clone();
        move || -> Arc<MatrixChatClient> {
            let session_token = crate::session::get_auth_token();
            let token = if !session_token.is_empty() {
                session_token
            } else {
                effective_token.clone()
            };
            let mut c = MatrixChatClient::from_shared(&base_client, &api_url);
            if !token.is_empty() {
                c.set_auth_token(token);
            }
            Arc::new(c)
        }
    };

    // Load the recent-conversations list as soon as an agent is selected, not
    // only when the drawer/history dropdown opens. The Easy Mode drawer and the
    // conversation view both render from this list, so it must be warm before
    // either is opened. Keyed on the agent id (via a last-loaded guard) so it
    // fetches once per agent rather than on every unrelated re-render; the
    // drawer's on_refresh_conversations still re-syncs on demand.
    {
        let make_client = make_client.clone();
        let mut last_loaded_agent = use_signal(|| None::<String>);
        use_effect(move || {
            let Some(agent_id) = selected_agent.read().as_ref().map(|a| a.id.clone()) else {
                return;
            };
            if last_loaded_agent.peek().as_deref() == Some(agent_id.as_str()) {
                return; // already loaded for this agent
            }
            last_loaded_agent.set(Some(agent_id.clone()));
            let client = make_client();
            history_loading.set(true);
            spawn(async move {
                match client.list_conversations(Some(&agent_id)).await {
                    Ok(mut list) => {
                        list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
                        conversation_list.set(list);
                    }
                    Err(e) => tracing::warn!("Failed to load conversation list on select: {}", e),
                }
                history_loading.set(false);
            });
        });
    }

    // -----------------------------------------------------------------------
    // One-time initialisations
    // -----------------------------------------------------------------------

    // Inject shared JS utilities (scroll, form submit, etc.)
    let utils_init = use_hook(|| std::cell::Cell::new(false));
    if !utils_init.get() {
        utils_init.set(true);
        spawn(async move {
            if let Err(e) = document::eval(UTILS_JS).await {
                tracing::warn!("JS eval failed (utils.js init): {e}");
            }
        });
    }

    // Inject chart processor JS (mermaid + echarts CDN + post-processor)
    let chart_init = use_hook(|| std::cell::Cell::new(false));
    if !chart_init.get() {
        chart_init.set(true);
        spawn(async move {
            if let Err(e) = document::eval(CHART_PROCESSOR_JS).await {
                tracing::warn!("JS eval failed (chart processor init): {e}");
            }
        });
    }

    // Debug: log credential state to both tracing and the Logs sidebar
    if props.visible && !agents_loaded() {
        let log_msg = format!(
            "[chat] waiting for credentials: api_url={} token_len={} session_token_len={} fetch_started={}",
            if api_url.is_empty() { "(empty)" } else { "(set)" },
            effective_token.len(),
            crate::session::get_auth_token().len(),
            fetch_started(),
        );
        tracing::info!("{}", log_msg);
        crate::liveview_server::push_terminal_line(TerminalLine::info(log_msg));
    }

    // -----------------------------------------------------------------------
    // Lazy browser-OAuth: trigger on first Chat panel visit when token is missing
    // -----------------------------------------------------------------------

    // Track whether we've attempted browser auth
    let browser_auth_attempted = use_signal(|| false);

    // Shared browser-OAuth kickoff — used both by the expert sidebar's lazy
    // auto-trigger and the full-page empty-state "Sign in" button. Marks the
    // attempt, opens the browser, and on success writes + persists the chat
    // token (the effect on `effective_token` picks it up and loads agents).
    let start_browser_auth = {
        let api_url = api_url.clone();
        move || {
            if api_url.is_empty() {
                return;
            }
            // Re-bind the Copy signals mutably per call so this stays an `Fn`
            // closure (usable by both the auto-trigger and the button handler).
            let mut browser_auth_attempted = browser_auth_attempted;
            let mut token_tick = token_tick;
            browser_auth_attempted.set(true);
            let api_url_clone = api_url.clone();
            crate::liveview_server::push_terminal_line(TerminalLine::info(
                "[chat] No auth token — opening browser for authentication...",
            ));
            spawn(async move {
                match pentest_core::matrix::fetch_matrix_token_browser(&api_url_clone).await {
                    Ok(token) => {
                        tracing::info!(
                            "[chat] Browser auth succeeded, token length: {}",
                            token.len()
                        );
                        crate::liveview_server::set_matrix_credentials(&api_url_clone, &token);
                        crate::session::set_auth_token(&token);
                        // Persist so relaunch skips sign-in: token → secure store,
                        // api_url → settings. This path has no `settings` signal in
                        // scope, so it writes the URL detached; the connector_app /
                        // lib.rs paths (which own the signal) write it there.
                        crate::session::persist_matrix_token(&token);
                        crate::session::persist_matrix_api_url_detached(&api_url_clone);
                        // Bump the tick so the render re-reads the session store
                        // (RwLock, not a signal) and drops the awaiting state.
                        token_tick += 1;
                        crate::liveview_server::push_terminal_line(TerminalLine::success(
                            "[chat] Authentication successful — chat ready",
                        ));
                    }
                    Err(e) => {
                        tracing::warn!("[chat] Browser auth failed: {}", e);
                        crate::liveview_server::push_terminal_line(TerminalLine::error(format!(
                            "[chat] Authentication failed: {}",
                            e
                        )));
                    }
                }
            });
        }
    };

    // Lazy browser-OAuth is for the EXPERT SIDEBAR only (not full_page). The
    // full-page chat — expert AND easy — makes sign-in an explicit user gesture
    // instead: mobile OAuth REQUIRES a user gesture with the scene foreground-
    // active (auto-firing silently fails to present), and the expert full-page
    // chat has no connection screen to kick it off. So full_page shows a
    // "Sign in to Strike48" button (see `needs_sign_in` below); only the
    // sidebar auto-triggers here.
    if !props.full_page
        && props.visible
        && effective_token.is_empty()
        && !api_url.is_empty()
        && !browser_auth_attempted()
        && !agents_loaded()
    {
        start_browser_auth.clone()();
    }

    // Browser OAuth for the chat token has been opened but hasn't returned yet
    // (no token, agents not loaded). Drives the "finish sign-in in the browser"
    // empty state so the user isn't shown a misleading "Select an agent".
    let awaiting_auth = browser_auth_attempted() && effective_token.is_empty() && !agents_loaded();

    // Full-page chat with no token and sign-in not yet started: show the
    // explicit "Sign in to Strike48" button in the empty state.
    let needs_sign_in = props.full_page
        && effective_token.is_empty()
        && !api_url.is_empty()
        && !browser_auth_attempted()
        && !agents_loaded();

    // -----------------------------------------------------------------------
    // Fetch agents when we have a token
    // -----------------------------------------------------------------------

    if !effective_token.is_empty() && !api_url.is_empty() && !agents_loaded() && !fetch_started() {
        fetch_started.set(true);
        let client = make_client();
        let tenant_id = props.tenant_id.clone();
        let log_url = api_url.clone();
        // Captured for the auth-error recovery path below (Signals are Copy).
        let mut auth_fail_count = auth_fail_count;
        crate::liveview_server::push_terminal_line(TerminalLine::info(format!(
            "[chat] fetching agents from {}",
            api_url
        )));
        spawn(async move {
            match client.list_agents().await {
                Ok(mut list) => {
                    crate::liveview_server::push_terminal_line(TerminalLine::success(format!(
                        "[chat] loaded {} agents from {}",
                        list.len(),
                        log_url
                    )));
                    let connector_name = crate::session::get_connector_name();
                    let auto = list.iter().find(|a| a.name == connector_name).cloned();

                    // Ensure the Validator Agent sibling exists. It rides on
                    // the same connector but with a separate system prompt
                    // and a minimal tool surface (doc read + mermaid
                    // validation). Scanner tools are NOT auto-approved —
                    // the Validator re-probes only with human consent.
                    // Idempotent: if the sibling is already registered we
                    // leave it alone.
                    let validator_name = format!("{}{}", connector_name, VALIDATOR_AGENT_SUFFIX);
                    let has_validator = list.iter().any(|a| a.name == validator_name);
                    if !has_validator {
                        tracing::info!(
                            "ChatPanel: no {} agent found, creating Validator Agent sibling",
                            validator_name
                        );
                        match client
                            .create_agent(default_validator_agent_input(
                                &tenant_id,
                                &connector_name,
                            ))
                            .await
                        {
                            Ok(new_agent) => {
                                tracing::info!(
                                    "ChatPanel: created Validator Agent: {}",
                                    new_agent.name
                                );
                                list.push(new_agent);
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "ChatPanel: failed to create Validator Agent: {}",
                                    e
                                );
                            }
                        }
                    }

                    // Ensure the Report Agent sibling exists. It rides on the
                    // same connector but uses a separate system prompt and a
                    // minimal tool surface (diagram validators + write_file).
                    // Idempotent: if the sibling is already registered we
                    // leave it alone — its prompt/tools don't depend on the
                    // scanner tool list and updating risks thrashing state.
                    let report_name = format!("{}{}", connector_name, REPORT_AGENT_SUFFIX);
                    let has_report = list.iter().any(|a| a.name == report_name);
                    if !has_report {
                        tracing::info!(
                            "ChatPanel: no {} agent found, creating Report Agent sibling",
                            report_name
                        );
                        match client
                            .create_agent(default_report_agent_input(&tenant_id, &connector_name))
                            .await
                        {
                            Ok(new_agent) => {
                                tracing::info!(
                                    "ChatPanel: created Report Agent: {}",
                                    new_agent.name
                                );
                                list.push(new_agent);
                            }
                            Err(e) => {
                                tracing::warn!("ChatPanel: failed to create Report Agent: {}", e);
                            }
                        }
                    }

                    if let Some(agent) = auto {
                        tracing::info!(
                            "ChatPanel: auto-selected agent: {}, updating tool configs",
                            agent.name
                        );
                        // Update the existing agent's tool configs with current tools
                        let fresh_input = default_pentest_agent_input(&tenant_id, &connector_name);
                        let update_input = UpdateAgentInput {
                            id: agent.id.clone(),
                            tools: fresh_input.tools,
                        };
                        match client.update_agent(update_input).await {
                            Ok(updated) => {
                                tracing::info!(
                                    "ChatPanel: updated agent tools for {}",
                                    updated.name
                                );
                                agents.set(list);
                                agents_loaded.set(true);
                                props
                                    .on_chat_event
                                    .call(crate::auth_flow::AuthEvent::ChatReady);
                                selected_agent.set(Some(updated.clone()));
                                if let Some(mut out) = props.selected_agent_out {
                                    out.set(Some(updated.id.clone()));
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "ChatPanel: failed to update agent tools: {}, using existing",
                                    e
                                );
                                agents.set(list);
                                agents_loaded.set(true);
                                props
                                    .on_chat_event
                                    .call(crate::auth_flow::AuthEvent::ChatReady);
                                selected_agent.set(Some(agent.clone()));
                                if let Some(mut out) = props.selected_agent_out {
                                    out.set(Some(agent.id.clone()));
                                }
                            }
                        }
                    } else {
                        tracing::info!(
                            "ChatPanel: no {} agent found, creating one",
                            connector_name
                        );
                        match client
                            .create_agent(default_pentest_agent_input(&tenant_id, &connector_name))
                            .await
                        {
                            Ok(new_agent) => {
                                tracing::info!("ChatPanel: created agent: {}", new_agent.name);
                                list.push(new_agent.clone());
                                agents.set(list);
                                agents_loaded.set(true);
                                props
                                    .on_chat_event
                                    .call(crate::auth_flow::AuthEvent::ChatReady);
                                selected_agent.set(Some(new_agent.clone()));
                                if let Some(mut out) = props.selected_agent_out {
                                    out.set(Some(new_agent.id.clone()));
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "ChatPanel: failed to create pentest-connector agent: {}",
                                    e
                                );
                                agents.set(list);
                                agents_loaded.set(true);
                                props
                                    .on_chat_event
                                    .call(crate::auth_flow::AuthEvent::ChatReady);
                            }
                        }
                    }
                }
                Err(e) => {
                    let err_str = e.to_string();
                    let session_tok = crate::session::get_auth_token();
                    tracing::error!(
                        "ChatPanel: failed to fetch agents: {} (token_len={})",
                        err_str,
                        session_tok.len(),
                    );
                    crate::liveview_server::push_terminal_line(TerminalLine::error(format!(
                        "[chat] failed to fetch agents: {}",
                        err_str
                    )));

                    let is_auth_err = err_str.contains("authenticated")
                        || err_str.contains("authorized")
                        || err_str.contains("401")
                        || err_str.contains("403")
                        || err_str.contains("jwt")
                        || err_str.contains("expired");

                    if is_auth_err {
                        // A restored/persisted token whose server session is gone
                        // (backend "session not found" -> "Not authenticated")
                        // never recovers by retrying — the token is simply dead.
                        // After a couple of attempts, clear it and emit ChatAuthDead
                        // so the flow state machine routes back to the sign-in overlay.
                        let n = auth_fail_count() + 1;
                        auth_fail_count.set(n);
                        if n >= 2 {
                            tracing::info!(
                                "ChatPanel: auth error persisted ({n}x); clearing stale token and emitting ChatAuthDead"
                            );
                            crate::session::clear_matrix_token();
                            crate::session::set_auth_token("");
                            pentest_core::matrix::clear_browser_token_cache();
                            props
                                .on_chat_event
                                .call(crate::auth_flow::AuthEvent::ChatAuthDead);
                            return;
                        }
                        tracing::info!("ChatPanel: auth error, will retry in 5s");
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        fetch_started.set(false);
                    } else {
                        error_msg.set(Some(format!("Failed to load agents: {}", err_str)));
                    }
                }
            }
        });
    }

    // -----------------------------------------------------------------------
    // Live conversation subscription (replaces HTTP polling)
    // -----------------------------------------------------------------------
    //
    // A single `use_resource` owns the streaming lifecycle. It is keyed on the
    // active `conversation_id` (+ `retry_tick`): when either changes, Dioxus
    // drops the previous future — which drops the `ConversationSubscription`,
    // whose `AbortOnDrop` tears the WebSocket down — and starts a fresh one for
    // the new conversation. For each conversation it: (a) does one
    // `get_conversation` to seed history + initial thinking state; (b) opens the
    // subscription; (c) folds every event into `messages` via `apply_event` and
    // updates the thinking/status/error/notice signals from the `ApplyOutcome`,
    // mirroring the transport's connection state into `connection_state`; (d)
    // re-runs the seed fetch on a Reconnecting -> Live transition to catch up on
    // anything missed while offline. There is no post-send poll: replies arrive
    // over this subscription.
    {
        let make_client = make_client.clone();
        let api_url = api_url.clone();
        let _subscription = use_resource(move || {
            let make_client = make_client.clone();
            let api_url = api_url.clone();
            // Read the reactive deps synchronously so the resource restarts when
            // the conversation changes, the user hits Retry, or the token lands.
            // token_tick() is bumped whenever the session token is written, so
            // reading it here makes a late/refreshed token restart the
            // subscription instead of churning connects on an empty token.
            let cid_opt = conversation_id();
            let _ = retry_tick();
            let _ = token_tick();
            let token = crate::session::get_auth_token();
            async move {
                // Re-bind Copy signals mutably for use inside the async task.
                let mut messages = messages;
                let mut agent_thinking = agent_thinking;
                let mut agent_status_text = agent_status_text;
                let mut error_msg = error_msg;
                let mut chat_notice = chat_notice;
                let mut connection_state = connection_state;
                let mut pending_validator_apply = pending_validator_apply;

                let Some(cid) = cid_opt else {
                    // No active conversation: nothing to stream. Reset the
                    // connection chip so a stale Reconnecting/Failed doesn't linger.
                    connection_state.set(ConnectionState::Connecting);
                    return;
                };

                // Gate on credentials: without a token or api_url the WS join is
                // rejected and the transport would churn connect attempts to
                // Failed. Wait quietly instead; the resource restarts when the
                // token lands (effective_token -> token_tick dependency above).
                if token.is_empty() || api_url.is_empty() {
                    connection_state.set(ConnectionState::Connecting);
                    return;
                }

                let client = make_client();

                // (a) Seed history + initial status.
                seed_from_conversation(
                    &client,
                    &cid,
                    &mut messages,
                    &mut agent_thinking,
                    &mut agent_status_text,
                    &mut error_msg,
                )
                .await;

                // (b) Open the live subscription. `token_fn` reads the current
                // session token on every (re)connect so reconnects use a fresh
                // token; `insecure_tls` matches the rest of the app's dev flag.
                let token_fn: Arc<dyn Fn() -> String + Send + Sync> =
                    Arc::new(crate::session::get_auth_token);
                let insecure = subscription_insecure_tls();
                let mut sub =
                    subscribe_conversation(api_url.clone(), cid.clone(), insecure, token_fn);

                let mut last_state = *sub.state.borrow();
                connection_state.set(last_state);

                // (c) Stream loop. `select!` over events + connection-state; a
                // top-of-loop guard is a belt-and-suspenders check in case the
                // conversation id changes while the future is being torn down.
                loop {
                    if conversation_id.peek().as_deref() != Some(cid.as_str()) {
                        break;
                    }
                    tokio::select! {
                        maybe_ev = sub.events.recv() => {
                            match maybe_ev {
                                Some(ev) => {
                                    // Re-check the active conversation AFTER the
                                    // await: if the user switched while this event
                                    // was in flight, drop it rather than apply the
                                    // old conversation's event to the new one.
                                    if conversation_id.peek().as_deref() != Some(cid.as_str()) {
                                        break;
                                    }
                                    // Tight write scope: never hold a signal guard
                                    // across an await (AlreadyBorrowed panic).
                                    let outcome = {
                                        let mut m = messages.write();
                                        apply_event(&mut m, &ev)
                                    };
                                    apply_outcome(
                                        outcome,
                                        &client,
                                        &mut agent_thinking,
                                        &mut agent_status_text,
                                        &mut error_msg,
                                        &mut chat_notice,
                                        &mut pending_validator_apply,
                                        &mut messages,
                                        &cid,
                                    )
                                    .await;
                                    // A final assistant Message clears the
                                    // "Thinking…" spinner even if the terminal
                                    // AgentStatusEvent is missed/late — otherwise
                                    // a dropped status would leave it stuck on
                                    // (no poller re-derives it now).
                                    if let ConversationStreamEvent::Message(m) = &ev {
                                        if m.sender_type != "USER" {
                                            agent_thinking.set(false);
                                            agent_status_text.set(String::new());
                                        }
                                    }
                                }
                                None => break, // transport ended for good
                            }
                        }
                        changed = sub.state.changed() => {
                            if changed.is_err() {
                                break;
                            }
                            let new_state = *sub.state.borrow();
                            connection_state.set(new_state);
                            // (d) Catch-up fetch on EVERY transition into Live —
                            // both the first connect and reconnects. The initial
                            // seed (a) runs before subscribe, so a turn that
                            // completes in the connect gap would otherwise be lost
                            // (no polling fallback). Re-seeding on first Live
                            // closes that window; on reconnect it fills the drop.
                            if last_state != ConnectionState::Live
                                && new_state == ConnectionState::Live
                            {
                                seed_from_conversation(
                                    &client,
                                    &cid,
                                    &mut messages,
                                    &mut agent_thinking,
                                    &mut agent_status_text,
                                    &mut error_msg,
                                )
                                .await;
                            }
                            last_state = new_state;
                        }
                    }
                }
                // `sub` drops here -> AbortOnDrop stops the transport.
            }
        });
    }

    // -----------------------------------------------------------------------
    // Handlers
    // -----------------------------------------------------------------------

    // Handler: select agent (takes agent ID string directly)
    let on_agent_select = EventHandler::new({
        let make_client = make_client.clone();
        move |val: String| {
            if val.is_empty() {
                selected_agent.set(None);
                conversation_id.set(None);
                messages.set(Vec::new());
                show_history.set(false);
                return;
            }

            // Save current conversation for the old agent
            if let Some(old_agent) = selected_agent.peek().as_ref() {
                if let Some(cid) = conversation_id.peek().clone() {
                    agent_conversations
                        .write()
                        .insert(old_agent.id.clone(), cid);
                }
            }

            let agent = agents.peek().iter().find(|a| a.id == val).cloned();
            error_msg.set(None);
            chat_notice.set(None);
            show_history.set(false);
            agent_thinking.set(false);
            agent_status_text.set(String::new());

            if let Some(ref ag) = agent {
                let stored_cid = agent_conversations.peek().get(&ag.id).cloned();
                if let Some(cid) = stored_cid {
                    // Clear the previous conversation's messages and switch the
                    // active id. The subscription resource (keyed on
                    // conversation_id) seeds history via get_conversation and
                    // streams live updates from here on.
                    messages.set(Vec::new());
                    pending_validator_apply.set(None);
                    conversation_id.set(Some(cid));
                } else {
                    conversation_id.set(None);
                    messages.set(Vec::new());
                }

                // Fetch conversation list for the new agent in background
                let agent_id = ag.id.clone();
                let client = make_client();
                history_loading.set(true);
                spawn(async move {
                    match client.list_conversations(Some(&agent_id)).await {
                        Ok(mut list) => {
                            // Sort by updated_at in reverse order (newest first)
                            list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
                            conversation_list.set(list);
                        }
                        Err(e) => tracing::warn!("Failed to fetch conversation list: {}", e),
                    }
                    history_loading.set(false);
                });
            } else {
                conversation_id.set(None);
                messages.set(Vec::new());
            }

            selected_agent.set(agent);
        }
    });

    // Handler: send message
    let send_message = {
        let make_client = make_client.clone();
        move |text: String| {
            let text = text.trim().to_string();
            if text.is_empty() || is_sending() {
                return;
            }
            let Some(agent) = selected_agent.peek().clone() else {
                return;
            };

            let client = make_client();
            is_sending.set(true);
            error_msg.set(None);
            chat_notice.set(None);

            spawn(async move {
                let existing_id: Option<String> = conversation_id.peek().clone();
                let conv_id: String = match existing_id {
                    Some(id) => id,
                    None => match client
                        .create_conversation(Some(&format!("Chat with {}", agent.name)))
                        .await
                    {
                        Ok(id) => {
                            conversation_id.set(Some(id.clone()));
                            agent_conversations
                                .write()
                                .insert(agent.id.clone(), id.clone());
                            id
                        }
                        Err(e) => {
                            error_msg.set(Some(format!("Failed to create conversation: {}", e)));
                            is_sending.set(false);
                            return;
                        }
                    },
                };

                let user_msg = ChatMessage {
                    id: format!("local-{}", messages.peek().len()),
                    sender_type: "USER".to_string(),
                    sender_name: "You".to_string(),
                    text: text.clone(),
                    parts: vec![pentest_core::matrix::MessagePart::Text(text.clone())],
                };
                messages.write().push(user_msg);
                user_scrolled_up.set(false);

                // Fire-and-forget: don't await these UI polish evals before
                // the API call. On Windows WebView2 in LiveView mode,
                // document::eval responses can hang indefinitely, which
                // would block send_message from ever executing.
                spawn(async move {
                    let _ = document::eval("resetScrollFlag('.chat-messages')").await;
                    let _ = document::eval("clearTextarea('.chat-input')").await;
                });

                // Send over HTTP; the reply streams back in via the live
                // subscription (no post-send poll).
                match client.send_message(&conv_id, &agent.id, &text).await {
                    Ok(_) => {
                        agent_thinking.set(true);
                        agent_status_text.set("Thinking...".to_string());
                        is_sending.set(false);
                    }
                    Err(e) => {
                        error_msg.set(Some(format!("Failed to send: {}", e)));
                        is_sending.set(false);
                    }
                }
            });
        }
    };

    // Consume messages from the send mailbox.
    // Wrapped in use_effect so it only fires when the mailbox signal changes,
    // avoiding an infinite re-render loop when selected_agent is None or is_sending.
    if let Some(mut mailbox) = props.send_mailbox {
        let send_fn = send_message.clone();
        use_effect(move || {
            let msg = (mailbox)();
            if let Some(text) = msg {
                if selected_agent.read().is_some() && !is_sending() {
                    mailbox.set(None);
                    let mut send_now = send_fn.clone();
                    send_now(text);
                }
            }
        });
    }

    // Consume conversation ID from the open_conversation_id mailbox (sidebar recent conversations).
    if let Some(mut conv_mailbox) = props.open_conversation_id {
        use_effect(move || {
            let cid_opt = (conv_mailbox)();
            if let Some(cid) = cid_opt {
                conv_mailbox.set(None);
                agent_thinking.set(false);
                agent_status_text.set(String::new());
                show_history.set(false);
                // Switch the active id; the subscription resource seeds history
                // and streams. Clear stale messages first so the previous
                // conversation doesn't flash while the seed fetch runs.
                messages.set(Vec::new());
                pending_validator_apply.set(None);
                conversation_id.set(Some(cid));
            }
        });
    }

    // -----------------------------------------------------------------------
    // History handlers (closures passed down as EventHandlers)
    // -----------------------------------------------------------------------

    let on_new_chat = EventHandler::new({
        let make_client = make_client.clone();
        move |_: ()| {
            if let Some(agent) = selected_agent.peek().as_ref() {
                if let Some(cid) = conversation_id.peek().clone() {
                    agent_conversations.write().insert(agent.id.clone(), cid);
                }
            }
            conversation_id.set(None);
            messages.set(Vec::new());
            if let Some(agent) = selected_agent.peek().as_ref() {
                agent_conversations.write().remove(&agent.id);
            }
            show_history.set(false);
            error_msg.set(None);
            agent_thinking.set(false);
            agent_status_text.set(String::new());
            chat_notice.set(None);

            // Focus the chat input so user can start typing immediately
            spawn(async move {
                for _ in 0..3 {
                    let _ = document::eval(
                        "let el = document.querySelector('.chat-textarea'); if(el) el.focus();",
                    )
                    .await;
                    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
                }
            });

            if let Some(agent) = selected_agent.peek().as_ref() {
                let agent_id = agent.id.clone();
                let client = make_client();
                history_loading.set(true);
                spawn(async move {
                    match client.list_conversations(Some(&agent_id)).await {
                        Ok(mut list) => {
                            // Sort by updated_at in reverse order (newest first)
                            list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
                            conversation_list.set(list);
                        }
                        Err(e) => tracing::warn!("Failed to refresh conversation list: {}", e),
                    }
                    history_loading.set(false);
                });
            }
        }
    });

    let on_toggle_history = EventHandler::new({
        let make_client = make_client.clone();
        move |_: ()| {
            let opening = !show_history();
            show_history.set(opening);
            if opening {
                if let Some(agent) = selected_agent.peek().as_ref() {
                    let agent_id = agent.id.clone();
                    let client = make_client();
                    history_loading.set(true);
                    spawn(async move {
                        match client.list_conversations(Some(&agent_id)).await {
                            Ok(mut list) => {
                                // Sort by updated_at in reverse order (newest first)
                                list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
                                conversation_list.set(list);
                            }
                            Err(e) => tracing::warn!("Failed to fetch conversation list: {}", e),
                        }
                        history_loading.set(false);
                    });
                }
            }
        }
    });

    // Handler: refresh the conversation list WITHOUT opening the history
    // dropdown. Used by the Easy Mode drawer, which renders its own "Recent
    // chats" from the ctx snapshot — it needs the list fetched but must not
    // toggle ChatPanel's `show_history` UI (that would stack a second list on
    // top of the drawer).
    let on_refresh_conversations = EventHandler::new({
        let make_client = make_client.clone();
        move |_: ()| {
            if let Some(agent) = selected_agent.peek().as_ref() {
                let agent_id = agent.id.clone();
                let client = make_client();
                history_loading.set(true);
                spawn(async move {
                    match client.list_conversations(Some(&agent_id)).await {
                        Ok(mut list) => {
                            list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
                            conversation_list.set(list);
                        }
                        Err(e) => tracing::warn!("Failed to refresh conversation list: {}", e),
                    }
                    history_loading.set(false);
                });
            }
        }
    });

    // Handler: validate findings.
    //
    // The Validator round-trip that sits between evidence collection and
    // report generation (pick#174 seams 2 & 3). Without it every node stays
    // `Pending` and `gate_for_report` refuses, so this must run before
    // Generate Report on any real engagement.
    //
    // 1. Snapshot the graph and build the `pending_evidence_manifest`. If there
    //    are no pending nodes, tell the operator and bail — nothing to do.
    // 2. Resolve the Validator sibling (`{connector_name}-validator`) and switch
    //    to it in a fresh conversation, seeding the pending manifest.
    // 3. Poll until it finishes, then parse the verdicts out of its reply and
    //    apply them to the graph. Surface how many were applied / left pending
    //    so the operator knows whether Generate Report will succeed.
    let on_validate_findings = EventHandler::new({
        let make_client = make_client.clone();
        move |_: ()| {
            let snapshot = crate::session::evidence_snapshot();
            let engagement = pentest_core::orchestrator::EngagementInfo::new(
                crate::session::get_connector_name(),
                chrono::Utc::now(),
            );
            let manifest =
                pentest_core::orchestrator::build_pending_evidence_manifest(&snapshot, engagement);
            if manifest.nodes.is_empty() {
                error_msg.set(Some(
                    "No pending findings to validate. Run tools to collect evidence first, \
                     or the Validator has already adjudicated everything."
                        .to_string(),
                ));
                return;
            }
            let pending_count = manifest.nodes.len();

            // Resolve the Validator sibling. Same deterministic-name lookup as
            // the Report handoff below.
            let connector_name = crate::session::get_connector_name();
            let validator_name = format!("{}{}", connector_name, VALIDATOR_AGENT_SUFFIX);
            let validator_agent = agents
                .peek()
                .iter()
                .find(|a| a.name == validator_name)
                .cloned();
            let Some(validator_agent) = validator_agent else {
                error_msg.set(Some(format!(
                    "Validator Agent '{validator_name}' is not registered. Reload the page \
                     so the chat panel can create it."
                )));
                return;
            };

            // Save current conversation under the previously selected agent
            // before switching the panel to the Validator.
            if let Some(old_agent) = selected_agent.peek().as_ref() {
                if let Some(cid) = conversation_id.peek().clone() {
                    agent_conversations
                        .write()
                        .insert(old_agent.id.clone(), cid);
                }
            }

            selected_agent.set(Some(validator_agent.clone()));
            if let Some(mut out) = props.selected_agent_out {
                out.set(Some(validator_agent.id.clone()));
            }
            conversation_id.set(None);
            messages.set(Vec::new());
            show_history.set(false);
            error_msg.set(None);
            chat_notice.set(None);
            agent_thinking.set(false);
            agent_status_text.set(String::new());

            let seed = match pentest_core::orchestrator::build_validator_seed_message(&manifest) {
                Ok(s) => s,
                Err(e) => {
                    error_msg.set(Some(format!(
                        "Cannot validate findings: {e}. This indicates a bug in evidence \
                         serialization. Please report this error."
                    )));
                    return;
                }
            };
            let client = make_client();
            is_sending.set(true);
            // Arm the terminal-status handler to parse + apply the Validator's
            // verdicts once its turn finishes over the subscription (this used
            // to run right after the poll loop returned).
            pending_validator_apply.set(Some(pending_count));

            spawn(async move {
                let conv_title = format!("Validation for {}", manifest.engagement.target);
                let conv_id = match client.create_conversation(Some(&conv_title)).await {
                    Ok(id) => {
                        agent_conversations
                            .write()
                            .insert(validator_agent.id.clone(), id.clone());
                        conversation_id.set(Some(id.clone()));
                        id
                    }
                    Err(e) => {
                        error_msg.set(Some(format!(
                            "Failed to create validation conversation with Validator Agent '{}': {}. \
                             Check that Strike48 backend is accessible.",
                            validator_agent.name, e
                        )));
                        is_sending.set(false);
                        pending_validator_apply.set(None);
                        return;
                    }
                };

                let user_msg = ChatMessage {
                    id: format!("local-{}", messages.peek().len()),
                    sender_type: "USER".to_string(),
                    sender_name: "Orchestrator".to_string(),
                    text: seed.clone(),
                    parts: vec![pentest_core::matrix::MessagePart::Text(seed.clone())],
                };
                messages.write().push(user_msg);
                user_scrolled_up.set(false);

                // Send over HTTP; the Validator's reply streams back via the
                // subscription. When the turn reaches a terminal status,
                // apply_outcome parses the verdicts (see pending_validator_apply).
                match client
                    .send_message(&conv_id, &validator_agent.id, &seed)
                    .await
                {
                    Ok(_) => {
                        agent_thinking.set(true);
                        agent_status_text.set("Validating findings...".to_string());
                        is_sending.set(false);
                    }
                    Err(e) => {
                        error_msg.set(Some(format!("Failed to send validation seed: {e}")));
                        is_sending.set(false);
                        pending_validator_apply.set(None);
                    }
                }
            });
        }
    });

    // Handler: generate final report.
    //
    // 1. Snapshot the evidence graph and ask the orchestrator gate to build
    //    a `validated_findings_manifest`. If any node is still Pending the
    //    gate refuses — we surface the blocker as an error banner and bail.
    // 2. Resolve the Report Agent sibling (`{connector_name}-report`) from
    //    the agent list. If we can't find it, the auto-registration step in
    //    the fetch-agents block didn't complete; tell the user so they can
    //    reload.
    // 3. Switch the selected agent to the Report sibling, create a fresh
    //    conversation, and send the seed message the Report Agent expects.
    //
    // This is the single point at which the three-agent pipeline hands off
    // to report rendering — no other path should write to the Report Agent.
    let on_generate_report = EventHandler::new({
        let make_client = make_client.clone();
        move |_: ()| {
            // Gate the evidence graph before doing anything UI-visible.
            let snapshot = crate::session::evidence_snapshot();
            let engagement = pentest_core::orchestrator::EngagementInfo::new(
                crate::session::get_connector_name(),
                chrono::Utc::now(),
            );
            let manifest = match pentest_core::orchestrator::gate_for_report(&snapshot, engagement)
            {
                Ok(m) => m,
                Err(pentest_core::orchestrator::GateError::PendingNodes { pending_ids }) => {
                    // The most common gate failure: report requested before the
                    // findings were validated. Show an ACTIONABLE message that
                    // points at the Validate Findings (shield) button, rather
                    // than dumping the raw evidence-node UUIDs at the operator.
                    let n = pending_ids.len();
                    error_msg.set(Some(format!(
                        "{n} finding{} need{} validation first. Click the shield \
                         (\"Validate Findings\") button, then Generate Report.",
                        if n == 1 { "" } else { "s" },
                        if n == 1 { "s" } else { "" },
                    )));
                    return;
                }
                Err(e) => {
                    error_msg.set(Some(format!("Cannot generate report: {e}")));
                    return;
                }
            };

            // Resolve the Report Agent sibling. Its name is deterministic
            // (see REPORT_AGENT_SUFFIX), so we look it up rather than trust
            // whatever happens to be selected.
            let connector_name = crate::session::get_connector_name();
            let report_name = format!("{}{}", connector_name, REPORT_AGENT_SUFFIX);
            let report_agent = agents
                .peek()
                .iter()
                .find(|a| a.name == report_name)
                .cloned();
            let Some(report_agent) = report_agent else {
                error_msg.set(Some(format!(
                    "Report Agent '{report_name}' is not registered. Reload the page \
                     so the chat panel can create it."
                )));
                return;
            };

            // Save current conversation under the previously selected agent
            // before we hijack the panel with the Report Agent.
            if let Some(old_agent) = selected_agent.peek().as_ref() {
                if let Some(cid) = conversation_id.peek().clone() {
                    agent_conversations
                        .write()
                        .insert(old_agent.id.clone(), cid);
                }
            }

            selected_agent.set(Some(report_agent.clone()));
            if let Some(mut out) = props.selected_agent_out {
                out.set(Some(report_agent.id.clone()));
            }
            conversation_id.set(None);
            messages.set(Vec::new());
            show_history.set(false);
            error_msg.set(None);
            chat_notice.set(None);
            agent_thinking.set(false);
            agent_status_text.set(String::new());

            let seed = pentest_core::orchestrator::build_report_agent_seed_message(&manifest);
            let client = make_client();
            is_sending.set(true);

            spawn(async move {
                let conv_title = format!("Report for {}", manifest.engagement.target);
                let conv_id = match client.create_conversation(Some(&conv_title)).await {
                    Ok(id) => {
                        conversation_id.set(Some(id.clone()));
                        agent_conversations
                            .write()
                            .insert(report_agent.id.clone(), id.clone());
                        id
                    }
                    Err(e) => {
                        error_msg.set(Some(format!("Failed to create report conversation: {e}")));
                        is_sending.set(false);
                        return;
                    }
                };

                let user_msg = ChatMessage {
                    id: format!("local-{}", messages.peek().len()),
                    sender_type: "USER".to_string(),
                    sender_name: "Orchestrator".to_string(),
                    text: seed.clone(),
                    parts: vec![pentest_core::matrix::MessagePart::Text(seed.clone())],
                };
                messages.write().push(user_msg);
                user_scrolled_up.set(false);

                // Send over HTTP; the Report Agent's reply streams back via the
                // subscription (no post-send poll).
                match client.send_message(&conv_id, &report_agent.id, &seed).await {
                    Ok(_) => {
                        agent_thinking.set(true);
                        agent_status_text.set("Rendering report...".to_string());
                        is_sending.set(false);
                    }
                    Err(e) => {
                        error_msg.set(Some(format!("Failed to send report seed: {e}")));
                        is_sending.set(false);
                    }
                }
            });
        }
    });

    let on_select_conversation = EventHandler::new({
        move |cid: String| {
            if let Some(agent) = selected_agent.peek().as_ref() {
                agent_conversations
                    .write()
                    .insert(agent.id.clone(), cid.clone());
            }
            show_history.set(false);
            agent_thinking.set(false);
            agent_status_text.set(String::new());
            // Switch the active id; the subscription resource seeds history and
            // streams. Clear stale messages so the previous conversation doesn't
            // flash while the seed fetch runs.
            messages.set(Vec::new());
            pending_validator_apply.set(None);
            conversation_id.set(Some(cid));
        }
    });

    // -----------------------------------------------------------------------
    // Publish header actions to AppLayout (full-page mode)
    // -----------------------------------------------------------------------
    //
    // We use `use_effect` to avoid writing to the context signal during render,
    // which would trigger parent→child re-render cascades (infinite loop).
    // The effect runs AFTER render and only re-runs when its tracked signal
    // dependencies (agents, selected_agent, agents_loaded, show_history) change.
    // Retry handler for the desktop header bar's chip: bump retry_tick so the
    // subscription resource respawns.
    // This handler is published into the parent AppLayout's ChatHeaderCtx and can
    // outlive the ChatPanel (e.g. the workspace is replaced by the session-expired
    // overlay, unmounting the panel). Writing the dropped `retry_tick` signal via
    // `+=` would panic with ValueDroppedError, so write fallibly and no-op if the
    // signal is already gone.
    let on_retry = EventHandler::new(move |_: ()| {
        if let Ok(mut t) = retry_tick.try_write() {
            *t += 1;
        }
    });
    {
        let is_full = props.full_page;
        let api_url_empty = api_url.is_empty();
        let token_empty = effective_token.is_empty();
        use_effect(move || {
            if !is_full {
                return;
            }
            let new_ctx = ChatHeaderCtx {
                agents: agents.read().clone(),
                selected_agent: selected_agent.read().clone(),
                agents_loaded: agents_loaded(),
                show_history: show_history(),
                api_url_empty,
                token_empty,
                conversations: conversation_list.read().clone(),
                on_agent_select,
                on_new_chat,
                on_toggle_history,
                on_refresh_conversations,
                on_select_conversation,
                on_validate_findings,
                on_generate_report,
                connection_state: connection_state(),
                on_retry,
            };
            // Only write if the data actually changed (avoids unnecessary parent re-renders).
            let needs_update = {
                let current = chat_header_ctx.peek();
                match &*current {
                    Some(existing) => existing != &new_ctx,
                    None => true,
                }
            };
            if needs_update {
                chat_header_ctx.set(Some(new_ctx));
            }
        });
    }

    // When this ChatPanel unmounts (e.g. the workspace is replaced by the
    // session-expired overlay, or the user navigates off the Chat page), clear
    // the published header context. The ChatHeaderCtx we set above holds
    // EventHandlers bound to THIS component's scope; if the parent AppLayout's
    // desktop header bar fires one after we're gone, dioxus-core panics with
    // ValueDroppedError (the handler's generational box was dropped with our
    // scope). Dropping the ctx to None removes those stale handlers so the
    // header bar simply renders nothing to fire.
    {
        let mut chat_header_ctx = chat_header_ctx;
        use_drop(move || {
            if chat_header_ctx
                .try_peek()
                .map(|c| c.is_some())
                .unwrap_or(false)
            {
                let _ = chat_header_ctx.try_write().map(|mut c| *c = None);
            }
        });
    }

    // -----------------------------------------------------------------------
    // Resize handlers
    // -----------------------------------------------------------------------

    let mut drag_start_x = use_signal(|| 0i32);
    let mut drag_start_width = use_signal(|| CHAT_DEFAULT_WIDTH);

    let handle_mousemove = move |evt: MouseEvent| {
        if is_resizing() {
            let mouse_x = evt.client_coordinates().x as i32;
            let delta = drag_start_x() - mouse_x;
            let new_width = (drag_start_width() + delta).clamp(CHAT_MIN_WIDTH, CHAT_MAX_WIDTH);
            panel_width.set(new_width);
        }
    };

    let handle_mouseup = move |_evt: MouseEvent| {
        if is_resizing() {
            is_resizing.set(false);
        }
    };

    // -----------------------------------------------------------------------
    // Early return when hidden
    // -----------------------------------------------------------------------

    if !props.full_page && !props.visible && !closing() {
        return rsx! {};
    }

    // Trigger animated close (only used in overlay mode)
    let mut trigger_close = {
        let on_close = props.on_close;
        move || {
            if closing() {
                return;
            }
            closing.set(true);
            spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                on_close.call(());
            });
        }
    };

    let is_full = props.full_page;
    let user_select = if is_resizing() { "none" } else { "auto" };
    let panel_style = if is_full {
        "user-select: auto;".to_string()
    } else {
        format!("width: {}px; user-select: {};", panel_width(), user_select)
    };
    let backdrop_class = if closing() {
        "chat-backdrop closing"
    } else {
        "chat-backdrop"
    };
    let panel_class = if is_full {
        "chat-page"
    } else if closing() {
        "chat-panel closing"
    } else {
        "chat-panel"
    };

    // -----------------------------------------------------------------------
    // Render
    // -----------------------------------------------------------------------

    rsx! {
        style { {include_str!("css/style.css")} }
        style { {include_str!("../../styles/prose.css")} }

        // Backdrop (overlay mode only)
        if !is_full {
            div {
                class: "{backdrop_class}",
                onclick: move |_| trigger_close(),
            }
        }

        // Resize overlay (overlay mode only)
        if !is_full && is_resizing() {
            div {
                style: "position: fixed; top: 0; left: 0; right: 0; bottom: 0; z-index: 9999; cursor: col-resize; user-select: none;",
                onmousemove: handle_mousemove,
                onmouseup: handle_mouseup,
            }
        }

        div {
            class: "{panel_class}",
            style: "{panel_style}",
            onkeydown: move |evt: Event<KeyboardData>| {
                evt.stop_propagation();
            },

            // Resize handle (overlay mode only)
            if !is_full {
                div {
                    class: "chat-resize-handle",
                    onmousedown: move |evt: MouseEvent| {
                        drag_start_x.set(evt.client_coordinates().x as i32);
                        drag_start_width.set(panel_width());
                        is_resizing.set(true);
                        evt.stop_propagation();
                    },
                }
            }

            // Header (overlay mode only — full-page mode publishes actions
            // to AppLayout's desktop header bar via ChatHeaderCtx context)
            if !is_full {
                ChatHeader {
                    agents: agents,
                    selected_agent: selected_agent,
                    agents_loaded: agents_loaded,
                    api_url_empty: api_url.is_empty(),
                    token_empty: effective_token.is_empty(),
                    on_agent_select: on_agent_select,
                    on_new_chat: on_new_chat,
                    on_toggle_history: on_toggle_history,
                    on_validate_findings: on_validate_findings,
                    on_generate_report: on_generate_report,
                    show_history: show_history,
                    is_full: is_full,
                    on_close: move |_| trigger_close(),
                    connection_state: connection_state,
                    on_retry: move |_| { if let Ok(mut t) = retry_tick.try_write() { *t += 1; } },
                }
            }

            // History dropdown (shown when toggled) with click-outside backdrop
            if selected_agent.read().is_some() && agents_loaded() && show_history() {
                div {
                    class: "dropdown-backdrop",
                    onclick: move |_| show_history.set(false),
                }
                HistoryDropdown {
                    conversation_list: conversation_list,
                    history_loading: history_loading,
                    conversation_id: conversation_id,
                    on_select_conversation: on_select_conversation,
                }
            }

            // Error banner — loud red strip for caller-side failures (send/load).
            if let Some(err) = error_msg.read().as_ref() {
                div { class: "chat-error", "{err}" }
            }

            // Messages area
            MessageList {
                messages: messages,
                expanded_tools: expanded_tools,
                user_scrolled_up: user_scrolled_up,
                agent_thinking: agent_thinking,
                agent_status_text: agent_status_text,
                selected_agent: selected_agent,
                on_send: send_message.clone(),
                conversation_list: conversation_list,
                on_select_conversation: on_select_conversation,
                easy_mode: props.easy_mode,
                awaiting_auth: awaiting_auth,
                needs_sign_in: needs_sign_in,
                on_sign_in: {
                    let start = start_browser_auth.clone();
                    move |_| start()
                },
            }

            // Inline notice — quieter than `chat-error`, sits above the input.
            // Surfaced by polling when the agent backend returned an error
            // (token limit, rate limit, generic upstream failure).
            if let Some(notice) = chat_notice.read().as_ref() {
                {
                    let kind_class = match notice.kind {
                        ChatNoticeKind::TokenLimit => "chat-notice chat-notice--limit",
                        ChatNoticeKind::UpstreamError => "chat-notice chat-notice--error",
                    };
                    let icon = match notice.kind {
                        ChatNoticeKind::TokenLimit => "⏱",
                        ChatNoticeKind::UpstreamError => "⚠",
                    };
                    let title = notice.title.clone();
                    let detail = notice.detail.clone();
                    let studio_url = notice.studio_url.clone();
                    rsx! {
                        div { class: "{kind_class}",
                            span { class: "chat-notice__icon", "{icon}" }
                            div { class: "chat-notice__body",
                                div { class: "chat-notice__title", "{title}" }
                                div { class: "chat-notice__detail", "{detail}" }
                                if let Some(url) = studio_url {
                                    // Use the existing Link-variant Button rather than a raw
                                    // <button> with custom CSS — it already has properly-tested
                                    // hover/focus/active states that won't bleed WebKit's
                                    // native button chrome (the "blob on hover" bug). A real
                                    // <button> element is required (vs. <a href>) so that the
                                    // browser can't follow a link in the connector iframe
                                    // while open::that() is also opening the system browser.
                                    Button {
                                        variant: ButtonVariant::Link,
                                        size: ButtonSize::Small,
                                        on_click: move |_| {
                                            if let Err(e) = pentest_core::matrix::open_url_in_browser(&url) {
                                                tracing::warn!("Failed to open Studio URL: {}", e);
                                            }
                                        },
                                        "Open Studio →"
                                    }
                                }
                            }
                            button {
                                class: "chat-notice__close",
                                aria_label: "Dismiss",
                                onclick: move |_| chat_notice.set(None),
                                "×"
                            }
                        }
                    }
                }
            }

            // Input area
            if selected_agent.read().is_some() {
                ChatInput {
                    on_send: send_message.clone(),
                    is_sending: is_sending,
                    agent_thinking: agent_thinking,
                }
            }
        }
    }
}
