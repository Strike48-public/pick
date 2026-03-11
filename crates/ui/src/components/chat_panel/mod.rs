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
mod polling;
mod render;

use dioxus::prelude::*;
use pentest_core::matrix::{
    AgentInfo, ChatClient, ChatMessage, ConversationInfo, MatrixChatClient, UpdateAgentInput,
};
use std::collections::HashMap;
use std::sync::Arc;

use agent_selector::ChatHeader;
pub use agent_selector::{ChatHeaderActions, ChatHeaderCtx};
use constants::*;
use history::HistoryDropdown;
use input::ChatInput;
use messages::MessageList;
use polling::poll_and_update;
pub use render::format_relative_time;
use render::{CHART_PROCESSOR_JS, UTILS_JS};

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
    #[props(default)]
    pub full_page: bool,
    /// Mailbox to open a specific conversation by ID (set by sidebar recent conversations).
    #[props(default)]
    pub open_conversation_id: Option<Signal<Option<String>>>,
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
    let mut is_sending = use_signal(|| false);
    let mut agent_thinking = use_signal(|| false);
    let mut agent_status_text = use_signal(String::new);
    let mut error_msg = use_signal(|| None::<String>);

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

    // Reset closing when panel becomes visible again
    if props.visible && closing() {
        closing.set(false);
    }

    let api_url = props.api_url.clone();
    let auth_token = props.auth_token.clone();

    // -----------------------------------------------------------------------
    // Auth token resolution — prefer session store (set by connector), then prop
    // -----------------------------------------------------------------------

    let effective_token = {
        let session_token = crate::session::get_auth_token();
        if !session_token.is_empty() {
            session_token
        } else {
            auth_token.clone()
        }
    };

    // Build client helper — reads session store at call time for freshest token
    let make_client = {
        let api_url = api_url.clone();
        let effective_token = effective_token.clone();
        move || -> Arc<MatrixChatClient> {
            let session_token = crate::session::get_auth_token();
            let token = if !session_token.is_empty() {
                session_token
            } else {
                effective_token.clone()
            };
            let mut c = MatrixChatClient::new(api_url.clone());
            if !token.is_empty() {
                c.set_auth_token(token);
            }
            Arc::new(c)
        }
    };

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

    // Debug: log credential state on each render when panel is visible
    if props.visible && !agents_loaded() {
        tracing::info!(
            "[ChatPanel] render: api_url={:?} auth_token_len={} session_token_len={} agents_loaded={} fetch_started={}",
            if api_url.is_empty() { "(empty)" } else { &api_url },
            effective_token.len(),
            crate::session::get_auth_token().len(),
            agents_loaded(),
            fetch_started(),
        );
    }

    // -----------------------------------------------------------------------
    // Fetch agents when we have a token
    // -----------------------------------------------------------------------

    if !effective_token.is_empty() && !agents_loaded() && !fetch_started() {
        fetch_started.set(true);
        tracing::info!("ChatPanel: fetch_started set to true (will not retry)");
        let client = make_client();
        let tenant_id = props.tenant_id.clone();
        tracing::info!("ChatPanel: fetching agents from {}", api_url);
        spawn(async move {
            match client.list_agents().await {
                Ok(mut list) => {
                    tracing::info!("ChatPanel: loaded {} agents", list.len());
                    let auto = list
                        .iter()
                        .find(|a| a.name.to_lowercase().contains(PENTEST_AGENT_NAME))
                        .cloned();

                    if let Some(agent) = auto {
                        tracing::info!(
                            "ChatPanel: auto-selected agent: {}, updating tool configs",
                            agent.name
                        );
                        // Update the existing agent's tool configs with current tools
                        let fresh_input = default_pentest_agent_input(&tenant_id);
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
                                selected_agent.set(Some(updated));
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "ChatPanel: failed to update agent tools: {}, using existing",
                                    e
                                );
                                agents.set(list);
                                agents_loaded.set(true);
                                selected_agent.set(Some(agent));
                            }
                        }
                    } else {
                        tracing::info!("ChatPanel: no pentest-connector agent found, creating one");
                        match client
                            .create_agent(default_pentest_agent_input(&tenant_id))
                            .await
                        {
                            Ok(new_agent) => {
                                tracing::info!("ChatPanel: created agent: {}", new_agent.name);
                                list.push(new_agent.clone());
                                agents.set(list);
                                agents_loaded.set(true);
                                selected_agent.set(Some(new_agent));
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "ChatPanel: failed to create pentest-connector agent: {}",
                                    e
                                );
                                agents.set(list);
                                agents_loaded.set(true);
                            }
                        }
                    }
                }
                Err(e) => {
                    let err_str = e.to_string();
                    // Log the token prefix for debugging (first 20 chars)
                    let session_tok = crate::session::get_auth_token();
                    let tok_preview = if session_tok.len() > 20 {
                        format!("{}...", &session_tok[..20])
                    } else {
                        session_tok.clone()
                    };
                    tracing::error!(
                        "ChatPanel: failed to fetch agents: {} (token_len={} preview={:?})",
                        err_str,
                        session_tok.len(),
                        tok_preview,
                    );

                    let is_auth_err = err_str.contains("authenticated")
                        || err_str.contains("authorized")
                        || err_str.contains("401")
                        || err_str.contains("403")
                        || err_str.contains("jwt")
                        || err_str.contains("expired");

                    if is_auth_err {
                        // Auth error — wait before retrying to avoid tight loop
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
            show_history.set(false);
            agent_thinking.set(false);
            agent_status_text.set(String::new());

            if let Some(ref ag) = agent {
                let stored_cid = agent_conversations.peek().get(&ag.id).cloned();
                if let Some(cid) = stored_cid {
                    conversation_id.set(Some(cid.clone()));
                    let client = make_client();
                    spawn(async move {
                        match client.get_conversation(&cid).await {
                            Ok(state) => {
                                let active = !state.agent_status.is_terminal();
                                messages.set(state.messages);
                                if active {
                                    agent_thinking.set(true);
                                    agent_status_text.set("Thinking...".to_string());
                                    poll_and_update(
                                        client,
                                        cid,
                                        conversation_id,
                                        messages,
                                        agent_thinking,
                                        agent_status_text,
                                        error_msg,
                                    )
                                    .await;
                                }
                            }
                            Err(e) => {
                                tracing::warn!("Failed to restore conversation: {}", e);
                                conversation_id.set(None);
                                messages.set(Vec::new());
                            }
                        }
                    });
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
                if let Err(e) = document::eval("resetScrollFlag('.chat-messages')").await {
                    tracing::warn!("JS eval failed (reset scroll flag): {e}");
                }

                if let Err(e) = document::eval("clearTextarea('.chat-input')").await {
                    tracing::warn!("JS eval failed (clear input): {e}");
                }

                match client.send_message(&conv_id, &agent.id, &text).await {
                    Ok(_) => {
                        agent_thinking.set(true);
                        agent_status_text.set("Thinking...".to_string());
                        is_sending.set(false);
                        poll_and_update(
                            client,
                            conv_id,
                            conversation_id,
                            messages,
                            agent_thinking,
                            agent_status_text,
                            error_msg,
                        )
                        .await;
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
        let make_client = make_client.clone();
        use_effect(move || {
            let cid_opt = (conv_mailbox)();
            if let Some(cid) = cid_opt {
                conv_mailbox.set(None);
                conversation_id.set(Some(cid.clone()));
                agent_thinking.set(false);
                agent_status_text.set(String::new());
                show_history.set(false);
                let client = make_client();
                spawn(async move {
                    match client.get_conversation(&cid).await {
                        Ok(state) => {
                            messages.set(state.messages);
                            let active = !state.agent_status.is_terminal();
                            if active {
                                agent_thinking.set(true);
                                agent_status_text.set("Thinking...".to_string());
                                poll_and_update(
                                    client,
                                    cid,
                                    conversation_id,
                                    messages,
                                    agent_thinking,
                                    agent_status_text,
                                    error_msg,
                                )
                                .await;
                            }
                        }
                        Err(e) => {
                            error_msg.set(Some(format!("Failed to load conversation: {}", e)));
                        }
                    }
                });
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

    let on_select_conversation = EventHandler::new({
        let make_client = make_client.clone();
        move |cid: String| {
            conversation_id.set(Some(cid.clone()));
            if let Some(agent) = selected_agent.peek().as_ref() {
                agent_conversations
                    .write()
                    .insert(agent.id.clone(), cid.clone());
            }
            show_history.set(false);
            agent_thinking.set(false);
            agent_status_text.set(String::new());
            let client = make_client();
            spawn(async move {
                match client.get_conversation(&cid).await {
                    Ok(state) => {
                        messages.set(state.messages);
                        let active = !state.agent_status.is_terminal();
                        if active {
                            agent_thinking.set(true);
                            agent_status_text.set("Thinking...".to_string());
                            poll_and_update(
                                client,
                                cid,
                                conversation_id,
                                messages,
                                agent_thinking,
                                agent_status_text,
                                error_msg,
                            )
                            .await;
                        }
                    }
                    Err(e) => {
                        error_msg.set(Some(format!("Failed to load conversation: {}", e)));
                    }
                }
            });
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
                on_agent_select,
                on_new_chat,
                on_toggle_history,
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
                    show_history: show_history,
                    is_full: is_full,
                    on_close: move |_| trigger_close(),
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

            // Error banner
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
