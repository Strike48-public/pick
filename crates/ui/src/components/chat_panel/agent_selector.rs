//! Chat header and suggested-actions grid.
//!
//! `ChatHeader` replaces the old `AgentSelector` + standalone header div.
//! It renders the title on the left with history toggle, segmented new-chat
//! button, and optional close button on the right.

use dioxus::prelude::*;
use pentest_core::matrix::{AgentInfo, ConversationInfo};

use super::constants::SUGGESTED_ACTIONS;
use super::render::format_relative_time;
use crate::components::icons::{ChevronDown, History, Plus};

/// Props for [`ChatHeader`].
#[derive(Props, Clone, PartialEq)]
pub struct ChatHeaderProps {
    /// Full list of available agents.
    pub agents: Signal<Vec<AgentInfo>>,
    /// Currently selected agent (None = nothing selected).
    pub selected_agent: Signal<Option<AgentInfo>>,
    /// Whether the agent list has finished loading.
    pub agents_loaded: Signal<bool>,
    /// True while the API URL is still empty (waiting for credentials).
    pub api_url_empty: bool,
    /// True while the effective auth token is still empty.
    pub token_empty: bool,
    /// Called with the agent **id** when the user picks one from the dropdown.
    pub on_agent_select: EventHandler<String>,
    /// Called when the user clicks the plus button to start a new chat.
    pub on_new_chat: EventHandler<()>,
    /// Called when the user clicks the history icon to toggle the history dropdown.
    pub on_toggle_history: EventHandler<()>,
    /// Whether the history dropdown is currently visible.
    pub show_history: Signal<bool>,
    /// True when rendered as a full-page view (hides close button).
    pub is_full: bool,
    /// Called when the close button is clicked (overlay mode only).
    pub on_close: EventHandler<()>,
}

/// Chat panel header with title, history toggle, and segmented new-chat button.
#[component]
pub fn ChatHeader(props: ChatHeaderProps) -> Element {
    let mut agent_menu_open = use_signal(|| false);
    let agents = props.agents;
    let selected_agent = props.selected_agent;

    let selected_id = selected_agent
        .read()
        .as_ref()
        .map(|a| a.id.clone())
        .unwrap_or_default();

    let ready = !props.api_url_empty && !props.token_empty && (props.agents_loaded)();

    rsx! {
        // Click-outside backdrop for agent menu
        if agent_menu_open() {
            div {
                class: "dropdown-backdrop",
                onclick: move |_| agent_menu_open.set(false),
            }
        }

        div { class: "chat-panel-header",
            h3 { "Chat" }

            div { class: "chat-header-actions",
                if !ready {
                    span { class: "chat-loading-sm",
                        if props.api_url_empty {
                            "Waiting..."
                        } else if props.token_empty {
                            "Auth..."
                        } else {
                            "Loading..."
                        }
                    }
                } else {
                    // History toggle
                    button {
                        class: if (props.show_history)() { "chat-header-btn active" } else { "chat-header-btn" },
                        title: "History",
                        onclick: {
                            let h = props.on_toggle_history;
                            move |_| h.call(())
                        },
                        History { size: 16 }
                    }

                    // Segmented new-chat button
                    div { class: "chat-new-segmented",
                        button {
                            class: "chat-new-plus",
                            title: "New chat",
                            onclick: {
                                let nc = props.on_new_chat;
                                move |_| nc.call(())
                            },
                            Plus { size: 14 }
                        }
                        button {
                            class: if agent_menu_open() { "chat-new-dropdown-toggle active" } else { "chat-new-dropdown-toggle" },
                            title: "Pick agent",
                            onclick: move |_| agent_menu_open.set(!agent_menu_open()),
                            ChevronDown { size: 12 }
                        }

                        if agent_menu_open() {
                            div { class: "chat-new-agent-menu",
                                for agent in agents.read().iter() {
                                    {
                                        let aid = agent.id.clone();
                                        let is_active = aid == selected_id;
                                        let name = agent.name.clone();
                                        let desc = agent.description.clone().unwrap_or_default();
                                        let on_select = props.on_agent_select;
                                        rsx! {
                                            div {
                                                key: "{aid}",
                                                class: if is_active { "agent-dropdown-item active" } else { "agent-dropdown-item" },
                                                onclick: move |_| {
                                                    on_select.call(aid.clone());
                                                    agent_menu_open.set(false);
                                                },
                                                div { class: "agent-dropdown-item-name", "{name}" }
                                                if !desc.is_empty() {
                                                    div { class: "agent-dropdown-item-desc", "{desc}" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                // Close button (overlay mode only)
                if !props.is_full {
                    button {
                        class: "chat-panel-close",
                        onclick: {
                            let c = props.on_close;
                            move |_| c.call(())
                        },
                        "\u{00D7}"
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ChatHeaderCtx — context for sharing chat header state with AppLayout
// ---------------------------------------------------------------------------

/// Plain-data context shared between ChatPanel (full-page mode) and AppLayout.
///
/// Contains cloned snapshots of chat state — **not** Signal handles — so that
/// parent components can safely read it without violating Dioxus's signal
/// ownership rules.  ChatPanel writes a fresh snapshot on each render (guarded
/// by a PartialEq check to avoid loops).
#[derive(Clone, PartialEq)]
pub struct ChatHeaderCtx {
    pub agents: Vec<AgentInfo>,
    pub selected_agent: Option<AgentInfo>,
    pub agents_loaded: bool,
    pub show_history: bool,
    pub api_url_empty: bool,
    pub token_empty: bool,
    pub on_agent_select: EventHandler<String>,
    pub on_new_chat: EventHandler<()>,
    pub on_toggle_history: EventHandler<()>,
}

// ---------------------------------------------------------------------------
// ChatHeaderActions — action buttons for the desktop header bar
// ---------------------------------------------------------------------------

/// Chat action buttons rendered in AppLayout's desktop header bar (full-page mode).
///
/// Reads plain data from [`ChatHeaderCtx`] — no child-owned Signals.
#[component]
pub fn ChatHeaderActions(ctx: ChatHeaderCtx) -> Element {
    let mut agent_menu_open = use_signal(|| false);
    let selected_id = ctx
        .selected_agent
        .as_ref()
        .map(|a| a.id.clone())
        .unwrap_or_default();

    let ready = !ctx.api_url_empty && !ctx.token_empty && ctx.agents_loaded;

    rsx! {
        // Click-outside backdrop for agent menu
        if agent_menu_open() {
            div {
                class: "dropdown-backdrop",
                onclick: move |_| agent_menu_open.set(false),
            }
        }

        if !ready {
            span { class: "chat-loading-sm",
                if ctx.api_url_empty {
                    "Waiting..."
                } else if ctx.token_empty {
                    "Auth..."
                } else {
                    "Loading..."
                }
            }
        } else {
            // History toggle
            button {
                class: if ctx.show_history { "chat-header-btn active" } else { "chat-header-btn" },
                title: "History",
                onclick: move |_| ctx.on_toggle_history.call(()),
                History { size: 16 }
            }

            // Segmented new-chat button
            div { class: "chat-new-segmented",
                button {
                    class: "chat-new-plus",
                    title: "New chat",
                    onclick: move |_| ctx.on_new_chat.call(()),
                    Plus { size: 14 }
                }
                button {
                    class: if agent_menu_open() { "chat-new-dropdown-toggle active" } else { "chat-new-dropdown-toggle" },
                    title: "Pick agent",
                    onclick: move |_| agent_menu_open.set(!agent_menu_open()),
                    ChevronDown { size: 12 }
                }

                if agent_menu_open() {
                    div { class: "chat-new-agent-menu",
                        for agent in ctx.agents.iter() {
                            {
                                let aid = agent.id.clone();
                                let is_active = aid == selected_id;
                                let name = agent.name.clone();
                                let desc = agent.description.clone().unwrap_or_default();
                                let on_select = ctx.on_agent_select;
                                rsx! {
                                    div {
                                        key: "{aid}",
                                        class: if is_active { "agent-dropdown-item active" } else { "agent-dropdown-item" },
                                        onclick: move |_| {
                                            on_select.call(aid.clone());
                                            agent_menu_open.set(false);
                                        },
                                        div { class: "agent-dropdown-item-name", "{name}" }
                                        if !desc.is_empty() {
                                            div { class: "agent-dropdown-item-desc", "{desc}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SuggestedActions
// ---------------------------------------------------------------------------

/// Props for [`SuggestedActions`].
#[derive(Props, Clone, PartialEq)]
pub struct SuggestedActionsProps {
    /// Currently selected agent (used for the greeting message).
    pub selected_agent: Signal<Option<AgentInfo>>,
    /// Callback fired with the prompt text when a quick-action button is clicked.
    pub on_send: EventHandler<String>,
    /// Recent conversations to show below the suggested actions.
    pub conversation_list: Signal<Vec<ConversationInfo>>,
    /// Called when the user clicks a recent conversation.
    pub on_select_conversation: EventHandler<String>,
}

/// Grid of suggested quick-action buttons + recent conversations shown in the empty-chat state.
#[component]
pub fn SuggestedActions(props: SuggestedActionsProps) -> Element {
    let selected_agent = props.selected_agent;
    let conversation_list = props.conversation_list;

    rsx! {
        div { class: "chat-empty",
            if let Some(agent) = selected_agent.read().as_ref() {
                if let Some(greeting) = &agent.greeting {
                    p { class: "chat-greeting", "{greeting}" }
                } else {
                    p { class: "chat-greeting", "Start a conversation with {agent.name}" }
                }
            }
            div { class: "chat-suggested-actions",
                for (label, prompt) in SUGGESTED_ACTIONS.iter() {
                    {
                        let prompt_text = prompt.to_string();
                        let on_send = props.on_send;
                        rsx! {
                            button {
                                class: "chat-suggested-btn",
                                onclick: move |_| {
                                    on_send.call(prompt_text.clone());
                                },
                                "{label}"
                            }
                        }
                    }
                }
            }

            // Recent conversations (up to 5)
            if !conversation_list.read().is_empty() {
                div { class: "chat-recent-section",
                    p { class: "chat-recent-heading", "Recent conversations" }
                    div { class: "chat-recent-list",
                        for conv in conversation_list.read().iter().take(5) {
                            {
                                let cid = conv.id.clone();
                                let title = if conv.title.is_empty() {
                                    "Untitled".to_string()
                                } else if conv.title.len() > 50 {
                                    format!("{}...", &conv.title[..47])
                                } else {
                                    conv.title.clone()
                                };
                                let time_str = format_relative_time(&conv.updated_at);
                                let on_select = props.on_select_conversation;
                                rsx! {
                                    div {
                                        key: "{cid}",
                                        class: "chat-recent-item",
                                        onclick: move |_| on_select.call(cid.clone()),
                                        span { class: "chat-recent-title", "{title}" }
                                        span { class: "chat-recent-time", "{time_str}" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
