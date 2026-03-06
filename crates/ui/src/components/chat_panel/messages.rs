//! Message list area with auto-scroll.
//!
//! Renders the scrollable message list, the thinking indicator,
//! the scroll-to-bottom button, and the suggested-actions empty state.

use dioxus::prelude::*;
use pentest_core::matrix::{AgentInfo, ChatMessage, ConversationInfo};

use super::agent_selector::SuggestedActions;
use super::render::render_message;

/// Props for [`MessageList`].
#[derive(Props, Clone, PartialEq)]
pub struct MessageListProps {
    /// All messages in the current conversation.
    pub messages: Signal<Vec<ChatMessage>>,
    /// Expanded tool-call ids (shared with render_message).
    pub expanded_tools: Signal<Vec<String>>,
    /// Whether the user has scrolled away from the bottom.
    pub user_scrolled_up: Signal<bool>,
    /// Whether the agent is currently processing.
    pub agent_thinking: Signal<bool>,
    /// Status text shown in the thinking indicator.
    pub agent_status_text: Signal<String>,
    /// Currently selected agent (used for the thinking bubble label and empty state).
    pub selected_agent: Signal<Option<AgentInfo>>,
    /// Callback to send a message (used by suggested actions).
    pub on_send: EventHandler<String>,
    /// Recent conversations shown in the empty-chat state.
    pub conversation_list: Signal<Vec<ConversationInfo>>,
    /// Called when the user clicks a recent conversation in the empty state.
    pub on_select_conversation: EventHandler<String>,
}

/// Scrollable message list, thinking indicator, and scroll-to-bottom FAB.
#[component]
pub fn MessageList(props: MessageListProps) -> Element {
    let messages = props.messages;
    let mut expanded_tools = props.expanded_tools;
    let mut user_scrolled_up = props.user_scrolled_up;
    let agent_thinking = props.agent_thinking;
    let agent_status_text = props.agent_status_text;
    let selected_agent = props.selected_agent;

    // Auto-scroll effect: scroll down when new messages arrive or agent is thinking.
    let prev_msg_count = use_hook(|| std::cell::Cell::new(0usize));
    use_effect(move || {
        let current_count = messages.read().len();
        let thinking = agent_thinking();
        if current_count != prev_msg_count.get() || thinking {
            prev_msg_count.set(current_count);
            spawn(async move {
                if let Err(e) =
                    document::eval("scrollToBottomIfNotScrolled('.chat-messages')").await
                {
                    tracing::warn!("JS eval failed (auto-scroll): {e}");
                }
            });
        }
    });

    // Install JS-side scroll listeners once.
    let scroll_listener_installed = use_hook(|| std::cell::Cell::new(false));
    if !scroll_listener_installed.get() {
        scroll_listener_installed.set(true);
        spawn(async move {
            if let Err(e) = document::eval("installScrollListeners('.chat-messages', 40)").await {
                tracing::warn!("JS eval failed (scroll listener install): {e}");
            }
        });
    }

    rsx! {
        div { class: "chat-messages-wrapper",
            div {
                class: "chat-messages",
                onscroll: move |_| {
                    spawn(async move {
                        match document::eval("return isNearBottom('.chat-messages', 40)").await {
                            Ok(val) => {
                                user_scrolled_up.set(val.as_str() != Some("bottom"));
                            }
                            Err(e) => {
                                tracing::warn!("JS eval failed (scroll position check): {e}");
                            }
                        }
                    });
                },

                // Empty state: suggested actions or "select an agent"
                if messages.read().is_empty() && selected_agent.read().is_some() {
                    SuggestedActions {
                        selected_agent: selected_agent,
                        on_send: props.on_send,
                        conversation_list: props.conversation_list,
                        on_select_conversation: props.on_select_conversation,
                    }
                } else if selected_agent.read().is_none() {
                    div { class: "chat-empty",
                        p { "Select an agent to begin" }
                    }
                }

                // Message bubbles
                for msg in messages.read().iter() {
                    {render_message(msg, &mut expanded_tools)}
                }

                // Thinking indicator
                if agent_thinking() {
                    div { class: "chat-bubble chat-bubble-agent chat-thinking",
                        div { class: "chat-bubble-sender",
                            if let Some(agent) = selected_agent.read().as_ref() {
                                "{agent.name}"
                            }
                        }
                        div { class: "chat-thinking-status",
                            if !agent_status_text.read().is_empty() {
                                span { class: "chat-status-label", "{agent_status_text}" }
                            }
                            div { class: "chat-thinking-dots",
                                span { "." }
                                span { "." }
                                span { "." }
                            }
                        }
                    }
                }
            }

            // Scroll-to-bottom button
            if user_scrolled_up() && !messages.read().is_empty() {
                button {
                    class: "chat-scroll-to-bottom",
                    title: "Scroll to bottom",
                    onclick: move |_| {
                        user_scrolled_up.set(false);
                        spawn(async move {
                            if let Err(e) = document::eval("forceScrollToBottom('.chat-messages')").await {
                                tracing::warn!("JS eval failed (scroll to bottom): {e}");
                            }
                        });
                    },
                    "\u{2193}"
                }
            }
        }
    }
}
