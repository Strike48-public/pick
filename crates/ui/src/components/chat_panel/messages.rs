//! Message list area with auto-scroll.
//!
//! Renders the scrollable message list, the thinking indicator,
//! the scroll-to-bottom button, and the suggested-actions empty state.

use dioxus::prelude::*;
use pentest_core::matrix::{AgentInfo, ChatMessage, ConversationInfo};

use super::agent_selector::SuggestedActions;
use super::next_steps::NextStepsActions;
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
    /// Easy Mode: show lay-friendly empty-state prompts instead of the expert
    /// red-team suggestions (the big "Scan My Network" card is the primary action).
    #[props(default)]
    pub easy_mode: bool,
    /// True while the browser OAuth for the chat token is in flight (opened, not
    /// yet returned). The empty state then tells the user to finish sign-in in
    /// the browser rather than the misleading "Select an agent to begin".
    #[props(default)]
    pub awaiting_auth: bool,
    /// True when the chat has no auth token yet and sign-in has not started.
    /// The empty state then shows an explicit "Sign in to Strike48" button
    /// instead of the misleading "Select an agent to begin". Used by the
    /// expert full-page chat, which (unlike the lazy-OAuth expert sidebar) has
    /// no other way to kick off sign-in.
    #[props(default)]
    pub needs_sign_in: bool,
    /// Called when the user clicks the empty-state "Sign in to Strike48" button.
    #[props(default)]
    pub on_sign_in: EventHandler<()>,
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

    // Auto-scroll and chart post-process when new messages arrive or agent is thinking.
    // Chart processing was previously per-bubble via `onmounted`, but that triggers a
    // panic in dioxus-liveview 0.7.x convert_mounted_data on history reload (issue #130).
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
                if let Err(e) = document::eval("triggerChartPostProcess()").await {
                    tracing::warn!("JS eval failed (chart post-process): {e}");
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
                        easy_mode: props.easy_mode,
                    }
                } else if selected_agent.read().is_none() {
                    if props.awaiting_auth {
                        div { class: "chat-empty chat-empty-auth",
                            p { class: "chat-empty-auth-title", "Complete your sign-in in the browser" }
                            p { class: "chat-empty-auth-sub", "We opened your browser to sign in to Strike48. Come back here once you're done — this will update automatically." }
                        }
                    } else if props.needs_sign_in {
                        div { class: "chat-empty chat-empty-auth",
                            p { class: "chat-empty-auth-title", "Chat needs sign-in" }
                            p { class: "chat-empty-auth-sub", "Sign in to Strike48 to talk to the agent." }
                            button {
                                class: "button",
                                "data-style": "primary",
                                onclick: move |_| props.on_sign_in.call(()),
                                "Sign in to Strike48"
                            }
                        }
                    } else {
                        // No agent selected and we're not mid/awaiting sign-in. The
                        // user never picks an agent (the connector owns its one
                        // agent), so "Select an agent" is nonsense — this state means
                        // agent setup hasn't completed. An error_msg is surfaced
                        // separately (chat-error) when creation actually failed; this
                        // is the neutral in-between copy.
                        div { class: "chat-empty",
                            p { "Setting up your assistant…" }
                        }
                    }
                }

                // Message bubbles (collapse sender label for consecutive same-sender)
                {
                    let msgs = messages.read();
                    let mut prev_sender: Option<String> = None;
                    rsx! {
                        for msg in msgs.iter() {
                            {
                                let show_sender = prev_sender.as_ref() != Some(&msg.sender_name);
                                prev_sender = Some(msg.sender_name.clone());
                                render_message(msg, &mut expanded_tools, show_sender)
                            }
                        }
                    }
                }

                // Next Steps action buttons (context-sensitive)
                if !messages.read().is_empty() && !agent_thinking() {
                    NextStepsActions {
                        messages: messages,
                        on_send: props.on_send,
                    }
                }

                // Thinking indicator (standard)
                if agent_thinking() {
                    div { class: "chat-bubble chat-bubble-agent chat-thinking",
                        // Easy mode hides the connector/agent name above the
                        // in-progress status — the user thinks of it as "Pick",
                        // not "pentest-connector".
                        if !props.easy_mode {
                            div { class: "chat-bubble-sender",
                                if let Some(agent) = selected_agent.read().as_ref() {
                                    "{agent.name}"
                                }
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
