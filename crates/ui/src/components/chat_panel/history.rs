//! Conversation history dropdown.
//!
//! Renders the list of past conversations for the selected agent.
//! Show/hide is controlled by the parent via the `show` prop.
//! The old button bar (New + History) has been moved into `ChatHeader`.

use dioxus::prelude::*;
use pentest_core::matrix::ConversationInfo;

use super::render::format_relative_time;

/// Props for [`HistoryDropdown`].
#[derive(Props, Clone, PartialEq)]
pub struct HistoryDropdownProps {
    /// Full list of conversations for the current agent.
    pub conversation_list: Signal<Vec<ConversationInfo>>,
    /// True while the conversation list is being fetched.
    pub history_loading: Signal<bool>,
    /// The currently-active conversation id (used to highlight it).
    pub conversation_id: Signal<Option<String>>,
    /// Called when the user clicks a conversation row. Payload is the conversation id.
    pub on_select_conversation: EventHandler<String>,
}

/// Dropdown list of past conversations (no button bar — that lives in ChatHeader).
#[component]
pub fn HistoryDropdown(props: HistoryDropdownProps) -> Element {
    let history_loading = props.history_loading;
    let conversation_list = props.conversation_list;
    let conversation_id = props.conversation_id;

    rsx! {
        div { class: "chat-history-dropdown",
            if history_loading() {
                div { class: "chat-history-loading", "Loading..." }
            } else if conversation_list.read().is_empty() {
                div { class: "chat-history-empty", "No past conversations" }
            } else {
                for conv in conversation_list.read().iter() {
                    {
                        let conv_id_val = conv.id.clone();
                        let conv_title = if conv.title.is_empty() {
                            "Untitled".to_string()
                        } else if conv.title.len() > 40 {
                            format!("{}...", &conv.title[..37])
                        } else {
                            conv.title.clone()
                        };
                        let is_active = conversation_id
                            .read()
                            .as_ref()
                            .map(|c| c == &conv_id_val)
                            .unwrap_or(false);
                        let item_class = if is_active {
                            "chat-history-item active"
                        } else {
                            "chat-history-item"
                        };
                        let time_str = format_relative_time(&conv.updated_at);
                        let cid = conv_id_val.clone();
                        let on_select = props.on_select_conversation;
                        rsx! {
                            div {
                                key: "{conv_id_val}",
                                class: "{item_class}",
                                onclick: move |_| {
                                    on_select.call(cid.clone());
                                },
                                span { class: "chat-history-title", "{conv_title}" }
                                span { class: "chat-history-time", "{time_str}" }
                            }
                        }
                    }
                }
            }
        }
    }
}
