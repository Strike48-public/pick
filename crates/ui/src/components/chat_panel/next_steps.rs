//! Contextual "Next Steps" action buttons that appear after specific tool completions.

use dioxus::prelude::*;
use pentest_core::matrix::{ChatMessage, MessagePart, ToolCallStatus};
use pentest_tools::registry::{ActionStyle, QuickAction};

/// Props for [`NextStepsActions`].
#[derive(Props, Clone, PartialEq)]
pub struct NextStepsActionsProps {
    /// All messages in the conversation.
    pub messages: Signal<Vec<ChatMessage>>,
    /// Callback to send a follow-up message.
    pub on_send: EventHandler<String>,
}

/// Renders contextual action buttons after specific tool completions.
///
/// Uses the quick action registry to dynamically provide context-aware actions
/// based on tool output.
#[component]
pub fn NextStepsActions(props: NextStepsActionsProps) -> Element {
    let messages = props.messages.read();

    // Find the last agent message with a successful tool call
    let last_tool_call = messages.iter().rev().find_map(|msg| {
        if msg.sender_type == "USER" {
            return None;
        }
        msg.parts.iter().find_map(|part| {
            if let MessagePart::ToolCall(tc) = part {
                if tc.status == ToolCallStatus::Success {
                    return Some((tc.name.clone(), tc.result.clone().unwrap_or_default()));
                }
            }
            None
        })
    });

    // Get actions from registry
    let actions = if let Some((tool_name, result_json)) = last_tool_call {
        let registry = crate::session::get_action_registry();
        registry.get_actions(&tool_name, &result_json)
    } else {
        vec![]
    };

    if actions.is_empty() {
        return rsx! {};
    }

    render_quick_actions(&actions, props.on_send)
}

/// Render quick actions from registry
fn render_quick_actions(actions: &[QuickAction], on_send: EventHandler<String>) -> Element {
    rsx! {
        style { {include_str!("css/next_steps.css")} }
        style { {include_str!("../../../assets/tabler-icons/tabler-icons.css")} }

        div { class: "next-steps-container",
            div { class: "next-steps-header", "Next Steps" }
            div { class: "next-steps-actions",
                for action in actions {
                    {render_action_button(action, on_send)}
                }
            }
        }
    }
}

/// Render a single action button
fn render_action_button(action: &QuickAction, on_send: EventHandler<String>) -> Element {
    let prompt = action.prompt.clone();
    let style_class = match action.style {
        ActionStyle::Primary => "next-steps-btn-primary",
        ActionStyle::Secondary => "next-steps-btn-secondary",
        ActionStyle::Danger => "next-steps-btn-danger",
        ActionStyle::Info => "next-steps-btn-info",
    };

    let icon_class = action.icon.to_class();
    let icon_fallback = action.icon.emoji_fallback();

    rsx! {
        button {
            class: format!("next-steps-btn {}", style_class),
            onclick: move |_| {
                on_send.call(prompt.clone());
            },
            // Use Tabler icon if class is not empty, otherwise fallback to emoji
            if !icon_class.is_empty() {
                span { class: format!("next-steps-icon {}", icon_class) }
            } else {
                span { class: "next-steps-icon", {icon_fallback} }
            }
            span { class: "next-steps-label", {action.label.clone()} }
            span { class: "next-steps-desc", {action.description.clone()} }
        }
    }
}
