//! Contextual "Next Steps" action buttons that appear after specific tool completions.

use dioxus::prelude::*;
use pentest_core::matrix::{ChatMessage, MessagePart, ToolCallStatus};

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
/// Currently supports:
/// - `wifi_scan` → "Detailed Scan" button to run wifi_scan_detailed
#[component]
pub fn NextStepsActions(props: NextStepsActionsProps) -> Element {
    let messages = props.messages.read();

    // Find the last agent message
    let last_agent_msg = messages.iter().rev().find(|msg| msg.sender_type != "USER");

    // Check if it contains a successful wifi_scan tool call
    let has_wifi_scan = last_agent_msg
        .and_then(|msg| {
            msg.parts.iter().find_map(|part| {
                if let MessagePart::ToolCall(tc) = part {
                    if tc.name == "wifi_scan" && tc.status == ToolCallStatus::Success {
                        return Some(tc.name.as_str());
                    }
                }
                None
            })
        })
        .is_some();

    if !has_wifi_scan {
        return rsx! {};
    }

    let on_send = props.on_send;

    rsx! {
        style { {include_str!("css/next_steps.css")} }

        div { class: "next-steps-container",
            div { class: "next-steps-header", "Next Steps" }
            div { class: "next-steps-actions",
                button {
                    class: "next-steps-btn",
                    onclick: move |_| {
                        on_send.call(
                            "Run a detailed WiFi scan with client detection (~30 seconds). \
                             This will show how many devices are connected to each network, \
                             which helps identify easier targets for WPA/WPA2/WPA3 attacks.".to_string()
                        );
                    },
                    span { class: "next-steps-icon", "🔍" }
                    span { class: "next-steps-label", "Detailed Scan" }
                    span { class: "next-steps-desc", "Show client counts (~30s)" }
                }
            }
        }
    }
}
