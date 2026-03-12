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
/// - `wifi_scan_detailed` → Network autopwn options if no pentest adapter available
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
                        return Some(());
                    }
                }
                None
            })
        })
        .is_some();

    // Check if it contains a successful wifi_scan_detailed tool call
    let has_wifi_scan_detailed = last_agent_msg
        .and_then(|msg| {
            msg.parts.iter().find_map(|part| {
                if let MessagePart::ToolCall(tc) = part {
                    if tc.name == "wifi_scan_detailed" && tc.status == ToolCallStatus::Success {
                        return Some(());
                    }
                }
                None
            })
        })
        .is_some();

    if has_wifi_scan {
        return render_wifi_scan_actions(props.on_send);
    }

    if has_wifi_scan_detailed {
        return render_wifi_detailed_actions(props.on_send);
    }

    rsx! {}
}

/// Render actions after basic wifi_scan
fn render_wifi_scan_actions(on_send: EventHandler<String>) -> Element {
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

/// Render actions after wifi_scan_detailed (offer network autopwn as fallback)
fn render_wifi_detailed_actions(on_send: EventHandler<String>) -> Element {
    rsx! {
        style { {include_str!("css/next_steps.css")} }

        div { class: "next-steps-container",
            div { class: "next-steps-header", "Next Steps" }
            div { class: "next-steps-text",
                "If you don't have a WiFi pentesting adapter, you can pivot to network-based attacks:"
            }
            div { class: "next-steps-actions",
                button {
                    class: "next-steps-btn",
                    onclick: move |_| {
                        on_send.call(
                            "Plan a full network penetration test sequence. This will create an \
                             automated attack plan covering: network discovery, port scanning, \
                             service enumeration, vulnerability assessment, and exploitation planning.".to_string()
                        );
                    },
                    span { class: "next-steps-icon", "🌐" }
                    span { class: "next-steps-label", "Full Network Pentest" }
                    span { class: "next-steps-desc", "Complete attack sequence (~30 min)" }
                }
                button {
                    class: "next-steps-btn",
                    onclick: move |_| {
                        on_send.call(
                            "Plan a quick network reconnaissance scan. This will discover live hosts, \
                             advertised services, and perform a light port scan without active exploitation.".to_string()
                        );
                    },
                    span { class: "next-steps-icon", "🗺️" }
                    span { class: "next-steps-label", "Network Recon" }
                    span { class: "next-steps-desc", "Discovery only (~5 min)" }
                }
            }
        }
    }
}
