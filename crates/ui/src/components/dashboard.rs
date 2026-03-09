//! Dashboard component for the connected home screen

use dioxus::prelude::*;
use pentest_core::terminal::TerminalLine;

use super::icons::{Info, MessageCircle, Network, Shield, Terminal, Wifi, Wrench};

/// Connected home screen with status, quick actions, and recent activity.
/// Settings (shell mode) and disconnect are now in the sidebar.
#[component]
pub fn Dashboard(
    host: String,
    on_open_chat: EventHandler<String>,
    on_open_shell: EventHandler<()>,
    recent_lines: Vec<TerminalLine>,
) -> Element {
    let last_five: Vec<&TerminalLine> = recent_lines.iter().rev().take(5).collect();

    rsx! {
        style { {include_str!("css/dashboard.css")} }

        div { class: "dashboard",
            div { class: "dashboard-body",
                // Quick actions grid — 2x2, each opens chat with a seeded prompt
                div { class: "dashboard-section",
                    h3 { class: "dashboard-section-title", "Quick Actions" }
                    div { class: "action-grid",
                        div {
                            class: "action-card",
                            onclick: move |_| on_open_chat.call("Get the device info for this connector — OS, hostname, architecture, and resources.".to_string()),
                            span { class: "action-card-icon", Info { size: 24 } }
                            span { class: "action-card-label", "Device Info" }
                        }
                        div {
                            class: "action-card",
                            onclick: move |_| on_open_chat.call("Run a full network discovery — ARP, mDNS, and SSDP — and summarize what you find.".to_string()),
                            span { class: "action-card-icon", Network { size: 24 } }
                            span { class: "action-card-label", "Network Scan" }
                        }
                        div {
                            class: "action-card",
                            onclick: move |_| on_open_chat.call("Scan for nearby WiFi networks and list SSIDs, channels, and signal strengths.".to_string()),
                            span { class: "action-card-icon", Wifi { size: 24 } }
                            span { class: "action-card-label", "WiFi Scan" }
                        }
                        div {
                            class: "action-card",
                            onclick: move |_| on_open_chat.call("Scan the local gateway for common open ports and identify running services.".to_string()),
                            span { class: "action-card-icon", Shield { size: 24 } }
                            span { class: "action-card-label", "Port Scan" }
                        }
                        div {
                            class: "action-card",
                            onclick: move |_| on_open_shell.call(()),
                            span { class: "action-card-icon", Terminal { size: 24 } }
                            span { class: "action-card-label", "Shell" }
                        }
                        div {
                            class: "action-card",
                            onclick: move |_| on_open_chat.call("Run autopwn for automated WiFi penetration testing. First use the list_wifi_interfaces tool to show available wireless interfaces, let me select which one to use, then configure and run autopwn with my chosen interface and wordlist.".to_string()),
                            span { class: "action-card-icon", Wrench { size: 24 } }
                            span { class: "action-card-label", "Autopwn" }
                        }
                    }
                }

                // Agent chat onboarding card
                div {
                    class: "dashboard-card onboarding-card",
                    onclick: move |_| on_open_chat.call(String::new()),
                    style: "cursor: pointer;",
                    div { class: "onboarding-icon", MessageCircle { size: 24 } }
                    div { class: "onboarding-content",
                        h3 { class: "onboarding-title", "AI Red Team Agent" }
                        p { class: "onboarding-desc",
                            "Chat with the pentest agent to run tools, analyze networks, and build attack chains."
                        }
                    }
                }

                // Recent activity
                if !last_five.is_empty() {
                    div { class: "dashboard-section",
                        h3 { class: "dashboard-section-title", "Recent Activity" }
                        div { class: "dashboard-card",
                            for line in last_five {
                                div { class: "recent-line", "{line.message}" }
                            }
                        }
                    }
                }
            }
        }
    }
}
