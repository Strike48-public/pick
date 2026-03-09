//! Dashboard component for the connected home screen

use dioxus::prelude::*;
use pentest_core::terminal::TerminalLine;
use pentest_platform::WifiConnectionStatus;

use crate::platform_helper;
use super::icons::{Info, MessageCircle, Network, Shield, Terminal, Wifi};
use super::WifiWarningDialog;

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

    // WiFi warning dialog state
    let mut wifi_warning_visible = use_signal(|| false);
    let mut pending_wifi_action = use_signal(|| None::<String>);
    let mut wifi_status = use_signal(|| None::<WifiConnectionStatus>);

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
                            onclick: move |_| {
                                let action = "Scan for nearby WiFi networks and list SSIDs, channels, and signal strengths.".to_string();
                                spawn(async move {
                                    // Check WiFi connection status
                                    match platform_helper::check_wifi_status().await {
                                        Ok(status) => {
                                            wifi_status.set(Some(status.clone()));
                                            if !status.safe_to_scan && status.connected_via_wifi {
                                                // Show warning for high-risk scenario
                                                pending_wifi_action.set(Some(action));
                                                wifi_warning_visible.set(true);
                                            } else if status.connected_via_wifi && status.total_adapters > 1 {
                                                // Show caution for multiple adapters
                                                pending_wifi_action.set(Some(action));
                                                wifi_warning_visible.set(true);
                                            } else {
                                                // Safe to proceed (ethernet or no WiFi detected)
                                                on_open_chat.call(action);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("Failed to check WiFi status: {}", e);
                                            // Proceed anyway if detection fails
                                            on_open_chat.call(action);
                                        }
                                    }
                                });
                            },
                            span { class: "action-card-icon", Wifi { size: 24 } }
                            span { class: "action-card-label", "WiFi Scan" }
                            // Warning badge if WiFi detected
                            if let Some(status) = wifi_status.read().as_ref() {
                                if status.connected_via_wifi {
                                    span {
                                        class: "warning-badge",
                                        title: "WiFi scan may disconnect your connection",
                                        "⚠️"
                                    }
                                }
                            }
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

        // WiFi warning dialog
        if let Some(status) = wifi_status.read().as_ref() {
            WifiWarningDialog {
                visible: wifi_warning_visible(),
                status: status.clone(),
                on_proceed: move |_| {
                    if let Some(action) = pending_wifi_action.read().as_ref() {
                        on_open_chat.call(action.clone());
                    }
                    wifi_warning_visible.set(false);
                    pending_wifi_action.set(None);
                },
                on_cancel: move |_| {
                    wifi_warning_visible.set(false);
                    pending_wifi_action.set(None);
                },
            }
        }
    }
}
