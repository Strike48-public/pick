//! Dashboard component for the connected home screen

use dioxus::prelude::*;
use pentest_core::terminal::TerminalLine;
use pentest_platform::WifiConnectionStatus;

use super::icons::{Bolt, Info, MessageCircle, Network, Shield, Terminal, Wifi};
use crate::platform_helper;

/// Connected home screen with status, quick actions, and recent activity.
/// Settings (shell mode) and disconnect are now in the sidebar.
#[component]
pub fn Dashboard(
    host: String,
    on_open_chat: EventHandler<String>,
    on_open_shell: EventHandler<()>,
    recent_lines: Vec<TerminalLine>,
    #[props(default)] wifi_adapter: Option<String>,
    /// Callback to show the WiFi warning dialog at the top level (outside overflow containers).
    #[props(default)]
    on_wifi_warning: EventHandler<(WifiConnectionStatus, String)>,
) -> Element {
    let last_five: Vec<&TerminalLine> = recent_lines.iter().rev().take(5).collect();
    let wifi_adapter = use_memo(move || wifi_adapter.clone());

    // WiFi status for the warning badge on the WiFi Scan card
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
                                let selected_adapter = wifi_adapter();
                                spawn(async move {
                                    // Check WiFi connection status with selected adapter
                                    match platform_helper::check_wifi_status(selected_adapter).await {
                                        Ok(status) => {
                                            wifi_status.set(Some(status.clone()));
                                            if !status.safe_to_scan {
                                                // Show warning at top level (outside overflow containers)
                                                on_wifi_warning.call((status, action));
                                            } else {
                                                // Safe to proceed
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
                            onclick: move |_| {
                                let action = "Scan for nearby WiFi networks and show them in a table. I'll tell you which network to attack after I see the scan results.".to_string();
                                let selected_adapter = wifi_adapter();
                                spawn(async move {
                                    match platform_helper::check_wifi_status(selected_adapter).await {
                                        Ok(status) => {
                                            wifi_status.set(Some(status.clone()));
                                            if !status.safe_to_scan {
                                                on_wifi_warning.call((status, action));
                                            } else {
                                                on_open_chat.call(action);
                                            }
                                        }
                                        Err(e) => {
                                            tracing::warn!("Failed to check WiFi status: {}", e);
                                            on_open_chat.call(action);
                                        }
                                    }
                                });
                            },
                            span { class: "action-card-icon", Bolt { size: 24 } }
                            span { class: "action-card-label", "AutoPwn" }
                        }
                        div {
                            class: "action-card",
                            onclick: move |_| on_open_chat.call("Scan the local gateway for common open ports and identify running services.".to_string()),
                            span { class: "action-card-icon", Shield { size: 24 } }
                            span { class: "action-card-label", "Port Scan" }
                        }
                        div {
                            class: "action-card",
                            onclick: move |_| on_open_chat.call("Perform a comprehensive network vulnerability assessment. Phase 1: Discover all hosts (ARP scan, mDNS, SSDP, WiFi). Phase 2: For each host, scan ports and grab service banners. Phase 3: Lookup CVEs for discovered services, test default credentials, scan for web vulnerabilities. Generate a detailed report with severity ratings and remediation recommendations.".to_string()),
                            span { class: "action-card-icon", Shield { size: 24 } }
                            span { class: "action-card-label", "Vuln Assessment" }
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

    }
}
