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
    /// Current shell mode: "proot" or "native".
    #[props(default = "native".to_string())]
    shell_mode: String,
    /// Whether root/su access is granted on this device.
    #[props(default)]
    root_granted: bool,
) -> Element {
    let last_five: Vec<&TerminalLine> = recent_lines.iter().rev().take(5).collect();
    let wifi_adapter = use_memo(move || wifi_adapter.clone());

    // Build execution context string to append to quick action prompts
    let exec_context = {
        let mut parts = Vec::new();
        if cfg!(target_os = "android") {
            parts.push(format!("Shell mode: {}", if shell_mode == "proot" { "Proot (BlackArch sandbox)" } else { "Native (direct Android host)" }));
            if root_granted {
                parts.push("Root: GRANTED via Magisk — WiFi/hardware commands (airmon-ng, iw, ip, etc.) run via `su -c` on the host with full kernel access. General tools run in proot.".to_string());
            } else {
                parts.push("Root: NOT GRANTED — WiFi monitor mode and hardware access will fail. Grant su access in Magisk first.".to_string());
            }
            if shell_mode == "proot" {
                parts.push("Proot capabilities: pacman package manager, aircrack-ng suite installed, hashcat, john, hydra, etc. No direct hardware/kernel access from proot — hardware commands are automatically routed via su on the host.".to_string());
            }
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("\n\n[Execution Context: {}]", parts.join(" | "))
        }
    };

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
                            onclick: {
                                let ctx = exec_context.clone();
                                move |_| on_open_chat.call(format!("Get the device info for this connector — OS, hostname, architecture, and resources.{ctx}"))
                            },
                            span { class: "action-card-icon", Info { size: 24 } }
                            span { class: "action-card-label", "Device Info" }
                        }
                        div {
                            class: "action-card",
                            onclick: {
                                let ctx = exec_context.clone();
                                move |_| on_open_chat.call(format!("Run a full network discovery — ARP, mDNS, and SSDP — and summarize what you find.{ctx}"))
                            },
                            span { class: "action-card-icon", Network { size: 24 } }
                            span { class: "action-card-label", "Network Scan" }
                        }
                        div {
                            class: "action-card",
                            onclick: {
                                let ctx = exec_context.clone();
                                move |_| {
                                    let action = format!("Scan for nearby WiFi networks and list SSIDs, channels, and signal strengths.{ctx}");
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
                                }
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
                            onclick: {
                                let ctx = exec_context.clone();
                                move |_| {
                                    let action = format!("Execute automated penetration test: \
                                        \
                                        1. Check if I have WiFi pentesting hardware (monitor mode capable adapter). \
                                        \
                                        2. If YES (WiFi pentest adapter available): \
                                           - Scan for WiFi networks \
                                           - Run detailed scan to detect clients \
                                           - Automatically select the best target (strongest signal, most clients, attackable security) \
                                           - Plan and execute the WiFi attack (WEP/WPA2 capture + crack) \
                                        \
                                        3. If NO (no WiFi pentest adapter): \
                                           - Skip WiFi and pivot to network-based attacks \
                                           - Plan a full network penetration test (autopwn_network_plan) \
                                           - Execute each phase: discovery → port scanning → service enumeration → vuln assessment → exploitation planning \
                                        \
                                        Make all decisions autonomously. Only ask me for confirmation before destructive actions. \
                                        Walk through the complete attack sequence like a professional penetration tester.{ctx}");
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
                                }
                            },
                            span { class: "action-card-icon", Bolt { size: 24 } }
                            span { class: "action-card-label", "AutoPwn" }
                        }
                        div {
                            class: "action-card",
                            onclick: {
                                let ctx = exec_context.clone();
                                move |_| on_open_chat.call(format!("Scan the local gateway for common open ports and identify running services.{ctx}"))
                            },
                            span { class: "action-card-icon", Shield { size: 24 } }
                            span { class: "action-card-label", "Port Scan" }
                        }
                        div {
                            class: "action-card",
                            onclick: {
                                let ctx = exec_context.clone();
                                move |_| on_open_chat.call(format!("Perform a comprehensive network vulnerability assessment. Phase 1: Discover all hosts (ARP scan, mDNS, SSDP, WiFi). Phase 2: For each host, scan ports and grab service banners. Phase 3: Lookup CVEs for discovered services, test default credentials, scan for web vulnerabilities. Generate a detailed report with severity ratings and remediation recommendations.{ctx}"))
                            },
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
