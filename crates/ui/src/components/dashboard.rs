//! Dashboard component for the connected home screen

use dioxus::prelude::*;
use pentest_core::terminal::TerminalLine;
use pentest_platform::WifiConnectionStatus;

use super::icons::{Bolt, Info, MessageCircle, Network, ScrollText, Shield, Terminal, Wifi};
use crate::platform_helper;

/// Seeded chat prompt for the "Network Attack Plan" quick action.
///
/// Plan-only review gate: instructs the agent to call `autopwn_network_plan`,
/// present the phased plan for review, execute no phase, and offer AutoPwn as
/// the follow-on. The plan-only invariant is load-bearing, so it is pinned by a
/// unit test rather than left as an inline literal.
const NETWORK_ATTACK_PLAN_PROMPT: &str = "Call the autopwn_network_plan tool to produce a phased attack plan for the current network (the discovery, scanning, and exploitation sequence it lays out). Present the complete plan for my review but do NOT execute any phase; this is plan-only, so run no scans or attacks. When the plan is ready, offer to launch AutoPwn as the follow-on if I want to execute it.";

/// Connected home screen with status, quick actions, and recent activity.
/// Settings (shell mode) and disconnect are now in the sidebar.
/// Seeded chat message for the dashboard's Safety Check card.
///
/// The agent's write-up follows the refined summary layout
/// (project-management#490), the same five sections `safety_check`'s own
/// report uses, so the tool output and the final answer read alike.
pub(crate) const SAFETY_CHECK_PROMPT: &str = "Run the safety_check tool to validate whether this network is safe to use.

The tool checks DNS integrity (hijacking/captive portals), discovers and maps local network devices, and identifies the gateway and DNS resolver IPs. Any check it marks PENDING means a public IP still needs a reputation lookup.

After running safety_check: for each public gateway or DNS IP it reports as needing enrichment, run abuseipdb_check and virustotal on that IP, then fold the threat scores into the final verdict (a confirmed-malicious IP makes the network Not safe).

Write the answer for a non-technical traveler, in exactly these sections and in this order, starting from the tool's `summary` and updating it with the reputation results:
1. A heading with the verdict: Looks safe, Probably safe, Use with caution, or Not safe.
2. \"Your network at a glance\": the tool's network diagram, with any flagged hop highlighted.
3. \"The verdict: is anything malicious?\": exactly two short sentences: whether you saw signs of an attacker, then the bottom line on weaknesses. No list of findings here, and never more certain than the checks allow.
4. \"How this could impact you\": a Scenario | Risk to you table (High direct risk / Medium risk / Low direct risk, and why it touches this person).
5. \"What we recommend\": exactly one sentence they can act on (e.g. use a VPN, avoid sensitive logins, disconnect). End the answer there.";

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
                // Safety Check section - single prominent card
                div { class: "dashboard-section safety-check-section",
                    h3 { class: "dashboard-section-title", "Safety Check" }
                    div { class: "action-grid",
                        div {
                            class: "action-card safety-check-card",
                            onclick: move |_| on_open_chat.call(SAFETY_CHECK_PROMPT.to_string()),
                            span { class: "action-card-icon", Shield { size: 24 } }
                            div { class: "action-card-content",
                                span { class: "action-card-label", "Safety Check" }
                                span { class: "action-card-description", "Verify network security before testing" }
                            }
                        }
                    }
                }

                // Quick actions grid — responsive tiles, each opens chat with a
                // seeded prompt; ordered least- to most-autonomous (AutoPwn last).
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
                            onclick: move |_| on_open_chat.call("Perform a comprehensive network vulnerability assessment. Phase 1: Discover all hosts (ARP scan, mDNS, SSDP, WiFi). Phase 2: For each host, scan ports and grab service banners. Phase 3: Lookup CVEs for discovered services, test default credentials, scan for web vulnerabilities. Generate a detailed report with severity ratings and remediation recommendations.".to_string()),
                            span { class: "action-card-icon", Shield { size: 24 } }
                            span { class: "action-card-label", "Vuln Assessment" }
                        }
                        div {
                            class: "action-card",
                            onclick: move |_| on_open_chat.call("Run a full network discovery — ARP, mDNS, and SSDP — and summarize what you find.".to_string()),
                            span { class: "action-card-icon", Network { size: 24 } }
                            span { class: "action-card-label", "Network Scan" }
                        }
                        div {
                            class: "action-card",
                            onclick: move |_| on_open_chat.call("Scan the local gateway for common open ports and identify running services.".to_string()),
                            span { class: "action-card-icon", Shield { size: 24 } }
                            span { class: "action-card-label", "Port Scan" }
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
                        // Plan-only review gate: produces the phased attack plan via
                        // autopwn_network_plan but executes nothing. No root/WiFi
                        // preflight needed (the tool is Requires Root: No), unlike
                        // the WiFi/AutoPwn tiles.
                        div {
                            class: "action-card",
                            onclick: move |_| on_open_chat.call(NETWORK_ATTACK_PLAN_PROMPT.to_string()),
                            span { class: "action-card-icon", ScrollText { size: 24 } }
                            span { class: "action-card-label", "Network Attack Plan" }
                        }
                        // No interactive shell on iOS (no PTY/proot in the iOS
                        // sandbox), so hide the shell quick-action there.
                        if !cfg!(target_os = "ios") {
                            div {
                                class: "action-card",
                                onclick: move |_| on_open_shell.call(()),
                                span { class: "action-card-icon", Terminal { size: 24 } }
                                span { class: "action-card-label", "Shell" }
                            }
                        }
                        // AutoPwn is the most autonomous / destructive action and is
                        // still maturing, so it sits last and carries a BETA pill to
                        // set expectations before an operator commits to a full run.
                        div {
                            class: "action-card",
                            onclick: move |_| {
                                let action = "Execute automated penetration test: \
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
                                    Walk through the complete attack sequence like a professional penetration tester.".to_string();
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
                            span { class: "beta-badge", "BETA" }
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

#[cfg(test)]
mod tests {
    use super::{NETWORK_ATTACK_PLAN_PROMPT, SAFETY_CHECK_PROMPT};

    #[test]
    fn safety_check_prompt_asks_for_the_summary_layout() {
        // project-management#490: the dashboard write-up uses the same five
        // sections as the safety_check report, in the same order.
        let mut last = 0;
        for section in [
            "safety_check",
            "Use with caution",
            "Your network at a glance",
            "The verdict: is anything malicious?",
            "How this could impact you",
            "Scenario | Risk to you",
            "What we recommend",
        ] {
            let at = SAFETY_CHECK_PROMPT[last..]
                .find(section)
                .unwrap_or_else(|| panic!("'{section}' missing or out of order"));
            last += at + section.len();
        }
        assert!(SAFETY_CHECK_PROMPT.contains("exactly one sentence"));
        assert!(SAFETY_CHECK_PROMPT.contains("exactly two short sentences"));
        assert!(SAFETY_CHECK_PROMPT.contains("End the answer there."));
        // Reputation enrichment still feeds the verdict.
        assert!(SAFETY_CHECK_PROMPT.contains("abuseipdb_check"));
    }

    #[test]
    fn network_attack_plan_prompt_targets_the_planning_tool() {
        assert!(
            NETWORK_ATTACK_PLAN_PROMPT.contains("autopwn_network_plan"),
            "prompt must invoke the autopwn_network_plan tool"
        );
    }

    #[test]
    fn network_attack_plan_prompt_is_plan_only() {
        // The tile's whole point is a review gate that executes nothing; guard the
        // do-not-execute wording so a future edit can't silently make it run phases.
        assert!(
            NETWORK_ATTACK_PLAN_PROMPT.contains("do NOT execute any phase"),
            "prompt must forbid executing any phase"
        );
        assert!(
            NETWORK_ATTACK_PLAN_PROMPT.contains("plan-only"),
            "prompt must state it is plan-only"
        );
        assert!(
            NETWORK_ATTACK_PLAN_PROMPT.contains("run no scans or attacks"),
            "prompt must forbid running scans or attacks"
        );
    }

    #[test]
    fn network_attack_plan_prompt_offers_autopwn_follow_on() {
        assert!(
            NETWORK_ATTACK_PLAN_PROMPT.contains("AutoPwn"),
            "prompt must offer AutoPwn as the follow-on"
        );
    }
}
