//! Central registration of all quick actions

use super::{ActionStyle, ActionTemplate, QuickAction, QuickActionProvider, QuickActionRegistry, TablerIcon};

/// Register all tool quick actions
pub fn register_all_actions(registry: &mut QuickActionRegistry) {
    // WiFi tools
    register_wifi_scan_actions(registry);
    register_wifi_scan_detailed_actions(registry);

    // Network scanning tools
    register_port_scan_actions(registry);
    register_network_discover_actions(registry);
}

// WiFi Scan Actions

struct WifiScanActionProvider;

impl QuickActionProvider for WifiScanActionProvider {
    fn tool_name(&self) -> &str {
        "wifi_scan"
    }

    fn provide_actions(&self, _result_json: &str) -> Vec<QuickAction> {
        vec![ActionTemplate {
            id: "wifi_detailed".into(),
            label: "Detailed Scan".into(),
            description: "Show client counts (~30s)".into(),
            icon: TablerIcon::Scan,
            style: ActionStyle::Primary,
            prompt: "Run a detailed WiFi scan with client detection (~30 seconds). \
                     This will show how many devices are connected to each network, \
                     which helps identify easier targets for WPA/WPA2/WPA3 attacks."
                .into(),
        }
        .to_action()]
    }
}

fn register_wifi_scan_actions(registry: &mut QuickActionRegistry) {
    registry.register_dynamic(Box::new(WifiScanActionProvider));
}

// WiFi Scan Detailed Actions

struct WifiScanDetailedActionProvider;

impl QuickActionProvider for WifiScanDetailedActionProvider {
    fn tool_name(&self) -> &str {
        "wifi_scan_detailed"
    }

    fn provide_actions(&self, _result_json: &str) -> Vec<QuickAction> {
        vec![
            ActionTemplate {
                id: "network_pentest".into(),
                label: "Full Network Pentest".into(),
                description: "Complete attack sequence (~30 min)".into(),
                icon: TablerIcon::Network,
                style: ActionStyle::Primary,
                prompt: "Plan a full network penetration test sequence. This will create an \
                         automated attack plan covering: network discovery, port scanning, \
                         service enumeration, vulnerability assessment, and exploitation planning."
                    .into(),
            }
            .to_action(),
            ActionTemplate {
                id: "network_recon".into(),
                label: "Network Recon".into(),
                description: "Discovery only (~5 min)".into(),
                icon: TablerIcon::Radar,
                style: ActionStyle::Secondary,
                prompt: "Plan a quick network reconnaissance scan. This will discover live hosts, \
                         advertised services, and perform a light port scan without active exploitation."
                    .into(),
            }
            .to_action(),
        ]
    }
}

fn register_wifi_scan_detailed_actions(registry: &mut QuickActionRegistry) {
    registry.register_dynamic(Box::new(WifiScanDetailedActionProvider));
}

// Port Scan Actions

struct PortScanActionProvider;

impl QuickActionProvider for PortScanActionProvider {
    fn tool_name(&self) -> &str {
        "port_scan"
    }

    fn provide_actions(&self, result_json: &str) -> Vec<QuickAction> {
        let mut actions = vec![];

        // Try to parse the result to provide smart actions
        if let Ok(scan_result) = serde_json::from_str::<serde_json::Value>(result_json) {
            // Check if we found open ports
            let has_web = check_for_port(&scan_result, 80) || check_for_port(&scan_result, 443);
            let has_ssh = check_for_port(&scan_result, 22);
            let has_smb = check_for_port(&scan_result, 445) || check_for_port(&scan_result, 139);

            // Web server detected - offer web vulnerability scan
            if has_web {
                actions.push(
                    ActionTemplate {
                        id: "web_vuln_scan".into(),
                        label: "Web Vulnerability Scan".into(),
                        description: "Test for SQL injection, XSS, etc.".into(),
                        icon: TablerIcon::Bug,
                        style: ActionStyle::Danger,
                        prompt: "Run a web vulnerability scan on the discovered web server. \
                                 This will test for common vulnerabilities like SQL injection, \
                                 XSS, directory traversal, and misconfigurations."
                            .into(),
                    }
                    .to_action(),
                );
            }

            // SSH detected - offer credential testing
            if has_ssh {
                actions.push(
                    ActionTemplate {
                        id: "ssh_default_creds".into(),
                        label: "Test SSH Credentials".into(),
                        description: "Try common username/password combos".into(),
                        icon: TablerIcon::Key,
                        style: ActionStyle::Danger,
                        prompt: "Test default SSH credentials on the target. \
                                 This will try common username/password combinations."
                            .into(),
                    }
                    .to_action(),
                );
            }

            // SMB detected - offer enumeration
            if has_smb {
                actions.push(
                    ActionTemplate {
                        id: "smb_enum".into(),
                        label: "SMB Enumeration".into(),
                        description: "Enumerate shares and users".into(),
                        icon: TablerIcon::Database,
                        style: ActionStyle::Primary,
                        prompt: "Run SMB enumeration to discover shares, users, and domain information."
                            .into(),
                    }
                    .to_action(),
                );
            }

            // Always offer service banner grabbing if we found any ports
            if !actions.is_empty() {
                actions.push(
                    ActionTemplate {
                        id: "service_banner".into(),
                        label: "Grab Service Banners".into(),
                        description: "Identify service versions".into(),
                        icon: TablerIcon::FileReport,
                        style: ActionStyle::Secondary,
                        prompt: "Grab service banners from open ports to identify software versions \
                                 and potential vulnerabilities."
                            .into(),
                    }
                    .to_action(),
                );
            }
        }

        actions
    }
}

fn register_port_scan_actions(registry: &mut QuickActionRegistry) {
    registry.register_dynamic(Box::new(PortScanActionProvider));
}

// Network Discover Actions

struct NetworkDiscoverActionProvider;

impl QuickActionProvider for NetworkDiscoverActionProvider {
    fn tool_name(&self) -> &str {
        "network_discover"
    }

    fn provide_actions(&self, result_json: &str) -> Vec<QuickAction> {
        let mut actions = vec![];

        // Try to parse and count discovered hosts
        if let Ok(discover_result) = serde_json::from_str::<serde_json::Value>(result_json) {
            let host_count = discover_result
                .get("hosts")
                .and_then(|h| h.as_array())
                .map(|arr| arr.len())
                .unwrap_or(0);

            if host_count > 0 {
                // Offer to port scan discovered hosts
                actions.push(
                    ActionTemplate {
                        id: "port_scan_all".into(),
                        label: format!("Port Scan {} Host{}", host_count, if host_count == 1 { "" } else { "s" }),
                        description: "Scan for open ports".into(),
                        icon: TablerIcon::Target,
                        style: ActionStyle::Primary,
                        prompt: format!(
                            "Run a port scan on the {} discovered host{}. \
                             This will identify open ports and running services.",
                            host_count,
                            if host_count == 1 { "" } else { "s" }
                        ),
                    }
                    .to_action(),
                );

                // Offer service enumeration
                actions.push(
                    ActionTemplate {
                        id: "service_enum".into(),
                        label: "Service Enumeration".into(),
                        description: "Identify running services".into(),
                        icon: TablerIcon::Search,
                        style: ActionStyle::Secondary,
                        prompt: "Run service enumeration to identify software versions \
                                 and gather detailed information about running services."
                            .into(),
                    }
                    .to_action(),
                );
            }
        }

        actions
    }
}

fn register_network_discover_actions(registry: &mut QuickActionRegistry) {
    registry.register_dynamic(Box::new(NetworkDiscoverActionProvider));
}

// Helper functions

/// Check if a port appears in the scan result
fn check_for_port(result: &serde_json::Value, port: u16) -> bool {
    result
        .get("open_ports")
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().any(|p| p.as_u64() == Some(port as u64)))
        .unwrap_or(false)
}
