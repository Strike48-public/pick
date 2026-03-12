//! Parser for wifi_scan_detailed tool output

use chrono::Utc;
use pentest_core::output_parser::{
    Evidence, FindingReported, FindingStatus, OutputParser, ParserContext, Severity,
    StructuredMessage, TargetDiscovered, TargetType,
};
use pentest_core::tools::ToolResult;

/// Parser for detailed WiFi scan results with client detection
pub struct WifiScanDetailedParser;

impl OutputParser for WifiScanDetailedParser {
    fn parser_name(&self) -> &str {
        "wifi_scan_detailed"
    }

    fn parse(
        &self,
        _tool_name: &str,
        result: &ToolResult,
        _context: &ParserContext,
    ) -> Vec<StructuredMessage> {
        // Only parse successful results
        if !result.success {
            return vec![];
        }

        let mut messages = vec![];

        // Extract networks array
        let networks = match result.data.get("networks").and_then(|v| v.as_array()) {
            Some(n) => n,
            None => {
                tracing::warn!("wifi_scan_detailed result missing 'networks' array");
                return vec![];
            }
        };

        // Parse each network
        for network in networks {
            if let Some(network_obj) = network.as_object() {
                // Extract network details
                let ssid = match network_obj.get("ssid").and_then(|v| v.as_str()) {
                    Some(s) => s,
                    None => continue, // Skip networks without SSID
                };

                let bssid = network_obj
                    .get("bssid")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");

                let security = network_obj
                    .get("security")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");

                let signal_strength = network_obj
                    .get("signal_strength")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0) as i32;

                let channel = network_obj
                    .get("channel")
                    .and_then(|v| v.as_u64())
                    .map(|c| c as u32);

                let frequency = network_obj
                    .get("frequency")
                    .and_then(|v| v.as_u64())
                    .map(|f| f as u32);

                let clients = network_obj
                    .get("clients")
                    .and_then(|v| v.as_u64())
                    .map(|c| c as u32);

                // Build notes with client info
                let mut notes = format!(
                    "BSSID: {}, Security: {}, Signal: {} dBm, Channel: {}, Frequency: {} MHz",
                    bssid,
                    security,
                    signal_strength,
                    channel
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "Unknown".to_string()),
                    frequency
                        .map(|f| f.to_string())
                        .unwrap_or_else(|| "Unknown".to_string())
                );

                // Add client count if detected
                if let Some(client_count) = clients {
                    notes.push_str(&format!("\nConnected Clients: {}", client_count));
                }

                // Create TargetDiscovered for this WiFi network
                let target = TargetDiscovered {
                    target_type: TargetType::Network,
                    name: format!("{} ({})", ssid, bssid),
                    ip_address: None,
                    hostname: Some(ssid.to_string()),
                    domain: None,
                    os: None,
                    ports: vec![],
                    tags: vec![
                        "wifi".to_string(),
                        "detailed_scan".to_string(),
                        security.to_lowercase(),
                        format!("channel_{}", channel.unwrap_or(0)),
                    ],
                    detection_source: "pick:wifi_scan_detailed".to_string(),
                    confidence: Some(95), // Higher confidence due to client detection
                    notes: Some(notes),
                };

                messages.push(StructuredMessage::TargetDiscovered(target));

                // Check for security issues and create findings

                // 1. Open network (no encryption)
                if security.to_lowercase() == "open" || security.to_lowercase() == "none" {
                    let finding = FindingReported {
                        title: format!("Open WiFi Network Detected: {}", ssid),
                        description: format!(
                            "The WiFi network '{}' (BSSID: {}) is configured without encryption. \
                            Anyone within range can connect and intercept network traffic. \
                            {} detected during detailed scan.",
                            ssid,
                            bssid,
                            if let Some(count) = clients {
                                format!("{} client(s) connected", count)
                            } else {
                                "Client count unknown".to_string()
                            }
                        ),
                        severity: Severity::High,
                        status: FindingStatus::Confirmed,
                        evidence: vec![Evidence {
                            evidence_type: "wifi_scan_detailed".to_string(),
                            description: format!("Open network detected at {} dBm signal strength", signal_strength),
                            data: format!(
                                "SSID: {}, BSSID: {}, Security: {}, Clients: {}",
                                ssid,
                                bssid,
                                security,
                                clients.map(|c| c.to_string()).unwrap_or_else(|| "unknown".to_string())
                            ),
                            timestamp: Utc::now(),
                        }],
                        mitre_techniques: vec!["T1040".to_string()], // Network Sniffing
                        remediation: Some(
                            "Enable WPA3 or at minimum WPA2 encryption on the wireless network. \
                            Open networks should only be used for guest access with proper network segmentation."
                                .to_string(),
                        ),
                        cve_ids: vec![],
                        target_ids: vec![],
                        credential_ids: vec![],
                    };

                    messages.push(StructuredMessage::FindingReported(finding));
                }

                // 2. WEP encryption (deprecated and insecure)
                if security.to_lowercase().contains("wep") {
                    let finding = FindingReported {
                        title: format!("Insecure WEP Encryption Detected: {}", ssid),
                        description: format!(
                            "The WiFi network '{}' (BSSID: {}) uses WEP encryption, which has been \
                            deprecated since 2004 and can be cracked in minutes. WEP provides no \
                            meaningful security against modern attacks. \
                            {} detected during detailed scan.",
                            ssid,
                            bssid,
                            if let Some(count) = clients {
                                format!("{} client(s) connected", count)
                            } else {
                                "Client count unknown".to_string()
                            }
                        ),
                        severity: Severity::Critical,
                        status: FindingStatus::Confirmed,
                        evidence: vec![Evidence {
                            evidence_type: "wifi_scan_detailed".to_string(),
                            description: format!(
                                "WEP encryption detected at {} dBm signal strength",
                                signal_strength
                            ),
                            data: format!(
                                "SSID: {}, BSSID: {}, Security: {}, Clients: {}",
                                ssid,
                                bssid,
                                security,
                                clients
                                    .map(|c| c.to_string())
                                    .unwrap_or_else(|| "unknown".to_string())
                            ),
                            timestamp: Utc::now(),
                        }],
                        mitre_techniques: vec!["T1040".to_string(), "T1557".to_string()], // Network Sniffing, MITM
                        remediation: Some(
                            "Immediately upgrade to WPA3 or at minimum WPA2 with AES encryption. \
                            WEP should never be used in any security context."
                                .to_string(),
                        ),
                        cve_ids: vec![],
                        target_ids: vec![],
                        credential_ids: vec![],
                    };

                    messages.push(StructuredMessage::FindingReported(finding));
                }

                // 3. Networks with many clients (potential high-value targets for WPA attacks)
                if let Some(count) = clients {
                    if count >= 5 && (security.contains("WPA") || security.contains("PSK")) {
                        let finding = FindingReported {
                            title: format!("High-Value WiFi Target: {} ({} clients)", ssid, count),
                            description: format!(
                                "The WiFi network '{}' (BSSID: {}) has {} connected clients. \
                                Networks with active clients are valuable targets for WPA handshake capture and \
                                credential attacks. With sufficient client activity, a 4-way handshake can be \
                                captured for offline password cracking.",
                                ssid, bssid, count
                            ),
                            severity: Severity::Medium,
                            status: FindingStatus::Confirmed,
                            evidence: vec![Evidence {
                                evidence_type: "wifi_scan_detailed".to_string(),
                                description: format!("{} connected clients detected", count),
                                data: format!(
                                    "SSID: {}, BSSID: {}, Security: {}, Clients: {}, Signal: {} dBm",
                                    ssid, bssid, security, count, signal_strength
                                ),
                                timestamp: Utc::now(),
                            }],
                            mitre_techniques: vec![
                                "T1040".to_string(), // Network Sniffing
                                "T1110".to_string(), // Brute Force
                            ],
                            remediation: Some(
                                "Use WPA3 with strong passwords (20+ characters). \
                                Regularly rotate WiFi passwords. \
                                Implement network segmentation to limit impact of credential compromise."
                                    .to_string(),
                            ),
                            cve_ids: vec![],
                            target_ids: vec![],
                            credential_ids: vec![],
                        };

                        messages.push(StructuredMessage::FindingReported(finding));
                    }
                }
            }
        }

        messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::output_parser::ParserContext;
    use pentest_core::tools::ToolResult;
    use serde_json::json;

    #[test]
    fn test_parse_wifi_scan_detailed_with_clients() {
        let parser = WifiScanDetailedParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "networks": [
                    {
                        "ssid": "CoffeeShop-WiFi",
                        "bssid": "AA:BB:CC:DD:EE:FF",
                        "signal_strength": -45,
                        "frequency": 2437,
                        "channel": 6,
                        "security": "WPA2-PSK",
                        "clients": 8
                    }
                ],
                "count": 1,
                "duration_sec": 30
            }),
            error: None,
            duration_ms: 35000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("wifi_scan_detailed", &result, &context);

        // Should create 1 target + 1 finding (high-value target with 8 clients)
        assert_eq!(messages.len(), 2);

        // Check target
        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.target_type, TargetType::Network);
                assert!(target.name.contains("CoffeeShop-WiFi"));
                assert!(target.tags.contains(&"detailed_scan".to_string()));
                assert!(target
                    .notes
                    .as_ref()
                    .unwrap()
                    .contains("Connected Clients: 8"));
                assert_eq!(target.confidence, Some(95));
            }
            _ => panic!("Expected TargetDiscovered message"),
        }

        // Check high-value target finding
        match &messages[1] {
            StructuredMessage::FindingReported(finding) => {
                assert!(finding.title.contains("High-Value WiFi Target"));
                assert!(finding.title.contains("8 clients"));
                assert_eq!(finding.severity, Severity::Medium);
                assert!(finding.mitre_techniques.contains(&"T1110".to_string()));
            }
            _ => panic!("Expected FindingReported message"),
        }
    }

    #[test]
    fn test_parse_wifi_scan_detailed_open_network() {
        let parser = WifiScanDetailedParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "networks": [
                    {
                        "ssid": "FreeWiFi",
                        "bssid": "11:22:33:44:55:66",
                        "signal_strength": -60,
                        "frequency": 2412,
                        "channel": 1,
                        "security": "Open",
                        "clients": 3
                    }
                ],
                "count": 1,
                "duration_sec": 30
            }),
            error: None,
            duration_ms: 32000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("wifi_scan_detailed", &result, &context);

        // Should create 1 target + 1 finding (open network)
        assert_eq!(messages.len(), 2);

        match &messages[1] {
            StructuredMessage::FindingReported(finding) => {
                assert!(finding.title.contains("Open WiFi Network"));
                assert_eq!(finding.severity, Severity::High);
                assert!(finding.description.contains("3 client(s) connected"));
            }
            _ => panic!("Expected FindingReported message"),
        }
    }

    #[test]
    fn test_parse_wifi_scan_detailed_no_clients() {
        let parser = WifiScanDetailedParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "networks": [
                    {
                        "ssid": "SecureNet",
                        "bssid": "AA:BB:CC:DD:EE:00",
                        "signal_strength": -50,
                        "frequency": 5180,
                        "channel": 36,
                        "security": "WPA3",
                        "clients": 0
                    }
                ],
                "count": 1,
                "duration_sec": 30
            }),
            error: None,
            duration_ms: 31000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("wifi_scan_detailed", &result, &context);

        // Should only create target, no findings (secure WPA3 with no clients)
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn test_parse_failed_wifi_scan_detailed() {
        let parser = WifiScanDetailedParser;
        let result = ToolResult {
            success: false,
            data: json!({}),
            error: Some("Failed to enable monitor mode".to_string()),
            duration_ms: 5000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("wifi_scan_detailed", &result, &context);
        assert_eq!(messages.len(), 0);
    }
}
