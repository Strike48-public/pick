//! Parser for wifi_scan tool output

use pentest_core::output_parser::{
    Evidence, FindingReported, FindingStatus, OutputParser, ParserContext, Severity,
    StructuredMessage, TargetDiscovered, TargetType,
};
use pentest_core::tools::ToolResult;
use chrono::Utc;

/// Parser for WiFi scan results
pub struct WifiScanParser;

impl OutputParser for WifiScanParser {
    fn parser_name(&self) -> &str {
        "wifi_scan"
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
                tracing::warn!("wifi_scan result missing 'networks' array");
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
                        security.to_lowercase(),
                        format!("channel_{}", channel.unwrap_or(0)),
                    ],
                    detection_source: "pick:wifi_scan".to_string(),
                    confidence: Some(90),
                    notes: Some(format!(
                        "BSSID: {}, Security: {}, Signal: {} dBm, Channel: {}, Frequency: {} MHz",
                        bssid,
                        security,
                        signal_strength,
                        channel.map(|c| c.to_string()).unwrap_or_else(|| "Unknown".to_string()),
                        frequency.map(|f| f.to_string()).unwrap_or_else(|| "Unknown".to_string())
                    )),
                };

                messages.push(StructuredMessage::TargetDiscovered(target));

                // Check for security issues and create findings

                // 1. Open network (no encryption)
                if security.to_lowercase() == "open" || security.to_lowercase() == "none" {
                    let finding = FindingReported {
                        title: format!("Open WiFi Network Detected: {}", ssid),
                        description: format!(
                            "The WiFi network '{}' (BSSID: {}) is configured without encryption. \
                            Anyone within range can connect and intercept network traffic.",
                            ssid, bssid
                        ),
                        severity: Severity::High,
                        status: FindingStatus::Confirmed,
                        evidence: vec![Evidence {
                            evidence_type: "wifi_scan".to_string(),
                            description: format!("Open network detected at {} dBm signal strength", signal_strength),
                            data: format!("SSID: {}, BSSID: {}, Security: {}", ssid, bssid, security),
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
                            meaningful security against modern attacks.",
                            ssid, bssid
                        ),
                        severity: Severity::Critical,
                        status: FindingStatus::Confirmed,
                        evidence: vec![Evidence {
                            evidence_type: "wifi_scan".to_string(),
                            description: format!("WEP encryption detected at {} dBm signal strength", signal_strength),
                            data: format!("SSID: {}, BSSID: {}, Security: {}", ssid, bssid, security),
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

                // 3. WPA (original, deprecated) vs WPA2/WPA3
                if security.to_lowercase() == "wpa" && !security.to_lowercase().contains("wpa2") && !security.to_lowercase().contains("wpa3") {
                    let finding = FindingReported {
                        title: format!("Deprecated WPA Encryption Detected: {}", ssid),
                        description: format!(
                            "The WiFi network '{}' (BSSID: {}) uses the original WPA encryption, \
                            which has known vulnerabilities. WPA2 or WPA3 should be used instead.",
                            ssid, bssid
                        ),
                        severity: Severity::Medium,
                        status: FindingStatus::Confirmed,
                        evidence: vec![Evidence {
                            evidence_type: "wifi_scan".to_string(),
                            description: format!("WPA (non-WPA2/WPA3) encryption detected at {} dBm signal strength", signal_strength),
                            data: format!("SSID: {}, BSSID: {}, Security: {}", ssid, bssid, security),
                            timestamp: Utc::now(),
                        }],
                        mitre_techniques: vec!["T1040".to_string()],
                        remediation: Some(
                            "Upgrade to WPA3 (preferred) or WPA2 with AES encryption."
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
    fn test_parse_wifi_scan_with_open_network() {
        let parser = WifiScanParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "networks": [
                    {
                        "ssid": "OpenNetwork",
                        "bssid": "AA:BB:CC:DD:EE:FF",
                        "signal_strength": -45,
                        "signal_quality": 85,
                        "signal_bars": 4,
                        "frequency": 2437,
                        "channel": 6,
                        "security": "Open",
                        "clients": 3
                    }
                ],
                "count": 1
            }),
            error: None,
            duration_ms: 2000,
        };

        let context = ParserContext::new(
            "test-engagement".to_string(),
            "test-connector".to_string(),
        );

        let messages = parser.parse("wifi_scan", &result, &context);

        // Should create 1 target + 1 finding (open network)
        assert_eq!(messages.len(), 2);

        // Check target
        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.target_type, TargetType::Network);
                assert!(target.name.contains("OpenNetwork"));
                assert!(target.tags.contains(&"open".to_string()));
                assert_eq!(target.detection_source, "pick:wifi_scan");
            }
            _ => panic!("Expected TargetDiscovered message"),
        }

        // Check finding
        match &messages[1] {
            StructuredMessage::FindingReported(finding) => {
                assert!(finding.title.contains("Open WiFi Network"));
                assert_eq!(finding.severity, Severity::High);
                assert!(finding.mitre_techniques.contains(&"T1040".to_string()));
            }
            _ => panic!("Expected FindingReported message"),
        }
    }

    #[test]
    fn test_parse_wifi_scan_with_wep() {
        let parser = WifiScanParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "networks": [
                    {
                        "ssid": "InsecureNetwork",
                        "bssid": "11:22:33:44:55:66",
                        "signal_strength": -60,
                        "frequency": 2412,
                        "channel": 1,
                        "security": "WEP",
                        "clients": 1
                    }
                ],
                "count": 1
            }),
            error: None,
            duration_ms: 2000,
        };

        let context = ParserContext::new(
            "test-engagement".to_string(),
            "test-connector".to_string(),
        );

        let messages = parser.parse("wifi_scan", &result, &context);

        // Should create 1 target + 1 finding (WEP)
        assert_eq!(messages.len(), 2);

        match &messages[1] {
            StructuredMessage::FindingReported(finding) => {
                assert!(finding.title.contains("Insecure WEP"));
                assert_eq!(finding.severity, Severity::Critical);
                assert!(finding.description.contains("cracked in minutes"));
            }
            _ => panic!("Expected FindingReported message"),
        }
    }

    #[test]
    fn test_parse_wifi_scan_with_secure_network() {
        let parser = WifiScanParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "networks": [
                    {
                        "ssid": "SecureNetwork",
                        "bssid": "AA:BB:CC:DD:EE:FF",
                        "signal_strength": -50,
                        "frequency": 5180,
                        "channel": 36,
                        "security": "WPA2-PSK",
                        "clients": 5
                    }
                ],
                "count": 1
            }),
            error: None,
            duration_ms: 2000,
        };

        let context = ParserContext::new(
            "test-engagement".to_string(),
            "test-connector".to_string(),
        );

        let messages = parser.parse("wifi_scan", &result, &context);

        // Should only create 1 target (no findings for secure WPA2)
        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert!(target.name.contains("SecureNetwork"));
                assert!(target.tags.contains(&"wpa2-psk".to_string()));
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_failed_wifi_scan() {
        let parser = WifiScanParser;
        let result = ToolResult {
            success: false,
            data: json!({}),
            error: Some("No WiFi adapter found".to_string()),
            duration_ms: 100,
        };

        let context = ParserContext::new(
            "test-engagement".to_string(),
            "test-connector".to_string(),
        );

        let messages = parser.parse("wifi_scan", &result, &context);
        assert_eq!(messages.len(), 0);
    }
}
