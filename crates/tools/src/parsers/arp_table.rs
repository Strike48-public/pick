//! Parser for arp_table tool output

use pentest_core::output_parser::{
    OutputParser, ParserContext, StructuredMessage, TargetDiscovered, TargetType,
};
use pentest_core::tools::ToolResult;

/// Parser for ARP table results
pub struct ArpTableParser;

impl OutputParser for ArpTableParser {
    fn parser_name(&self) -> &str {
        "arp_table"
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

        // Extract entries array
        let entries = match result.data.get("entries").and_then(|v| v.as_array()) {
            Some(e) => e,
            None => {
                tracing::warn!("arp_table result missing 'entries' array");
                return vec![];
            }
        };

        // Parse each ARP entry
        for entry in entries {
            if let Some(entry_obj) = entry.as_object() {
                // Extract entry details
                let ip = match entry_obj.get("ip").and_then(|v| v.as_str()) {
                    Some(i) => i,
                    None => continue, // Skip entries without IP
                };

                let mac = entry_obj
                    .get("mac")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");

                let interface = entry_obj
                    .get("interface")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");

                let hostname = entry_obj
                    .get("hostname")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // Create TargetDiscovered for this host
                let target = TargetDiscovered {
                    target_type: TargetType::Host,
                    name: hostname.clone().unwrap_or_else(|| ip.to_string()),
                    ip_address: Some(ip.to_string()),
                    hostname: hostname.clone(),
                    domain: None,
                    os: None,
                    ports: vec![],
                    tags: vec!["arp".to_string(), "local-network".to_string()],
                    detection_source: "pick:arp_table".to_string(),
                    confidence: Some(95), // Very high confidence - from ARP cache
                    notes: Some(format!(
                        "MAC: {}, Interface: {}",
                        mac, interface
                    )),
                };

                messages.push(StructuredMessage::TargetDiscovered(target));
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
    fn test_parse_arp_table_with_hostnames() {
        let parser = ArpTableParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "entries": [
                    {
                        "ip": "192.168.1.1",
                        "mac": "00:11:22:33:44:55",
                        "interface": "eth0",
                        "hostname": "router.local"
                    },
                    {
                        "ip": "192.168.1.100",
                        "mac": "AA:BB:CC:DD:EE:FF",
                        "interface": "eth0",
                        "hostname": "workstation.local"
                    }
                ],
                "count": 2
            }),
            error: None,
            duration_ms: 50,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("arp_table", &result, &context);

        assert_eq!(messages.len(), 2);

        // Check first entry
        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.name, "router.local");
                assert_eq!(target.ip_address, Some("192.168.1.1".to_string()));
                assert_eq!(target.hostname, Some("router.local".to_string()));
                assert_eq!(target.target_type, TargetType::Host);
                assert!(target.tags.contains(&"arp".to_string()));
                assert!(target.tags.contains(&"local-network".to_string()));
                assert_eq!(target.detection_source, "pick:arp_table");
                assert!(target.notes.as_ref().unwrap().contains("00:11:22:33:44:55"));
            }
            _ => panic!("Expected TargetDiscovered message"),
        }

        // Check second entry
        match &messages[1] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.name, "workstation.local");
                assert_eq!(target.ip_address, Some("192.168.1.100".to_string()));
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_arp_table_without_hostnames() {
        let parser = ArpTableParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "entries": [
                    {
                        "ip": "192.168.1.50",
                        "mac": "11:22:33:44:55:66",
                        "interface": "wlan0",
                        "hostname": null
                    }
                ],
                "count": 1
            }),
            error: None,
            duration_ms: 30,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("arp_table", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.name, "192.168.1.50"); // IP used as name when no hostname
                assert_eq!(target.hostname, None);
                assert!(target.notes.as_ref().unwrap().contains("wlan0"));
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_empty_arp_table() {
        let parser = ArpTableParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "entries": [],
                "count": 0
            }),
            error: None,
            duration_ms: 20,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("arp_table", &result, &context);
        assert_eq!(messages.len(), 0);
    }

    #[test]
    fn test_parse_failed_arp_table() {
        let parser = ArpTableParser;
        let result = ToolResult {
            success: false,
            data: json!({}),
            error: Some("Permission denied".to_string()),
            duration_ms: 10,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("arp_table", &result, &context);
        assert_eq!(messages.len(), 0);
    }
}
