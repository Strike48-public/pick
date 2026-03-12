//! Parser for port_scan tool output

use pentest_core::output_parser::{
    OutputParser, ParserContext, PortInfo, PortState, StructuredMessage, TargetDiscovered,
    TargetType,
};
use pentest_core::tools::ToolResult;

/// Parser for port scan results
pub struct PortScanParser;

impl OutputParser for PortScanParser {
    fn parser_name(&self) -> &str {
        "port_scan"
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

        // Extract host information
        let host = match result.data.get("host").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => {
                tracing::warn!("port_scan result missing 'host' field");
                return vec![];
            }
        };

        // Extract ports array
        let ports_data = match result.data.get("ports").and_then(|v| v.as_array()) {
            Some(p) => p,
            None => {
                tracing::warn!("port_scan result missing 'ports' array");
                return vec![];
            }
        };

        // Parse ports
        let mut ports = Vec::new();
        for port_value in ports_data {
            if let Some(port_obj) = port_value.as_object() {
                // Extract port number
                let port_number = match port_obj.get("port").and_then(|v| v.as_u64()) {
                    Some(p) => p as u16,
                    None => continue,
                };

                // Extract open status
                let is_open = port_obj.get("open").and_then(|v| v.as_bool()).unwrap_or(false);

                // Only include open ports in the target discovery
                if is_open {
                    // Extract service info if available
                    let service = port_obj.get("service").and_then(|v| v.as_str()).map(|s| s.to_string());
                    let version = port_obj.get("version").and_then(|v| v.as_str()).map(|s| s.to_string());

                    ports.push(PortInfo {
                        number: port_number,
                        protocol: "tcp".to_string(), // port_scan uses TCP
                        service,
                        version,
                        state: PortState::Open,
                    });
                }
            }
        }

        // Create TargetDiscovered message
        let target = TargetDiscovered {
            target_type: TargetType::Host,
            name: host.to_string(),
            ip_address: Some(host.to_string()),
            hostname: None,
            domain: None,
            os: None,
            ports,
            tags: vec![],
            detection_source: "pick:port_scan".to_string(),
            confidence: Some(95), // High confidence for port scan results
            notes: None,
        };

        messages.push(StructuredMessage::TargetDiscovered(target));

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
    fn test_parse_successful_port_scan() {
        let parser = PortScanParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "host": "192.168.1.1",
                "ports": [
                    {"port": 22, "open": true, "service": "ssh", "version": "OpenSSH 8.2"},
                    {"port": 80, "open": true, "service": "http"},
                    {"port": 443, "open": false}
                ],
                "open_count": 2,
                "total_scanned": 3
            }),
            error: None,
            duration_ms: 1523,
        };

        let context = ParserContext::new(
            "test-engagement".to_string(),
            "test-connector".to_string(),
        );

        let messages = parser.parse("port_scan", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.name, "192.168.1.1");
                assert_eq!(target.ip_address, Some("192.168.1.1".to_string()));
                assert_eq!(target.target_type, TargetType::Host);
                assert_eq!(target.ports.len(), 2); // Only open ports
                assert_eq!(target.ports[0].number, 22);
                assert_eq!(target.ports[0].service, Some("ssh".to_string()));
                assert_eq!(target.ports[0].version, Some("OpenSSH 8.2".to_string()));
                assert_eq!(target.ports[1].number, 80);
                assert_eq!(target.detection_source, "pick:port_scan");
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_failed_result() {
        let parser = PortScanParser;
        let result = ToolResult {
            success: false,
            data: json!({}),
            error: Some("Connection timeout".to_string()),
            duration_ms: 5000,
        };

        let context = ParserContext::new(
            "test-engagement".to_string(),
            "test-connector".to_string(),
        );

        let messages = parser.parse("port_scan", &result, &context);
        assert_eq!(messages.len(), 0);
    }

    #[test]
    fn test_parse_no_open_ports() {
        let parser = PortScanParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "host": "192.168.1.1",
                "ports": [
                    {"port": 22, "open": false},
                    {"port": 80, "open": false}
                ],
                "open_count": 0,
                "total_scanned": 2
            }),
            error: None,
            duration_ms: 1000,
        };

        let context = ParserContext::new(
            "test-engagement".to_string(),
            "test-connector".to_string(),
        );

        let messages = parser.parse("port_scan", &result, &context);

        // Should still create a target, just with no ports
        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.ports.len(), 0);
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }
}
