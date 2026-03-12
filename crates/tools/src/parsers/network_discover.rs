//! Parser for network_discover tool output

use pentest_core::output_parser::{
    OutputParser, ParserContext, PortInfo, PortState, StructuredMessage, TargetDiscovered,
    TargetType,
};
use pentest_core::tools::ToolResult;

/// Parser for mDNS/DNS-SD network discovery results
pub struct NetworkDiscoverParser;

impl OutputParser for NetworkDiscoverParser {
    fn parser_name(&self) -> &str {
        "network_discover"
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

        // Extract services array
        let services = match result.data.get("services").and_then(|v| v.as_array()) {
            Some(s) => s,
            None => {
                tracing::warn!("network_discover result missing 'services' array");
                return vec![];
            }
        };

        // Parse each discovered service
        for service in services {
            if let Some(service_obj) = service.as_object() {
                // Extract service details
                let name = service_obj
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown Service");

                let service_type = service_obj
                    .get("service_type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("_unknown._tcp.local.");

                let host = match service_obj.get("host").and_then(|v| v.as_str()) {
                    Some(h) => h,
                    None => continue, // Skip services without host
                };

                let port = service_obj
                    .get("port")
                    .and_then(|v| v.as_u64())
                    .map(|p| p as u16);

                // Extract TXT records if available
                let txt_records = service_obj
                    .get("txt_records")
                    .and_then(|v| v.as_object())
                    .map(|obj| {
                        obj.iter()
                            .map(|(k, v)| {
                                let value = v.as_str().map(|s| s.to_string()).unwrap_or_else(|| v.to_string());
                                format!("{}={}", k, value)
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    });

                // Determine target type based on service
                let target_type = if service_type.contains("_http") || service_type.contains("_https") {
                    TargetType::Service
                } else if service_type.contains("_printer") || service_type.contains("_ipp") {
                    TargetType::Service
                } else if service_type.contains("_smb") || service_type.contains("_afp") {
                    TargetType::Service
                } else {
                    TargetType::Host
                };

                // Infer protocol from service type
                let protocol = if service_type.contains("._tcp.") {
                    "tcp"
                } else if service_type.contains("._udp.") {
                    "udp"
                } else {
                    "tcp" // default
                };

                // Create port info if port is available
                let ports = if let Some(port_num) = port {
                    vec![PortInfo {
                        number: port_num,
                        protocol: protocol.to_string(),
                        service: Some(extract_service_name(service_type)),
                        version: None,
                        state: PortState::Open,
                    }]
                } else {
                    vec![]
                };

                // Extract tags from service type and txt records
                let mut tags = vec!["mdns".to_string(), extract_service_name(service_type)];

                // Add specific tags based on service type
                if service_type.contains("googlecast") {
                    tags.push("chromecast".to_string());
                } else if service_type.contains("airplay") {
                    tags.push("apple".to_string());
                } else if service_type.contains("printer") || service_type.contains("ipp") {
                    tags.push("printer".to_string());
                } else if service_type.contains("smb") {
                    tags.push("file-sharing".to_string());
                }

                // Build notes with TXT record info
                let notes = if let Some(ref txt) = txt_records {
                    Some(format!(
                        "mDNS service: {} ({})\nTXT Records: {}",
                        name, service_type, txt
                    ))
                } else {
                    Some(format!("mDNS service: {} ({})", name, service_type))
                };

                // Create TargetDiscovered message
                let target = TargetDiscovered {
                    target_type,
                    name: name.to_string(),
                    ip_address: Some(host.to_string()),
                    hostname: Some(host.to_string()),
                    domain: None,
                    os: None,
                    ports,
                    tags,
                    detection_source: "pick:network_discover".to_string(),
                    confidence: Some(85), // High confidence for mDNS responses
                    notes,
                };

                messages.push(StructuredMessage::TargetDiscovered(target));
            }
        }

        messages
    }
}

/// Extract service name from mDNS service type
/// e.g., "_http._tcp.local." -> "http"
fn extract_service_name(service_type: &str) -> String {
    service_type
        .trim_start_matches('_')
        .split('.')
        .next()
        .unwrap_or("unknown")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::output_parser::ParserContext;
    use pentest_core::tools::ToolResult;
    use serde_json::json;

    #[test]
    fn test_parse_chromecast_discovery() {
        let parser = NetworkDiscoverParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "services": [
                    {
                        "name": "Living Room TV",
                        "service_type": "_googlecast._tcp.local.",
                        "host": "192.168.1.50",
                        "port": 8009,
                        "txt_records": {
                            "id": "abc123def456",
                            "model": "Chromecast",
                            "version": "1.0"
                        }
                    }
                ],
                "count": 1
            }),
            error: None,
            duration_ms: 5000,
        };

        let context = ParserContext::new(
            "test-engagement".to_string(),
            "test-connector".to_string(),
        );

        let messages = parser.parse("network_discover", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.name, "Living Room TV");
                assert_eq!(target.ip_address, Some("192.168.1.50".to_string()));
                assert_eq!(target.ports.len(), 1);
                assert_eq!(target.ports[0].number, 8009);
                assert_eq!(target.ports[0].service, Some("googlecast".to_string()));
                assert!(target.tags.contains(&"chromecast".to_string()));
                assert!(target.tags.contains(&"mdns".to_string()));
                assert_eq!(target.detection_source, "pick:network_discover");
                assert!(target.notes.as_ref().unwrap().contains("TXT Records"));
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_multiple_services() {
        let parser = NetworkDiscoverParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "services": [
                    {
                        "name": "Network Printer",
                        "service_type": "_ipp._tcp.local.",
                        "host": "192.168.1.100",
                        "port": 631,
                        "txt_records": {}
                    },
                    {
                        "name": "File Server",
                        "service_type": "_smb._tcp.local.",
                        "host": "192.168.1.200",
                        "port": 445,
                        "txt_records": {}
                    }
                ],
                "count": 2
            }),
            error: None,
            duration_ms: 8000,
        };

        let context = ParserContext::new(
            "test-engagement".to_string(),
            "test-connector".to_string(),
        );

        let messages = parser.parse("network_discover", &result, &context);

        assert_eq!(messages.len(), 2);

        // Check printer
        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.name, "Network Printer");
                assert!(target.tags.contains(&"printer".to_string()));
                assert_eq!(target.ports[0].number, 631);
            }
            _ => panic!("Expected TargetDiscovered message"),
        }

        // Check file server
        match &messages[1] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.name, "File Server");
                assert!(target.tags.contains(&"file-sharing".to_string()));
                assert_eq!(target.ports[0].number, 445);
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_service_without_port() {
        let parser = NetworkDiscoverParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "services": [
                    {
                        "name": "Unknown Device",
                        "service_type": "_device-info._tcp.local.",
                        "host": "192.168.1.150",
                        "txt_records": {}
                    }
                ],
                "count": 1
            }),
            error: None,
            duration_ms: 3000,
        };

        let context = ParserContext::new(
            "test-engagement".to_string(),
            "test-connector".to_string(),
        );

        let messages = parser.parse("network_discover", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.ports.len(), 0); // No port info
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_extract_service_name() {
        assert_eq!(extract_service_name("_http._tcp.local."), "http");
        assert_eq!(extract_service_name("_googlecast._tcp.local."), "googlecast");
        assert_eq!(extract_service_name("_printer._tcp.local."), "printer");
        assert_eq!(extract_service_name("unknown"), "unknown");
    }

    #[test]
    fn test_parse_failed_discovery() {
        let parser = NetworkDiscoverParser;
        let result = ToolResult {
            success: false,
            data: json!({}),
            error: Some("Network timeout".to_string()),
            duration_ms: 10000,
        };

        let context = ParserContext::new(
            "test-engagement".to_string(),
            "test-connector".to_string(),
        );

        let messages = parser.parse("network_discover", &result, &context);
        assert_eq!(messages.len(), 0);
    }
}
