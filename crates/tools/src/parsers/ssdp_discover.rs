//! Parser for ssdp_discover tool output

use pentest_core::output_parser::{
    OutputParser, ParserContext, PortInfo, PortState, StructuredMessage, TargetDiscovered,
    TargetType,
};
use pentest_core::tools::ToolResult;

/// Parser for SSDP/UPnP discovery results
pub struct SsdpDiscoverParser;

impl SsdpDiscoverParser {
    /// Extract device type from USN or ST field
    fn extract_device_type(usn: &str, st: &str) -> String {
        // Try ST (service type) first
        if st.contains("MediaRenderer") {
            return "media_renderer".to_string();
        } else if st.contains("MediaServer") {
            return "media_server".to_string();
        } else if st.contains("WANDevice") || st.contains("InternetGateway") {
            return "router".to_string();
        } else if st.contains("Printer") {
            return "printer".to_string();
        }

        // Try USN as fallback
        if usn.contains("MediaRenderer") {
            "media_renderer".to_string()
        } else if usn.contains("MediaServer") {
            "media_server".to_string()
        } else if usn.contains("WANDevice") || usn.contains("InternetGateway") {
            "router".to_string()
        } else if usn.contains("Printer") {
            "printer".to_string()
        } else {
            "upnp_device".to_string()
        }
    }

    /// Extract hostname/IP from location URL
    fn extract_host(location: &str) -> Option<String> {
        location
            .split("://")
            .nth(1)
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.split(':').next())
            .map(|s| s.to_string())
    }

    /// Extract port from location URL
    fn extract_port(location: &str) -> Option<u16> {
        location
            .split("://")
            .nth(1)
            .and_then(|s| s.split('/').next())
            .and_then(|s| s.split(':').nth(1))
            .and_then(|p| p.parse().ok())
    }
}

impl OutputParser for SsdpDiscoverParser {
    fn parser_name(&self) -> &str {
        "ssdp_discover"
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

        // Extract devices array
        let devices = match result.data.get("devices").and_then(|v| v.as_array()) {
            Some(d) => d,
            None => {
                tracing::warn!("ssdp_discover result missing 'devices' array");
                return vec![];
            }
        };

        // Parse each discovered device
        for device in devices {
            if let Some(device_obj) = device.as_object() {
                let location = device_obj
                    .get("location")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let server = device_obj
                    .get("server")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");

                let usn = device_obj
                    .get("usn")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let st = device_obj
                    .get("st")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let friendly_name = device_obj
                    .get("friendly_name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let manufacturer = device_obj
                    .get("manufacturer")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                let model = device_obj
                    .get("model")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());

                // Extract host and port from location
                let host = Self::extract_host(location);
                let port = Self::extract_port(location);

                // Determine device type for tagging
                let device_type = Self::extract_device_type(usn, st);

                // Build device name
                let name = if let Some(ref fname) = friendly_name {
                    fname.clone()
                } else if let Some(ref m) = model {
                    m.clone()
                } else if let Some(ref h) = host {
                    format!("UPnP Device ({})", h)
                } else {
                    "UPnP Device".to_string()
                };

                // Build port info if available
                let ports = if let Some(port_num) = port {
                    vec![PortInfo {
                        number: port_num,
                        protocol: "tcp".to_string(),
                        service: Some("upnp".to_string()),
                        version: None,
                        state: PortState::Open,
                    }]
                } else {
                    vec![]
                };

                // Build tags
                let mut tags = vec!["upnp".to_string(), "ssdp".to_string(), device_type.clone()];
                if let Some(ref mfr) = manufacturer {
                    tags.push(format!("mfr:{}", mfr.to_lowercase().replace(" ", "_")));
                }

                // Build notes
                let mut notes_parts = vec![format!("UPnP Device: {}", st)];
                if !server.is_empty() && server != "Unknown" {
                    notes_parts.push(format!("Server: {}", server));
                }
                if let Some(ref mfr) = manufacturer {
                    notes_parts.push(format!("Manufacturer: {}", mfr));
                }
                if let Some(ref m) = model {
                    notes_parts.push(format!("Model: {}", m));
                }
                if !location.is_empty() {
                    notes_parts.push(format!("Location: {}", location));
                }

                // Create TargetDiscovered
                let target = TargetDiscovered {
                    target_type: TargetType::Service,
                    name,
                    ip_address: host.clone(),
                    hostname: host.clone(),
                    domain: None,
                    os: None,
                    ports,
                    tags,
                    detection_source: "pick:ssdp_discover".to_string(),
                    confidence: Some(90), // High confidence - device responded to SSDP
                    notes: Some(notes_parts.join("\n")),
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
    fn test_parse_ssdp_discover_with_devices() {
        let parser = SsdpDiscoverParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "devices": [
                    {
                        "location": "http://192.168.1.1:5000/rootDesc.xml",
                        "server": "Linux/3.4 UPnP/1.0 IGD/1.0",
                        "usn": "uuid:12345678-abcd-1234-abcd-123456789abc::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                        "st": "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                        "friendly_name": "Home Router",
                        "manufacturer": "ACME Corp",
                        "model": "Router Pro"
                    },
                    {
                        "location": "http://192.168.1.50:8080/description.xml",
                        "server": "Roku/9.4.0 UPnP/1.0",
                        "usn": "uuid:87654321-dcba-4321-dcba-987654321cba::urn:schemas-upnp-org:device:MediaRenderer:1",
                        "st": "urn:schemas-upnp-org:device:MediaRenderer:1",
                        "friendly_name": "Living Room Roku",
                        "manufacturer": "Roku",
                        "model": "Roku Ultra"
                    }
                ],
                "count": 2
            }),
            error: None,
            duration_ms: 5000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("ssdp_discover", &result, &context);

        assert_eq!(messages.len(), 2);

        // Check router device
        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.name, "Home Router");
                assert_eq!(target.ip_address, Some("192.168.1.1".to_string()));
                assert_eq!(target.target_type, TargetType::Service);
                assert!(target.tags.contains(&"router".to_string()));
                assert!(target.tags.contains(&"upnp".to_string()));
                assert!(target.tags.contains(&"mfr:acme_corp".to_string()));
                assert_eq!(target.ports.len(), 1);
                assert_eq!(target.ports[0].number, 5000);
                assert!(target.notes.as_ref().unwrap().contains("ACME Corp"));
            }
            _ => panic!("Expected TargetDiscovered message"),
        }

        // Check media renderer device
        match &messages[1] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.name, "Living Room Roku");
                assert_eq!(target.ip_address, Some("192.168.1.50".to_string()));
                assert!(target.tags.contains(&"media_renderer".to_string()));
                assert_eq!(target.ports[0].number, 8080);
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_ssdp_discover_minimal_info() {
        let parser = SsdpDiscoverParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "devices": [
                    {
                        "location": "http://192.168.1.100:1900/",
                        "server": "Unknown",
                        "usn": "uuid:unknown-device",
                        "st": "upnp:rootdevice",
                        "friendly_name": null,
                        "manufacturer": null,
                        "model": null
                    }
                ],
                "count": 1
            }),
            error: None,
            duration_ms: 3000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("ssdp_discover", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert!(target.name.contains("UPnP Device"));
                assert_eq!(target.ip_address, Some("192.168.1.100".to_string()));
                assert!(target.tags.contains(&"upnp_device".to_string()));
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_ssdp_discover_no_devices() {
        let parser = SsdpDiscoverParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "devices": [],
                "count": 0
            }),
            error: None,
            duration_ms: 5000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("ssdp_discover", &result, &context);
        assert_eq!(messages.len(), 0);
    }

    #[test]
    fn test_parse_failed_ssdp_discover() {
        let parser = SsdpDiscoverParser;
        let result = ToolResult {
            success: false,
            data: json!({}),
            error: Some("Network timeout".to_string()),
            duration_ms: 6000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("ssdp_discover", &result, &context);
        assert_eq!(messages.len(), 0);
    }

    #[test]
    fn test_extract_device_type() {
        assert_eq!(
            SsdpDiscoverParser::extract_device_type("", "urn:MediaRenderer:1"),
            "media_renderer"
        );
        assert_eq!(
            SsdpDiscoverParser::extract_device_type("", "urn:MediaServer:1"),
            "media_server"
        );
        assert_eq!(
            SsdpDiscoverParser::extract_device_type("", "urn:InternetGatewayDevice:1"),
            "router"
        );
        assert_eq!(
            SsdpDiscoverParser::extract_device_type("uuid:device::MediaRenderer", ""),
            "media_renderer"
        );
    }

    #[test]
    fn test_extract_host_and_port() {
        assert_eq!(
            SsdpDiscoverParser::extract_host("http://192.168.1.1:5000/desc.xml"),
            Some("192.168.1.1".to_string())
        );
        assert_eq!(
            SsdpDiscoverParser::extract_port("http://192.168.1.1:5000/desc.xml"),
            Some(5000)
        );
        assert_eq!(
            SsdpDiscoverParser::extract_host("http://device.local:8080/"),
            Some("device.local".to_string())
        );
    }
}
