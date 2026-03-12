//! Parser for service_banner tool output

use pentest_core::output_parser::{
    OutputParser, ParserContext, PortInfo, PortState, StructuredMessage, TargetDiscovered,
    TargetType,
};
use pentest_core::tools::ToolResult;

/// Parser for service banner grabbing results
pub struct ServiceBannerParser;

impl OutputParser for ServiceBannerParser {
    fn parser_name(&self) -> &str {
        "service_banner"
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

        // Extract host and port
        let host = match result.data.get("host").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => {
                tracing::warn!("service_banner result missing 'host' field");
                return vec![];
            }
        };

        let port = match result.data.get("port").and_then(|v| v.as_u64()) {
            Some(p) => p as u16,
            None => {
                tracing::warn!("service_banner result missing 'port' field");
                return vec![];
            }
        };

        // Extract service info
        let service = result
            .data
            .get("service")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let version = result
            .data
            .get("version")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let banner = result
            .data
            .get("banner")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Create TargetDiscovered with enriched port info
        let target = TargetDiscovered {
            target_type: TargetType::Host,
            name: host.to_string(),
            ip_address: Some(host.to_string()),
            hostname: None,
            domain: None,
            os: None,
            ports: vec![PortInfo {
                number: port,
                protocol: "tcp".to_string(),
                service,
                version,
                state: PortState::Open,
            }],
            tags: vec!["banner-grabbed".to_string()],
            detection_source: "pick:service_banner".to_string(),
            confidence: Some(90), // High confidence - directly connected
            notes: if !banner.is_empty() {
                Some(format!("Banner: {}", banner.lines().next().unwrap_or(banner)))
            } else {
                None
            },
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
    fn test_parse_ssh_banner() {
        let parser = ServiceBannerParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "host": "192.168.1.50",
                "port": 22,
                "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
                "service": "ssh",
                "version": "SSH-2.0-OpenSSH_8.2p1",
            }),
            error: None,
            duration_ms: 150,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("service_banner", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.name, "192.168.1.50");
                assert_eq!(target.ports.len(), 1);
                assert_eq!(target.ports[0].number, 22);
                assert_eq!(target.ports[0].service, Some("ssh".to_string()));
                assert_eq!(
                    target.ports[0].version,
                    Some("SSH-2.0-OpenSSH_8.2p1".to_string())
                );
                assert_eq!(target.detection_source, "pick:service_banner");
                assert!(target.notes.as_ref().unwrap().contains("SSH-2.0"));
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_http_banner() {
        let parser = ServiceBannerParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "host": "192.168.1.100",
                "port": 80,
                "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT",
                "service": "http",
                "version": "nginx/1.18.0",
            }),
            error: None,
            duration_ms: 200,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("service_banner", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.ports[0].number, 80);
                assert_eq!(target.ports[0].service, Some("http".to_string()));
                assert_eq!(target.ports[0].version, Some("nginx/1.18.0".to_string()));
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_unknown_service() {
        let parser = ServiceBannerParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "host": "192.168.1.200",
                "port": 9999,
                "banner": "Some proprietary protocol banner",
                "service": null,
                "version": null,
            }),
            error: None,
            duration_ms: 100,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("service_banner", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.ports[0].number, 9999);
                assert_eq!(target.ports[0].service, None);
                assert_eq!(target.ports[0].version, None);
                assert!(target.notes.is_some());
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_failed_banner_grab() {
        let parser = ServiceBannerParser;
        let result = ToolResult {
            success: false,
            data: json!({}),
            error: Some("Connection refused".to_string()),
            duration_ms: 50,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("service_banner", &result, &context);
        assert_eq!(messages.len(), 0);
    }
}
