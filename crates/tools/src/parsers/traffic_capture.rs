//! Parser for traffic_capture tool output

use pentest_core::output_parser::{
    OutputParser, ParserContext, StructuredMessage, ToolExecuted,
};
use pentest_core::tools::ToolResult;

/// Parser for network traffic capture results
pub struct TrafficCaptureParser;

impl OutputParser for TrafficCaptureParser {
    fn parser_name(&self) -> &str {
        "traffic_capture"
    }

    fn parse(
        &self,
        _tool_name: &str,
        result: &ToolResult,
        _context: &ParserContext,
    ) -> Vec<StructuredMessage> {
        if !result.success {
            return vec![];
        }

        let capture_file = result
            .data
            .get("capture_file")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let packet_count = result
            .data
            .get("packet_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let duration = result
            .data
            .get("duration_sec")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let interface = result
            .data
            .get("interface")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let tool_executed = ToolExecuted {
            target_id: None,
            category: "collection".to_string(),
            title: format!("Network Traffic Capture ({})", interface),
            description: Some(format!(
                "Captured {} packets over {}s. Output: {}",
                packet_count, duration, capture_file
            )),
            command: None,
            output: Some(format!("PCAP file: {}", capture_file)),
            success: true,
            duration_ms: result.duration_ms,
            mitre_techniques: vec![
                "T1040".to_string(), // Network Sniffing
            ],
        };

        vec![StructuredMessage::ToolExecuted(tool_executed)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::output_parser::ParserContext;
    use pentest_core::tools::ToolResult;
    use serde_json::json;

    #[test]
    fn test_parse_traffic_capture() {
        let parser = TrafficCaptureParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "capture_file": "/tmp/capture-20240101.pcap",
                "packet_count": 15420,
                "duration_sec": 60,
                "interface": "eth0",
                "filter": "tcp port 80"
            }),
            error: None,
            duration_ms: 60000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("traffic_capture", &result, &context);
        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::ToolExecuted(te) => {
                assert_eq!(te.category, "collection");
                assert!(te.title.contains("eth0"));
                assert!(te.description.as_ref().unwrap().contains("15420 packets"));
                assert!(te.mitre_techniques.contains(&"T1040".to_string()));
            }
            _ => panic!("Expected ToolExecuted message"),
        }
    }
}
