//! Parser for autopwn_capture tool output

use pentest_core::output_parser::{OutputParser, ParserContext, StructuredMessage, ToolExecuted};
use pentest_core::tools::ToolResult;

/// Parser for AutoPwn capture results
pub struct AutoPwnCaptureParser;

impl OutputParser for AutoPwnCaptureParser {
    fn parser_name(&self) -> &str {
        "autopwn_capture"
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

        let success = result
            .data
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let capture_file = result
            .data
            .get("capture_file")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let duration = result
            .data
            .get("duration_sec")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Determine capture type
        let capture_type = if let Some(ct) = result.data.get("capture_type") {
            if ct.get("WpaHandshake").is_some() {
                "WPA Handshake"
            } else if ct.get("WepIvs").is_some() {
                "WEP IVs"
            } else {
                "Unknown"
            }
        } else {
            "Unknown"
        };

        let description = if success {
            format!(
                "Successfully captured {} in {}s. Capture file: {}",
                capture_type, duration, capture_file
            )
        } else {
            format!("Failed to capture {} after {}s", capture_type, duration)
        };

        // Create ToolExecuted for activity tracking
        let tool_executed = ToolExecuted {
            target_id: None,
            category: "wifi_attack".to_string(),
            title: format!("WiFi Packet Capture ({})", capture_type),
            description: Some(description),
            command: None,
            output: Some(format!("Capture file: {}", capture_file)),
            success,
            duration_ms: duration * 1000,
            mitre_techniques: vec![
                "T1040".to_string(), // Network Sniffing
            ],
        };

        messages.push(StructuredMessage::ToolExecuted(tool_executed));

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
    fn test_parse_successful_wpa_capture() {
        let parser = AutoPwnCaptureParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "success": true,
                "capture_file": "/tmp/autopwn-20240101/capture-01.cap",
                "capture_type": {
                    "WpaHandshake": {
                        "verified": true
                    }
                },
                "quality": "Excellent",
                "duration_sec": 45
            }),
            error: None,
            duration_ms: 45000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("autopwn_capture", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::ToolExecuted(te) => {
                assert_eq!(te.category, "wifi_attack");
                assert!(te.title.contains("WPA Handshake"));
                assert!(te.description.as_ref().unwrap().contains("Successfully"));
                assert_eq!(te.success, true);
                assert!(te.mitre_techniques.contains(&"T1040".to_string()));
            }
            _ => panic!("Expected ToolExecuted message"),
        }
    }

    #[test]
    fn test_parse_successful_wep_capture() {
        let parser = AutoPwnCaptureParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "success": true,
                "capture_file": "/tmp/autopwn-20240101/capture-01.cap",
                "capture_type": {
                    "WepIvs": {
                        "count": 45000
                    }
                },
                "quality": "Excellent",
                "duration_sec": 120
            }),
            error: None,
            duration_ms: 120000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("autopwn_capture", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::ToolExecuted(te) => {
                assert!(te.title.contains("WEP IVs"));
            }
            _ => panic!("Expected ToolExecuted message"),
        }
    }

    #[test]
    fn test_parse_failed_capture() {
        let parser = AutoPwnCaptureParser;
        let result = ToolResult {
            success: false,
            data: json!({}),
            error: Some("Timeout - no handshake captured".to_string()),
            duration_ms: 120000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("autopwn_capture", &result, &context);
        assert_eq!(messages.len(), 0);
    }
}
