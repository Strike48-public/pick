//! Parser for autopwn_plan tool output

use pentest_core::output_parser::{
    OutputParser, ParserContext, StructuredMessage, ToolExecuted,
};
use pentest_core::tools::ToolResult;

/// Parser for AutoPwn planning results
pub struct AutoPwnPlanParser;

impl OutputParser for AutoPwnPlanParser {
    fn parser_name(&self) -> &str {
        "autopwn_plan"
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

        let target_ssid = result
            .data
            .get("target_ssid")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");

        let security = result
            .data
            .get("security")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");

        let estimated_duration = result
            .data
            .get("estimated_duration_sec")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let strategy = result
            .data
            .get("strategy")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");

        // Create ToolExecuted for planning activity
        let tool_executed = ToolExecuted {
            target_id: None,
            category: "reconnaissance".to_string(),
            title: format!("WiFi Attack Planning: {}", target_ssid),
            description: Some(format!(
                "Analyzed {} network with {} security. \
                Recommended strategy: {}. Estimated duration: {}s",
                target_ssid, security, strategy, estimated_duration
            )),
            command: None,
            output: None,
            success: true,
            duration_ms: result.duration_ms,
            mitre_techniques: vec![
                "T1595".to_string(), // Active Scanning
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
    fn test_parse_autopwn_plan() {
        let parser = AutoPwnPlanParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "target_ssid": "TestNetwork",
                "target_bssid": "AA:BB:CC:DD:EE:FF",
                "channel": 6,
                "security": "WPA2-PSK",
                "strategy": "WPA2_HANDSHAKE_CRACK",
                "requires_monitor_mode": true,
                "requires_mac_cloning": false,
                "estimated_duration_sec": 300,
                "warnings": []
            }),
            error: None,
            duration_ms: 50,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("autopwn_plan", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::ToolExecuted(te) => {
                assert_eq!(te.category, "reconnaissance");
                assert!(te.title.contains("TestNetwork"));
                assert!(te
                    .description
                    .as_ref()
                    .unwrap()
                    .contains("WPA2_HANDSHAKE_CRACK"));
            }
            _ => panic!("Expected ToolExecuted message"),
        }
    }
}
