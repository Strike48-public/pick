//! Parser for screenshot tool output

use pentest_core::output_parser::{OutputParser, ParserContext, StructuredMessage, ToolExecuted};
use pentest_core::tools::ToolResult;

/// Parser for screenshot results
pub struct ScreenshotParser;

impl OutputParser for ScreenshotParser {
    fn parser_name(&self) -> &str {
        "screenshot"
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

        let format = result
            .data
            .get("format")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let size = result
            .data
            .get("size_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let tool_executed = ToolExecuted {
            target_id: None,
            category: "collection".to_string(),
            title: "Screen Capture".to_string(),
            description: Some(format!(
                "Captured screenshot ({} format, {} KB)",
                format,
                size / 1024
            )),
            command: None,
            output: None,
            success: true,
            duration_ms: result.duration_ms,
            mitre_techniques: vec![
                "T1113".to_string(), // Screen Capture
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
    fn test_parse_screenshot() {
        let parser = ScreenshotParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "format": "png",
                "size_bytes": 512000,
                "data": "base64encodeddata..."
            }),
            error: None,
            duration_ms: 200,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("screenshot", &result, &context);
        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::ToolExecuted(te) => {
                assert_eq!(te.category, "collection");
                assert_eq!(te.title, "Screen Capture");
                assert!(te.description.as_ref().unwrap().contains("500 KB"));
                assert!(te.mitre_techniques.contains(&"T1113".to_string()));
            }
            _ => panic!("Expected ToolExecuted message"),
        }
    }
}
