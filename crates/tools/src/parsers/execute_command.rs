//! Parser for execute_command tool output

use pentest_core::output_parser::{OutputParser, ParserContext, StructuredMessage, ToolExecuted};
use pentest_core::tools::ToolResult;

/// Parser for command execution results
pub struct ExecuteCommandParser;

impl OutputParser for ExecuteCommandParser {
    fn parser_name(&self) -> &str {
        "execute_command"
    }

    fn parse(
        &self,
        _tool_name: &str,
        result: &ToolResult,
        _context: &ParserContext,
    ) -> Vec<StructuredMessage> {
        // Parse both successful and failed results (command execution is activity)
        let mut messages = vec![];

        let exit_code = result
            .data
            .get("exit_code")
            .and_then(|v| v.as_i64())
            .unwrap_or(-1);

        let stdout = result
            .data
            .get("stdout")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let stderr = result
            .data
            .get("stderr")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let timed_out = result
            .data
            .get("timed_out")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let success = result.success && exit_code == 0 && !timed_out;

        // Create ToolExecuted for command execution activity
        let tool_executed = ToolExecuted {
            target_id: None,
            category: "execution".to_string(),
            title: "Command Execution".to_string(),
            description: if timed_out {
                Some("Command execution timed out".to_string())
            } else {
                Some(format!("Exit code: {}", exit_code))
            },
            command: None, // Don't expose potentially sensitive commands
            output: if !stdout.is_empty() {
                Some(format!(
                    "stdout: {} bytes, stderr: {} bytes",
                    stdout.len(),
                    stderr.len()
                ))
            } else {
                None
            },
            success,
            duration_ms: result.duration_ms,
            mitre_techniques: vec![
                "T1059".to_string(), // Command and Scripting Interpreter
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
    fn test_parse_successful_command() {
        let parser = ExecuteCommandParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "stdout": "Hello, World!",
                "stderr": "",
                "exit_code": 0,
                "timed_out": false,
                "duration_ms": 100
            }),
            error: None,
            duration_ms: 100,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("execute_command", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::ToolExecuted(te) => {
                assert_eq!(te.category, "execution");
                assert_eq!(te.success, true);
                assert!(te.mitre_techniques.contains(&"T1059".to_string()));
            }
            _ => panic!("Expected ToolExecuted message"),
        }
    }

    #[test]
    fn test_parse_failed_command() {
        let parser = ExecuteCommandParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "stdout": "",
                "stderr": "command not found",
                "exit_code": 127,
                "timed_out": false,
                "duration_ms": 50
            }),
            error: None,
            duration_ms: 50,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("execute_command", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::ToolExecuted(te) => {
                assert_eq!(te.success, false);
                assert!(te.description.as_ref().unwrap().contains("127"));
            }
            _ => panic!("Expected ToolExecuted message"),
        }
    }
}
