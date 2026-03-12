//! Parsers for file operation tools (read_file, write_file, list_files)

use pentest_core::output_parser::{
    OutputParser, ParserContext, StructuredMessage, ToolExecuted,
};
use pentest_core::tools::ToolResult;

/// Parser for read_file tool
pub struct ReadFileParser;

impl OutputParser for ReadFileParser {
    fn parser_name(&self) -> &str {
        "read_file"
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

        let path = result
            .data
            .get("path")
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
            title: format!("Read File: {}", path),
            description: Some(format!("Read {} bytes from {}", size, path)),
            command: None,
            output: None,
            success: true,
            duration_ms: result.duration_ms,
            mitre_techniques: vec![
                "T1005".to_string(), // Data from Local System
            ],
        };

        vec![StructuredMessage::ToolExecuted(tool_executed)]
    }
}

/// Parser for write_file tool
pub struct WriteFileParser;

impl OutputParser for WriteFileParser {
    fn parser_name(&self) -> &str {
        "write_file"
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

        let path = result
            .data
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let size = result
            .data
            .get("size_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let appended = result
            .data
            .get("appended")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let tool_executed = ToolExecuted {
            target_id: None,
            category: "exfiltration".to_string(),
            title: format!("Write File: {}", path),
            description: Some(format!(
                "{} {} bytes to {}",
                if appended { "Appended" } else { "Wrote" },
                size,
                path
            )),
            command: None,
            output: None,
            success: true,
            duration_ms: result.duration_ms,
            mitre_techniques: vec![
                "T1105".to_string(), // Ingress Tool Transfer
            ],
        };

        vec![StructuredMessage::ToolExecuted(tool_executed)]
    }
}

/// Parser for list_files tool
pub struct ListFilesParser;

impl OutputParser for ListFilesParser {
    fn parser_name(&self) -> &str {
        "list_files"
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

        let path = result
            .data
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        let count = result
            .data
            .get("count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let tool_executed = ToolExecuted {
            target_id: None,
            category: "discovery".to_string(),
            title: format!("List Files: {}", path),
            description: Some(format!("Found {} items in {}", count, path)),
            command: None,
            output: None,
            success: true,
            duration_ms: result.duration_ms,
            mitre_techniques: vec![
                "T1083".to_string(), // File and Directory Discovery
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
    fn test_parse_read_file() {
        let parser = ReadFileParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "path": "/etc/passwd",
                "encoding": "utf8",
                "content": "root:x:0:0:root:/root:/bin/bash",
                "size_bytes": 1024
            }),
            error: None,
            duration_ms: 50,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("read_file", &result, &context);
        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::ToolExecuted(te) => {
                assert_eq!(te.category, "collection");
                assert!(te.title.contains("/etc/passwd"));
                assert!(te.mitre_techniques.contains(&"T1005".to_string()));
            }
            _ => panic!("Expected ToolExecuted message"),
        }
    }

    #[test]
    fn test_parse_write_file() {
        let parser = WriteFileParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "path": "/tmp/output.txt",
                "size_bytes": 512,
                "appended": false
            }),
            error: None,
            duration_ms: 30,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("write_file", &result, &context);
        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::ToolExecuted(te) => {
                assert_eq!(te.category, "exfiltration");
                assert!(te.description.as_ref().unwrap().contains("Wrote"));
            }
            _ => panic!("Expected ToolExecuted message"),
        }
    }

    #[test]
    fn test_parse_list_files() {
        let parser = ListFilesParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "path": "/home/user",
                "entries": [],
                "count": 42
            }),
            error: None,
            duration_ms: 100,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("list_files", &result, &context);
        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::ToolExecuted(te) => {
                assert_eq!(te.category, "discovery");
                assert!(te.description.as_ref().unwrap().contains("42 items"));
            }
            _ => panic!("Expected ToolExecuted message"),
        }
    }
}
