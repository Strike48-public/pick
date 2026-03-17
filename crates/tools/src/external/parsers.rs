//! Output parsing framework for external tools
//!
//! Provides standardized parsing strategies for tool outputs in various formats
//! (JSON, XML, line-delimited, regex-based).

use pentest_core::error::{Error, Result};
use serde_json::Value;

/// Output parsing strategy
#[derive(Debug, Clone)]
pub enum OutputFormat {
    /// Tool outputs JSON natively (e.g., ffuf -of json)
    Json,
    /// Tool writes JSON to a file
    JsonFile(String),
    /// Tool outputs XML (e.g., nmap -oX -)
    Xml,
    /// Parse with regex patterns
    Regex,
    /// Parse line by line with custom function
    LineDelimited,
}

/// Parse JSON output from a tool
pub fn parse_json_output(stdout: &str) -> Result<Value> {
    serde_json::from_str(stdout).map_err(|e| {
        Error::ToolExecution(format!(
            "Failed to parse JSON output: {} (output: {})",
            e, stdout
        ))
    })
}

/// Parse JSON from a file path in the tool output
pub fn parse_json_file_output(file_path: &str, file_content: &str) -> Result<Value> {
    serde_json::from_str(file_content).map_err(|e| {
        Error::ToolExecution(format!(
            "Failed to parse JSON from file '{}': {}",
            file_path, e
        ))
    })
}

/// Extract key-value pairs from output using regex
pub fn extract_key_value_pairs(output: &str, pattern: &str) -> Result<Vec<(String, String)>> {
    let re = regex::Regex::new(pattern)
        .map_err(|e| Error::ToolExecution(format!("Invalid regex pattern: {}", e)))?;

    let mut pairs = Vec::new();
    for line in output.lines() {
        if let Some(caps) = re.captures(line) {
            if caps.len() >= 3 {
                let key = caps.get(1).map(|m| m.as_str().to_string());
                let value = caps.get(2).map(|m| m.as_str().to_string());
                if let (Some(k), Some(v)) = (key, value) {
                    pairs.push((k, v));
                }
            }
        }
    }

    Ok(pairs)
}

/// Parse line-delimited output with a custom parser function
pub fn parse_lines<F>(output: &str, parser: F) -> Result<Vec<Value>>
where
    F: Fn(&str) -> Option<Value>,
{
    let results: Vec<Value> = output.lines().filter_map(parser).collect();

    if results.is_empty() {
        return Err(Error::ToolExecution(
            "No parseable output found".to_string(),
        ));
    }

    Ok(results)
}

/// Parse XML output (nmap)
pub fn parse_xml_output(xml: &str) -> Result<Value> {
    // For now, return raw XML as a string
    // TODO: Add proper XML parsing if needed (would require xml-rs or quick-xml)
    Ok(serde_json::json!({
        "xml": xml,
        "format": "xml"
    }))
}

/// Clean ANSI color codes from output
pub fn strip_ansi_codes(text: &str) -> String {
    // Simple regex to remove ANSI escape sequences
    let re = regex::Regex::new(r"\x1b\[[0-9;]*m").unwrap();
    re.replace_all(text, "").to_string()
}

/// Extract error message from stderr
pub fn extract_error_message(stderr: &str) -> String {
    // Take the first non-empty line as the error message
    stderr
        .lines()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("Unknown error")
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_json_output() {
        let json = r#"{"status": "success", "count": 42}"#;
        let result = parse_json_output(json);
        assert!(result.is_ok());
        let value = result.unwrap();
        assert_eq!(value["status"], "success");
        assert_eq!(value["count"], 42);
    }

    #[test]
    fn test_extract_key_value_pairs() {
        let output = "Name: test-service\nPort: 8080\nStatus: running";
        let pattern = r"^(\w+):\s*(.+)$";
        let result = extract_key_value_pairs(output, pattern);
        assert!(result.is_ok());
        let pairs = result.unwrap();
        assert_eq!(pairs.len(), 3);
        assert_eq!(pairs[0], ("Name".to_string(), "test-service".to_string()));
    }

    #[test]
    fn test_strip_ansi_codes() {
        let colored = "\x1b[31mError\x1b[0m: something failed";
        let clean = strip_ansi_codes(colored);
        assert_eq!(clean, "Error: something failed");
    }

    #[test]
    fn test_parse_lines() {
        let output = "192.168.1.1\n192.168.1.2\n192.168.1.3";
        let parser = |line: &str| Some(serde_json::json!({"ip": line}));
        let result = parse_lines(output, parser);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 3);
    }
}
