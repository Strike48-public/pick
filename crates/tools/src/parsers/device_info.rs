//! Parser for device_info tool output

use pentest_core::output_parser::{
    OutputParser, ParserContext, StructuredMessage, TargetDiscovered, TargetType,
};
use pentest_core::tools::ToolResult;

/// Parser for device information results
pub struct DeviceInfoParser;

impl OutputParser for DeviceInfoParser {
    fn parser_name(&self) -> &str {
        "device_info"
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

        // Extract device information
        let hostname = result
            .data
            .get("hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("localhost");

        let os_name = result
            .data
            .get("os_name")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");

        let os_version = result
            .data
            .get("os_version")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let architecture = result
            .data
            .get("architecture")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let cpu_count = result
            .data
            .get("cpu_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let total_memory_mb = result
            .data
            .get("total_memory_mb")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Build OS string
        let os = if !os_version.is_empty() {
            format!("{} {}", os_name, os_version)
        } else {
            os_name.to_string()
        };

        // Build tags
        let mut tags = vec!["local-system".to_string()];
        if !architecture.is_empty() {
            tags.push(architecture.to_lowercase().replace(" ", "_"));
        }
        tags.push(os_name.to_lowercase().replace(" ", "_"));

        // Build notes with hardware details
        let mut notes_parts = Vec::new();
        if cpu_count > 0 {
            notes_parts.push(format!("CPU Cores: {}", cpu_count));
        }
        if total_memory_mb > 0 {
            let memory_gb = total_memory_mb as f64 / 1024.0;
            notes_parts.push(format!("Memory: {:.1} GB", memory_gb));
        }
        if !architecture.is_empty() {
            notes_parts.push(format!("Architecture: {}", architecture));
        }

        // Add platform-specific info if available
        if let Some(platform_specific) = result.data.get("platform_specific") {
            if let Some(obj) = platform_specific.as_object() {
                for (key, value) in obj.iter() {
                    if let Some(val_str) = value.as_str() {
                        notes_parts.push(format!("{}: {}", key, val_str));
                    }
                }
            }
        }

        // Create TargetDiscovered for local system
        let target = TargetDiscovered {
            target_type: TargetType::Host,
            name: hostname.to_string(),
            ip_address: None, // Could be added if we query local IP
            hostname: Some(hostname.to_string()),
            domain: None,
            os: Some(os),
            ports: vec![],
            tags,
            detection_source: "pick:device_info".to_string(),
            confidence: Some(100), // Perfect confidence - we're on the system
            notes: if notes_parts.is_empty() {
                None
            } else {
                Some(notes_parts.join("\n"))
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
    fn test_parse_device_info_linux() {
        let parser = DeviceInfoParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "os_name": "Linux",
                "os_version": "6.17.0-14-generic",
                "hostname": "pentest-laptop",
                "architecture": "x86_64",
                "cpu_count": 8,
                "total_memory_mb": 16384,
                "platform_specific": {
                    "kernel": "6.17.0-14-generic",
                    "distribution": "Ubuntu 24.04"
                }
            }),
            error: None,
            duration_ms: 50,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("device_info", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.name, "pentest-laptop");
                assert_eq!(target.hostname, Some("pentest-laptop".to_string()));
                assert_eq!(target.os, Some("Linux 6.17.0-14-generic".to_string()));
                assert_eq!(target.target_type, TargetType::Host);
                assert!(target.tags.contains(&"local-system".to_string()));
                assert!(target.tags.contains(&"x86_64".to_string()));
                assert!(target.tags.contains(&"linux".to_string()));
                assert_eq!(target.confidence, Some(100));
                assert!(target.notes.as_ref().unwrap().contains("CPU Cores: 8"));
                assert!(target.notes.as_ref().unwrap().contains("Memory: 16.0 GB"));
                assert!(target.notes.as_ref().unwrap().contains("Ubuntu 24.04"));
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_device_info_windows() {
        let parser = DeviceInfoParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "os_name": "Windows",
                "os_version": "11",
                "hostname": "DESKTOP-ABC123",
                "architecture": "AMD64",
                "cpu_count": 12,
                "total_memory_mb": 32768,
                "platform_specific": {
                    "build": "22000.1042",
                    "edition": "Pro"
                }
            }),
            error: None,
            duration_ms: 40,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("device_info", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.name, "DESKTOP-ABC123");
                assert_eq!(target.os, Some("Windows 11".to_string()));
                assert!(target.tags.contains(&"amd64".to_string()));
                assert!(target.tags.contains(&"windows".to_string()));
                assert!(target.notes.as_ref().unwrap().contains("CPU Cores: 12"));
                assert!(target.notes.as_ref().unwrap().contains("Memory: 32.0 GB"));
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_device_info_minimal() {
        let parser = DeviceInfoParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "os_name": "Unknown",
                "os_version": "",
                "hostname": "localhost",
                "architecture": "",
                "cpu_count": 0,
                "total_memory_mb": 0,
                "platform_specific": null
            }),
            error: None,
            duration_ms: 30,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("device_info", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert_eq!(target.name, "localhost");
                assert_eq!(target.os, Some("Unknown".to_string()));
                assert!(target.notes.is_none());
            }
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_failed_device_info() {
        let parser = DeviceInfoParser;
        let result = ToolResult {
            success: false,
            data: json!({}),
            error: Some("Failed to query system".to_string()),
            duration_ms: 10,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("device_info", &result, &context);
        assert_eq!(messages.len(), 0);
    }
}
