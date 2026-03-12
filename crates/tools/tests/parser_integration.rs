//! Integration tests for parser registry
//!
//! These tests verify that all tools have parsers registered and that
//! the parser registry works correctly with the tool registry.

use pentest_core::output_parser::ParserContext;
use pentest_core::tools::ToolResult;
use pentest_tools::parsers::OutputParserRegistry;
use serde_json::json;

#[test]
fn test_all_tools_have_parsers() {
    let registry = OutputParserRegistry::new();
    let parser_names = registry.parser_names();

    // We have 21 parsers (20 tools + file_operations has 3 parsers)
    assert_eq!(
        parser_names.len(),
        21,
        "Expected 21 parsers, found {}",
        parser_names.len()
    );

    // Verify core tools have parsers
    let required_parsers = vec![
        "port_scan",
        "arp_table",
        "ssdp_discover",
        "network_discover",
        "wifi_scan",
        "wifi_scan_detailed",
        "autopwn_plan",
        "autopwn_capture",
        "autopwn_crack",
        "service_banner",
        "cve_lookup",
        "default_creds",
        "web_vuln_scan",
        "smb_enum",
        "device_info",
        "screenshot",
        "traffic_capture",
        "execute_command",
        "read_file",
        "write_file",
        "list_files",
    ];

    for parser_name in required_parsers {
        assert!(
            registry.has_parser(parser_name),
            "Missing parser for tool: {}",
            parser_name
        );
    }
}

#[test]
fn test_parser_registry_handles_unknown_tool() {
    let registry = OutputParserRegistry::new();
    let context = ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

    let result = ToolResult {
        success: true,
        data: json!({}),
        error: None,
        duration_ms: 100,
    };

    // Should return empty vec for unknown tool, not panic
    let messages = registry.parse("nonexistent_tool", &result, &context);
    assert_eq!(messages.len(), 0);
}

#[test]
fn test_parser_registry_handles_failed_result() {
    let registry = OutputParserRegistry::new();
    let context = ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

    let result = ToolResult {
        success: false,
        data: json!({}),
        error: Some("Tool execution failed".to_string()),
        duration_ms: 100,
    };

    // Most parsers return empty vec for failed results
    let messages = registry.parse("port_scan", &result, &context);
    assert_eq!(messages.len(), 0);
}

#[test]
fn test_parser_generates_messages_for_successful_result() {
    let registry = OutputParserRegistry::new();
    let context = ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

    let result = ToolResult {
        success: true,
        data: json!({
            "host": "192.168.1.100",
            "ports": [
                {"port": 80, "state": "open", "service": "http"},
                {"port": 443, "state": "open", "service": "https"}
            ]
        }),
        error: None,
        duration_ms: 5000,
    };

    let messages = registry.parse("port_scan", &result, &context);

    // Should generate at least one message
    assert!(
        !messages.is_empty(),
        "Expected messages from successful port scan"
    );
}

#[test]
fn test_parser_registry_default() {
    // Test that default implementation works
    let registry = OutputParserRegistry::default();
    assert_eq!(registry.parser_names().len(), 21);
}
