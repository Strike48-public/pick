//! Integration tests for PentestConnector::execute() request parsing.
//!
//! Request format: { "tool": "<name>", "parameters": { ... } }

use pentest_core::connector::PentestConnector;
use serde_json::{json, Value};
use strike48_connector::BaseConnector;

fn make_connector() -> PentestConnector {
    // Disable sandbox so tests use direct host execution.
    // The BlackArch sandbox (bubblewrap/proot) requires a local rootfs
    // that isn't available on CI runners.
    pentest_platform::set_use_sandbox(false);
    let registry = pentest_tools::create_tool_registry();
    PentestConnector::new(registry, None)
}

/// Helper: call execute and return the parsed result
async fn exec(connector: &PentestConnector, request: Value) -> Value {
    connector
        .execute(request, None)
        .await
        .expect("execute failed")
}

fn is_success(result: &Value) -> bool {
    result
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn get_stdout(result: &Value) -> Option<String> {
    result
        .get("data")
        .and_then(|d| d.get("stdout"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn get_error(result: &Value) -> Option<String> {
    result
        .get("error")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

// ── execute_command ───────────────────────────────────────────────────

#[tokio::test]
async fn execute_command_runs_command() {
    let c = make_connector();
    let result = exec(
        &c,
        json!({
            "tool": "execute_command",
            "parameters": {
                "command": "echo",
                "args": ["hello"]
            }
        }),
    )
    .await;

    assert!(is_success(&result), "Expected success, got: {result}");
    let stdout = get_stdout(&result).unwrap_or_default();
    assert!(stdout.contains("hello"), "stdout was: {stdout}");
}

#[tokio::test]
async fn execute_command_missing_params_errors() {
    let c = make_connector();
    let result = exec(
        &c,
        json!({
            "tool": "execute_command",
            "parameters": {}
        }),
    )
    .await;

    assert!(!is_success(&result), "Expected failure, got: {result}");
    let error = get_error(&result).unwrap_or_default();
    assert!(error.contains("Command is required"), "error was: {error}");
}

#[tokio::test]
async fn execute_command_no_params_key_errors() {
    let c = make_connector();
    let result = exec(
        &c,
        json!({
            "tool": "execute_command"
        }),
    )
    .await;

    assert!(!is_success(&result), "Expected failure, got: {result}");
    let error = get_error(&result).unwrap_or_default();
    assert!(error.contains("Command is required"), "error was: {error}");
}

// ── device_info (no params) ──────────────────────────────────────────

#[tokio::test]
async fn device_info_works() {
    let c = make_connector();
    let result = exec(&c, json!({"tool": "device_info"})).await;
    assert!(is_success(&result), "Expected success, got: {result}");
}

// ── missing tool name ────────────────────────────────────────────────

#[tokio::test]
async fn missing_tool_name_errors() {
    let c = make_connector();
    let result = c
        .execute(json!({"parameters": {"command": "echo"}}), None)
        .await;
    assert!(result.is_err(), "Expected error for missing tool name");
}

// ── capabilities ─────────────────────────────────────────────────────

#[test]
fn capabilities_include_all_tools() {
    let c = make_connector();
    let caps = c.capabilities();
    let names: Vec<&str> = caps.iter().map(|t| t.task_type_id.as_str()).collect();

    assert!(
        names.contains(&"execute_command"),
        "missing execute_command"
    );
    assert!(names.contains(&"read_file"), "missing read_file");
    assert!(names.contains(&"write_file"), "missing write_file");
    assert!(names.contains(&"list_files"), "missing list_files");
    assert!(names.contains(&"port_scan"), "missing port_scan");
    assert!(names.contains(&"device_info"), "missing device_info");

    // Every schema must be valid JSON with type: object
    for cap in &caps {
        let schema: Value = serde_json::from_str(&cap.input_schema_json).unwrap_or_else(|e| {
            panic!(
                "Invalid JSON in input_schema_json for {}: {}",
                cap.task_type_id, e
            )
        });
        assert_eq!(
            schema.get("type").and_then(|v| v.as_str()),
            Some("object"),
            "Schema for {} missing type:object",
            cap.task_type_id
        );
    }
}

#[test]
fn execute_command_schema_has_command_property() {
    let c = make_connector();
    let caps = c.capabilities();
    let exec_cap = caps
        .iter()
        .find(|t| t.task_type_id == "execute_command")
        .expect("execute_command capability missing");

    let schema: Value = serde_json::from_str(&exec_cap.input_schema_json).unwrap();

    let properties = schema.get("properties").expect("missing properties");
    assert!(
        properties.get("command").is_some(),
        "Schema missing 'command' property: {schema}"
    );

    let required = schema
        .get("required")
        .and_then(|v| v.as_array())
        .expect("missing required array");
    let required_names: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();
    assert!(
        required_names.contains(&"command"),
        "command not in required: {required_names:?}"
    );
}
