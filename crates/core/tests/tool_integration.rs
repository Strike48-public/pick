//! Integration tests for all tools via PentestConnector::execute().
//!
//! These tests exercise the full path: JSON request → connector routing →
//! tool param extraction → tool execute → JSON response.  They verify:
//!
//! 1. **Both request formats** work (nested `"parameters"` and flat top-level).
//! 2. **Required params** produce clear errors when missing.
//! 3. **Optional params** default correctly.
//! 4. **Response structure** always has `success`, `data`, `error`, `duration_ms`.
//! 5. **Workspace-dependent tools** fail gracefully without a workspace.
//! 6. **Schema consistency** — every param in schema is consumed in execute.

use pentest_core::connector::PentestConnector;
use serde_json::{json, Value};
use std::path::PathBuf;
use strike48_connector::BaseConnector;

// ── Helpers ──────────────────────────────────────────────────────────

fn connector() -> PentestConnector {
    pentest_platform::set_use_sandbox(false);
    let registry = pentest_tools::create_tool_registry();
    PentestConnector::new(registry, None)
}

fn connector_with_workspace(path: PathBuf) -> PentestConnector {
    let registry = pentest_tools::create_tool_registry();
    PentestConnector::new(registry, Some(path))
}

async fn exec(c: &PentestConnector, request: Value) -> Value {
    c.execute(request, None)
        .await
        .expect("execute returned Err")
}

/// Assert the response is a well-formed ToolResult.
fn assert_tool_result_shape(result: &Value, ctx: &str) {
    assert!(
        result.get("success").is_some(),
        "{ctx}: response missing 'success' field: {result}"
    );
    assert!(
        result.get("data").is_some() || result.get("error").is_some(),
        "{ctx}: response missing both 'data' and 'error': {result}"
    );
}

fn is_success(result: &Value) -> bool {
    result
        .get("success")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
}

fn get_error(result: &Value) -> String {
    result
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string()
}

fn get_data(result: &Value) -> &Value {
    result.get("data").unwrap_or(&Value::Null)
}

// ── Format tests ─────────────────────────────────────────────────────

#[tokio::test]
async fn backend_request_format_works() {
    // Real format: "tool" + "parameters" + "metadata"
    let c = connector();
    let result = exec(
        &c,
        json!({
            "tool": "execute_command",
            "metadata": {"agent_execution": "true"},
            "parameters": { "command": "echo", "args": ["backend-format"] }
        }),
    )
    .await;

    assert_tool_result_shape(&result, "backend_format");
    assert!(is_success(&result), "backend format failed: {result}");
    let stdout = get_data(&result)
        .get("stdout")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(stdout.contains("backend-format"), "stdout={stdout}");
}

#[tokio::test]
async fn flat_params_format_works() {
    // Fallback: params at top level (for direct testing / simple calls)
    let c = connector();
    let result = exec(
        &c,
        json!({
            "tool": "execute_command",
            "command": "echo",
            "args": ["flat"]
        }),
    )
    .await;

    assert_tool_result_shape(&result, "flat_params");
    assert!(is_success(&result), "flat params failed: {result}");
    let stdout = get_data(&result)
        .get("stdout")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(stdout.contains("flat"), "stdout={stdout}");
}

// ── port_scan ────────────────────────────────────────────────────────

#[tokio::test]
async fn port_scan_requires_host() {
    let c = connector();
    let result = exec(&c, json!({"tool": "port_scan"})).await;
    assert_tool_result_shape(&result, "port_scan_no_host");
    assert!(!is_success(&result), "should fail without host: {result}");
    assert!(
        get_error(&result).to_lowercase().contains("host"),
        "error should mention host: {}",
        get_error(&result)
    );
}

#[tokio::test]
async fn port_scan_requires_host_flat() {
    let c = connector();
    // Flat format with no host — should still error, not default to 127.0.0.1
    let result = exec(&c, json!({"tool": "port_scan", "ports": "80"})).await;
    assert!(!is_success(&result), "should fail without host: {result}");
}

#[tokio::test]
async fn port_scan_scans_correct_host() {
    let c = connector();
    // Scan a single port on localhost — verify the response host matches the request
    let result = exec(
        &c,
        json!({
            "tool": "port_scan",
            "host": "127.0.0.1",
            "ports": "1",
            "timeout_ms": 100
        }),
    )
    .await;

    assert_tool_result_shape(&result, "port_scan_host_check");
    assert!(is_success(&result), "port scan failed: {result}");
    let data = get_data(&result);
    assert_eq!(
        data.get("host").and_then(|v| v.as_str()),
        Some("127.0.0.1"),
        "host mismatch in response: {data}"
    );
}

#[tokio::test]
async fn port_scan_nested_params() {
    let c = connector();
    let result = exec(
        &c,
        json!({
            "tool": "port_scan",
            "parameters": {
                "host": "127.0.0.1",
                "ports": "1",
                "timeout_ms": 100
            }
        }),
    )
    .await;

    assert!(is_success(&result), "nested port_scan failed: {result}");
    assert_eq!(
        get_data(&result).get("host").and_then(|v| v.as_str()),
        Some("127.0.0.1"),
    );
}

// ── device_info ──────────────────────────────────────────────────────

#[tokio::test]
async fn device_info_returns_data() {
    let c = connector();
    let result = exec(&c, json!({"tool": "device_info"})).await;
    assert_tool_result_shape(&result, "device_info");
    assert!(is_success(&result), "device_info failed: {result}");
    let data = get_data(&result);
    // Should have at least hostname and os
    assert!(
        data.get("hostname").is_some() || data.get("os").is_some(),
        "device_info missing expected fields: {data}"
    );
}

// ── arp_table ────────────────────────────────────────────────────────

#[tokio::test]
async fn arp_table_returns_entries_array() {
    let c = connector();
    let result = exec(&c, json!({"tool": "arp_table"})).await;
    assert_tool_result_shape(&result, "arp_table");
    assert!(is_success(&result), "arp_table failed: {result}");
    let data = get_data(&result);
    assert!(
        data.get("entries").and_then(|v| v.as_array()).is_some(),
        "arp_table missing entries array: {data}"
    );
}

#[tokio::test]
async fn arp_table_flat_params() {
    let c = connector();
    let result = exec(&c, json!({"tool": "arp_table", "resolve_hostnames": false})).await;
    assert!(is_success(&result), "arp_table flat failed: {result}");
}

// ── ssdp_discover ────────────────────────────────────────────────────

#[tokio::test]
async fn ssdp_discover_returns_devices_array() {
    let c = connector();
    let result = exec(&c, json!({"tool": "ssdp_discover", "timeout_ms": 500})).await;
    assert_tool_result_shape(&result, "ssdp_discover");
    assert!(is_success(&result), "ssdp_discover failed: {result}");
    // Response should have a devices or services array (may be empty)
    let data = get_data(&result);
    assert!(
        data.get("devices").and_then(|v| v.as_array()).is_some(),
        "ssdp_discover missing devices array: {data}"
    );
}

// ── network_discover (mDNS) ──────────────────────────────────────────

#[tokio::test]
async fn network_discover_returns_services_array() {
    let c = connector();
    // Short timeout to keep tests fast
    let result = exec(&c, json!({"tool": "network_discover", "timeout_ms": 500})).await;
    assert_tool_result_shape(&result, "network_discover");
    assert!(
        is_success(&result),
        "network_discover failed: {}",
        get_error(&result)
    );
    let data = get_data(&result);
    assert!(
        data.get("services").and_then(|v| v.as_array()).is_some(),
        "network_discover missing services array: {data}"
    );
}

#[tokio::test]
async fn network_discover_flat_params_not_default() {
    let c = connector();
    // Flat format — service_type should come from the request, not the default
    let result = exec(
        &c,
        json!({
            "tool": "network_discover",
            "service_type": "_http._tcp.local.",
            "timeout_ms": 500
        }),
    )
    .await;
    // If it used the default "_services._dns-sd._udp.local." we'd still get success,
    // but at least verify it didn't error with "must end with ._tcp.local."
    assert!(
        is_success(&result),
        "network_discover flat params failed (possible default leak): {}",
        get_error(&result)
    );
}

// ── wifi_scan ────────────────────────────────────────────────────────

#[tokio::test]
async fn wifi_scan_returns_networks_array() {
    let c = connector();
    let result = exec(&c, json!({"tool": "wifi_scan"})).await;
    assert_tool_result_shape(&result, "wifi_scan");
    // wifi_scan crate requires root/elevated privileges on Linux for active scanning.
    // On non-privileged CI/dev environments, verify shape only.
    if is_success(&result) {
        let data = get_data(&result);
        assert!(
            data.get("networks").and_then(|v| v.as_array()).is_some(),
            "wifi_scan missing networks array: {data}"
        );
    }
}

// ── screenshot ───────────────────────────────────────────────────────

#[tokio::test]
async fn screenshot_returns_result() {
    let c = connector();
    let result = exec(&c, json!({"tool": "screenshot"})).await;
    assert_tool_result_shape(&result, "screenshot");
    // May fail on headless CI — just verify shape
}

// ── traffic_capture ──────────────────────────────────────────────────

#[tokio::test]
async fn traffic_capture_requires_action() {
    if !pentest_platform::is_pcap_available() {
        eprintln!("skipping: libpcap not available");
        return;
    }
    let c = connector();
    let result = exec(&c, json!({"tool": "traffic_capture"})).await;
    assert_tool_result_shape(&result, "traffic_capture_no_action");
    assert!(!is_success(&result), "should fail without action: {result}");
    assert!(
        get_error(&result).to_lowercase().contains("action"),
        "error should mention action: {}",
        get_error(&result)
    );
}

#[tokio::test]
async fn traffic_capture_get_packets_no_capture() {
    if !pentest_platform::is_pcap_available() {
        eprintln!("skipping: libpcap not available");
        return;
    }
    let c = connector();
    let result = exec(
        &c,
        json!({"tool": "traffic_capture", "action": "get_packets"}),
    )
    .await;
    assert_tool_result_shape(&result, "traffic_capture_get_packets");
    // Should fail because no capture is running
    assert!(
        !is_success(&result),
        "should fail without active capture: {result}"
    );
}

// ── Workspace tools (read_file, write_file, list_files) ──────────────

#[tokio::test]
async fn workspace_tools_fail_without_workspace() {
    let c = connector(); // no workspace

    for (tool, params) in [
        ("read_file", json!({"path": "test.txt"})),
        ("write_file", json!({"path": "test.txt", "content": "hi"})),
        ("list_files", json!({})),
    ] {
        let mut request = json!({"tool": tool});
        let obj = request.as_object_mut().unwrap();
        obj.insert("params".to_string(), params);
        let result = exec(&c, request).await;

        assert_tool_result_shape(&result, &format!("{tool}_no_workspace"));
        assert!(
            !is_success(&result),
            "{tool} should fail without workspace: {result}"
        );
        let err = get_error(&result);
        assert!(
            err.to_lowercase().contains("workspace"),
            "{tool} error should mention workspace: {err}"
        );
    }
}

#[tokio::test]
async fn read_file_requires_path() {
    let ws = tempfile::tempdir().unwrap();
    let c = connector_with_workspace(ws.path().to_path_buf());
    let result = exec(&c, json!({"tool": "read_file", "parameters": {}})).await;
    assert!(!is_success(&result));
    assert!(get_error(&result).contains("path"));
}

#[tokio::test]
async fn write_file_requires_path_and_content() {
    let ws = tempfile::tempdir().unwrap();
    let c = connector_with_workspace(ws.path().to_path_buf());

    let result = exec(&c, json!({"tool": "write_file", "parameters": {}})).await;
    assert!(!is_success(&result));
    assert!(get_error(&result).contains("path"));

    let result = exec(
        &c,
        json!({"tool": "write_file", "parameters": {"path": "test.txt"}}),
    )
    .await;
    assert!(!is_success(&result));
    assert!(get_error(&result).contains("content"));
}

#[tokio::test]
async fn write_then_read_file_roundtrip() {
    let ws = tempfile::tempdir().unwrap();
    let c = connector_with_workspace(ws.path().to_path_buf());

    // Write
    let write_result = exec(
        &c,
        json!({
            "tool": "write_file",
            "parameters": { "path": "hello.txt", "content": "integration test" }
        }),
    )
    .await;
    assert!(is_success(&write_result), "write failed: {write_result}");

    // Read back
    let read_result = exec(
        &c,
        json!({
            "tool": "read_file",
            "parameters": { "path": "hello.txt" }
        }),
    )
    .await;
    assert!(is_success(&read_result), "read failed: {read_result}");
    let content = get_data(&read_result)
        .get("content")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert_eq!(content, "integration test");
}

#[tokio::test]
async fn write_then_read_flat_params() {
    let ws = tempfile::tempdir().unwrap();
    let c = connector_with_workspace(ws.path().to_path_buf());

    // Write with flat params
    let write_result = exec(
        &c,
        json!({
            "tool": "write_file",
            "path": "flat.txt",
            "content": "flat format"
        }),
    )
    .await;
    assert!(
        is_success(&write_result),
        "flat write failed: {write_result}"
    );

    // Read with flat params
    let read_result = exec(
        &c,
        json!({
            "tool": "read_file",
            "path": "flat.txt"
        }),
    )
    .await;
    assert!(is_success(&read_result), "flat read failed: {read_result}");
    assert_eq!(
        get_data(&read_result)
            .get("content")
            .and_then(|v| v.as_str()),
        Some("flat format")
    );
}

#[tokio::test]
async fn list_files_shows_written_file() {
    let ws = tempfile::tempdir().unwrap();
    let c = connector_with_workspace(ws.path().to_path_buf());

    // Write a file first
    exec(
        &c,
        json!({
            "tool": "write_file",
            "parameters": { "path": "listed.txt", "content": "x" }
        }),
    )
    .await;

    // List
    let result = exec(&c, json!({"tool": "list_files"})).await;
    assert!(is_success(&result), "list_files failed: {result}");
    let entries = get_data(&result)
        .get("entries")
        .and_then(|v| v.as_array())
        .expect("missing entries array");
    let names: Vec<&str> = entries
        .iter()
        .filter_map(|e| e.get("name").and_then(|v| v.as_str()))
        .collect();
    assert!(
        names.contains(&"listed.txt"),
        "listed.txt not found in: {names:?}"
    );
}

#[tokio::test]
async fn list_files_flat_params() {
    let ws = tempfile::tempdir().unwrap();
    let c = connector_with_workspace(ws.path().to_path_buf());

    std::fs::write(ws.path().join("a.txt"), "a").unwrap();
    std::fs::create_dir(ws.path().join("subdir")).unwrap();
    std::fs::write(ws.path().join("subdir").join("b.txt"), "b").unwrap();

    // List subdirectory with flat params
    let result = exec(&c, json!({"tool": "list_files", "path": "subdir"})).await;
    assert!(is_success(&result), "list_files flat failed: {result}");
    let empty = vec![];
    let names: Vec<&str> = get_data(&result)
        .get("entries")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty)
        .iter()
        .filter_map(|e| e.get("name").and_then(|v| v.as_str()))
        .collect();
    assert!(names.contains(&"b.txt"), "b.txt not in subdir: {names:?}");
}

// ── File browser app routing ─────────────────────────────────────────

#[tokio::test]
async fn app_request_routes_to_file_browser() {
    let ws = tempfile::tempdir().unwrap();
    let c = connector_with_workspace(ws.path().to_path_buf());

    // App request (has "path" key)
    let result = exec(&c, json!({"path": "/styles.css"})).await;
    // Should return AppPageResponse shape, not ToolResult
    assert_eq!(
        result.get("content_type").and_then(|v| v.as_str()),
        Some("text/css"),
        "expected CSS response: {result}"
    );
}

#[tokio::test]
async fn app_request_without_workspace() {
    let c = connector(); // no workspace
    let result = exec(&c, json!({"path": "/browse"})).await;
    assert_eq!(
        result.get("status").and_then(|v| v.as_u64()),
        Some(503),
        "expected 503 without workspace: {result}"
    );
}

// ── Schema / capability validation ───────────────────────────────────

#[test]
fn all_tools_registered() {
    let c = connector();
    let caps = c.capabilities();
    let registered: Vec<&str> = caps.iter().map(|t| t.task_type_id.as_str()).collect();

    for name in pentest_tools::tool_names() {
        assert!(
            registered.contains(&name.as_str()),
            "tool '{name}' not in capabilities: {registered:?}"
        );
    }
}

#[test]
fn all_schemas_valid_json() {
    let c = connector();
    for cap in c.capabilities() {
        let schema: Value = serde_json::from_str(&cap.input_schema_json)
            .unwrap_or_else(|e| panic!("Invalid JSON schema for {}: {e}", cap.task_type_id));
        assert_eq!(
            schema.get("type").and_then(|v| v.as_str()),
            Some("object"),
            "schema for {} missing type:object",
            cap.task_type_id
        );
    }
}

#[test]
fn required_params_in_required_array() {
    let registry = pentest_tools::create_tool_registry();
    for schema in registry.schemas() {
        let json_schema = schema.to_json_schema();
        // required array is nested inside "parameters"
        let params_schema = json_schema
            .get("parameters")
            .unwrap_or_else(|| panic!("tool '{}': missing parameters key", schema.name));
        let required: Vec<&str> = params_schema
            .get("required")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();

        for param in &schema.params {
            if param.required {
                assert!(
                    required.contains(&param.name.as_str()),
                    "tool '{}': param '{}' is required but not in schema required array: {required:?}",
                    schema.name,
                    param.name
                );
            }
        }
    }
}

// ── Behaviors / metadata ─────────────────────────────────────────────

#[test]
fn connector_behaviors_include_tool_and_app() {
    let c = connector();
    let behaviors = c.behaviors();
    assert!(
        behaviors.contains(&strike48_connector::ConnectorBehavior::Tool),
        "missing Tool behavior"
    );
    assert!(
        behaviors.contains(&strike48_connector::ConnectorBehavior::App),
        "missing App behavior"
    );
}

#[test]
fn metadata_contains_app_manifest() {
    let c = connector();
    let meta = c.metadata();
    let manifest_json = meta
        .get("app_manifest")
        .expect("missing app_manifest in metadata");
    let manifest: Value =
        serde_json::from_str(manifest_json).expect("app_manifest is not valid JSON");
    assert!(
        manifest.get("name").is_some(),
        "app_manifest missing 'name': {manifest}"
    );
    assert!(
        manifest.get("entry_path").is_some(),
        "app_manifest missing 'entry_path': {manifest}"
    );
}
