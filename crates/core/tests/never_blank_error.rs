//! Integration tests for the "never a blank failure" contract
//! (Strike48/matrix#4715, defect 2).
//!
//! The DVWA run of 2026-09-24 failed with `nil x3` / empty error strings:
//! the model-shaped params were rejected and the failure crossed the
//! connector boundary with a BLANK message, so the model "diagnosed blind
//! all night". These tests pin the two choke points:
//!
//! 1. `ToolRegistry::execute` — a failed `ToolResult` with an empty error is
//!    replaced with a human-actionable message naming the tool.
//! 2. `strike48_connector::utils::sanitize_failure_payload` — the SDK wire
//!    layer patches blank payload failures and surfaces the message in the
//!    ExecuteResponse envelope.

use async_trait::async_trait;
use pentest_core::error::Result as CoreResult;
use pentest_core::tools::{PentestTool, ToolContext, ToolRegistry, ToolResult, ToolSchema};
use serde_json::{json, Value};

/// A tool that fails with a BLANK error — the exact shape that broke the
/// platform in the DVWA run.
struct BlankErrorTool;

#[async_trait]
impl PentestTool for BlankErrorTool {
    fn name(&self) -> &str {
        "blank_error_tool"
    }

    fn description(&self) -> &str {
        "A test tool that fails with an empty error string."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
    }

    async fn execute(&self, _params: Value, _ctx: &ToolContext) -> CoreResult<ToolResult> {
        Ok(ToolResult::error(""))
    }
}

/// A tool that fails with a REAL message — must pass through untouched.
struct HonestErrorTool;

#[async_trait]
impl PentestTool for HonestErrorTool {
    fn name(&self) -> &str {
        "honest_error_tool"
    }

    fn description(&self) -> &str {
        "A test tool that fails with a real message."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
    }

    async fn execute(&self, _params: Value, _ctx: &ToolContext) -> CoreResult<ToolResult> {
        Ok(ToolResult::error("target parameter is required"))
    }
}

/// A tool that succeeds — must pass through untouched.
struct SuccessTool;

#[async_trait]
impl PentestTool for SuccessTool {
    fn name(&self) -> &str {
        "success_tool"
    }

    fn description(&self) -> &str {
        "A test tool that succeeds."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
    }

    async fn execute(&self, _params: Value, _ctx: &ToolContext) -> CoreResult<ToolResult> {
        Ok(ToolResult::success(json!({"count": 1})))
    }
}

#[tokio::test]
async fn blank_tool_error_is_replaced_with_actionable_message() {
    let mut registry = ToolRegistry::new();
    registry.register(BlankErrorTool);

    let result = registry
        .execute("blank_error_tool", json!({}), &ToolContext::default())
        .await
        .expect("registry execute must not Err for a tool-level failure");

    assert!(!result.success, "the failure must stay a failure");
    let error = result.error.as_deref().unwrap_or("");
    assert!(
        !error.trim().is_empty(),
        "a blank failure must never leave the registry (issue #4715)"
    );
    assert!(
        error.contains("blank_error_tool"),
        "the actionable message should name the tool: {error}"
    );
}

#[tokio::test]
async fn real_tool_error_passes_through_untouched() {
    let mut registry = ToolRegistry::new();
    registry.register(HonestErrorTool);

    let result = registry
        .execute("honest_error_tool", json!({}), &ToolContext::default())
        .await
        .expect("registry execute must not Err for a tool-level failure");

    assert!(!result.success);
    assert_eq!(
        result.error.as_deref(),
        Some("target parameter is required")
    );
}

#[tokio::test]
async fn successful_tool_result_passes_through_untouched() {
    let mut registry = ToolRegistry::new();
    registry.register(SuccessTool);

    let result = registry
        .execute("success_tool", json!({}), &ToolContext::default())
        .await
        .expect("registry execute must not Err for a tool-level success");

    assert!(result.success);
    assert_eq!(result.data, json!({"count": 1}));
}

#[tokio::test]
async fn unknown_tool_error_is_never_blank() {
    let mut registry = ToolRegistry::new();
    registry.register(SuccessTool);

    let outcome = registry
        .execute("no_such_tool", json!({}), &ToolContext::default())
        .await;

    match outcome {
        Err(e) => assert!(!e.to_string().trim().is_empty()),
        Ok(r) => {
            assert!(!r.success);
            assert!(!r.error.as_deref().unwrap_or("").trim().is_empty());
        }
    }
}

#[test]
fn sdk_wire_layer_patches_blank_failures() {
    // The SDK envelope is `success: true, error: ""` for any Ok(payload);
    // sanitize_failure_payload is what keeps a BLANK payload failure from
    // crossing the wire. (The vendored SDK's own unit tests cover the same
    // function; this runs it through the public API from a dependent crate.)
    let payload = json!({
        "success": false,
        "data": Value::Null,
        "error": "",
        "outcome": "failed",
    });

    let (patched, envelope_error) =
        strike48_connector::utils::sanitize_failure_payload(&payload, Some("nmap"));

    let msg = envelope_error.expect("blank failure must yield an envelope message");
    assert!(!msg.trim().is_empty());
    assert_eq!(patched["error"], msg);

    // A failure that already carries a message is untouched.
    let honest = json!({"success": false, "error": "target parameter is required"});
    let (patched, envelope_error) =
        strike48_connector::utils::sanitize_failure_payload(&honest, Some("nmap"));
    assert!(envelope_error.is_none());
    assert_eq!(patched["error"], "target parameter is required");

    // Successes are untouched.
    let ok_payload = json!({"success": true, "data": json!({})});
    let (patched, envelope_error) =
        strike48_connector::utils::sanitize_failure_payload(&ok_payload, Some("nmap"));
    assert!(envelope_error.is_none());
    assert_eq!(patched["success"], true);
}
