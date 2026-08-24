//! Bridge from the high-level [`ToolConnector`] trait into the low-level
//! [`BaseConnector`] surface that [`ConnectorRunner`](crate::ConnectorRunner)
//! and [`MultiConnectorRunner`](crate::MultiConnectorRunner) consume.
//!
//! Tool authors implement [`ToolConnector`] (fluent schema builder, dispatch
//! by tool name, [`ToolResult`] return type), wrap it in [`ToolAdapter`], and
//! plug it directly into either runner. The adapter takes care of:
//!
//! - Declaring `ConnectorBehavior::Tool` (so the server validates as a tool).
//! - Mapping `tools()` → `capabilities()` (with the JSON-stringified
//!   `input_schema_json` the proto requires).
//! - Forwarding `BaseConnector::execute(payload, capability_id)` to
//!   `ToolConnector::execute(tool_name, params)` and converting [`ToolResult`]
//!   back into a `Result<Value>`.
//! - Combining user-supplied connector metadata. The `tool_schemas` field that
//!   the Matrix server requires for TOOL registration is populated *centrally*
//!   by `connector::build_registration_metadata` from `capabilities()`,
//!   so the adapter does not need to duplicate it here.
//!
//! # Example
//!
//! ```rust,ignore
//! use async_trait::async_trait;
//! use serde_json::{Value, json};
//! use std::sync::Arc;
//! use strike48_connector::*;
//!
//! struct Calculator;
//!
//! #[async_trait]
//! impl ToolConnector for Calculator {
//!     fn tools(&self) -> Vec<ToolSchema> {
//!         vec![ToolSchema::new("add", "Add two numbers")
//!             .param("a", ParamType::Number, "First operand", true)
//!             .param("b", ParamType::Number, "Second operand", true)]
//!     }
//!     async fn execute(&self, tool: &str, params: Value) -> ToolResult {
//!         // Tool arguments are nested under `params["parameters"]`; sibling
//!         // keys `metadata` and `tool` carry server-supplied per-request data.
//!         match tool {
//!             "add" => {
//!                 let a = params["parameters"]["a"].as_f64().unwrap_or(0.0);
//!                 let b = params["parameters"]["b"].as_f64().unwrap_or(0.0);
//!                 ToolResult::success(json!({ "result": a + b }))
//!             }
//!             _ => ToolResult::error_with_code("unknown tool", "UNKNOWN_TOOL"),
//!         }
//!     }
//! }
//!
//! let connector: Arc<dyn BaseConnector> = Arc::new(
//!     ToolAdapter::new("calculator", Calculator)
//!         .with_version("1.0.0")
//!         .with_category("math")
//!         .with_icon("calculator"),
//! );
//! ```

use std::collections::HashMap;
use std::pin::Pin;

use serde_json::Value;

use crate::behaviors::tool::{ToolConnector, ToolResult};
use crate::connector::BaseConnector;
use crate::error::{ConnectorError, Result};
use crate::types::{ConnectorBehavior, TaskTypeSchema};

/// Adapter that exposes any [`ToolConnector`] as a [`BaseConnector`].
///
/// Construct with [`ToolAdapter::new`], optionally override fields with the
/// builder methods, then wrap in `Arc<dyn BaseConnector>` and pass to a runner.
pub struct ToolAdapter<T: ToolConnector + 'static> {
    inner: T,
    connector_type: String,
    version: String,
    category: Option<String>,
    icon: Option<String>,
    output_schema_default: String,
    extra_metadata: HashMap<String, String>,
}

impl<T: ToolConnector + 'static> ToolAdapter<T> {
    /// Wrap the given [`ToolConnector`] as a [`BaseConnector`] with the
    /// supplied `connector_type`. Defaults: `version="0.1.0"`, no category/icon,
    /// empty output schema (`{}`), no extra metadata.
    pub fn new(connector_type: impl Into<String>, inner: T) -> Self {
        Self {
            inner,
            connector_type: connector_type.into(),
            version: "0.1.0".to_string(),
            category: None,
            icon: None,
            output_schema_default: "{}".to_string(),
            extra_metadata: HashMap::new(),
        }
    }

    /// Set the connector version (default `"0.1.0"`). Builder method.
    pub fn with_version(mut self, v: impl Into<String>) -> Self {
        self.version = v.into();
        self
    }

    /// Default category applied to every tool's [`TaskTypeSchema`].
    pub fn with_category(mut self, c: impl Into<String>) -> Self {
        self.category = Some(c.into());
        self
    }

    /// Default icon applied to every tool's [`TaskTypeSchema`].
    pub fn with_icon(mut self, i: impl Into<String>) -> Self {
        self.icon = Some(i.into());
        self
    }

    /// Default output schema applied to every tool (JSON-stringified). Most
    /// callers can leave this at the default `"{}"` since the server doesn't
    /// validate output shape today.
    pub fn with_output_schema_default(mut self, schema: impl Into<String>) -> Self {
        self.output_schema_default = schema.into();
        self
    }

    /// Add an extra `key=value` entry to the connector's registration metadata.
    /// `tool_schemas` is reserved and auto-populated from `tools()`; setting it
    /// here is allowed and will override the auto-injected value (escape hatch).
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_metadata.insert(key.into(), value.into());
        self
    }

    /// Borrow the wrapped [`ToolConnector`].
    pub fn inner(&self) -> &T {
        &self.inner
    }

    fn build_capabilities(&self) -> Vec<TaskTypeSchema> {
        let category = self.category.clone().unwrap_or_default();
        let icon = self.icon.clone().unwrap_or_default();
        let output = self.output_schema_default.clone();
        self.inner
            .tools()
            .into_iter()
            .map(|t| {
                let parameters_json =
                    serde_json::to_string(&t.parameters).unwrap_or_else(|_| "{}".to_string());
                TaskTypeSchema {
                    task_type_id: t.name.clone(),
                    name: t.name,
                    description: t.description,
                    category: category.clone(),
                    icon: icon.clone(),
                    input_schema_json: parameters_json,
                    output_schema_json: output.clone(),
                }
            })
            .collect()
    }
}

impl<T: ToolConnector + 'static> BaseConnector for ToolAdapter<T> {
    fn connector_type(&self) -> &str {
        &self.connector_type
    }

    fn version(&self) -> &str {
        &self.version
    }

    fn behavior(&self) -> ConnectorBehavior {
        ConnectorBehavior::Tool
    }

    fn metadata(&self) -> HashMap<String, String> {
        // tool_schemas is added centrally in build_registration_metadata.
        // Here we surface only user-configured + tool-trait-supplied keys.
        let mut m = self.extra_metadata.clone();
        m.entry("tool_count".to_string())
            .or_insert_with(|| self.inner.tools().len().to_string());
        m.entry("timeout_ms".to_string())
            .or_insert_with(|| self.inner.timeout_ms().to_string());
        m
    }

    fn capabilities(&self) -> Vec<TaskTypeSchema> {
        self.build_capabilities()
    }

    fn execute(
        &self,
        request: Value,
        capability_id: Option<&str>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Value>> + Send + '_>> {
        let tool_name = capability_id.map(|s| s.to_string());
        Box::pin(async move {
            let tool = match tool_name.as_deref() {
                Some(n) if !n.is_empty() => n.to_string(),
                _ => {
                    return Err(ConnectorError::InvalidConfig(
                        "TOOL connector invocation is missing capability_id (tool name)"
                            .to_string(),
                    ));
                }
            };
            tool_result_to_value(self.inner.execute(&tool, request).await, &tool)
        })
    }

    /// Forward the server-supplied context to the wrapped
    /// [`ToolConnector::execute_with_context`].
    ///
    /// This override is what allows per-caller context (tenant id, subject,
    /// attributes) to reach a tool implementation. Without it, the default
    /// `BaseConnector::execute_with_context` would delegate to
    /// `BaseConnector::execute` on this adapter, which then calls
    /// `ToolConnector::execute` and drops the context.
    fn execute_with_context<'a>(
        &'a self,
        request: Value,
        capability_id: Option<&'a str>,
        context: &'a HashMap<String, String>,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<Value>> + Send + 'a>> {
        let tool_name = capability_id.map(|s| s.to_string());
        Box::pin(async move {
            let tool = match tool_name.as_deref() {
                Some(n) if !n.is_empty() => n.to_string(),
                _ => {
                    return Err(ConnectorError::InvalidConfig(
                        "TOOL connector invocation is missing capability_id (tool name)"
                            .to_string(),
                    ));
                }
            };
            tool_result_to_value(
                self.inner
                    .execute_with_context(&tool, request, context)
                    .await,
                &tool,
            )
        })
    }
}

/// Convert a [`ToolResult`] returned by [`ToolConnector::execute`] into the
/// `Result<Value>` that [`BaseConnector::execute`] returns.
///
/// On success: returns the unwrapped result (or `{}` if the tool returned no
/// payload). On failure: returns `ConnectorError::InvokeFailed(...)` carrying
/// the tool's error code (if any) and message.
fn tool_result_to_value(result: ToolResult, tool: &str) -> Result<Value> {
    if result.success {
        Ok(result.result.unwrap_or_else(|| serde_json::json!({})))
    } else {
        let msg = result.error.unwrap_or_else(|| "tool error".to_string());
        let formatted = match result.error_code {
            Some(code) if !code.is_empty() => format!("[{code}] tool '{tool}': {msg}"),
            _ => format!("tool '{tool}': {msg}"),
        };
        Err(ConnectorError::InvokeFailed(formatted))
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::behaviors::tool::{ParamType, ToolSchema};
    use async_trait::async_trait;
    use serde_json::json;

    struct DemoTools;

    #[async_trait]
    impl ToolConnector for DemoTools {
        fn tools(&self) -> Vec<ToolSchema> {
            vec![
                ToolSchema::new("add", "Add two numbers")
                    .param("a", ParamType::Number, "First operand", true)
                    .param("b", ParamType::Number, "Second operand", true),
                ToolSchema::new("greet", "Greet a person").param(
                    "name",
                    ParamType::String,
                    "Name",
                    true,
                ),
            ]
        }
        async fn execute(&self, tool: &str, params: Value) -> ToolResult {
            match tool {
                "add" => {
                    let a = params["a"].as_f64().unwrap_or(0.0);
                    let b = params["b"].as_f64().unwrap_or(0.0);
                    ToolResult::success(json!({ "result": a + b }))
                }
                "greet" => {
                    let name = params["name"].as_str().unwrap_or("World");
                    ToolResult::success(json!({ "message": format!("Hello, {name}!") }))
                }
                "fail_no_code" => ToolResult::error("plain failure"),
                "fail_with_code" => ToolResult::error_with_code("validation broke", "BAD_INPUT"),
                _ => ToolResult::error_with_code("unknown tool", "UNKNOWN_TOOL"),
            }
        }
        fn timeout_ms(&self) -> u64 {
            7000
        }
    }

    fn adapter() -> ToolAdapter<DemoTools> {
        ToolAdapter::new("demo_tools", DemoTools)
            .with_version("1.2.3")
            .with_category("demo")
            .with_icon("flask")
            .with_metadata("docs_url", "https://example.com/demo")
    }

    #[test]
    fn adapter_advertises_tool_behavior() {
        let a = adapter();
        assert_eq!(a.behavior(), ConnectorBehavior::Tool);
        assert_eq!(a.behaviors(), vec![ConnectorBehavior::Tool]);
    }

    #[test]
    fn adapter_passes_through_identity() {
        let a = adapter();
        assert_eq!(a.connector_type(), "demo_tools");
        assert_eq!(a.version(), "1.2.3");
    }

    #[test]
    fn adapter_capabilities_match_tools() {
        let a = adapter();
        let caps = a.capabilities();
        assert_eq!(caps.len(), 2);

        let add = caps.iter().find(|c| c.task_type_id == "add").unwrap();
        assert_eq!(add.name, "add");
        assert_eq!(add.description, "Add two numbers");
        assert_eq!(add.category, "demo");
        assert_eq!(add.icon, "flask");
        let parsed: Value = serde_json::from_str(&add.input_schema_json).unwrap();
        assert_eq!(parsed["type"], "object");
        assert!(parsed["properties"]["a"].is_object());
        assert!(parsed["properties"]["b"].is_object());

        let greet = caps.iter().find(|c| c.task_type_id == "greet").unwrap();
        assert_eq!(greet.description, "Greet a person");
    }

    #[test]
    fn adapter_metadata_includes_user_keys_and_derived_counts() {
        let a = adapter();
        let m = a.metadata();
        assert_eq!(
            m.get("docs_url").map(|s| s.as_str()),
            Some("https://example.com/demo")
        );
        assert_eq!(m.get("tool_count").map(|s| s.as_str()), Some("2"));
        assert_eq!(m.get("timeout_ms").map(|s| s.as_str()), Some("7000"));
        // tool_schemas is NOT injected here — it's added by build_registration_metadata.
        assert!(!m.contains_key("tool_schemas"));
    }

    #[tokio::test]
    async fn adapter_dispatches_to_named_tool_on_success() {
        let a = adapter();
        let v = a
            .execute(json!({ "a": 2.5, "b": 3.0 }), Some("add"))
            .await
            .expect("add tool should succeed");
        assert_eq!(v["result"], json!(5.5));

        let g = a
            .execute(json!({ "name": "Sreejith" }), Some("greet"))
            .await
            .expect("greet tool should succeed");
        assert_eq!(g["message"], json!("Hello, Sreejith!"));
    }

    #[tokio::test]
    async fn adapter_returns_error_when_capability_id_missing() {
        let a = adapter();
        let err = a.execute(json!({}), None).await.unwrap_err();
        match err {
            ConnectorError::InvalidConfig(msg) => assert!(msg.contains("capability_id")),
            other => panic!("expected InvalidConfig, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn adapter_returns_error_when_capability_id_empty() {
        let a = adapter();
        let err = a.execute(json!({}), Some("")).await.unwrap_err();
        assert!(matches!(err, ConnectorError::InvalidConfig(_)));
    }

    #[tokio::test]
    async fn adapter_propagates_tool_error_with_code() {
        let a = adapter();
        let err = a
            .execute(json!({}), Some("fail_with_code"))
            .await
            .unwrap_err();
        match err {
            ConnectorError::InvokeFailed(msg) => {
                assert!(msg.contains("BAD_INPUT"), "missing error code in: {msg}");
                assert!(
                    msg.contains("validation broke"),
                    "missing message in: {msg}"
                );
                assert!(
                    msg.contains("fail_with_code"),
                    "missing tool name in: {msg}"
                );
            }
            other => panic!("expected InvokeFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn adapter_propagates_tool_error_without_code() {
        let a = adapter();
        let err = a
            .execute(json!({}), Some("fail_no_code"))
            .await
            .unwrap_err();
        match err {
            ConnectorError::InvokeFailed(msg) => {
                assert!(msg.contains("plain failure"), "missing message in: {msg}");
                assert!(!msg.contains("[]"), "stray empty code brackets in: {msg}");
            }
            other => panic!("expected InvokeFailed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn adapter_treats_unknown_tool_as_invoke_failed() {
        let a = adapter();
        let err = a
            .execute(json!({}), Some("does_not_exist"))
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::InvokeFailed(_)));
    }

    // ---- Context forwarding tests ------------------------------------------
    //
    // These tests pin the contract that `ToolAdapter` forwards the
    // server-supplied per-request context to `ToolConnector::execute_with_context`,
    // and that tools which only override `execute` keep working through the
    // default delegation path.

    use std::sync::Mutex as StdMutex;

    /// Tool that overrides `execute_with_context` and captures what it
    /// received. `execute` is `unreachable!()` so the test fails loudly if
    /// the adapter takes the legacy path.
    struct CtxCapturingTool {
        seen: std::sync::Arc<StdMutex<Option<HashMap<String, String>>>>,
    }

    #[async_trait]
    impl ToolConnector for CtxCapturingTool {
        fn tools(&self) -> Vec<ToolSchema> {
            vec![ToolSchema::new("noop", "Capture the calling context")]
        }
        async fn execute(&self, _tool: &str, _params: Value) -> ToolResult {
            unreachable!("ToolAdapter must dispatch to execute_with_context, not bare execute")
        }
        async fn execute_with_context(
            &self,
            _tool: &str,
            _params: Value,
            context: &HashMap<String, String>,
        ) -> ToolResult {
            *self.seen.lock().unwrap() = Some(context.clone());
            ToolResult::ok()
        }
    }

    /// Tool that only implements `execute`. Verifies the default
    /// `execute_with_context` correctly delegates here.
    struct LegacyTool {
        called: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    #[async_trait]
    impl ToolConnector for LegacyTool {
        fn tools(&self) -> Vec<ToolSchema> {
            vec![ToolSchema::new(
                "noop",
                "Legacy tool with no context support",
            )]
        }
        async fn execute(&self, _tool: &str, _params: Value) -> ToolResult {
            self.called.store(true, std::sync::atomic::Ordering::SeqCst);
            ToolResult::ok()
        }
    }

    #[tokio::test]
    async fn tool_adapter_forwards_context_to_execute_with_context() {
        let seen = std::sync::Arc::new(StdMutex::new(None));
        let adapter = ToolAdapter::new("ctx_tool", CtxCapturingTool { seen: seen.clone() });

        let mut context = HashMap::new();
        context.insert("tenant_id".into(), "tenant-acme".into());
        context.insert("user_id".into(), "subject-99".into());

        adapter
            .execute_with_context(json!({}), Some("noop"), &context)
            .await
            .expect("execute_with_context must succeed");

        let captured = seen
            .lock()
            .unwrap()
            .clone()
            .expect("ToolAdapter must invoke execute_with_context on the inner tool");
        assert_eq!(
            captured, context,
            "context must round-trip through ToolAdapter to the inner ToolConnector"
        );
    }

    #[tokio::test]
    async fn tool_adapter_default_path_keeps_working_for_legacy_tool() {
        let called = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let adapter = ToolAdapter::new(
            "legacy_tool",
            LegacyTool {
                called: called.clone(),
            },
        );

        // Even though we pass a non-empty context, a tool that only
        // implements `execute` must still be reached via the default
        // `ToolConnector::execute_with_context` delegation.
        let mut context = HashMap::new();
        context.insert("tenant_id".into(), "ignored-by-legacy".into());

        adapter
            .execute_with_context(json!({}), Some("noop"), &context)
            .await
            .expect("legacy tool must still execute through the default path");

        assert!(
            called.load(std::sync::atomic::Ordering::SeqCst),
            "default ToolConnector::execute_with_context must delegate to execute"
        );
    }

    #[tokio::test]
    async fn tool_adapter_execute_with_context_requires_capability_id() {
        // Mirrors `adapter_returns_error_when_capability_id_missing` for the
        // context-aware path so the validation invariant doesn't drift if
        // someone refactors one without the other.
        let seen = std::sync::Arc::new(StdMutex::new(None));
        let adapter = ToolAdapter::new("ctx_tool", CtxCapturingTool { seen: seen.clone() });
        let context = HashMap::new();
        let err = adapter
            .execute_with_context(json!({}), None, &context)
            .await
            .unwrap_err();
        assert!(matches!(err, ConnectorError::InvalidConfig(_)));
        // The inner tool must NOT have been called when validation fails up
        // front — otherwise we'd be losing the early-return guarantee.
        assert!(seen.lock().unwrap().is_none());
    }

    #[test]
    fn build_registration_metadata_injects_tool_schemas_for_adapter() {
        // Integration with the SDK-level auto-injection helper: ensure a
        // ToolAdapter passed into build_registration_metadata produces the
        // tool_schemas JSON the Matrix server validates against.
        let a = adapter();
        let merged = crate::connector::build_registration_metadata(&a);
        let tool_schemas_json = merged
            .get("tool_schemas")
            .expect("tool_schemas must be auto-injected for TOOL behavior");
        let parsed: Value = serde_json::from_str(tool_schemas_json).unwrap();
        let arr = parsed.as_array().expect("tool_schemas must be an array");
        assert_eq!(arr.len(), 2);
        for entry in arr {
            assert!(entry["name"].is_string());
            assert!(entry["description"].is_string());
            assert!(!entry["name"].as_str().unwrap().is_empty());
            assert!(!entry["description"].as_str().unwrap().is_empty());
        }
    }
}
