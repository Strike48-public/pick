//! Tool-only `BaseConnector` implementation.
//!
//! [`ToolConnector`] declares `behaviors() = [Tool]` and nothing else: it
//! registers the device's tool set (nmap, etc.) with Strike48 and executes
//! those tools when the agent invokes them. It is the UI-independent sibling of
//! the shipping Dioxus `PickConnector` (crates/ui) — that one adds the `App`
//! (LiveView) behavior, which pulls in Dioxus, an IPC server, and a WebSocket
//! proxy. Here we keep ONLY the Tool path so the crux mobile shells (which do
//! not embed a Dioxus frontend) can still register a connector and give the
//! agent real tools to run.
//!
//! The SDK's `ConnectorRunner` drives this struct: connection, registration,
//! keepalive, OTT exchange, and reconnection are all handled by the runner — we
//! only implement the business callbacks (`capabilities`, `metadata`,
//! `execute_with_context`).

use crate::tools::{ToolContext, ToolRegistry};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use strike48_connector::{
    BaseConnector, ConnectorBehavior, ConnectorError, PayloadEncoding, Result as SdkResult,
    TaskTypeSchema,
};
use tokio::sync::RwLock;

/// Tool timeout advertised to the platform and used by the runner. Matches the
/// shipping `PickConnector` — some tools (e.g. long scans) run for minutes.
const TOOL_TIMEOUT_MS: u64 = 300_000;

/// A Tool-only `BaseConnector`.
///
/// Holds just the state the tool path needs: the registry, the connector
/// identity used for registration and agent tagging, an optional workspace
/// path, and the Matrix API URL used to build a per-execution chat client.
/// There is deliberately NO WebSocket connection map, IPC address, event
/// broadcast, or app manifest — those are App-behavior concerns.
pub struct ToolConnector {
    tools: Arc<RwLock<ToolRegistry>>,
    connector_name: String,
    instance_id: String,
    workspace_path: Option<PathBuf>,
    matrix_api_url: String,
}

impl ToolConnector {
    /// Construct a Tool-only connector.
    pub fn new(
        tools: Arc<RwLock<ToolRegistry>>,
        connector_name: impl Into<String>,
        instance_id: impl Into<String>,
        workspace_path: Option<PathBuf>,
        matrix_api_url: impl Into<String>,
    ) -> Self {
        Self {
            tools,
            connector_name: connector_name.into(),
            instance_id: instance_id.into(),
            workspace_path,
            matrix_api_url: matrix_api_url.into(),
        }
    }
}

impl BaseConnector for ToolConnector {
    fn connector_type(&self) -> &str {
        &self.connector_name
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn behaviors(&self) -> Vec<ConnectorBehavior> {
        // Tool-only: no App/LiveView behavior. This is the whole point of this
        // connector — it registers device tools without a Dioxus frontend.
        vec![ConnectorBehavior::Tool]
    }

    fn metadata(&self) -> HashMap<String, String> {
        // No app_manifest here (that is an App-behavior concern). We advertise
        // the supported tool names and the timeout so the platform sees a
        // consistent picture of what this connector can run.
        let mut metadata = HashMap::new();
        metadata.insert("timeout_ms".to_string(), TOOL_TIMEOUT_MS.to_string());

        // Advertise only tools supported on this host (platform + desktop OS)
        // so a Linux-only tool never appears in the tool list on another OS.
        // See #183. try_read() is used because this sync callback runs inside
        // the tokio runtime; the registry is written once at startup and never
        // mutated during execution.
        if let Ok(tools) = self.tools.try_read() {
            let tool_names: Vec<String> = tools
                .supported_names()
                .iter()
                .map(|s| s.to_string())
                .collect();
            metadata.insert("tool_names".to_string(), tool_names.join(","));
        }

        metadata
    }

    fn capabilities(&self) -> Vec<TaskTypeSchema> {
        // These sync callbacks are called from within the tokio runtime so we
        // cannot use blocking_read(). try_read() is acceptable because the tools
        // registry is written once at startup and never mutated during execution.
        let Ok(tools) = self.tools.try_read() else {
            return Vec::new();
        };
        // Advertise only tools supported on this host (platform + desktop OS). See #183.
        tools
            .supported_schemas()
            .iter()
            .map(|schema| {
                // `to_json_schema()` returns the full tool wrapper
                // `{name, description, parameters: {type, properties, required}, ...}`.
                // `TaskTypeSchema.input_schema_json` must carry ONLY the JSON schema
                // (the `parameters` sub-object): the SDK's `build_registration_metadata`
                // wraps `input_schema_json` under a `"parameters"` key itself, so passing
                // the full wrapper here produces a double-nested schema whose ROOT has no
                // `type`, which AWS Bedrock rejects
                // (`toolConfig.tools.N.toolSpec.inputSchema.json.type must be object`).
                // Unwrap `.parameters` to match `PickConnector::capabilities`.
                let json_schema = schema.to_json_schema();
                let input_schema = json_schema
                    .get("parameters")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({"type": "object", "properties": {}}));
                TaskTypeSchema {
                    task_type_id: schema.name.clone(),
                    name: schema.name.clone(),
                    description: schema.description.clone(),
                    category: String::new(),
                    icon: String::new(),
                    input_schema_json: serde_json::to_string(&input_schema)
                        .unwrap_or_else(|_| r#"{"type":"object","properties":{}}"#.to_string()),
                    output_schema_json: "{}".to_string(),
                }
            })
            .collect()
    }

    fn supported_encodings(&self) -> Vec<PayloadEncoding> {
        vec![PayloadEncoding::Json]
    }

    fn timeout_ms(&self) -> u64 {
        TOOL_TIMEOUT_MS
    }

    fn execute(
        &self,
        _request: Value,
        _capability_id: Option<&str>,
    ) -> Pin<Box<dyn std::future::Future<Output = SdkResult<Value>> + Send + '_>> {
        // The runner always calls execute_with_context; this is a stub that
        // should never be reached in practice. If it is, return an error.
        Box::pin(async move {
            Err(ConnectorError::StreamError(
                "execute() called without context; use execute_with_context".to_string(),
            ))
        })
    }

    fn execute_with_context<'a>(
        &'a self,
        request: Value,
        _capability_id: Option<&'a str>,
        context: &'a HashMap<String, String>,
    ) -> Pin<Box<dyn std::future::Future<Output = SdkResult<Value>> + Send + 'a>> {
        Box::pin(async move {
            // Tool-only connector: every request is a tool invocation. The SDK
            // spawns execute_with_context in its own tokio task already, so we
            // run synchronously here.
            let tool_name = request
                .get("tool")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let params = request
                .get("parameters")
                .cloned()
                .unwrap_or_else(|| request.clone());

            tracing::info!(tool = tool_name.as_str(), "tool execution started");

            let start = std::time::Instant::now();

            // Build ToolContext, attaching the workspace when configured.
            let mut ctx = match &self.workspace_path {
                Some(path) => ToolContext::default().with_workspace(path.clone()),
                None => ToolContext::default(),
            };

            // Populate metadata (instance_id, request_id, tool_call_id) from the
            // caller-supplied context so tools that correlate live state can find
            // their task.
            let request_id = context.get("request_id").cloned().unwrap_or_default();
            ctx.metadata
                .insert("instance_id".to_string(), self.instance_id.clone());
            ctx.metadata
                .insert("request_id".to_string(), request_id.clone());
            if let Some(tool_call_id) = context.get("tool_call_id") {
                if !tool_call_id.is_empty() {
                    ctx.metadata
                        .insert("tool_call_id".to_string(), tool_call_id.clone());
                }
            }

            // Forward the platform session token so tools that call back into
            // Strike48 (StrikeKit uploads, document_write, etc.) can authenticate.
            if let Some(token) = context.get("session_token") {
                ctx.metadata
                    .insert("session_token".to_string(), token.clone());
            }

            // Tag the executing agent for provenance/logging.
            ctx = ctx.with_agent_name(self.connector_name.clone());

            // Build a Matrix client when we know the API URL so tools that create
            // documents/evidence can reach the platform.
            if !self.matrix_api_url.is_empty() {
                let matrix_client =
                    Arc::new(crate::matrix::MatrixChatClient::new(&self.matrix_api_url));
                ctx = ctx.with_matrix_client(matrix_client);
            }

            let tools = self.tools.read().await;
            let result = match tools.execute(&tool_name, params, &ctx).await {
                Ok(result) => {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    tracing::info!(
                        tool = tool_name.as_str(),
                        duration_ms,
                        success = result.success,
                        "tool execution completed"
                    );
                    result
                }
                Err(e) => {
                    tracing::warn!(
                        tool = tool_name.as_str(),
                        error = %e,
                        "tool execution failed"
                    );
                    crate::tools::ToolResult::error(e.to_string())
                }
            };

            let result_json = serde_json::to_value(&result).unwrap_or(Value::Null);
            Ok(result_json)
        })
    }
}

/// Build the SDK config and run the Tool-only connector to completion.
///
/// This is the entrypoint the crux FFI spawns on its tokio runtime. It blocks
/// (awaits) for the connector's lifetime: the `ConnectorRunner` manages
/// connection, registration, keepalive, OTT exchange, and reconnection, so this
/// future only resolves on a clean shutdown or a non-recoverable error. Errors
/// are mapped to `String` for the FFI caller's logging.
pub async fn run_tool_connector(
    config: crate::config::ConnectorConfig,
    tools: Arc<RwLock<ToolRegistry>>,
) -> Result<(), String> {
    use strike48_connector::ConnectorRunner;

    let sdk_config = config.to_sdk_config();

    // Derive the Matrix API URL for tool context. The connector host and the
    // Matrix API host can differ; the config host is the best default we have
    // here, and MATRIX_API_URL / MATRIX_URL env vars still override inside the
    // tools that need it.
    let matrix_api_url = config.host.clone();

    let connector = Arc::new(ToolConnector::new(
        tools,
        config.connector_name.clone(),
        config.instance_id.clone(),
        None,
        matrix_api_url,
    ));

    tracing::info!(
        connector = config.connector_name.as_str(),
        instance_id = config.instance_id.as_str(),
        host = config.host.as_str(),
        "starting tool-only connector"
    );

    let runner = ConnectorRunner::new(sdk_config, connector);
    runner.run().await.map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Result as ToolFnResult;
    use crate::tools::{PentestTool, ToolResult, ToolSchema};
    use async_trait::async_trait;

    // A minimal tool so `capabilities()`/`metadata()` exercise a non-empty
    // registry. We build the registry directly here (rather than pulling
    // `pentest_tools::create_tool_registry`) because the core->tools->core
    // dev-dependency cycle would otherwise produce two `pentest_core` builds
    // whose `ToolRegistry` types don't unify.
    struct StubTool;

    #[async_trait]
    impl PentestTool for StubTool {
        fn name(&self) -> &str {
            "stub_tool"
        }
        fn description(&self) -> &str {
            "A stub tool for tests"
        }
        fn schema(&self) -> ToolSchema {
            ToolSchema::new("stub_tool", "A stub tool for tests")
        }
        async fn execute(&self, _params: Value, _ctx: &ToolContext) -> ToolFnResult<ToolResult> {
            Ok(ToolResult::success(serde_json::json!({})))
        }
    }

    fn test_connector() -> ToolConnector {
        let mut registry = ToolRegistry::new();
        registry.register(StubTool);
        ToolConnector::new(
            Arc::new(RwLock::new(registry)),
            "pentest-connector",
            "test-instance",
            None,
            String::new(),
        )
    }

    #[test]
    fn behaviors_is_tool_only() {
        let connector = test_connector();
        assert_eq!(connector.behaviors(), vec![ConnectorBehavior::Tool]);
    }

    #[test]
    fn capabilities_non_empty_and_root_object_schema() {
        let connector = test_connector();
        let caps = connector.capabilities();
        assert!(
            !caps.is_empty(),
            "expected the real registry to expose tools"
        );
        // Regression guard mirroring PickConnector: each input_schema_json must
        // be a ROOT object schema, not the double-wrapped tool wrapper.
        for cap in &caps {
            let parsed: Value = serde_json::from_str(&cap.input_schema_json)
                .unwrap_or_else(|e| panic!("{}: input_schema_json not valid JSON: {e}", cap.name));
            assert_eq!(
                parsed["type"], "object",
                "{}: input_schema_json root must have type=object",
                cap.name
            );
            assert!(
                !parsed["parameters"].is_object(),
                "{}: input_schema_json is double-wrapped",
                cap.name
            );
        }
    }

    #[test]
    fn metadata_has_no_app_manifest() {
        let connector = test_connector();
        let metadata = connector.metadata();
        assert!(
            !metadata.contains_key("app_manifest"),
            "tool-only connector must not advertise an app_manifest"
        );
        assert!(
            metadata.contains_key("tool_names"),
            "metadata should advertise tool_names"
        );
    }
}
