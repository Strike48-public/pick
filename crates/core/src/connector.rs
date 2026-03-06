//! Strike48 Connector SDK integration

use crate::tools::{ToolContext, ToolRegistry, ToolSchema};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use strike48_connector::{
    AppPageRequest, AppPageResponse, BaseConnector, ConnectorBehavior, ConnectorError,
    PayloadEncoding, Result as SdkResult, TaskTypeSchema,
};
use tokio::sync::{broadcast, RwLock};

use crate::terminal::TerminalLine;

/// Event emitted during tool execution
#[derive(Debug, Clone)]
pub enum ToolEvent {
    /// A tool has started executing
    Started { tool_name: String, params: Value },
    /// A tool completed execution
    Completed {
        tool_name: String,
        duration_ms: u64,
        success: bool,
        result: Value,
    },
    /// A tool execution failed
    Failed { tool_name: String, error: String },
}

impl ToolEvent {
    /// Format a JSON value as a compact summary (truncated for readability)
    fn pretty_json(value: &Value) -> String {
        serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
    }

    /// Convert this event into a TerminalLine for display
    pub fn to_terminal_line(&self) -> TerminalLine {
        match self {
            ToolEvent::Started { tool_name, params } => {
                let details = Self::pretty_json(params);
                TerminalLine::info(format!("[tool] {} started", tool_name))
                    .with_details(format!("args: {}", details))
            }
            ToolEvent::Completed {
                tool_name,
                duration_ms,
                success,
                result,
            } => {
                let details = Self::pretty_json(result);
                if *success {
                    TerminalLine::success(format!(
                        "[tool] {} completed ({}ms)",
                        tool_name, duration_ms
                    ))
                    .with_details(details)
                } else {
                    TerminalLine::error(format!(
                        "[tool] {} returned error ({}ms)",
                        tool_name, duration_ms
                    ))
                    .with_details(details)
                }
            }
            ToolEvent::Failed { tool_name, error } => {
                TerminalLine::error(format!("[tool] {} failed", tool_name))
                    .with_details(error.clone())
            }
        }
    }
}

/// Pentest connector implementation for the Strike48 Connector SDK.
///
/// Implements `BaseConnector` to route incoming requests to the tool registry
/// or built-in file browser. Used directly in integration tests; production
/// apps use `LiveViewConnector` from the UI crate instead.
pub struct PentestConnector {
    tools: Arc<RwLock<ToolRegistry>>,
    metadata: HashMap<String, String>,
    task_types: Vec<TaskTypeSchema>,
    tool_event_tx: broadcast::Sender<ToolEvent>,
    workspace_path: Option<PathBuf>,
}

/// Build `TaskTypeSchema` entries from the tool registry so the backend
/// knows each tool's input format.
fn build_task_types(tools: &ToolRegistry) -> Vec<TaskTypeSchema> {
    tools
        .schemas()
        .iter()
        .map(|s| {
            let json_schema = s.to_json_schema();
            let input_schema = json_schema
                .get("parameters")
                .cloned()
                .unwrap_or(serde_json::json!({"type": "object", "properties": {}}));
            TaskTypeSchema {
                task_type_id: s.name.clone(),
                name: s.name.clone(),
                description: s.description.clone(),
                category: "pentest".to_string(),
                icon: String::new(),
                input_schema_json: serde_json::to_string(&input_schema).unwrap_or_default(),
                output_schema_json: String::new(),
            }
        })
        .collect()
}

/// Build the connector metadata map with tool info and the app manifest.
fn build_metadata(tools: &ToolRegistry) -> HashMap<String, String> {
    let schemas: Vec<ToolSchema> = tools.schemas();
    let tool_names: Vec<String> = tools.names().iter().map(|s| s.to_string()).collect();
    let json_schemas: Vec<Value> = schemas.iter().map(|s| s.to_json_schema()).collect();

    let mut metadata = HashMap::new();
    metadata.insert(
        "tool_schemas".to_string(),
        serde_json::to_string(&json_schemas).unwrap_or_default(),
    );
    metadata.insert("tool_names".to_string(), tool_names.join(","));
    metadata.insert("tool_count".to_string(), tools.tools().len().to_string());

    // Register app manifest for the file browser
    let manifest = crate::file_browser::file_browser_manifest();
    metadata.insert(
        "app_manifest".to_string(),
        serde_json::to_string(&manifest).unwrap_or_default(),
    );

    metadata
}

impl PentestConnector {
    /// Create a new pentest connector
    pub fn new(tools: ToolRegistry, workspace_path: Option<PathBuf>) -> Self {
        let task_types = build_task_types(&tools);
        let metadata = build_metadata(&tools);
        let (tool_event_tx, _) = broadcast::channel(64);

        Self {
            tools: Arc::new(RwLock::new(tools)),
            metadata,
            task_types,
            tool_event_tx,
            workspace_path,
        }
    }

    /// Get the tool registry
    pub fn tools(&self) -> Arc<RwLock<ToolRegistry>> {
        self.tools.clone()
    }

    /// Subscribe to tool execution events
    pub fn tool_event_rx(&self) -> broadcast::Receiver<ToolEvent> {
        self.tool_event_tx.subscribe()
    }
}

impl BaseConnector for PentestConnector {
    fn connector_type(&self) -> &str {
        "dioxus-pentest"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn execute(
        &self,
        request: Value,
        _capability_id: Option<&str>,
    ) -> Pin<Box<dyn std::future::Future<Output = SdkResult<Value>> + Send>> {
        let tools = self.tools.clone();
        let event_tx = self.tool_event_tx.clone();
        let workspace_path = self.workspace_path.clone();

        Box::pin(async move {
            tracing::debug!("Raw execute request: {}", request);

            // Route by request shape: app requests have "path" but no "tool"
            if request.get("path").is_some() && request.get("tool").is_none() {
                let page_request: AppPageRequest = serde_json::from_value(request.clone())
                    .unwrap_or_else(|_| AppPageRequest::new("/"));

                tracing::info!("App request received: path={}", page_request.path);

                // Built-in HTML file browser
                tracing::info!("Using HTML file browser fallback");
                let response = match workspace_path.as_deref() {
                    Some(ws) => crate::file_browser::handle_request(ws, &page_request),
                    None => AppPageResponse::error(503, "No workspace configured"),
                };
                return serde_json::to_value(response)
                    .map_err(|e| ConnectorError::SerializationError(e.to_string()));
            }

            // Parse the request
            let tool_name = request
                .get("tool")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ConnectorError::InvalidConfig("Missing tool name".to_string()))?;

            // Backend sends params under "parameters" key
            let params = request
                .get("parameters")
                .cloned()
                .unwrap_or_else(|| request.clone());

            let name = tool_name.to_string();
            tracing::debug!(tool = %name, "Dispatching tool request");

            // Broadcast start event with params
            let _ = event_tx.send(ToolEvent::Started {
                tool_name: name.clone(),
                params: params.clone(),
            });

            let start = std::time::Instant::now();

            // Execute the tool with workspace context
            let ctx = match workspace_path {
                Some(path) => ToolContext::default().with_workspace(path),
                None => ToolContext::default(),
            };
            let registry = tools.read().await;

            match registry.execute(tool_name, params, &ctx).await {
                Ok(result) => {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    let success = result.success;
                    let result_value = serde_json::to_value(&result).unwrap_or(Value::Null);
                    let _ = event_tx.send(ToolEvent::Completed {
                        tool_name: name,
                        duration_ms,
                        success,
                        result: result_value.clone(),
                    });
                    Ok(result_value)
                }
                Err(e) => {
                    let _ = event_tx.send(ToolEvent::Failed {
                        tool_name: name,
                        error: e.to_string(),
                    });
                    Ok(serde_json::json!({
                        "success": false,
                        "error": e.to_string()
                    }))
                }
            }
        })
    }

    fn behavior(&self) -> ConnectorBehavior {
        ConnectorBehavior::Tool
    }

    fn behaviors(&self) -> Vec<ConnectorBehavior> {
        vec![ConnectorBehavior::Tool, ConnectorBehavior::App]
    }

    fn supported_encodings(&self) -> Vec<PayloadEncoding> {
        vec![PayloadEncoding::Json]
    }

    /// SDK trait requires owned `HashMap<String, String>`, so we must clone.
    /// The data is built once at construction and is immutable thereafter,
    /// so the cost is bounded and paid only on (re)registration.
    fn metadata(&self) -> HashMap<String, String> {
        self.metadata.clone()
    }

    /// SDK trait requires owned `Vec<TaskTypeSchema>`, so we must clone.
    /// Same rationale as `metadata()` above: built once, cloned only on
    /// (re)registration with the Strike48 backend.
    fn capabilities(&self) -> Vec<TaskTypeSchema> {
        self.task_types.clone()
    }

    fn timeout_ms(&self) -> u64 {
        300_000 // 5 minutes
    }
}
