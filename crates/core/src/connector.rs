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
///
/// TEST-ONLY: this connector must never be driven through the SDK's
/// production registration paths. Its `connector_type()` returns the
/// sentinel `"dioxus-pentest"` on purpose — a tripwire that would fail OTT
/// redemption against StrikeHub's `pentest-connector` pre-approvals if this
/// struct were ever wired into `register_with_ott`/`load_saved_credentials`.
/// The shipping connectors (`PickConnector` in crates/ui and `ToolConnector`
/// in this crate) return `config::CONNECTOR_TYPE` instead.
pub struct PentestConnector {
    tools: Arc<RwLock<ToolRegistry>>,
    metadata: HashMap<String, String>,
    task_types: Vec<TaskTypeSchema>,
    tool_event_tx: broadcast::Sender<ToolEvent>,
    workspace_path: Option<PathBuf>,
    /// Per-engagement tool-execution budget envelope (agent hardening C3).
    /// Defaults to the Balanced capacity; confident callers can replace it
    /// with [`SessionBudget::default_for`] before the engagement starts.
    budget: crate::budget::SessionBudget,
}

/// Build `TaskTypeSchema` entries from the tool registry so the backend
/// knows each tool's input format.
fn build_task_types(tools: &ToolRegistry) -> Vec<TaskTypeSchema> {
    tools
        .supported_schemas()
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
    // Advertise only tools supported on this host (platform + desktop OS) so a
    // Linux-only tool never appears in the tool list on Windows. See #183.
    let schemas: Vec<ToolSchema> = tools.supported_schemas();
    let tool_names: Vec<String> = tools
        .supported_names()
        .iter()
        .map(|s| s.to_string())
        .collect();
    let json_schemas: Vec<Value> = schemas.iter().map(|s| s.to_json_schema()).collect();

    let mut metadata = HashMap::new();
    metadata.insert(
        "tool_schemas".to_string(),
        serde_json::to_string(&json_schemas).unwrap_or_default(),
    );
    metadata.insert("tool_names".to_string(), tool_names.join(","));
    metadata.insert("tool_count".to_string(), schemas.len().to_string());

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
            budget: crate::budget::SessionBudget::default(),
        }
    }

    /// Replace the default session budget (e.g. tuned to the engagement's
    /// aggression level before the scan starts).
    pub fn with_budget(mut self, budget: crate::budget::SessionBudget) -> Self {
        self.budget = budget;
        self
    }

    /// Reset the budget envelope (fresh engagement).
    pub async fn reset_budget(&self) {
        self.budget.reset().await;
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
    /// Test-only sentinel, NOT a valid production connector type (#386).
    /// See the struct-level docs: production registration must go through
    /// `PickConnector`/`ToolConnector`, which return `CONNECTOR_TYPE`.
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
        // Budget envelope (agent hardening C3): refuse tool calls once the
        // per-engagement cap is hit so a runaway/stuck agent can't burn the
        // remaining budget on dead ends.
        let budget = self.budget.clone();

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

            // --- Session budget check (agent hardening C3) ---
            // App requests bypass (they don't consume tool budget).
            match budget.check().await {
                crate::budget::BudgetCheck::Exhausted => {
                    let (used, max) = budget.usage().await;
                    return Ok(serde_json::json!({
                        "success": false,
                        "error": format!("session budget exhausted ({used}/{max}); wind down and produce the report")
                    }));
                }
                crate::budget::BudgetCheck::StallWarning => {
                    tracing::warn!(
                        tool = %name,
                        "session stall detected: consecutive no-progress tool calls; agent may be stuck"
                    );
                    budget.mark_stall_warned().await;
                }
                crate::budget::BudgetCheck::Ok => {}
            }
            tracing::debug!(tool = %name, "Dispatching tool request");

            // Broadcast start event with params
            let _ = event_tx.send(ToolEvent::Started {
                tool_name: name.clone(),
                params: params.clone(),
            });

            let start = std::time::Instant::now();

            // Execute the tool with workspace context. Copy any distributed-
            // trace headers the backend forwarded (request.metadata.sentry_trace
            // / .baggage) into the tool context so the tool span can join the
            // backend's conversation trace (see telemetry::start_tool_span).
            let mut ctx = match workspace_path {
                Some(path) => ToolContext::default().with_workspace(path),
                None => ToolContext::default(),
            };
            if let Some(meta) = request.get("metadata").and_then(|m| m.as_object()) {
                for key in [
                    crate::telemetry::SENTRY_TRACE_HEADER,
                    crate::telemetry::BAGGAGE_HEADER,
                ] {
                    if let Some(val) = meta.get(key).and_then(|v| v.as_str()) {
                        ctx.metadata.insert(key.to_string(), val.to_string());
                    }
                }
            }
            let registry = tools.read().await;

            match registry.execute(tool_name, params, &ctx).await {
                Ok(result) => {
                    let duration_ms = start.elapsed().as_millis() as u64;
                    let success = result.success;
                    let mut result_value = serde_json::to_value(&result).unwrap_or(Value::Null);
                    // Sanitize target-controlled tool output before it re-enters
                    // any LLM agent (#320): scrub secrets and neutralize injected
                    // instructions in `data`/`error`. This is the single agent-
                    // facing choke point, so every tool is covered here rather
                    // than per-tool. `provenance` keeps the (already-redacted)
                    // raw excerpt as the audit trail.
                    let scrub = crate::sanitize::sanitize_agent_result(&mut result_value);
                    if scrub.changed_anything() {
                        tracing::info!(
                            tool = %name,
                            injection_suspected = scrub.injection_suspected,
                            secrets_redacted = scrub.secrets_redacted,
                            markers_neutralized = scrub.markers_neutralized,
                            "sanitized tool output before returning to agent"
                        );
                    }
                    // Budget: a successful run that produced no new evidence
                    // feeds the stall counter; evidence-bearing runs reset it.
                    let made_progress =
                        result.provenance.is_some() || !result.data.is_null() || result.success;
                    if tool_name == "begin_scan" && success {
                        // Agent-reachable reset: bounded so a stuck/injected
                        // agent cannot restart its own envelope at will (review
                        // #452, V1). Once the reset budget is spent this counts
                        // the begin_scan as a normal execution instead.
                        budget.reset_for_new_scan().await;
                    } else {
                        budget.record(made_progress).await;
                    }
                    let _ = event_tx.send(ToolEvent::Completed {
                        tool_name: name,
                        duration_ms,
                        success,
                        result: result_value.clone(),
                    });
                    Ok(result_value)
                }
                Err(e) => {
                    // A failed/skipped run made no progress — feed the stall
                    // detector so a loop of failing probes gets flagged.
                    budget.record(false).await;
                    let _ = event_tx.send(ToolEvent::Failed {
                        tool_name: name,
                        error: e.to_string(),
                    });
                    // The error string is connector-internal (not target output),
                    // but pass it through the same scrub so a secret echoed into
                    // an error message can't leak to the agent either (#320).
                    let mut err_value = serde_json::json!({
                        "success": false,
                        "error": e.to_string()
                    });
                    let _ = crate::sanitize::sanitize_agent_result(&mut err_value);
                    Ok(err_value)
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
