//! `BaseConnector` implementation for Pick.
//!
//! `PickConnector` wraps the shared domain state (tool registry, workspace,
//! event bus, WS connection map, etc.) and delegates to the tool execution
//! and LiveView proxy logic that previously lived in `LiveViewConnector`'s
//! manual message loop.
//!
//! The SDK's `ConnectorRunner` drives this struct: connection management,
//! registration, keepalive, OTT exchange, and reconnection are all handled
//! by the runner — we only implement the business callbacks.

use crate::ipc::IpcAddr;
use crate::liveview_connector::tools;
use crate::liveview_connector::{ConnectorEvent, WsConnectionState};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use pentest_core::tools::ToolRegistry;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use strike48_connector::{
    AppManifest, AppPageRequest, AppPageResponse, BaseConnector, BodyEncoding, ConnectorBehavior,
    ConnectorHandle, NavigationConfig, PayloadEncoding, TaskTypeSchema, WsCloseRequest, WsFrame,
    WsFrameType, WsOpenRequest,
};
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use super::injections::inject_websocket_shim;
use super::token_refresh;

/// Pick's `BaseConnector` implementation.
///
/// Holds all shared state needed by execute and WS callbacks. Constructed
/// once and handed to `ConnectorRunner::new()` as `Arc<dyn BaseConnector>`.
pub(crate) struct PickConnector {
    pub tools: Arc<RwLock<ToolRegistry>>,
    pub workspace_path: Option<PathBuf>,
    pub event_tx: broadcast::Sender<ConnectorEvent>,
    pub ws_connections: Arc<DashMap<String, WsConnectionState>>,
    pub matrix_client: Arc<RwLock<Option<pentest_core::matrix::MatrixChatClient>>>,
    pub connector_name: String,
    pub instance_id: String,
    pub aggression_level: Arc<RwLock<pentest_core::aggression::AggressionLevel>>,
    /// IPC address for the local LiveView server (set after start_liveview_server)
    pub ipc_addr: Arc<RwLock<Option<IpcAddr>>>,
    /// Reference to the ConnectorRunner for invoke_capability calls (artifact uploads).
    /// Set after the runner is created, before `.run()` is called.
    pub runner: Arc<RwLock<Option<Arc<strike48_connector::ConnectorRunner>>>>,
    /// Matrix API URL derived from config for tool context
    pub matrix_api_url: String,
    /// Operator-provided test identities (pick#162), loaded once from the
    /// gitignored identities file at construction and cloned into each tool
    /// context. Empty when no identities file is present.
    pub identities: Arc<pentest_core::identity::IdentityStore>,
}

impl PickConnector {
    /// Proxy an app request to the local LiveView server over IPC.
    async fn proxy_to_liveview(&self, request: &AppPageRequest) -> AppPageResponse {
        let path = &request.path;
        let target_path = if path == "/" || path.is_empty() {
            "/liveview"
        } else {
            path
        };

        let ipc_addr = self.ipc_addr.read().await.clone();
        let Some(ipc_addr) = ipc_addr else {
            return AppPageResponse::error(502, "LiveView server not started".to_string());
        };

        tracing::debug!("Proxying {} -> {}{}", path, ipc_addr, target_path);

        match tools::ipc_http_get(&ipc_addr, target_path).await {
            Ok((status, content_type, body)) => {
                let mut body_str = String::from_utf8_lossy(&body).to_string();

                if content_type.contains("html") {
                    body_str = inject_websocket_shim(&body_str);
                }

                AppPageResponse {
                    content_type,
                    body: body_str,
                    status,
                    encoding: BodyEncoding::Utf8,
                    headers: HashMap::new(),
                }
            }
            Err(e) => {
                tracing::error!("LiveView proxy error: {}", e);
                AppPageResponse::error(502, format!("LiveView unavailable: {}", e))
            }
        }
    }

    /// Derive Matrix API URL (forwarded from config to maintain same logic)
    fn derive_matrix_api_url(&self) -> String {
        self.matrix_api_url.clone()
    }

    /// Emit a ConnectorEvent
    fn send_event(&self, event: ConnectorEvent) {
        let _ = self.event_tx.send(event);
    }
}

impl BaseConnector for PickConnector {
    fn connector_type(&self) -> &str {
        &self.connector_name
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn behaviors(&self) -> Vec<ConnectorBehavior> {
        vec![ConnectorBehavior::Tool, ConnectorBehavior::App]
    }

    fn metadata(&self) -> HashMap<String, String> {
        // We build tool_schemas and app_manifest dynamically. The SDK's
        // `build_registration_metadata` will auto-inject tool_schemas from
        // capabilities() if we don't provide it, but we include it explicitly
        // for the app_manifest.
        let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());

        let manifest = AppManifest::new(&hostname, "/")
            .description("Browse files and access the interactive shell")
            .icon("hero-command-line")
            .navigation(NavigationConfig::nested(&["Apps"]))
            .api_access();

        let manifest_json = serde_json::to_string(&manifest).unwrap_or_default();

        let mut metadata = HashMap::new();
        metadata.insert("app_manifest".to_string(), manifest_json);
        metadata.insert("timeout_ms".to_string(), "300000".to_string());

        // Advertise only tools supported on this host (platform + desktop OS)
        // so a Linux-only tool never appears in the tool list on Windows. See #183.
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
                // Unwrap `.parameters` to match `PentestConnector::build_task_types`.
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
        300_000 // 5 minutes — tools like webwright can run long
    }

    fn execute(
        &self,
        _request: Value,
        _capability_id: Option<&str>,
    ) -> Pin<Box<dyn std::future::Future<Output = strike48_connector::Result<Value>> + Send + '_>>
    {
        // The runner always calls execute_with_context; this is a stub that
        // should never be reached in practice. If it is, return an error.
        Box::pin(async move {
            Err(strike48_connector::ConnectorError::StreamError(
                "execute() called without context; use execute_with_context".to_string(),
            ))
        })
    }

    fn execute_with_context<'a>(
        &'a self,
        request: Value,
        _capability_id: Option<&'a str>,
        context: &'a HashMap<String, String>,
    ) -> Pin<Box<dyn std::future::Future<Output = strike48_connector::Result<Value>> + Send + 'a>>
    {
        Box::pin(async move {
            // Route: app requests (have "path", no "tool") vs tool requests
            let is_app_request = request.get("path").is_some() && request.get("tool").is_none();

            if is_app_request {
                // App/HTTP proxy to LiveView
                let page_request: AppPageRequest = serde_json::from_value(request.clone())
                    .unwrap_or_else(|_| AppPageRequest::new("/"));

                let response = self.proxy_to_liveview(&page_request).await;
                let response_json = serde_json::to_value(&response)
                    .unwrap_or_else(|_| serde_json::json!({"error": "serialization failed"}));
                Ok(response_json)
            } else {
                // Tool execution — run synchronously in this task.
                // The SDK spawns execute_with_context in its own tokio task already,
                // so we don't need to spawn again.
                let tool_name = request
                    .get("tool")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let params = request
                    .get("parameters")
                    .cloned()
                    .unwrap_or(request.clone());

                self.send_event(ConnectorEvent::ToolStarted {
                    tool_name: tool_name.clone(),
                    params: params.clone(),
                });

                let start = std::time::Instant::now();

                // Build ToolContext
                let mut ctx = match &self.workspace_path {
                    Some(path) => {
                        pentest_core::tools::ToolContext::default().with_workspace(path.clone())
                    }
                    None => pentest_core::tools::ToolContext::default(),
                };

                // Populate metadata (instance_id, request_id, tool_call_id)
                // We don't have a request_id from the SDK's perspective here
                // (the runner handles it), but we can extract from context.
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

                // Forward session token
                if let Some(token) = context.get("session_token") {
                    ctx.metadata
                        .insert("session_token".to_string(), token.clone());
                }

                // Log context keys
                tools::log_execute_request_context_pub(&request_id, &tool_name, context);

                // Set aggression level and agent name
                ctx = ctx.with_aggression_level(*self.aggression_level.read().await);
                ctx = ctx.with_agent_name(self.connector_name.clone());

                // Provide operator identities for differential-authz tools
                // (pick#162). Loaded once at construction; cloned per call.
                ctx = ctx.with_identities((*self.identities).clone());

                // Create Matrix client if API URL is available
                let api_url = self.derive_matrix_api_url();
                if !api_url.is_empty() {
                    let matrix_client =
                        Arc::new(pentest_core::matrix::MatrixChatClient::new(&api_url));
                    ctx = ctx.with_matrix_client(matrix_client);
                }

                let tools = self.tools.read().await;
                let result = match tools.execute(&tool_name, params, &ctx).await {
                    Ok(result) => {
                        let duration_ms = start.elapsed().as_millis() as u64;
                        self.send_event(ConnectorEvent::ToolCompleted {
                            tool_name: tool_name.clone(),
                            duration_ms,
                            success: result.success,
                            result: serde_json::to_value(&result).unwrap_or(Value::Null),
                        });
                        result
                    }
                    Err(e) => {
                        self.send_event(ConnectorEvent::ToolFailed {
                            tool_name: tool_name.clone(),
                            error: e.to_string(),
                        });
                        pentest_core::tools::ToolResult::error(e.to_string())
                    }
                };

                // A successful `begin_scan` marks the start of a fresh
                // engagement. Clear any evidence left over from a previous scan
                // so it cannot bleed into this report (pick#172). `begin_scan`
                // itself produces no findings, so nothing is lost by clearing
                // here rather than draining first.
                if tool_name == "begin_scan" && result.success {
                    crate::session::clear_evidence();
                    tracing::debug!("begin_scan: cleared evidence graph for new engagement");
                }

                // Bridge tool-produced evidence into the report graph (pick#172).
                // Tools push findings into the process-global PENDING_EVIDENCE
                // buffer as a side effect of execution; if we don't drain them
                // here they never reach `gate_for_report` and the report comes
                // out empty. This is the single production drain point shared by
                // both the headless and desktop connectors.
                let forwarded = crate::session::drain_tool_evidence_into_graph();
                if forwarded > 0 {
                    tracing::debug!(
                        tool = tool_name.as_str(),
                        forwarded,
                        "forwarded tool evidence into report graph"
                    );
                }

                // Upload artifacts (webwright) if applicable
                let upload_status = if result.success && tool_name == "webwright" {
                    if let Some(engagement_id) = tools::extract_engagement_id_pub(context) {
                        let runner_guard = self.runner.read().await;
                        if let Some(ref runner) = *runner_guard {
                            let session_token =
                                context.get("session_token").cloned().unwrap_or_default();
                            let artifacts =
                                result.data.get("artifacts").cloned().unwrap_or_default();
                            let ws_path = self
                                .workspace_path
                                .as_ref()
                                .map(|p| p.to_string_lossy().to_string())
                                .unwrap_or_default();
                            Some(
                                tools::upload_artifacts_via_runner(
                                    runner,
                                    &engagement_id,
                                    &session_token,
                                    &artifacts,
                                    &ws_path,
                                )
                                .await,
                            )
                        } else {
                            tracing::warn!("[strikekit] runner not available for artifact upload");
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Serialize result, injecting upload status if present
                let mut result_json = serde_json::to_value(&result).unwrap_or(Value::Null);
                if let Some(status) = upload_status {
                    tools::inject_upload_status_pub(&mut result_json, &status);
                }

                Ok(result_json)
            }
        })
    }

    fn handle_ws_open(
        &self,
        req: WsOpenRequest,
        handle: ConnectorHandle,
    ) -> Pin<Box<dyn std::future::Future<Output = strike48_connector::Result<()>> + Send + '_>>
    {
        Box::pin(async move {
            let connection_id = req.connection_id.clone();

            tracing::info!(
                "[WsOpen] connection_id={} path={} query_string_len={}",
                connection_id,
                req.path,
                req.query_string.len(),
            );

            // Extract __st session token from query string
            if !req.query_string.is_empty() {
                let found_st = req.query_string.split('&').find_map(|pair| {
                    let (k, v) = pair.split_once('=')?;
                    if k == "__st" {
                        Some(v.to_string())
                    } else {
                        None
                    }
                });
                if let Some(ref token) = found_st {
                    if !token.is_empty() {
                        tracing::info!(
                            "[WsOpen] Captured __st session token from query (len={})",
                            token.len(),
                        );
                        let api_url = self.derive_matrix_api_url();
                        self.send_event(ConnectorEvent::MatrixTokenObtained {
                            auth_token: token.clone(),
                            api_url: api_url.clone(),
                        });

                        // Initialize Matrix HTTP client
                        if !api_url.is_empty() {
                            let mut client = pentest_core::matrix::MatrixChatClient::new(&api_url);
                            client.set_auth_token(token);
                            *self.matrix_client.write().await = Some(client);
                            tracing::info!("Matrix HTTP client initialized");
                        }

                        // Start token refresh loop
                        if !api_url.is_empty() {
                            token_refresh::spawn_token_refresh(api_url);
                        }
                    }
                }
            }

            let ws_path = if req.path.is_empty() {
                "/ws"
            } else {
                &req.path
            };
            let ws_url = if req.query_string.is_empty() {
                format!("ws://localhost{}", ws_path)
            } else {
                format!("ws://localhost{}?{}", ws_path, req.query_string)
            };

            // Get IPC address for local LiveView
            let ipc_addr = self.ipc_addr.read().await.clone();
            let Some(ref addr) = ipc_addr else {
                tracing::error!("No LiveView IPC address available for WebSocket");
                handle
                    .send_ws_open_response(&connection_id, false, "LiveView server not started")
                    .await?;
                return Ok(());
            };

            tracing::info!("Opening WebSocket to backend: {} ({})", ws_url, addr);

            let stream = match crate::ipc::IpcStream::connect(addr).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to connect to IPC endpoint: {}", e);
                    handle
                        .send_ws_open_response(
                            &connection_id,
                            false,
                            &format!("Failed to connect: {}", e),
                        )
                        .await?;
                    return Ok(());
                }
            };

            match tokio_tungstenite::client_async_with_config(&ws_url, stream, None).await {
                Ok((ws_stream, _)) => {
                    tracing::info!("WebSocket connected: {}", connection_id);

                    let (mut ws_sink, mut ws_source) = ws_stream.split();
                    let (to_backend_tx, mut to_backend_rx) = mpsc::channel::<WsMessage>(100);

                    self.ws_connections
                        .insert(connection_id.clone(), WsConnectionState { to_backend_tx });

                    // Send success response via ConnectorHandle
                    handle
                        .send_ws_open_response(&connection_id, true, "")
                        .await?;

                    // Spawn: forward messages FROM platform TO backend (Dioxus)
                    let conn_id_write = connection_id.clone();
                    tokio::spawn(async move {
                        while let Some(msg) = to_backend_rx.recv().await {
                            if let Err(e) = ws_sink.send(msg).await {
                                tracing::error!(
                                    "Error sending to backend WS {}: {}",
                                    conn_id_write,
                                    e
                                );
                                break;
                            }
                        }
                    });

                    // Spawn: forward messages FROM backend (Dioxus) TO platform
                    let conn_id_read = connection_id.clone();
                    let ws_connections = self.ws_connections.clone();
                    let handle_clone = handle.clone();
                    tokio::spawn(async move {
                        while let Some(msg_result) = ws_source.next().await {
                            match msg_result {
                                Ok(msg) => {
                                    let (frame_type, data) = match msg {
                                        WsMessage::Text(text) => (
                                            WsFrameType::Text,
                                            BASE64.encode(text.as_bytes()).into_bytes(),
                                        ),
                                        WsMessage::Binary(data) => {
                                            (WsFrameType::Binary, BASE64.encode(&data).into_bytes())
                                        }
                                        WsMessage::Ping(data) => {
                                            (WsFrameType::Ping, BASE64.encode(&data).into_bytes())
                                        }
                                        WsMessage::Pong(data) => {
                                            (WsFrameType::Pong, BASE64.encode(&data).into_bytes())
                                        }
                                        WsMessage::Close(_) => {
                                            tracing::info!("Backend WS closed: {}", conn_id_read);
                                            break;
                                        }
                                        WsMessage::Frame(_) => continue,
                                    };

                                    if let Err(e) = handle_clone
                                        .send_ws_frame(&conn_id_read, frame_type, data)
                                        .await
                                    {
                                        tracing::error!("Error sending frame to platform: {}", e);
                                        break;
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(
                                        "Error reading from backend WS {}: {}",
                                        conn_id_read,
                                        e
                                    );
                                    break;
                                }
                            }
                        }
                        ws_connections.remove(&conn_id_read);
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to connect to backend WS: {}", e);
                    handle
                        .send_ws_open_response(
                            &connection_id,
                            false,
                            &format!("Failed to connect: {}", e),
                        )
                        .await?;
                }
            }

            Ok(())
        })
    }

    fn handle_ws_frame(
        &self,
        frame: WsFrame,
        _handle: ConnectorHandle,
    ) -> Pin<Box<dyn std::future::Future<Output = strike48_connector::Result<()>> + Send + '_>>
    {
        Box::pin(async move {
            if let Some(conn) = self.ws_connections.get(&frame.connection_id) {
                // Decode base64 payload
                let decoded = match String::from_utf8(frame.data.clone()) {
                    Ok(base64_str) => BASE64.decode(&base64_str).unwrap_or(frame.data),
                    Err(_) => frame.data,
                };

                // Preserve frame type: text frames must arrive as WsMessage::Text
                let msg = if frame.frame_type == WsFrameType::Text {
                    let text = String::from_utf8_lossy(&decoded).to_string();
                    WsMessage::Text(text.into())
                } else {
                    WsMessage::Binary(decoded.into())
                };

                if let Err(e) = conn.to_backend_tx.send(msg).await {
                    tracing::error!("Error forwarding frame to backend: {}", e);
                }
            }
            Ok(())
        })
    }

    fn handle_ws_close(&self, req: WsCloseRequest) {
        tracing::info!("Closing WebSocket: {}", req.connection_id);
        self.ws_connections.remove(&req.connection_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::aggression::AggressionLevel;

    // Build a PickConnector backed by the real tool registry so `capabilities()`
    // exercises the exact production schema-emission path.
    fn test_connector() -> PickConnector {
        let (event_tx, _event_rx) = broadcast::channel(16);
        PickConnector {
            tools: Arc::new(RwLock::new(pentest_tools::create_tool_registry())),
            workspace_path: None,
            event_tx,
            ws_connections: Arc::new(DashMap::new()),
            matrix_client: Arc::new(RwLock::new(None)),
            connector_name: "pentest-connector".to_string(),
            instance_id: "test".to_string(),
            aggression_level: Arc::new(RwLock::new(AggressionLevel::default())),
            ipc_addr: Arc::new(RwLock::new(None)),
            runner: Arc::new(RwLock::new(None)),
            matrix_api_url: String::new(),
            identities: Arc::new(pentest_core::identity::IdentityStore::new()),
        }
    }

    /// Regression guard: every `capabilities()` entry's `input_schema_json` must be
    /// the JSON schema itself — a ROOT object with `type: "object"` — NOT the full
    /// `to_json_schema()` wrapper (`{name, description, parameters, ...}`).
    ///
    /// The SDK's `build_registration_metadata` wraps `input_schema_json` under a
    /// `"parameters"` key, so emitting the full wrapper here produces a double-nested
    /// schema whose root lacks `type`, which AWS Bedrock rejects
    /// (`toolConfig.tools.N.toolSpec.inputSchema.json.type must be object`).
    #[test]
    fn capabilities_input_schema_is_root_object_not_wrapper() {
        let connector = test_connector();
        let caps = connector.capabilities();
        assert!(
            !caps.is_empty(),
            "expected the real registry to expose tools"
        );

        for cap in &caps {
            let parsed: Value = serde_json::from_str(&cap.input_schema_json)
                .unwrap_or_else(|e| panic!("{}: input_schema_json not valid JSON: {e}", cap.name));

            // Root must declare an object schema.
            assert_eq!(
                parsed["type"], "object",
                "{}: input_schema_json root must have type=object, got: {}",
                cap.name, cap.input_schema_json
            );

            // Must NOT be the tool wrapper: a wrapper has a nested `parameters`
            // object and carries the tool `name`/`description` at its root.
            assert!(
                !parsed["parameters"].is_object(),
                "{}: input_schema_json is double-wrapped (nested `parameters` present)",
                cap.name
            );
            assert!(
                parsed.get("name").is_none(),
                "{}: input_schema_json leaked the tool wrapper (root `name` present)",
                cap.name
            );
        }
    }
}
