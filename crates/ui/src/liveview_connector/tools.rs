//! Tool execution routing and result formatting.

use crate::ipc::{IpcAddr, IpcStream};
use pentest_core::strikekit_client::StrikeKitClient;
use pentest_core::tools::{ToolContext, ToolRegistry, ToolResult};
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use strike48_connector::{AppPageRequest, AppPageResponse, BodyEncoding, PayloadEncoding};
use strike48_proto::proto::{self, stream_message::Message, ExecuteResponse, StreamMessage};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, RwLock};

use super::injections::inject_websocket_shim;
use super::{ConnectorEvent, LiveViewConnector};

/// Perform an HTTP GET over the IPC transport, returning (status, content_type, body).
async fn ipc_http_get(addr: &IpcAddr, path: &str) -> Result<(u16, String, Vec<u8>), String> {
    let mut stream = IpcStream::connect(addr)
        .await
        .map_err(|e| format!("IPC connect to {}: {}", addr, e))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        path
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| format!("Write request: {}", e))?;

    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .map_err(|e| format!("Read response: {}", e))?;

    let response = String::from_utf8_lossy(&buf);

    // Parse status line
    let status_line = response
        .lines()
        .next()
        .ok_or_else(|| "Empty response".to_string())?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(502);

    // Parse headers for content-type
    let mut content_type = "text/html".to_string();
    for line in response.lines().skip(1) {
        if line.is_empty() || line == "\r" {
            break;
        }
        if let Some(ct) = line
            .strip_prefix("content-type: ")
            .or_else(|| line.strip_prefix("Content-Type: "))
        {
            content_type = ct.trim().to_string();
        }
    }

    // Extract body (after \r\n\r\n)
    let body = if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        buf[pos + 4..].to_vec()
    } else {
        Vec::new()
    };

    Ok((status, content_type, body))
}

/// Emit a ConnectorEvent and mirror it to the global terminal buffer.
///
/// Background tasks can't call `LiveViewConnector::send_event()` (no `&self`),
/// so this standalone helper does both: broadcast + global buffer push.
fn emit_event(event_tx: &broadcast::Sender<ConnectorEvent>, event: ConnectorEvent) {
    use pentest_core::terminal::TerminalLine;
    // Mirror to global terminal buffer (same logic as LiveViewConnector::send_event)
    match &event {
        ConnectorEvent::Log(line) => {
            crate::liveview_server::push_terminal_line(line.clone());
        }
        ConnectorEvent::ToolStarted { tool_name, params } => {
            let details = serde_json::to_string(params).unwrap_or_default();
            crate::liveview_server::push_terminal_line(
                TerminalLine::info(format!("[tool] {} started", tool_name))
                    .with_details(format!("args: {}", details)),
            );
        }
        ConnectorEvent::ToolCompleted {
            tool_name,
            duration_ms,
            success,
            result,
        } => {
            let details = serde_json::to_string(result).unwrap_or_default();
            let line = if *success {
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
            };
            crate::liveview_server::push_terminal_line(line);
        }
        ConnectorEvent::ToolFailed { tool_name, error } => {
            crate::liveview_server::push_terminal_line(
                TerminalLine::error(format!("[tool] {} failed", tool_name))
                    .with_details(error.clone()),
            );
        }
        _ => {}
    }
    let _ = event_tx.send(event);
}

/// Parameters for tool execution
pub(crate) struct ExecuteParams {
    pub tools: Arc<RwLock<ToolRegistry>>,
    pub workspace_path: Option<PathBuf>,
    pub instance_id: String,
    pub matrix_tx: Arc<RwLock<Option<mpsc::UnboundedSender<StreamMessage>>>>,
    pub event_tx: broadcast::Sender<ConnectorEvent>,
    pub aggression_level: pentest_core::aggression::AggressionLevel,
    pub agent_name: String,
    pub matrix_api_url: Option<String>,
}

/// Standalone execute handler that can run in a background task.
/// `matrix_tx` is shared via Arc so the task always uses the current sender
/// even if the gRPC stream was cycled while the tool was running.
pub(crate) async fn handle_execute_impl(req: proto::ExecuteRequest, params: ExecuteParams) {
    let ExecuteParams {
        tools,
        workspace_path,
        instance_id,
        matrix_tx,
        event_tx,
        aggression_level,
        agent_name,
        matrix_api_url,
    } = params;
    let request_id = req.request_id.clone();

    // Defense against hostile targets: limit tool result payload size to prevent OOM
    // This protects against malicious targets returning massive outputs (e.g., 100MB nmap XML)
    const MAX_TOOL_PAYLOAD: usize = 5 * 1024 * 1024; // 5 MB

    if req.payload.len() > MAX_TOOL_PAYLOAD {
        tracing::error!(
            "Tool result payload too large: {} bytes (max {} MB). \
             This may indicate a hostile target attempting resource exhaustion.",
            req.payload.len(),
            MAX_TOOL_PAYLOAD / (1024 * 1024)
        );

        let error_payload = serde_json::json!({
            "success": false,
            "error": format!(
                "Tool output exceeded {} MB limit. Output truncated for safety.",
                MAX_TOOL_PAYLOAD / (1024 * 1024)
            )
        });

        if let Some(tx) = matrix_tx.read().await.as_ref() {
            let response_msg = StreamMessage {
                message: Some(Message::ExecuteResponse(ExecuteResponse {
                    request_id,
                    success: false,
                    payload: serde_json::to_vec(&error_payload).unwrap_or_default(),
                    payload_encoding: PayloadEncoding::Json as i32,
                    error: "Payload size limit exceeded".to_string(),
                    duration_ms: 0,
                })),
            };
            let _ = tx.send(response_msg);
        }
        return;
    }

    let request: Value = serde_json::from_slice(&req.payload).unwrap_or(Value::Null);

    // For now, we only handle tool execution (app proxying requires LiveViewConnector)
    let response_payload = if request.get("path").is_some() && request.get("tool").is_none() {
        // App request - not supported in background task yet
        tracing::warn!("App proxying not supported in background task");
        Vec::new()
    } else {
        // Tool execution
        let tool_name = request.get("tool").and_then(|v| v.as_str()).unwrap_or("");
        let params = request
            .get("parameters")
            .cloned()
            .unwrap_or(request.clone());

        emit_event(
            &event_tx,
            ConnectorEvent::ToolStarted {
                tool_name: tool_name.to_string(),
                params: params.clone(),
            },
        );

        let start = std::time::Instant::now();

        // Build ToolContext with all enhancements
        let mut ctx = match &workspace_path {
            Some(path) => ToolContext::default().with_workspace(path.clone()),
            None => ToolContext::default(),
        };

        // Add instance_id, request_id, and tool_call_id to context metadata for tools.
        // tool_call_id is the platform agent's ID for the calling tool_call (e.g. "call_abc");
        // the chat-panel widget keys live-progress lookups on it, so tools must register their
        // live-state bindings under it. Forwarded by the platform in req.context["tool_call_id"].
        populate_tool_metadata(&mut ctx.metadata, &instance_id, &request_id, &req.context);

        // Forward session token from execute request context (if provided by StrikeKit)
        // so tools like webwright can pass it to their sidecar for LLM proxy auth.
        if let Some(token) = req.context.get("session_token") {
            ctx.metadata
                .insert("session_token".to_string(), token.clone());
        }

        // Set aggression level
        ctx = ctx.with_aggression_level(aggression_level);

        // Set agent name (e.g., "pentest-connector-red-team")
        ctx = ctx.with_agent_name(agent_name.clone());

        // Create Matrix client if API URL is available
        if let Some(api_url) = matrix_api_url {
            let matrix_client = Arc::new(pentest_core::matrix::MatrixChatClient::new(api_url));
            ctx = ctx.with_matrix_client(matrix_client);
        }

        let tools = tools.read().await;
        let result = match tools.execute(tool_name, params, &ctx).await {
            Ok(result) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                emit_event(
                    &event_tx,
                    ConnectorEvent::ToolCompleted {
                        tool_name: tool_name.to_string(),
                        duration_ms,
                        success: result.success,
                        result: serde_json::to_value(&result).unwrap_or(Value::Null),
                    },
                );
                result
            }
            Err(e) => {
                emit_event(
                    &event_tx,
                    ConnectorEvent::ToolFailed {
                        tool_name: tool_name.to_string(),
                        error: e.to_string(),
                    },
                );
                ToolResult::error(e.to_string())
            }
        };

        // Upload artifacts to StrikeKit in the background if engagement context is available.
        // This handles webwright screenshots, scripts, and DOM snapshots.
        if tool_name == "webwright" {
            tracing::info!(
                "[strikekit] webwright completed: success={}, has_engagement_id={}",
                result.success,
                extract_engagement_id(&req.context).is_some()
            );
        }
        if result.success && tool_name == "webwright" {
            if let Some(engagement_id) = extract_engagement_id(&req.context) {
                let sk_client = StrikeKitClient::new(Arc::clone(&matrix_tx));
                let artifacts = result.data.get("artifacts").cloned().unwrap_or_default();
                // workspace_path is needed to resolve relative artifact paths
                let ws_path = workspace_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                tokio::spawn(async move {
                    upload_artifacts_to_strikekit(sk_client, &engagement_id, &artifacts, &ws_path)
                        .await;
                });
            }
        }

        serde_json::to_vec(&result).unwrap_or_default()
    };

    // Send response — read the current sender at completion time (may be a new stream after reconnect)
    let tx_clone = {
        let guard = matrix_tx.read().await;
        guard.as_ref().cloned()
    };

    match tx_clone {
        Some(tx) => {
            let response_msg = StreamMessage {
                message: Some(Message::ExecuteResponse(ExecuteResponse {
                    request_id: request_id.clone(),
                    success: true,
                    payload: response_payload,
                    payload_encoding: PayloadEncoding::Json as i32,
                    error: String::new(),
                    duration_ms: 0,
                })),
            };
            match tx.send(response_msg) {
                Ok(_) => tracing::info!("[tool] execute_response sent for request_id={}", request_id),
                Err(e) => tracing::error!(
                    "[tool] FAILED to send execute_response for request_id={}: {} (stream likely dropped during execution)",
                    request_id, e
                ),
            }
        }
        None => {
            tracing::error!(
                "[tool] NO STREAM SENDER available for request_id={} — response DROPPED. \
                 Stream may have been disconnected during tool execution.",
                request_id
            );
        }
    }
}

impl LiveViewConnector {
    /// Handle an execute request (tool or app) - kept for backwards compatibility
    pub(crate) async fn handle_execute(&self, req: proto::ExecuteRequest) {
        // For app requests, we still need to proxy through LiveViewConnector
        let request: Value = serde_json::from_slice(&req.payload).unwrap_or(Value::Null);

        if request.get("path").is_some() && request.get("tool").is_none() {
            // App request - handle synchronously
            let request_id = req.request_id.clone();
            let page_request: AppPageRequest = serde_json::from_value(request.clone())
                .unwrap_or_else(|_| AppPageRequest::new("/"));

            let response = self.proxy_to_liveview(&page_request).await;
            let response_payload = serde_json::to_vec(&response).unwrap_or_default();

            let tx_clone = {
                let guard = self.matrix_tx.read().await;
                guard.as_ref().cloned()
            };

            if let Some(tx) = tx_clone {
                let response_msg = StreamMessage {
                    message: Some(Message::ExecuteResponse(ExecuteResponse {
                        request_id,
                        success: true,
                        payload: response_payload,
                        payload_encoding: PayloadEncoding::Json as i32,
                        error: String::new(),
                        duration_ms: 0,
                    })),
                };
                let _ = tx.send(response_msg);
            }
        } else {
            // Tool request - delegate to standalone function
            let params = ExecuteParams {
                tools: self.tools.clone(),
                workspace_path: self.workspace_path.clone(),
                instance_id: self.config.instance_id.clone(),
                matrix_tx: Arc::clone(&self.matrix_tx),
                event_tx: self.event_tx.clone(),
                aggression_level: self.config.aggression_level,
                agent_name: self.config.connector_name.clone(),
                matrix_api_url: Some(self.derive_matrix_api_url()),
            };
            handle_execute_impl(req, params).await;
        }
    }

    /// Proxy an app request to the LiveView server over IPC.
    pub(crate) async fn proxy_to_liveview(&self, request: &AppPageRequest) -> AppPageResponse {
        let path = &request.path;
        // LiveView serves HTML at /liveview
        let target_path = if path == "/" || path.is_empty() {
            "/liveview"
        } else {
            path
        };

        let ipc_addr = self
            .liveview_handle
            .as_ref()
            .and_then(|h| h.ipc_addr().cloned());

        let Some(ipc_addr) = ipc_addr else {
            return AppPageResponse::error(502, "LiveView server not started".to_string());
        };

        tracing::debug!("Proxying {} -> {}{}", path, ipc_addr, target_path);

        match ipc_http_get(&ipc_addr, target_path).await {
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
}

/// Copy IDs from the platform's ExecuteRequest context into the ToolContext metadata.
///
/// Sets `instance_id`, `request_id` always; copies `tool_call_id` from req.context when present
/// and non-empty. Tools that need a stable widget-binding ID should read `tool_call_id` first,
/// falling back to `request_id` for compatibility with platform versions that don't forward it.
fn populate_tool_metadata(
    metadata: &mut HashMap<String, String>,
    instance_id: &str,
    request_id: &str,
    req_context: &HashMap<String, String>,
) {
    metadata.insert("instance_id".to_string(), instance_id.to_string());
    metadata.insert("request_id".to_string(), request_id.to_string());
    if let Some(tool_call_id) = req_context.get("tool_call_id") {
        if !tool_call_id.is_empty() {
            metadata.insert("tool_call_id".to_string(), tool_call_id.clone());
        }
    }
}

/// Extract engagement_id from the execute request context.
/// Checks both a top-level key and the nested agent_context JSON.
fn extract_engagement_id(context: &HashMap<String, String>) -> Option<String> {
    // Direct key
    if let Some(eid) = context.get("engagement_id") {
        return Some(eid.clone());
    }
    // Nested in agent_context JSON
    let agent_ctx_str = context.get("agent_context")?;
    let parsed: Value = serde_json::from_str(agent_ctx_str).ok()?;
    parsed
        .get("engagement_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Upload webwright artifacts (screenshots, scripts, DOM snapshots) to StrikeKit.
async fn upload_artifacts_to_strikekit(
    client: StrikeKitClient,
    engagement_id: &str,
    artifacts: &Value,
    workspace_path: &str,
) {
    let mut count = 0;

    // Resolve a potentially relative path against the workspace
    let resolve = |path: &str| -> String {
        if path.starts_with('/') {
            path.to_string()
        } else {
            format!("{}/{}", workspace_path, path)
        }
    };

    // Screenshots
    if let Some(paths) = artifacts["screenshots"].as_array() {
        for path_val in paths {
            if let Some(path) = path_val.as_str() {
                client
                    .upload_file(engagement_id, &resolve(path), "screenshot", "webwright")
                    .await;
                count += 1;
            }
        }
    }

    // Scripts
    if let Some(paths) = artifacts["scripts"].as_array() {
        for path_val in paths {
            if let Some(path) = path_val.as_str() {
                client
                    .upload_file(engagement_id, &resolve(path), "code", "webwright")
                    .await;
                count += 1;
            }
        }
    }

    // DOM snapshots
    if let Some(paths) = artifacts["dom_snapshots"].as_array() {
        for path_val in paths {
            if let Some(path) = path_val.as_str() {
                client
                    .upload_file(engagement_id, &resolve(path), "file", "webwright")
                    .await;
                count += 1;
            }
        }
    }

    if count > 0 {
        tracing::info!(
            "[strikekit] Uploaded {} webwright artifacts for engagement {}",
            count,
            engagement_id
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_payload_limit_value() {
        const MAX_TOOL_PAYLOAD: usize = 5 * 1024 * 1024;
        assert_eq!(MAX_TOOL_PAYLOAD, 5_242_880);
    }

    #[test]
    fn extract_engagement_id_direct() {
        let mut ctx = HashMap::new();
        ctx.insert("engagement_id".to_string(), "abc-123".to_string());
        assert_eq!(extract_engagement_id(&ctx), Some("abc-123".to_string()));
    }

    #[test]
    fn extract_engagement_id_from_agent_context() {
        let mut ctx = HashMap::new();
        ctx.insert(
            "agent_context".to_string(),
            r#"{"engagement_id":"xyz-789","phase":"recon"}"#.to_string(),
        );
        assert_eq!(extract_engagement_id(&ctx), Some("xyz-789".to_string()));
    }

    #[test]
    fn extract_engagement_id_missing() {
        let ctx = HashMap::new();
        assert_eq!(extract_engagement_id(&ctx), None);
    }

    #[test]
    fn populate_tool_metadata_forwards_tool_call_id() {
        let mut req_ctx = HashMap::new();
        req_ctx.insert("tool_call_id".to_string(), "call_abc_xyz".to_string());
        req_ctx.insert("engagement_id".to_string(), "eng-1".to_string());

        let mut metadata = HashMap::new();
        populate_tool_metadata(&mut metadata, "inst-1", "agent-12345", &req_ctx);

        assert_eq!(metadata.get("instance_id"), Some(&"inst-1".to_string()));
        assert_eq!(metadata.get("request_id"), Some(&"agent-12345".to_string()));
        assert_eq!(
            metadata.get("tool_call_id"),
            Some(&"call_abc_xyz".to_string()),
            "tool_call_id from req.context must be forwarded for widget binding"
        );
    }

    #[test]
    fn populate_tool_metadata_skips_empty_tool_call_id() {
        let mut req_ctx = HashMap::new();
        req_ctx.insert("tool_call_id".to_string(), "".to_string());

        let mut metadata = HashMap::new();
        populate_tool_metadata(&mut metadata, "inst-1", "agent-12345", &req_ctx);

        assert_eq!(
            metadata.get("tool_call_id"),
            None,
            "empty tool_call_id should be ignored so tools fall back to request_id"
        );
    }

    #[test]
    fn populate_tool_metadata_omits_tool_call_id_when_absent() {
        let req_ctx = HashMap::new();
        let mut metadata = HashMap::new();
        populate_tool_metadata(&mut metadata, "inst-1", "agent-12345", &req_ctx);

        assert!(!metadata.contains_key("tool_call_id"));
        assert_eq!(metadata.get("request_id"), Some(&"agent-12345".to_string()));
    }
}
