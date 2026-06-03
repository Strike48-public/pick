//! Tool execution routing and result formatting.

use crate::ipc::{IpcAddr, IpcStream};
use pentest_core::tools::{ToolContext, ToolRegistry, ToolResult};
use serde::Serialize;
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
    pub connector_client: Arc<RwLock<Option<strike48_connector::ConnectorClient>>>,
    pub event_tx: broadcast::Sender<ConnectorEvent>,
    pub aggression_level: pentest_core::aggression::AggressionLevel,
    pub agent_name: String,
    pub matrix_api_url: Option<String>,
}

/// Redact a context value if its key looks sensitive.
///
/// Keys whose lowercase form contains any of `token`, `secret`, `key`,
/// `password`, or `auth` have their value replaced with
/// `<redacted:len=N>` where `N` is the byte length of the original value.
/// All other values are returned unchanged.
pub(crate) fn redact_sensitive(key: &str, value: &str) -> String {
    const SENSITIVE_NEEDLES: &[&str] = &["token", "secret", "key", "password", "auth"];
    let key_lc = key.to_ascii_lowercase();
    if SENSITIVE_NEEDLES
        .iter()
        .any(|needle| key_lc.contains(needle))
    {
        format!("<redacted:len={}>", value.len())
    } else {
        value.to_string()
    }
}

/// Log the full set of context key/value pairs from an ExecuteRequest at INFO,
/// one pair per line, with sensitive values redacted. Lines are prefixed with
/// `[execreq-ctx]` for grep-ability and tagged with request_id + tool name.
fn log_execute_request_context(
    request_id: &str,
    tool_name: &str,
    context: &HashMap<String, String>,
) {
    tracing::info!(
        "[execreq-ctx] request_id={} tool={} context_key_count={}",
        request_id,
        tool_name,
        context.len(),
    );
    if context.is_empty() {
        tracing::info!(
            "[execreq-ctx] request_id={} tool={} (no context keys)",
            request_id,
            tool_name,
        );
        return;
    }
    // Sort keys so log order is deterministic across runs — makes diffs against
    // the platform-side log readable.
    let mut keys: Vec<&String> = context.keys().collect();
    keys.sort();
    for key in keys {
        let raw = context.get(key).map(String::as_str).unwrap_or("");
        let rendered = redact_sensitive(key, raw);
        tracing::info!(
            "[execreq-ctx] request_id={} tool={} {}={}",
            request_id,
            tool_name,
            key,
            rendered,
        );
    }
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
        connector_client,
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

        // Dump the full ExecuteRequest context map at INFO so we can reconcile what
        // Pick received against what the platform thinks it sent. Sensitive values
        // are redacted (length preserved). One line per key, sorted deterministically.
        log_execute_request_context(&request_id, tool_name, &req.context);

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

        // Upload artifacts to StrikeKit if engagement context is available.
        // This handles webwright screenshots, scripts, and DOM snapshots.
        //
        // We await the upload (instead of fire-and-forget) so the outcome lands
        // in the tool result payload — the LLM/UI need to know whether artifacts
        // actually arrived. The latency penalty (a few hundred ms per file over
        // local gRPC) is paid after the multi-second webwright run, so it's
        // negligible compared to total tool time.
        if tool_name == "webwright" {
            tracing::info!(
                "[strikekit] webwright completed: success={}, has_engagement_id={}",
                result.success,
                extract_engagement_id(&req.context).is_some()
            );
        }
        let upload_status: Option<UploadStatus> = if result.success && tool_name == "webwright" {
            if let Some(engagement_id) = extract_engagement_id(&req.context) {
                let client_guard = connector_client.read().await;
                if let Some(ref client) = *client_guard {
                    let session_token = req
                        .context
                        .get("session_token")
                        .cloned()
                        .unwrap_or_default();
                    let artifacts = result.data.get("artifacts").cloned().unwrap_or_default();
                    let ws_path = workspace_path
                        .as_ref()
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();
                    Some(
                        upload_artifacts_to_strikekit(
                            client,
                            &engagement_id,
                            &session_token,
                            &artifacts,
                            &ws_path,
                        )
                        .await,
                    )
                } else {
                    tracing::warn!("[strikekit] connector_client not available for upload");
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // If we have an upload status, splice it into data.artifacts.upload_status
        // before serializing the response. We mutate the JSON rather than widening
        // the ToolResult API — only one tool (webwright) cares about this field,
        // and adding an Option<Value> to ToolResult would force every tool/test
        // to think about it.
        //
        // When there is no upload_status (non-StrikeKit conversation, or no
        // engagement_id), the key is OMITTED entirely — we never inject a
        // fake-zero status, so consumers can distinguish "no uploads attempted"
        // from "uploads attempted, all failed".
        match serde_json::to_value(&result) {
            Ok(mut result_json) => {
                if let Some(status) = upload_status {
                    inject_upload_status(&mut result_json, &status);
                }
                serde_json::to_vec(&result_json).unwrap_or_default()
            }
            Err(_) => serde_json::to_vec(&result).unwrap_or_default(),
        }
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
                connector_client: Arc::clone(&self.connector_client),
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

/// Reported outcome of a StrikeKit artifact upload batch.
///
/// Serialized into `data.artifacts.upload_status` on the webwright tool result
/// so the LLM and chat-panel widget can see whether artifacts actually
/// reached the platform. Counts cover the number of files we *tried* to upload
/// vs. the number that returned without error from the gRPC enqueue (the
/// platform's downstream processing is still asynchronous, so a success here
/// only proves the message was queued, not that it landed in storage).
///
/// `failed` is capped to avoid blowing up the tool result on pathological
/// runs where every file fails; overflow is preserved as a final synthetic
/// entry of the form `"... and N more"`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct UploadStatus {
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: Vec<String>,
    pub started_at_ms: i64,
    pub duration_ms: u64,
    pub engagement_id: String,
}

/// Cap on how many failed paths we keep verbatim before collapsing the rest
/// into a single overflow entry. Keeps the tool result payload bounded.
const UPLOAD_STATUS_FAILED_LIMIT: usize = 10;

/// Splice an [`UploadStatus`] into a serialized ToolResult JSON under
/// `data.artifacts.upload_status`. Defensively creates `data` and
/// `data.artifacts` as empty objects if either is missing so the splice
/// always lands somewhere queryable.
fn inject_upload_status(result_json: &mut Value, status: &UploadStatus) {
    let status_val = match serde_json::to_value(status) {
        Ok(v) => v,
        Err(_) => return,
    };

    let obj = match result_json.as_object_mut() {
        Some(o) => o,
        None => return,
    };

    let data_entry = obj
        .entry("data".to_string())
        .or_insert_with(|| Value::Object(Default::default()));
    let data_obj = match data_entry.as_object_mut() {
        Some(o) => o,
        // data exists but is not an object (e.g. Null for error results) — overwrite
        None => {
            *data_entry = Value::Object(Default::default());
            data_entry.as_object_mut().unwrap()
        }
    };

    let artifacts_entry = data_obj
        .entry("artifacts".to_string())
        .or_insert_with(|| Value::Object(Default::default()));
    let artifacts_obj = match artifacts_entry.as_object_mut() {
        Some(o) => o,
        None => {
            *artifacts_entry = Value::Object(Default::default());
            artifacts_entry.as_object_mut().unwrap()
        }
    };

    artifacts_obj.insert("upload_status".to_string(), status_val);
}

/// Upload webwright artifacts (screenshots, scripts, DOM snapshots) to StrikeKit
/// via the SDK's `invoke_capability` (request/response, not fire-and-forget).
///
/// Returns an [`UploadStatus`] describing what was attempted vs. what landed,
/// so the caller can splice the outcome into the tool result payload for the
/// LLM/UI to observe.
async fn upload_artifacts_to_strikekit(
    client: &strike48_connector::ConnectorClient,
    engagement_id: &str,
    session_token: &str,
    artifacts: &Value,
    workspace_path: &str,
) -> UploadStatus {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    let started_at_ms = chrono::Utc::now().timestamp_millis();
    let start = std::time::Instant::now();

    let mut attempted: usize = 0;
    let mut succeeded: usize = 0;
    let mut failed: Vec<String> = Vec::new();
    let mut overflow: usize = 0;

    let resolve = |path: &str| -> String {
        if path.starts_with('/') {
            path.to_string()
        } else {
            format!("{}/{}", workspace_path, path)
        }
    };

    let categories: [(&str, &str); 3] = [
        ("screenshots", "screenshot"),
        ("scripts", "code"),
        ("dom_snapshots", "file"),
    ];

    for (key, evidence_type) in categories.iter() {
        if let Some(paths) = artifacts[*key].as_array() {
            for path_val in paths {
                if let Some(path) = path_val.as_str() {
                    attempted += 1;
                    let resolved = resolve(path);

                    let file_bytes = match tokio::fs::read(&resolved).await {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!("[strikekit] failed to read {}: {}", resolved, e);
                            if failed.len() < UPLOAD_STATUS_FAILED_LIMIT {
                                failed.push(path.to_string());
                            } else {
                                overflow += 1;
                            }
                            continue;
                        }
                    };

                    let filename = std::path::Path::new(&resolved)
                        .file_name()
                        .and_then(|f| f.to_str())
                        .unwrap_or("unknown")
                        .to_string();

                    let payload = serde_json::json!({
                        "engagement_id": engagement_id,
                        "filename": filename,
                        "content_base64": BASE64.encode(&file_bytes),
                        "evidence_type": evidence_type,
                        "title": filename,
                        "source": "webwright",
                        "path": path,
                    });

                    let payload_bytes = serde_json::to_vec(&payload).unwrap_or_default();

                    let mut context = HashMap::new();
                    if !session_token.is_empty() {
                        context.insert("session_token".to_string(), session_token.to_string());
                    }

                    let options = strike48_connector::InvokeOptions {
                        capability_id: Some("upload_artifact".to_string()),
                        timeout_ms: Some(30000),
                        // TODO: switch to fire_and_forget=false once we migrate to
                        // ConnectorRunner (which handles InvokeResponse routing).
                        // Our custom message loop can't dispatch responses back to
                        // the SDK's pending_invokes map.
                        fire_and_forget: Some(true),
                        payload_encoding: Some(PayloadEncoding::Json),
                        context: Some(context),
                    };

                    match client
                        .invoke_capability("strikekit://evidence", payload_bytes, options)
                        .await
                    {
                        Ok(_) => succeeded += 1,
                        Err(e) => {
                            tracing::warn!("[strikekit] invoke failed for {}: {}", path, e);
                            if failed.len() < UPLOAD_STATUS_FAILED_LIMIT {
                                failed.push(path.to_string());
                            } else {
                                overflow += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    if overflow > 0 {
        failed.push(format!("... and {} more", overflow));
    }

    let duration_ms = start.elapsed().as_millis() as u64;

    if attempted > 0 {
        tracing::info!(
            "[strikekit] webwright artifact upload: attempted={} succeeded={} failed={} duration_ms={} engagement={}",
            attempted,
            succeeded,
            failed.len(),
            duration_ms,
            engagement_id,
        );
    }

    UploadStatus {
        attempted,
        succeeded,
        failed,
        started_at_ms,
        duration_ms,
        engagement_id: engagement_id.to_string(),
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
    fn redact_sensitive_passes_plain_keys_through() {
        assert_eq!(
            redact_sensitive("tool_call_id", "call-abc-123"),
            "call-abc-123"
        );
        assert_eq!(redact_sensitive("engagement_id", "eng-42"), "eng-42");
        assert_eq!(
            redact_sensitive("agent_context", "{\"foo\":1}"),
            "{\"foo\":1}"
        );
    }

    #[test]
    fn redact_sensitive_redacts_session_token() {
        assert_eq!(
            redact_sensitive("session_token", "abcdef123456"),
            "<redacted:len=12>"
        );
    }

    #[test]
    fn redact_sensitive_redacts_auth_token() {
        assert_eq!(redact_sensitive("auth_token", "xyz"), "<redacted:len=3>");
    }

    #[test]
    fn redact_sensitive_redacts_api_key() {
        assert_eq!(
            redact_sensitive("api_key", "sk-1234567890"),
            "<redacted:len=13>"
        );
    }

    #[test]
    fn redact_sensitive_redacts_bare_secret() {
        assert_eq!(redact_sensitive("secret", "hunter2"), "<redacted:len=7>");
    }

    #[test]
    fn redact_sensitive_redacts_password() {
        assert_eq!(
            redact_sensitive("user_password", "letmein"),
            "<redacted:len=7>"
        );
    }

    #[test]
    fn redact_sensitive_matching_is_case_insensitive() {
        assert_eq!(redact_sensitive("Session_Token", "abc"), "<redacted:len=3>");
        assert_eq!(redact_sensitive("API_KEY", "abc"), "<redacted:len=3>");
        assert_eq!(redact_sensitive("AUTH", "abc"), "<redacted:len=3>");
        assert_eq!(redact_sensitive("PASSWORD", "abc"), "<redacted:len=3>");
    }

    #[test]
    fn redact_sensitive_empty_value_still_surfaces() {
        assert_eq!(redact_sensitive("session_token", ""), "<redacted:len=0>");
    }

    #[test]
    fn redact_sensitive_partial_substring_matches() {
        assert_eq!(
            redact_sensitive("x_custom_auth_header", "v"),
            "<redacted:len=1>"
        );
        assert_eq!(redact_sensitive("private_key_pem", "v"), "<redacted:len=1>");
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

    #[test]
    fn upload_status_serializes_with_expected_keys() {
        // The LLM/UI look up these exact keys on data.artifacts.upload_status.
        // Renaming any of them is a breaking change for downstream consumers.
        let status = UploadStatus {
            attempted: 3,
            succeeded: 2,
            failed: vec!["screenshots/foo.png".to_string()],
            started_at_ms: 1_700_000_000_000,
            duration_ms: 250,
            engagement_id: "eng-42".to_string(),
        };

        let v = serde_json::to_value(&status).expect("serialize UploadStatus");
        let obj = v
            .as_object()
            .expect("UploadStatus must serialize as object");

        // Field names are part of the contract; assert exact match.
        let expected_keys: std::collections::BTreeSet<&str> = [
            "attempted",
            "succeeded",
            "failed",
            "started_at_ms",
            "duration_ms",
            "engagement_id",
        ]
        .into_iter()
        .collect();
        let actual_keys: std::collections::BTreeSet<&str> =
            obj.keys().map(|s| s.as_str()).collect();
        assert_eq!(
            actual_keys, expected_keys,
            "UploadStatus JSON keys drifted from the LLM/UI contract"
        );

        assert_eq!(obj["attempted"], 3);
        assert_eq!(obj["succeeded"], 2);
        assert_eq!(obj["failed"][0], "screenshots/foo.png");
        assert_eq!(obj["started_at_ms"], 1_700_000_000_000_i64);
        assert_eq!(obj["duration_ms"], 250);
        assert_eq!(obj["engagement_id"], "eng-42");
    }

    #[test]
    fn inject_upload_status_lands_under_data_artifacts() {
        let mut result_json = serde_json::json!({
            "success": true,
            "data": {
                "artifacts": {
                    "screenshots": ["a.png"]
                }
            },
            "error": null,
            "duration_ms": 100
        });
        let status = UploadStatus {
            attempted: 1,
            succeeded: 1,
            failed: Vec::new(),
            started_at_ms: 0,
            duration_ms: 5,
            engagement_id: "e".to_string(),
        };
        inject_upload_status(&mut result_json, &status);
        let injected = &result_json["data"]["artifacts"]["upload_status"];
        assert_eq!(injected["attempted"], 1);
        assert_eq!(injected["succeeded"], 1);
        assert_eq!(injected["engagement_id"], "e");
        // Original siblings preserved
        assert_eq!(result_json["data"]["artifacts"]["screenshots"][0], "a.png");
    }

    #[test]
    fn inject_upload_status_creates_missing_artifacts_object() {
        let mut result_json = serde_json::json!({
            "success": true,
            "data": {},
            "error": null,
            "duration_ms": 0
        });
        let status = UploadStatus {
            attempted: 0,
            succeeded: 0,
            failed: Vec::new(),
            started_at_ms: 0,
            duration_ms: 0,
            engagement_id: "e".to_string(),
        };
        inject_upload_status(&mut result_json, &status);
        assert!(result_json["data"]["artifacts"]["upload_status"].is_object());
    }

    #[test]
    fn inject_upload_status_handles_null_data() {
        // Error results have data: null. We still want to surface upload_status
        // when present (though in practice we only inject on success).
        let mut result_json = serde_json::json!({
            "success": false,
            "data": null,
            "error": "boom",
            "duration_ms": 0
        });
        let status = UploadStatus {
            attempted: 0,
            succeeded: 0,
            failed: Vec::new(),
            started_at_ms: 0,
            duration_ms: 0,
            engagement_id: "e".to_string(),
        };
        inject_upload_status(&mut result_json, &status);
        assert!(result_json["data"]["artifacts"]["upload_status"].is_object());
    }
}
