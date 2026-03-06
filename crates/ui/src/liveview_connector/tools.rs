//! Tool execution routing and result formatting.

use crate::ipc::{IpcAddr, IpcStream};
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

/// Standalone execute handler that can run in a background task.
/// `matrix_tx` is shared via Arc so the task always uses the current sender
/// even if the gRPC stream was cycled while the tool was running.
pub(crate) async fn handle_execute_impl(
    req: proto::ExecuteRequest,
    tools: Arc<RwLock<ToolRegistry>>,
    workspace_path: Option<PathBuf>,
    matrix_tx: Arc<RwLock<Option<mpsc::UnboundedSender<StreamMessage>>>>,
    event_tx: broadcast::Sender<ConnectorEvent>,
) {
    let request_id = req.request_id.clone();
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
        let ctx = match &workspace_path {
            Some(path) => ToolContext::default().with_workspace(path.clone()),
            None => ToolContext::default(),
        };

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

        serde_json::to_vec(&result).unwrap_or_default()
    };

    // Send response — read the current sender at completion time (may be a new stream after reconnect)
    if let Some(tx) = matrix_tx.read().await.as_ref() {
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

            if let Some(tx) = self.matrix_tx.read().await.as_ref() {
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
            handle_execute_impl(
                req,
                self.tools.clone(),
                self.workspace_path.clone(),
                Arc::clone(&self.matrix_tx),
                self.event_tx.clone(),
            )
            .await;
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
