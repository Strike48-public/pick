//! WebSocket ↔ PTY bridge for the interactive shell (shared)
//!
//! Exposes `/ws/shell` which connects a WebSocket to a PTY.
//! Protocol:
//! - Client→Server text: raw keystrokes, JSON `{"type":"resize","cols":N,"rows":N}`,
//!   or JSON `{"type":"input","data":"..."}` (restty PTY transport format)
//! - Server→Client text: raw terminal output

use axum::{
    extract::{
        ws::{Message, WebSocket},
        Query, WebSocketUpgrade,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use futures::{SinkExt, StreamExt};
use pentest_core::config::ShellMode;
use pentest_core::settings::load_settings;
use pentest_platform::PtyShell;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;
use tokio::sync::Mutex;

#[derive(Deserialize)]
struct ShellParams {
    cols: Option<u16>,
    rows: Option<u16>,
    /// Per-session token gating access to the shell. The page's shell_init.js
    /// is served the token via placeholder substitution; other local processes
    /// (which matters on Android, where any app can reach 127.0.0.1 TCP) do not
    /// have it and are rejected before the PTY is spawned.
    token: Option<String>,
}

/// Process-global per-session shell token. Generated once on first read with
/// `Uuid::new_v4()` and stable for the process lifetime. Mirrors the
/// `WORKSPACE_PATH` OnceLock pattern in liveview_server.rs — a value any thread
/// can read without threading it through the Dioxus component tree.
pub fn shell_token() -> &'static str {
    static SHELL_TOKEN: OnceLock<String> = OnceLock::new();
    SHELL_TOKEN.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

/// True when the supplied token exactly matches the session token.
fn token_ok(supplied: Option<&str>) -> bool {
    supplied == Some(shell_token())
}

/// Returns the router with shell WebSocket route.
///
/// The shell mode is read from the user's persisted settings on each new
/// connection, so changes made in the connector settings take effect immediately.
pub fn shell_routes(_default_mode: ShellMode) -> Router {
    Router::new().route("/ws/shell", get(ws_handler))
}

async fn ws_handler(ws: WebSocketUpgrade, Query(params): Query<ShellParams>) -> impl IntoResponse {
    // Reject before upgrading if the token is missing or wrong. On Android the
    // shell WS is served over a localhost TCP port reachable by any app, so this
    // gate is what keeps a root proot shell from being opened by another process.
    if !token_ok(params.token.as_deref()) {
        tracing::warn!("[shell_ws] rejecting /ws/shell: missing or invalid token");
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }

    let cols = params.cols.unwrap_or(80);
    let rows = params.rows.unwrap_or(24);

    // Always read the authoritative shell mode from the persisted settings
    // rather than relying on the client to pass it (the workspace_app's
    // settings signal can be stale).
    let shell_mode = load_settings().shell_mode;

    let workspace = crate::liveview_server::get_workspace_path();
    let cwd = if workspace.is_empty() {
        None
    } else {
        Some(PathBuf::from(workspace))
    };

    ws.on_upgrade(move |socket| handle_socket(socket, cols, rows, cwd, shell_mode))
        .into_response()
}

async fn handle_socket(
    socket: WebSocket,
    cols: u16,
    rows: u16,
    cwd: Option<PathBuf>,
    shell_mode: ShellMode,
) {
    tracing::info!(
        "[shell_ws] handle_socket: spawning PTY shell (mode={shell_mode:?}, {cols}x{rows})"
    );
    let pty = match PtyShell::spawn(cols, rows, None, cwd.as_deref(), shell_mode).await {
        Ok(pty) => pty,
        Err(e) => {
            tracing::error!("Failed to spawn PTY shell: {}", e);
            return;
        }
    };

    if let Some(backend) = pty.effective_backend() {
        if let Some(primary) = pty.primary_backend() {
            if primary != backend {
                crate::liveview_server::push_terminal_line(
                    pentest_core::terminal::TerminalLine::info(format!(
                        "Sandbox backend: {backend} (fell back from {primary})"
                    )),
                );
            }
        }
    }

    tracing::info!("[shell_ws] PtyShell::spawn returned OK; wiring reader/writer");

    let reader = match pty.try_clone_reader() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to get PTY reader: {}", e);
            return;
        }
    };

    let writer = match pty.take_writer() {
        Ok(w) => w,
        Err(e) => {
            tracing::error!("Failed to get PTY writer: {}", e);
            return;
        }
    };

    let pty = Arc::new(Mutex::new(pty));
    let writer = Arc::new(Mutex::new(writer));

    let (mut ws_sender, mut ws_receiver) = socket.split();

    // Channel for PTY output → WebSocket sender task
    let (pty_tx, mut pty_rx) = tokio::sync::mpsc::channel::<String>(256);

    // Task: Read from PTY in a blocking thread, send to channel
    let read_handle = tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut reader = reader;
        let mut buf = [0u8; 4096];
        let mut total: u64 = 0;
        let mut first = true;
        tracing::info!("[shell_ws] PTY reader loop started; blocking on first read()");
        loop {
            match reader.read(&mut buf) {
                Ok(0) => {
                    tracing::info!("[shell_ws] PTY reader hit EOF after {total} bytes");
                    break;
                }
                Ok(n) => {
                    if first {
                        tracing::info!("[shell_ws] PTY reader got FIRST {n} bytes");
                        first = false;
                    }
                    total += n as u64;
                    let text = String::from_utf8_lossy(&buf[..n]).to_string();
                    if pty_tx.blocking_send(text).is_err() {
                        tracing::info!("[shell_ws] PTY reader: channel closed, stopping");
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!("[shell_ws] PTY reader error after {total} bytes: {e}");
                    break;
                }
            }
        }
    });

    // Task: Forward channel messages to WebSocket
    let send_handle = tokio::spawn(async move {
        while let Some(text) = pty_rx.recv().await {
            if ws_sender.send(Message::Text(text.into())).await.is_err() {
                break;
            }
        }
    });

    // Main loop: WebSocket → PTY input (+ resize)
    while let Some(Ok(msg)) = ws_receiver.next().await {
        match msg {
            Message::Text(text) => {
                // Try to parse as JSON command (resize or input)
                if let Ok(cmd) = serde_json::from_str::<ShellCommand>(&text) {
                    match cmd {
                        ShellCommand::Resize { cols, rows } => {
                            let pty = pty.lock().await;
                            let _ = pty.resize(cols, rows);
                            continue;
                        }
                        ShellCommand::Input { data } => {
                            let mut w = writer.lock().await;
                            if std::io::Write::write_all(&mut *w, data.as_bytes()).is_err() {
                                break;
                            }
                            let _ = std::io::Write::flush(&mut *w);
                            continue;
                        }
                        ShellCommand::Unknown => {}
                    }
                }
                // Raw keystroke data (non-JSON)
                let mut w = writer.lock().await;
                if std::io::Write::write_all(&mut *w, text.as_bytes()).is_err() {
                    break;
                }
                let _ = std::io::Write::flush(&mut *w);
            }
            Message::Binary(data) => {
                let mut w = writer.lock().await;
                if std::io::Write::write_all(&mut *w, &data).is_err() {
                    break;
                }
                let _ = std::io::Write::flush(&mut *w);
            }
            Message::Close(_) => break,
            _ => {}
        }
    }

    read_handle.abort();
    send_handle.abort();
}

/// JSON commands from the terminal client (restty PTY transport or manual WebSocket).
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ShellCommand {
    Resize {
        cols: u16,
        rows: u16,
    },
    Input {
        data: String,
    },
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_token_is_stable_and_nonempty() {
        let a = shell_token();
        let b = shell_token();
        assert!(!a.is_empty(), "token must be non-empty");
        assert_eq!(a, b, "token must be stable across calls");
    }

    #[test]
    fn token_matches_only_exact_value() {
        let t = shell_token();
        // Accept path: exact match.
        assert!(token_ok(Some(t)));
        // Reject paths: absent or wrong.
        assert!(!token_ok(None));
        assert!(!token_ok(Some("not-the-token")));
    }
}
