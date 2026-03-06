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
use tokio::sync::Mutex;

#[derive(Deserialize)]
struct ShellParams {
    cols: Option<u16>,
    rows: Option<u16>,
}

/// Returns the router with shell WebSocket route.
///
/// The shell mode is read from the user's persisted settings on each new
/// connection, so changes made in the connector settings take effect immediately.
pub fn shell_routes(_default_mode: ShellMode) -> Router {
    Router::new().route("/ws/shell", get(ws_handler))
}

async fn ws_handler(ws: WebSocketUpgrade, Query(params): Query<ShellParams>) -> impl IntoResponse {
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
}

async fn handle_socket(
    socket: WebSocket,
    cols: u16,
    rows: u16,
    cwd: Option<PathBuf>,
    shell_mode: ShellMode,
) {
    let pty = match PtyShell::spawn(cols, rows, None, cwd.as_deref(), shell_mode).await {
        Ok(pty) => pty,
        Err(e) => {
            tracing::error!("Failed to spawn PTY shell: {}", e);
            return;
        }
    };

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
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let text = String::from_utf8_lossy(&buf[..n]).to_string();
                    if pty_tx.blocking_send(text).is_err() {
                        break;
                    }
                }
                Err(_) => break,
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
