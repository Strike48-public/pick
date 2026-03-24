//! Embedded LiveView server for file browser
//!
//! This module provides a way to run a Dioxus LiveView server internally
//! and proxy requests to it. LiveView uses WebSocket for interactivity,
//! which is proxied through the Strike48 Phoenix socket protocol.

#[cfg(feature = "liveview")]
use axum::Router;
#[cfg(feature = "liveview")]
use dioxus::prelude::*;
#[cfg(feature = "liveview")]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "liveview")]
use std::sync::Arc;
#[cfg(feature = "liveview")]
use std::sync::OnceLock;

#[cfg(feature = "liveview")]
use crate::ipc::{IpcAddr, IpcListener};

#[cfg(feature = "liveview")]
use crate::components::workspace_app::WorkspaceApp;

/// Global workspace path for the file browser
/// This is set before starting the server and read by the FileBrowser component
#[cfg(feature = "liveview")]
static WORKSPACE_PATH: OnceLock<String> = OnceLock::new();

/// Get the workspace path for the file browser
#[cfg(feature = "liveview")]
pub fn get_workspace_path() -> String {
    WORKSPACE_PATH.get().cloned().unwrap_or_default()
}

/// Global Matrix API credentials for the chat panel.
/// Set by the connector when credentials are received, read by WorkspaceApp.
#[cfg(feature = "liveview")]
static MATRIX_API_URL_GLOBAL: std::sync::RwLock<String> = std::sync::RwLock::new(String::new());
#[cfg(feature = "liveview")]
static MATRIX_AUTH_TOKEN_GLOBAL: std::sync::RwLock<String> = std::sync::RwLock::new(String::new());

/// Global terminal log lines — connector events get pushed here so the
/// WorkspaceApp Logs page can display them even in headless mode.
#[cfg(feature = "liveview")]
static TERMINAL_LINES_GLOBAL: std::sync::RwLock<Vec<pentest_core::terminal::TerminalLine>> =
    std::sync::RwLock::new(Vec::new());

/// Append a terminal line to the global log buffer.
#[cfg(feature = "liveview")]
pub fn push_terminal_line(line: pentest_core::terminal::TerminalLine) {
    if let Ok(mut lines) = TERMINAL_LINES_GLOBAL.write() {
        lines.push(line);
        // Cap at 5000 lines to avoid unbounded growth
        if lines.len() > 5000 {
            let drain_to = lines.len() - 5000;
            lines.drain(0..drain_to);
        }
    }
}

/// No-op when liveview is not enabled.
#[cfg(not(feature = "liveview"))]
pub fn push_terminal_line(_line: pentest_core::terminal::TerminalLine) {}

/// Return all terminal lines from the global buffer.
#[cfg(feature = "liveview")]
pub fn get_terminal_lines() -> Vec<pentest_core::terminal::TerminalLine> {
    TERMINAL_LINES_GLOBAL
        .read()
        .map(|l| l.clone())
        .unwrap_or_default()
}

/// Return the number of terminal lines currently in the global buffer.
#[cfg(feature = "liveview")]
pub fn terminal_lines_count() -> usize {
    TERMINAL_LINES_GLOBAL.read().map(|l| l.len()).unwrap_or(0)
}

/// Set the Matrix API credentials for the liveview workspace chat panel.
#[cfg(feature = "liveview")]
pub fn set_matrix_credentials(api_url: &str, auth_token: &str) {
    tracing::info!(
        "[MatrixCreds] set_matrix_credentials called: api_url={:?} token_len={}",
        api_url,
        auth_token.len(),
    );
    if let Ok(mut url) = MATRIX_API_URL_GLOBAL.write() {
        *url = api_url.to_string();
        tracing::info!("[MatrixCreds] MATRIX_API_URL_GLOBAL written OK");
    } else {
        tracing::error!("[MatrixCreds] FAILED to write MATRIX_API_URL_GLOBAL (lock poisoned)");
    }
    if let Ok(mut token) = MATRIX_AUTH_TOKEN_GLOBAL.write() {
        *token = auth_token.to_string();
        tracing::info!("[MatrixCreds] MATRIX_AUTH_TOKEN_GLOBAL written OK");
    } else {
        tracing::error!("[MatrixCreds] FAILED to write MATRIX_AUTH_TOKEN_GLOBAL (lock poisoned)");
    }
}

/// Get the Matrix API URL for the chat panel.
#[cfg(feature = "liveview")]
pub fn get_matrix_api_url() -> String {
    MATRIX_API_URL_GLOBAL
        .read()
        .map(|s| s.clone())
        .unwrap_or_default()
}

/// Get the Matrix auth token for the chat panel.
#[cfg(feature = "liveview")]
pub fn get_matrix_auth_token() -> String {
    MATRIX_AUTH_TOKEN_GLOBAL
        .read()
        .map(|s| s.clone())
        .unwrap_or_default()
}

/// Default port for the internal server
pub const LIVEVIEW_PORT: u16 = 3030;

/// Configuration for the LiveView server
#[derive(Clone, Debug)]
pub struct LiveViewConfig {
    /// Port to bind the server to
    pub port: u16,
    /// Workspace path for file browser
    pub workspace_path: String,
}

impl Default for LiveViewConfig {
    fn default() -> Self {
        Self {
            port: LIVEVIEW_PORT,
            workspace_path: String::new(),
        }
    }
}

impl LiveViewConfig {
    /// Create a new config with workspace path
    pub fn with_workspace(workspace_path: impl Into<String>) -> Self {
        Self {
            workspace_path: workspace_path.into(),
            ..Default::default()
        }
    }
}

/// Handle to control the server
#[cfg(feature = "liveview")]
pub struct LiveViewHandle {
    shutdown: Arc<AtomicBool>,
    port: u16,
    /// IPC address the server is listening on.
    ipc_addr: Option<IpcAddr>,
}

#[cfg(feature = "liveview")]
impl LiveViewHandle {
    /// Get the bound port
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the IPC address (Unix socket or named pipe)
    pub fn ipc_addr(&self) -> Option<&IpcAddr> {
        self.ipc_addr.as_ref()
    }

    /// Get the base URL for the server
    pub fn base_url(&self) -> String {
        if let Some(ref addr) = self.ipc_addr {
            addr.to_string()
        } else {
            format!("http://127.0.0.1:{}", self.port)
        }
    }

    /// Check if the server is running
    pub fn is_running(&self) -> bool {
        !self.shutdown.load(Ordering::SeqCst)
    }

    /// Signal the server to shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }
}

/// The Dioxus App component that wraps the Workspace App (Files + Shell)
#[cfg(feature = "liveview")]
#[component]
fn LiveViewApp() -> Element {
    rsx! {
        WorkspaceApp {}
    }
}

/// Serve the restty terminal JavaScript bundle (GPU-accelerated, xterm compat)
#[cfg(feature = "liveview")]
async fn serve_restty_js() -> axum::response::Response {
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;

    static RESTTY_JS: &[u8] = include_bytes!("assets/restty.js");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/javascript")],
        RESTTY_JS,
    )
        .into_response()
}

/// Serve the JetBrains Mono Regular font (for terminals in sandboxed iframes)
#[cfg(feature = "liveview")]
async fn serve_font_regular() -> axum::response::Response {
    use axum::http::{header, StatusCode};
    use axum::response::IntoResponse;

    static FONT_TTF: &[u8] = include_bytes!("assets/jetbrains-mono-regular.ttf");
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "font/ttf")],
        FONT_TTF,
    )
        .into_response()
}

/// Start the LiveView server in a background task
///
/// Returns a handle that can be used to get the server URL and shutdown.
///
/// The server exposes:
/// - `/liveview` - HTML page with LiveView JS client
/// - `/ws` - WebSocket endpoint for LiveView updates
/// - `/health` - Health check endpoint
/// - `/assets/restty.js` - restty terminal JavaScript bundle (GPU-accelerated)
///
/// Additional routes can be merged via `extra_routes`.
#[cfg(feature = "liveview")]
pub async fn start_liveview_server(
    config: LiveViewConfig,
    extra_routes: Router,
) -> std::io::Result<LiveViewHandle> {
    use axum::routing::get;
    use dioxus_liveview::LiveviewRouter;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();
    let port = config.port;

    // Set the global workspace path for the FileBrowser component
    let _ = WORKSPACE_PATH.set(config.workspace_path.clone());

    // Use `.with_app()` which creates a LiveViewPool that calls
    // `dioxus_html::set_event_converter()` — required for onclick and other
    // event handlers to work in the LiveView context.
    let router = Router::new()
        .with_app("/", LiveViewApp)
        .route("/health", get(|| async { "OK" }))
        .route(
            "/connector/info",
            get(|| async {
                axum::Json(serde_json::json!({
                    "name": "Pick",
                    "icon": "hero-shield-exclamation"
                }))
            }),
        )
        .route("/assets/restty.js", get(serve_restty_js))
        .route(
            "/assets/fonts/jetbrains-mono-regular.ttf",
            get(serve_font_regular),
        )
        .merge(extra_routes);

    // Check for IPC mode via STRIKEHUB_SOCKET env var (Unix only — StrikeHub runs on Linux)
    #[cfg(unix)]
    if let Ok(socket_env) = std::env::var("STRIKEHUB_SOCKET") {
        let addr = IpcAddr::from_path(std::path::PathBuf::from(&socket_env));
        let listener = IpcListener::bind(&addr)?;
        tracing::info!("LiveView server listening on {}", addr);

        let addr_clone = addr.clone();
        tokio::spawn(async move {
            tracing::info!("LiveView server task started (IPC mode)");
            let server = axum::serve(listener, router.into_make_service());

            tokio::select! {
                result = server => {
                    tracing::warn!("LiveView server exited: {:?}", result);
                    if let Err(e) = result {
                        tracing::error!("LiveView server error: {}", e);
                    }
                }
                _ = async {
                    while !shutdown_clone.load(Ordering::SeqCst) {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                } => {
                    tracing::info!("LiveView server shutting down");
                }
            }
            addr_clone.cleanup();
            tracing::warn!("LiveView server task ending");
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        return Ok(LiveViewHandle {
            shutdown,
            port,
            ipc_addr: Some(addr),
        });
    }

    #[cfg(not(unix))]
    if let Ok(socket_env) = std::env::var("STRIKEHUB_SOCKET") {
        let addr = IpcAddr::from_string(socket_env);
        let listener = IpcListener::bind(&addr)?;
        tracing::info!("LiveView server listening on {}", addr);

        let addr_clone = addr.clone();
        tokio::spawn(async move {
            tracing::info!("LiveView server task started (IPC mode)");
            let server = axum::serve(listener, router.into_make_service());

            tokio::select! {
                result = server => {
                    tracing::warn!("LiveView server exited: {:?}", result);
                    if let Err(e) = result {
                        tracing::error!("LiveView server error: {}", e);
                    }
                }
                _ = async {
                    while !shutdown_clone.load(Ordering::SeqCst) {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                } => {
                    tracing::info!("LiveView server shutting down");
                }
            }
            addr_clone.cleanup();
            tracing::warn!("LiveView server task ending");
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        return Ok(LiveViewHandle {
            shutdown,
            port,
            ipc_addr: Some(addr),
        });
    }

    // Standalone mode: PID-based IPC address (Unix socket or named pipe)
    // to avoid conflicts when multiple connectors run simultaneously.
    let addr = IpcAddr::for_agent(std::process::id());
    let listener = IpcListener::bind(&addr)?;
    tracing::info!("LiveView server listening on {}", addr);

    // On Android, also start a TCP listener so the WebView can reach assets
    // and WebSocket endpoints (the WebView can't connect to unix sockets).
    #[cfg(target_os = "android")]
    {
        let tcp_router = router.clone();
        let tcp_shutdown = shutdown.clone();
        let tcp_port = port;
        tokio::spawn(async move {
            let bind_addr = format!("127.0.0.1:{}", tcp_port);
            match tokio::net::TcpListener::bind(&bind_addr).await {
                Ok(tcp_listener) => {
                    tracing::info!("LiveView TCP server listening on {}", bind_addr);
                    let server =
                        axum::serve(tcp_listener, tcp_router.into_make_service());
                    tokio::select! {
                        result = server => {
                            if let Err(e) = result {
                                tracing::error!("LiveView TCP server error: {}", e);
                            }
                        }
                        _ = async {
                            while !tcp_shutdown.load(Ordering::SeqCst) {
                                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                            }
                        } => {
                            tracing::info!("LiveView TCP server shutting down");
                        }
                    }
                }
                Err(e) => {
                    tracing::error!("Failed to bind TCP listener on {}: {}", bind_addr, e);
                }
            }
        });
    }

    let addr_clone = addr.clone();
    tokio::spawn(async move {
        tracing::info!("LiveView server task started");
        let server = axum::serve(listener, router.into_make_service());

        tokio::select! {
            result = server => {
                tracing::warn!("LiveView server exited: {:?}", result);
                if let Err(e) = result {
                    tracing::error!("LiveView server error: {}", e);
                }
            }
            _ = async {
                while !shutdown_clone.load(Ordering::SeqCst) {
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            } => {
                tracing::info!("LiveView server shutting down");
            }
        }
        addr_clone.cleanup();
        tracing::warn!("LiveView server task ending");
    });

    // Wait a moment for the server to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    Ok(LiveViewHandle {
        shutdown,
        port,
        ipc_addr: Some(addr),
    })
}

// Non-liveview stubs
#[cfg(not(feature = "liveview"))]
pub struct LiveViewHandle;

#[cfg(not(feature = "liveview"))]
impl LiveViewHandle {
    pub fn port(&self) -> u16 {
        0
    }
    pub fn ipc_addr(&self) -> Option<&crate::ipc::IpcAddr> {
        None
    }
    pub fn base_url(&self) -> String {
        String::new()
    }
    pub fn is_running(&self) -> bool {
        false
    }
    pub fn shutdown(&self) {}
}

#[cfg(not(feature = "liveview"))]
pub async fn start_liveview_server(
    _config: LiveViewConfig,
    _extra_routes: (),
) -> std::io::Result<LiveViewHandle> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "LiveView feature not enabled",
    ))
}
