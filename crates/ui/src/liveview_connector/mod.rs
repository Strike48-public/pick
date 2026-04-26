//! LiveView Connector with WebSocket Support
//!
//! This module implements a connector that:
//! - Runs a Dioxus LiveView server internally
//! - Proxies HTTP requests to the LiveView server
//! - Proxies WebSocket connections for LiveView interactivity
//! - Executes tools via the tool registry
//!
//! Unlike the standard ConnectionManager which uses ConnectorRunner,
//! this directly handles the gRPC stream to support WebSocket messages.

mod api_routes;
mod auth;
mod injections;
mod token_refresh;
mod tools;

use tools::handle_execute_impl;

use crate::liveview_server::{start_liveview_server, LiveViewConfig, LiveViewHandle};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use pentest_core::config::ConnectorConfig;
use pentest_core::state::ConnectorStatus;
use pentest_core::terminal::TerminalLine;
use pentest_core::tools::ToolRegistry;
use pentest_core::workspace;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use strike48_connector::{
    AppManifest, ClientOptions, ConnectorBehavior, ConnectorClient, NavigationConfig, OttProvider,
    PayloadEncoding,
};
use strike48_proto::proto::{
    stream_message::Message, ConnectorCapabilities, RegisterConnectorRequest, StreamMessage,
    WebSocketCloseRequest, WebSocketFrame, WebSocketFrameType, WebSocketOpenRequest,
    WebSocketOpenResponse,
};
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message as WsMessage;

pub use self::injections::inject_websocket_shim;

use crate::components::ConnectingStep;

/// Default port for the internal Dioxus LiveView server
const DEFAULT_LIVEVIEW_PORT: u16 = 3030;

/// Exponential backoff for connection retries. Max 60 seconds.
fn reconnect_delay_ms(failures: u32) -> u64 {
    const BASE_MS: u64 = 2000;
    const MAX_MS: u64 = 60_000;

    let exp = failures.saturating_sub(1).min(5);
    BASE_MS.saturating_mul(2u64.pow(exp)).min(MAX_MS)
}

/// How far before JWT expiry to refresh. We parse the real `exp` claim from
/// the token and schedule the refresh this many seconds before it expires.
const JWT_REFRESH_BUFFER_SECS: u64 = 60;

/// Fallback refresh interval when we can't parse the token's `exp` claim.
const JWT_REFRESH_FALLBACK_SECS: u64 = 240;

/// Retry delay when a proactive JWT refresh fails.
const JWT_REFRESH_RETRY_SECS: u64 = 30;

/// Parse remaining seconds until expiry from a JWT (3-part `header.payload.signature`).
fn jwt_remaining_secs(token: &str) -> Option<i64> {
    let payload_b64 = token.split('.').nth(1)?;
    let standard = payload_b64.replace('-', "+").replace('_', "/");
    let padded = match standard.len() % 4 {
        2 => format!("{}==", standard),
        3 => format!("{}=", standard),
        _ => standard,
    };
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &padded).ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let exp = claims.get("exp")?.as_i64()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs() as i64;
    Some(exp - now)
}

/// Compute how long to wait before the next JWT refresh.
fn jwt_refresh_delay(token: &str) -> tokio::time::Duration {
    if let Some(remaining) = jwt_remaining_secs(token) {
        tracing::info!(
            "JWT expires in {}s ({}m), will refresh in {}s",
            remaining,
            remaining / 60,
            (remaining as u64).saturating_sub(JWT_REFRESH_BUFFER_SECS)
        );
        let secs = (remaining as u64).saturating_sub(JWT_REFRESH_BUFFER_SECS);
        if secs > 0 {
            return tokio::time::Duration::from_secs(secs);
        }
    }
    tokio::time::Duration::from_secs(JWT_REFRESH_FALLBACK_SECS)
}

/// WebSocket connection state
pub(crate) struct WsConnectionState {
    to_backend_tx: mpsc::Sender<WsMessage>,
}

/// Information about a spawned specialist agent
#[derive(Debug, Clone, serde::Serialize)]
pub struct SpecialistInfo {
    pub specialist_type: String,
    pub agent_id: String,
    pub agent_name: String,
    pub targets: Vec<String>,
    #[serde(with = "humantime_serde")]
    pub spawned_at: std::time::SystemTime,
}

/// Active scan state tracking
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanState {
    pub conversation_id: String,
    pub agent_id: String,
    #[serde(skip)]
    pub started_at: std::time::Instant,
    #[serde(with = "humantime_serde")]
    pub started_at_system: std::time::SystemTime,
    pub current_aggression: pentest_core::aggression::AggressionLevel,
    pub active_specialists: HashMap<String, SpecialistInfo>,
}

/// Event emitted during connector operations
#[derive(Debug, Clone)]
pub enum ConnectorEvent {
    StatusChanged(ConnectorStatus),
    StepChanged(ConnectingStep),
    ToolStarted {
        tool_name: String,
        params: serde_json::Value,
    },
    ToolCompleted {
        tool_name: String,
        duration_ms: u64,
        success: bool,
        result: serde_json::Value,
    },
    ToolFailed {
        tool_name: String,
        error: String,
    },
    Log(TerminalLine),
    /// Connector JWT obtained via OTT — should be saved to persist authorization.
    /// `api_url` is the Matrix API base URL (e.g. `https://studio.example.com:8443`).
    CredentialsUpdated {
        auth_token: String,
        api_url: String,
    },
    /// Short-lived Matrix access token (browser OAuth). For chat panel only —
    /// must NOT be saved as `config.auth_token` (it's not a connector JWT).
    MatrixTokenObtained {
        auth_token: String,
        api_url: String,
    },
}

/// LiveView-enabled connector that handles WebSocket proxying
pub struct LiveViewConnector {
    pub(crate) config: ConnectorConfig,
    pub(crate) tools: Arc<RwLock<ToolRegistry>>,
    pub(crate) workspace_path: Option<PathBuf>,
    pub(crate) ws_connections: Arc<DashMap<String, WsConnectionState>>,
    /// Shared sender for the current gRPC stream. Wrapped in Arc<RwLock> so
    /// background tool tasks can still deliver results after a reconnect.
    pub(crate) matrix_tx: Arc<RwLock<Option<mpsc::UnboundedSender<StreamMessage>>>>,
    pub(crate) event_tx: broadcast::Sender<ConnectorEvent>,
    pub(crate) shutdown: Arc<AtomicBool>,
    pub(crate) liveview_handle: Option<LiveViewHandle>,
    pub(crate) liveview_port: u16,
    pub(crate) ott_provider: Arc<RwLock<Option<OttProvider>>>,
    pub(crate) reconnect_with_jwt: Arc<AtomicBool>,
    /// Active scan state (if a scan is running)
    pub(crate) active_scan: Arc<RwLock<Option<ScanState>>>,
    /// Matrix HTTP client for sending system messages (aggression updates, etc.)
    pub(crate) matrix_client: Arc<RwLock<Option<pentest_core::matrix::MatrixChatClient>>>,
}

impl LiveViewConnector {
    /// Create a new LiveView connector
    pub fn new(config: ConnectorConfig, tools: ToolRegistry) -> Self {
        let (event_tx, _) = broadcast::channel(64);

        // Store tenant_id, connector_name, tool names, and registry in the global session so the
        // WorkspaceApp (liveview) can read them when auto-creating the agent persona and executing tools.
        crate::session::set_tenant_id(&config.tenant_id);
        crate::session::set_connector_name(&config.connector_name);
        crate::session::set_tool_names(tools.names().iter().map(|s| s.to_string()).collect());

        let tools_arc = Arc::new(RwLock::new(tools));
        crate::session::set_tool_registry(tools_arc.clone());

        // Create workspace directory
        let workspace_path = match workspace::create_workspace(&config.instance_id) {
            Ok(path) => {
                tracing::info!("Workspace created at {}", path.display());
                Some(path)
            }
            Err(e) => {
                tracing::warn!("Failed to create workspace: {}", e);
                None
            }
        };

        Self {
            config,
            tools: tools_arc,
            workspace_path,
            ws_connections: Arc::new(DashMap::new()),
            matrix_tx: Arc::new(RwLock::new(None)),
            event_tx,
            shutdown: Arc::new(AtomicBool::new(false)),
            liveview_handle: None,
            liveview_port: DEFAULT_LIVEVIEW_PORT,
            ott_provider: Arc::new(RwLock::new(None)),
            reconnect_with_jwt: Arc::new(AtomicBool::new(false)),
            active_scan: Arc::new(RwLock::new(None)),
            matrix_client: Arc::new(RwLock::new(None)),
        }
    }

    /// Subscribe to connector events
    pub fn event_rx(&self) -> broadcast::Receiver<ConnectorEvent> {
        self.event_tx.subscribe()
    }

    /// Get the workspace path
    pub fn workspace_path(&self) -> Option<&PathBuf> {
        self.workspace_path.as_ref()
    }

    /// Derive the Matrix API URL from the connector host.
    ///
    /// The connector host is typically `connectors-studio.example.com:port`.
    /// The Matrix API lives on the main studio host `studio.example.com:port`.
    /// If env var MATRIX_API_URL or MATRIX_URL is set, use that instead.
    pub(crate) fn derive_matrix_api_url(&self) -> String {
        // Prefer explicit env var
        if let Ok(url) = std::env::var("MATRIX_API_URL") {
            if !url.is_empty() {
                return url;
            }
        }
        if let Ok(url) = std::env::var("MATRIX_URL") {
            if !url.is_empty() {
                return url;
            }
        }

        let host = &self.config.host;
        let scheme = if self.config.use_tls { "https" } else { "http" };

        // Strip URL scheme prefixes (grpc://, grpcs://, etc.) first (case-insensitive)
        let schemes = [
            "grpc://", "grpcs://", "http://", "https://", "ws://", "wss://",
        ];
        let host_lower = host.to_lowercase();
        let mut bare_host = host.as_str();
        for prefix in &schemes {
            if host_lower.starts_with(prefix) {
                bare_host = &host[prefix.len()..];
                break;
            }
        }

        // Strip "connectors-" prefix if present (connectors-studio.x -> studio.x)
        let api_host = bare_host.strip_prefix("connectors-").unwrap_or(bare_host);

        format!("{}://{}", scheme, api_host)
    }

    /// Send an event
    pub(crate) fn send_event(&self, event: ConnectorEvent) {
        // Set global Matrix credentials for the liveview WorkspaceApp chat panel.
        // Only MatrixTokenObtained carries a session-backed token valid for GraphQL.
        // CredentialsUpdated carries the connector JWT (gRPC only, no DB session).
        if let ConnectorEvent::MatrixTokenObtained {
            ref auth_token,
            ref api_url,
        } = event
        {
            if !auth_token.is_empty() {
                tracing::info!(
                    "[SendEvent] Setting Matrix credentials: api_url={} token_len={}",
                    api_url,
                    auth_token.len(),
                );
                crate::liveview_server::set_matrix_credentials(api_url, auth_token);
                crate::session::set_auth_token(auth_token);
                crate::session::set_tenant_id(&self.config.tenant_id);
            }
        }

        // Mirror log/tool events into the global terminal buffer so the WorkspaceApp
        // Logs page shows connector activity even in headless (no desktop UI) mode.
        use pentest_core::terminal::TerminalLine;
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
                    .with_details(details.clone())
                } else {
                    TerminalLine::error(format!(
                        "[tool] {} returned error ({}ms)",
                        tool_name, duration_ms
                    ))
                    .with_details(details.clone())
                };
                crate::liveview_server::push_terminal_line(line);

                // Handle special tools that update scan state
                if *success {
                    if tool_name == "begin_scan" {
                        // Extract conversation_id and agent_id from result
                        if let Ok(scan_result) =
                            serde_json::from_value::<serde_json::Value>(result.clone())
                        {
                            if let (Some(conv_id), Some(agent_id)) = (
                                scan_result.get("scan_id").and_then(|v| v.as_str()),
                                result.get("agent_id").and_then(|v| v.as_str()),
                            ) {
                                // Initialize scan state
                                let scan_state = ScanState {
                                    conversation_id: conv_id.to_string(),
                                    agent_id: agent_id.to_string(),
                                    started_at: std::time::Instant::now(),
                                    started_at_system: std::time::SystemTime::now(),
                                    current_aggression: self.config.aggression_level.clone(),
                                    active_specialists: std::collections::HashMap::new(),
                                };

                                // Update active scan
                                if let Ok(mut scan_guard) = self.active_scan.try_write() {
                                    *scan_guard = Some(scan_state);
                                    tracing::info!(
                                        "Scan started: conv={} agent={}",
                                        conv_id,
                                        agent_id
                                    );
                                }
                            }
                        }
                    } else if tool_name == "spawn_specialist" {
                        // Extract specialist information from result
                        if let Ok(spawn_result) =
                            serde_json::from_value::<serde_json::Value>(result.clone())
                        {
                            if spawn_result
                                .get("spawned")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false)
                            {
                                if let (
                                    Some(specialist_type),
                                    Some(agent_id),
                                    Some(agent_name),
                                    Some(targets),
                                ) = (
                                    spawn_result.get("specialist_type").and_then(|v| v.as_str()),
                                    spawn_result.get("agent_id").and_then(|v| v.as_str()),
                                    spawn_result.get("agent_name").and_then(|v| v.as_str()),
                                    spawn_result.get("targets").and_then(|v| v.as_array()),
                                ) {
                                    let specialist_info = SpecialistInfo {
                                        specialist_type: specialist_type.to_string(),
                                        agent_id: agent_id.to_string(),
                                        agent_name: agent_name.to_string(),
                                        targets: targets
                                            .iter()
                                            .filter_map(|v| v.as_str().map(String::from))
                                            .collect(),
                                        spawned_at: std::time::SystemTime::now(),
                                    };

                                    // Add to active scan
                                    if let Ok(mut scan_guard) = self.active_scan.try_write() {
                                        if let Some(ref mut scan) = *scan_guard {
                                            scan.active_specialists
                                                .insert(agent_id.to_string(), specialist_info);
                                            tracing::info!(
                                                "Specialist spawned: type={} agent={}",
                                                specialist_type,
                                                agent_id
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            ConnectorEvent::ToolFailed { tool_name, error } => {
                crate::liveview_server::push_terminal_line(
                    TerminalLine::error(format!("[tool] {} failed", tool_name))
                        .with_details(error.clone()),
                );
            }
            _ => {}
        }

        let _ = self.event_tx.send(event);
    }

    /// Start the LiveView server with optional extra routes (e.g. shell WebSocket).
    pub async fn start_liveview_server(
        &mut self,
        extra_routes: axum::Router,
    ) -> Result<(), String> {
        let workspace_path = self
            .workspace_path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        if workspace_path.is_empty() {
            return Err("No workspace path configured".to_string());
        }

        let ipc_mode = std::env::var("STRIKEHUB_SOCKET").is_ok();
        self.send_event(ConnectorEvent::Log(TerminalLine::info(if ipc_mode {
            "Starting LiveView server (IPC socket mode)..."
        } else {
            "Starting LiveView server..."
        })));

        // Create API routes for scan status and aggression adjustment
        let api_state = api_routes::ApiState {
            scan_state: self.active_scan.clone(),
            config: Arc::new(RwLock::new(self.config.clone())),
            matrix_client: self.matrix_client.clone(),
        };
        let api_routes_router = api_routes::create_api_routes(api_state);

        // Merge API routes with extra routes
        let combined_routes = extra_routes.merge(api_routes_router);

        let lv_config = LiveViewConfig {
            port: DEFAULT_LIVEVIEW_PORT,
            workspace_path,
        };

        match start_liveview_server(lv_config, combined_routes).await {
            Ok(handle) => {
                self.liveview_port = handle.port();
                let url = handle.base_url();
                self.send_event(ConnectorEvent::Log(TerminalLine::success(format!(
                    "LiveView server ready at {}",
                    url
                ))));
                self.liveview_handle = Some(handle);
                Ok(())
            }
            Err(e) => {
                self.send_event(ConnectorEvent::Log(TerminalLine::error(format!(
                    "LiveView server failed: {}",
                    e
                ))));
                Err(e.to_string())
            }
        }
    }

    /// Connect to Strike48 and run the message loop
    pub async fn connect_and_run(&mut self) -> Result<(), String> {
        self.send_event(ConnectorEvent::StatusChanged(ConnectorStatus::Connecting));
        self.send_event(ConnectorEvent::StepChanged(ConnectingStep::Connecting));
        self.send_event(ConnectorEvent::Log(TerminalLine::info(format!(
            "Connecting to {}...",
            self.config.host
        ))));

        // If we already have a saved auth token, set the Matrix credentials
        // immediately so the workspace chat panel can use them.
        tracing::info!(
            "[ConnectAndRun] auth_token from config: len={} empty={}",
            self.config.auth_token.len(),
            self.config.auth_token.is_empty(),
        );
        if !self.config.auth_token.is_empty() {
            tracing::info!("[ConnectAndRun] Emitting CredentialsUpdated from saved token");
            self.send_event(ConnectorEvent::CredentialsUpdated {
                auth_token: self.config.auth_token.clone(),
                api_url: self.derive_matrix_api_url(),
            });
        } else {
            tracing::info!("[ConnectAndRun] No saved auth_token — trying pre-approval auth");

            // Auth initialization follows the SDK's priority order:
            // 1. Direct config (cert-manager / K8s secrets)
            // 2. Pre-approval OTT (env var / file)
            // 3. Saved credentials (loaded here, token fetched per-iteration)
            // 4. Post-approval (wait for admin via CredentialsIssued)
            let connector_type = "pentest-connector".to_string();
            let instance_id = self.config.instance_id.clone();
            let mut ott_provider =
                OttProvider::new(Some(connector_type.clone()), Some(instance_id.clone()));

            if ott_provider.has_direct_config() {
                tracing::info!("Direct configuration detected (cert-manager/direct auth mode)");
                match ott_provider.initialize_from_direct_config() {
                    Ok(creds) => {
                        tracing::info!("Direct config initialized: {}", creds.client_id);
                        match ott_provider.get_token().await {
                            Ok(token) => {
                                self.config.auth_token = token.clone();
                                self.send_event(ConnectorEvent::CredentialsUpdated {
                                    auth_token: token,
                                    api_url: self.derive_matrix_api_url(),
                                });
                                *self.ott_provider.write().await = Some(ott_provider);
                            }
                            Err(e) => {
                                tracing::error!("Direct config get_token() failed: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Direct config initialization failed: {}", e);
                    }
                }
            } else if ott_provider.has_ott() {
                tracing::info!("Pre-approval OTT detected, attempting registration");
                match ott_provider
                    .register_with_ott(&connector_type, Some(&instance_id))
                    .await
                {
                    Ok(creds) => {
                        tracing::info!(
                            "OTT pre-approval registration successful: {}",
                            creds.client_id
                        );
                        match ott_provider.get_token().await {
                            Ok(token) => {
                                self.config.auth_token = token.clone();
                                self.send_event(ConnectorEvent::CredentialsUpdated {
                                    auth_token: token,
                                    api_url: self.derive_matrix_api_url(),
                                });
                                *self.ott_provider.write().await = Some(ott_provider);
                            }
                            Err(e) => {
                                tracing::error!(
                                    "OTT registration succeeded but get_token() failed: {}",
                                    e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "OTT pre-approval registration failed: {}. \
                             Falling through to gRPC registration (will require admin approval).",
                            e
                        );
                    }
                }
            } else if ott_provider
                .load_saved_credentials(&connector_type, Some(&instance_id))
                .is_some()
            {
                // Store the OTT provider; token will be fetched at the start of
                // each connection loop iteration (matching kubestudio's pattern).
                tracing::info!("Loaded saved credentials, will use JWT authentication");
                *self.ott_provider.write().await = Some(ott_provider);
            }
        }

        let mut connection_failures: u32 = 0;

        // Self-healing connection loop: retries indefinitely until shutdown
        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                break;
            }

            // Get fresh JWT if we have an OTT provider (matches kubestudio pattern:
            // fetch a token at the start of each iteration so reconnects always use
            // a valid token instead of a potentially expired cached one).
            {
                let mut ott_guard = self.ott_provider.write().await;
                if let Some(ref mut ott) = *ott_guard {
                    match ott.get_token().await {
                        Ok(token) => {
                            tracing::info!("Got fresh JWT via OttProvider (len={})", token.len());
                            self.config.auth_token = token.clone();
                            self.send_event(ConnectorEvent::CredentialsUpdated {
                                auth_token: token,
                                api_url: self.derive_matrix_api_url(),
                            });
                        }
                        Err(e) => {
                            tracing::warn!("Failed to get JWT from saved credentials: {}", e);
                            self.config.auth_token.clear();
                            // Clean up stale credentials file
                            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                            let stale = format!(
                                "{}/.strike48/credentials/pentest-connector_{}.json",
                                home, self.config.instance_id
                            );
                            if std::fs::remove_file(&stale).is_ok() {
                                tracing::info!("Removed stale credentials file: {}", stale);
                            }
                            *ott_guard = None;
                        }
                    }
                }
            }

            self.send_event(ConnectorEvent::StepChanged(ConnectingStep::Connecting));

            // Use URL-based client creation for automatic transport detection
            // (wss:// → WebSocket, grpcs:// → gRPC). SDK handles TLS including
            // MATRIX_TLS_INSECURE for self-signed certs, and automatic keepalive.
            #[allow(deprecated)]
            let mut client = ConnectorClient::with_options(ClientOptions {
                url: Some(self.config.host.clone()),
                ..Default::default()
            });

            if let Err(e) = client.connect_channel().await {
                connection_failures = connection_failures.saturating_add(1);
                let delay = reconnect_delay_ms(connection_failures);
                tracing::error!(
                    "Connection failed (attempt {}), retrying in {}ms: {}",
                    connection_failures,
                    delay,
                    e
                );
                self.send_event(ConnectorEvent::Log(TerminalLine::error(format!(
                    "Connection failed (attempt {}): {}",
                    connection_failures, e
                ))));
                self.send_event(ConnectorEvent::StatusChanged(ConnectorStatus::Reconnecting));
                tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                continue;
            }

            self.send_event(ConnectorEvent::StepChanged(ConnectingStep::Registering));
            self.send_event(ConnectorEvent::Log(TerminalLine::info(
                "Connected, registering...",
            )));
            tracing::info!("Connected to {}, starting stream...", self.config.host);

            let registration_msg = self.build_registration_message().await;

            // SDK handles stream setup and spawns automatic 30s keepalive heartbeats
            let (tx, rx) = match client
                .start_stream_with_registration(registration_msg)
                .await
            {
                Ok(streams) => streams,
                Err(e) => {
                    connection_failures = connection_failures.saturating_add(1);
                    let delay = reconnect_delay_ms(connection_failures);
                    tracing::error!(
                        "Stream failed (attempt {}), retrying in {}ms: {}",
                        connection_failures,
                        delay,
                        e
                    );
                    self.send_event(ConnectorEvent::Log(TerminalLine::error(format!(
                        "Stream failed (attempt {}): {}",
                        connection_failures, e
                    ))));
                    self.send_event(ConnectorEvent::StatusChanged(ConnectorStatus::Reconnecting));
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                    continue;
                }
            };

            connection_failures = 0;

            *self.matrix_tx.write().await = Some(tx);

            self.run_message_loop(rx).await;

            *self.matrix_tx.write().await = None;

            if self.shutdown.load(Ordering::SeqCst) {
                break;
            }

            if self.reconnect_with_jwt.load(Ordering::SeqCst) {
                self.reconnect_with_jwt.store(false, Ordering::SeqCst);
                self.send_event(ConnectorEvent::StepChanged(ConnectingStep::Finalizing));
                self.send_event(ConnectorEvent::Log(TerminalLine::info(
                    "Reconnecting with JWT authentication...",
                )));
                self.send_event(ConnectorEvent::StatusChanged(ConnectorStatus::Reconnecting));
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                continue;
            }

            self.send_event(ConnectorEvent::Log(TerminalLine::info(
                "Connection closed, reconnecting...",
            )));
            self.send_event(ConnectorEvent::StatusChanged(ConnectorStatus::Reconnecting));
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }

        self.send_event(ConnectorEvent::StatusChanged(ConnectorStatus::Disconnected));
        Ok(())
    }

    /// Build the registration message
    async fn build_registration_message(&self) -> StreamMessage {
        // Build tool schemas for metadata
        let tools = self.tools.read().await;
        let schemas = tools.schemas();
        let tool_names: Vec<String> = tools.names().iter().map(|s| s.to_string()).collect();
        let json_schemas: Vec<serde_json::Value> =
            schemas.iter().map(|s| s.to_json_schema()).collect();
        drop(tools);

        // Build app manifest for workspace (Files + Shell)
        // Use hostname as the app name (display name); connector_name controls gateway identity
        let hostname = whoami::fallible::hostname().unwrap_or_else(|_| "unknown".to_string());
        let connector_type = self.config.connector_name.clone();

        let manifest = AppManifest::new(&hostname, "/")
            .description("Browse files and access the interactive shell")
            .icon("hero-command-line")
            .navigation(NavigationConfig::nested(&["Apps"]))
            .api_access();

        let manifest_json = serde_json::to_string(&manifest).unwrap_or_default();

        let mut metadata = HashMap::new();
        metadata.insert("app_manifest".to_string(), manifest_json);
        metadata.insert("timeout_ms".to_string(), "300000".to_string());
        metadata.insert(
            "tool_schemas".to_string(),
            serde_json::to_string(&json_schemas).unwrap_or_default(),
        );
        metadata.insert("tool_names".to_string(), tool_names.join(","));

        let capabilities = ConnectorCapabilities {
            connector_type: connector_type.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            supported_encodings: vec![PayloadEncoding::Json as i32],
            behaviors: vec![
                ConnectorBehavior::Tool as i32,
                ConnectorBehavior::App as i32,
            ],
            metadata,
            task_types: vec![],
        };

        let register_request = RegisterConnectorRequest {
            tenant_id: self.config.tenant_id.clone(),
            connector_type,
            instance_id: self.config.instance_id.clone(),
            capabilities: Some(capabilities),
            jwt_token: self.config.auth_token.clone(),
            session_token: String::new(),
            scope: 0,
            instance_metadata: None,
        };

        StreamMessage {
            message: Some(Message::RegisterRequest(register_request)),
        }
    }

    /// Run the message processing loop.
    /// Keepalive heartbeats are handled by the SDK's ConnectorClient automatically.
    async fn run_message_loop(&mut self, mut rx: mpsc::UnboundedReceiver<StreamMessage>) {
        // Proactive JWT refresh: silently refresh the token before it expires.
        // We do NOT reconnect — the existing stream stays alive. The fresh token
        // is stored so that if the stream drops for any reason, the reconnect
        // loop uses a valid token.
        let has_jwt_auth =
            !self.config.auth_token.is_empty() && self.ott_provider.read().await.is_some();
        let refresh_timer = tokio::time::sleep(if has_jwt_auth {
            jwt_refresh_delay(&self.config.auth_token)
        } else {
            // No OTT provider — disable refresh (effectively never fires)
            tokio::time::Duration::from_secs(365 * 86400)
        });
        tokio::pin!(refresh_timer);

        loop {
            if self.shutdown.load(Ordering::SeqCst) {
                tracing::info!("Shutdown requested, exiting message loop");
                return;
            }

            // Check if we need to reconnect with JWT (initial auth only)
            if self.reconnect_with_jwt.load(Ordering::SeqCst) {
                tracing::info!("Reconnect with JWT requested, breaking message loop");
                return;
            }

            tokio::select! {
                biased;

                // Silent JWT refresh — no reconnect, just update the stored token
                _ = &mut refresh_timer, if has_jwt_auth => {
                    tracing::info!("Proactive JWT refresh triggered (silent, no reconnect)");
                    let mut ott_taken = self.ott_provider.write().await.take();
                    let new_delay = if let Some(ref mut ott) = ott_taken {
                        match ott.get_token().await {
                            Ok(new_token) => {
                                let delay = jwt_refresh_delay(&new_token);
                                tracing::info!("JWT refreshed silently (len={})", new_token.len());
                                self.config.auth_token = new_token.clone();
                                self.send_event(ConnectorEvent::CredentialsUpdated {
                                    auth_token: new_token,
                                    api_url: self.derive_matrix_api_url(),
                                });
                                Some(delay)
                            }
                            Err(e) => {
                                tracing::warn!("Proactive JWT refresh failed: {}", e);
                                self.send_event(ConnectorEvent::Log(
                                    TerminalLine::error(format!("JWT refresh failed: {}", e))
                                ));
                                None
                            }
                        }
                    } else {
                        None
                    };
                    // Put the provider back
                    *self.ott_provider.write().await = ott_taken;

                    // Schedule next refresh
                    let next = new_delay.unwrap_or(
                        tokio::time::Duration::from_secs(JWT_REFRESH_RETRY_SECS)
                    );
                    refresh_timer.as_mut().reset(tokio::time::Instant::now() + next);
                }

                msg_opt = rx.recv() => {
                    let Some(msg) = msg_opt else {
                        tracing::info!("Stream closed by server");
                        return;
                    };

                    match msg.message {
                        Some(Message::RegisterResponse(resp)) => {
                            if resp.success {
                                tracing::info!("Registered: {}", resp.connector_arn);
                                self.send_event(ConnectorEvent::Log(
                                    TerminalLine::success("Registered with Strike48")
                                ));
                                if self.config.auth_token.is_empty() {
                                    // No JWT yet — try loading saved OTT credentials.
                                    // This may trigger a reconnect, so await it before
                                    // transitioning to Registered.
                                    self.handle_post_registration_auth().await;
                                }
                                // JWT case: Matrix chat token comes from the __st query param
                                // injected by the Strike48 proxy when the LiveView WebSocket
                                // connects (see handle_ws_open). The session store persists it
                                // across reconnects so ChatPanel doesn't need a fresh fetch.
                                self.send_event(ConnectorEvent::StatusChanged(ConnectorStatus::Registered));
                            } else {
                                tracing::error!("Registration failed: {}", resp.error);

                                // If auth failed (expired/invalid token), clear it and retry
                                if resp.error.contains("expired") || resp.error.contains("invalid") ||
                                   resp.error.contains("auth") || resp.error.contains("jwt") {
                                    tracing::info!("Auth token expired/invalid, clearing and will retry");
                                    self.config.auth_token.clear();
                                    // Clear the OTT provider so we don't try to refresh stale credentials
                                    *self.ott_provider.write().await = None;
                                    // Delete stale saved credentials file to break the retry loop
                                    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                                    let stale = format!(
                                        "{}/.strike48/credentials/pentest-connector_{}.json",
                                        home, self.config.instance_id
                                    );
                                    if std::fs::remove_file(&stale).is_ok() {
                                        tracing::info!("Removed stale credentials file: {}", stale);
                                    }
                                    // Notify main app to clear saved token
                                    self.send_event(ConnectorEvent::CredentialsUpdated {
                                        auth_token: String::new(),
                                        api_url: String::new(),
                                    });
                                    self.send_event(ConnectorEvent::Log(
                                        TerminalLine::info("Token expired, will re-register for approval")
                                    ));
                                    // Don't return - let the reconnect loop handle it
                                    return;
                                }

                                self.send_event(ConnectorEvent::Log(
                                    TerminalLine::error(format!("Registration failed: {}", resp.error))
                                ));
                                self.send_event(ConnectorEvent::StatusChanged(
                                    ConnectorStatus::Error(resp.error)
                                ));
                                return;
                            }
                        }
                        Some(Message::ExecuteRequest(req)) => {
                            tracing::info!("ExecuteRequest: {}", req.request_id);
                            // Check request type: app requests are fast (HTTP proxy), tools can be slow
                            let request: serde_json::Value = serde_json::from_slice(&req.payload).unwrap_or(serde_json::Value::Null);
                            let is_app_request = request.get("path").is_some() && request.get("tool").is_none();

                            if is_app_request {
                                // App request - handle synchronously (needs self.proxy_to_liveview)
                                self.handle_execute(req).await;
                            } else {
                                // Tool request - spawn in background to avoid blocking the message loop
                                // during long-running commands (e.g., nmap scans).
                                // Pass the Arc so the task uses the current sender after any reconnect.
                                let params = tools::ExecuteParams {
                                    tools: self.tools.clone(),
                                    workspace_path: self.workspace_path.clone(),
                                    instance_id: self.config.instance_id.clone(),
                                    matrix_tx: Arc::clone(&self.matrix_tx),
                                    event_tx: self.event_tx.clone(),
                                    aggression_level: self.config.aggression_level,
                                    agent_name: self.config.connector_name.clone(),
                                    matrix_api_url: Some(self.derive_matrix_api_url()),
                                };
                                tokio::spawn(async move {
                                    handle_execute_impl(req, params).await;
                                });
                            }
                        }
                        Some(Message::WsOpenRequest(req)) => {
                            tracing::info!("WsOpenRequest: {} path={}", req.connection_id, req.path);
                            self.handle_ws_open(req).await;
                        }
                        Some(Message::WsFrame(frame)) => {
                            self.handle_ws_frame(frame).await;
                        }
                        Some(Message::WsCloseRequest(req)) => {
                            self.handle_ws_close(req);
                        }
                        Some(Message::CredentialsIssued(creds)) => {
                            tracing::info!("CredentialsIssued received, processing OTT exchange...");
                            self.send_event(ConnectorEvent::StepChanged(ConnectingStep::ExchangingToken));
                            self.handle_credentials_issued(creds).await;
                        }
                        _ => {
                            tracing::debug!("Unhandled message variant");
                        }
                    }
                }
            }
        }
    }

    /// Handle WebSocket open request
    async fn handle_ws_open(&self, req: WebSocketOpenRequest) {
        let connection_id = req.connection_id.clone();

        // Debug: log every WS open request's query string
        tracing::info!(
            "[WsOpen] connection_id={} path={} query_string_len={} query_string={:?}",
            connection_id,
            req.path,
            req.query_string.len(),
            if req.query_string.len() > 200 {
                format!("{}...", &req.query_string[..200])
            } else {
                req.query_string.clone()
            },
        );

        // Extract __st session token from the query string (injected by Strike48 proxy).
        // This is a session-backed Keycloak access token valid for GraphQL calls.
        if !req.query_string.is_empty() {
            let found_st = req.query_string.split('&').find_map(|pair| {
                let (k, v) = pair.split_once('=')?;
                if k == "__st" {
                    Some(v.to_string())
                } else {
                    None
                }
            });
            match &found_st {
                Some(token) if !token.is_empty() => {
                    tracing::info!(
                        "[WsOpen] Captured __st session token from query (len={})",
                        token.len(),
                    );
                    let api_url = self.derive_matrix_api_url();
                    self.send_event(ConnectorEvent::MatrixTokenObtained {
                        auth_token: token.clone(),
                        api_url: api_url.clone(),
                    });

                    // Initialize Matrix HTTP client for API calls (system messages, etc.)
                    if !api_url.is_empty() {
                        let client = pentest_core::matrix::MatrixChatClient::new(&api_url, &token);
                        *self.matrix_client.write().await = Some(client);
                        tracing::info!("Matrix HTTP client initialized");
                    }

                    // Start server-side token refresh loop (idempotent) so
                    // the session token stays valid for GraphQL calls.
                    if !api_url.is_empty() {
                        token_refresh::spawn_token_refresh(api_url);
                    }
                }
                Some(_) => {
                    tracing::warn!("[WsOpen] __st param found but empty");
                }
                None => {
                    tracing::info!("[WsOpen] No __st param in query string");
                }
            }
        } else {
            tracing::info!("[WsOpen] Empty query string — no __st available");
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

        // Connect to the LiveView server over IPC (Unix socket or named pipe)
        let ipc_addr = self
            .liveview_handle
            .as_ref()
            .and_then(|h| h.ipc_addr().cloned());

        let Some(ref addr) = ipc_addr else {
            tracing::error!("No LiveView IPC address available for WebSocket");
            if let Some(tx) = self.matrix_tx.read().await.as_ref() {
                let response = StreamMessage {
                    message: Some(Message::WsOpenResponse(WebSocketOpenResponse {
                        connection_id,
                        success: false,
                        error: "LiveView server not started".to_string(),
                    })),
                };
                let _ = tx.send(response);
            }
            return;
        };

        tracing::info!("Opening WebSocket to backend: {} ({})", ws_url, addr);

        let stream = match crate::ipc::IpcStream::connect(addr).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to connect to IPC endpoint: {}", e);
                if let Some(tx) = self.matrix_tx.read().await.as_ref() {
                    let response = StreamMessage {
                        message: Some(Message::WsOpenResponse(WebSocketOpenResponse {
                            connection_id,
                            success: false,
                            error: format!("Failed to connect: {}", e),
                        })),
                    };
                    let _ = tx.send(response);
                }
                return;
            }
        };

        match tokio_tungstenite::client_async_with_config(&ws_url, stream, None).await {
            Ok((ws_stream, _)) => {
                tracing::info!("WebSocket connected: {}", connection_id);

                let (mut ws_sink, mut ws_source) = ws_stream.split();
                let (to_backend_tx, mut to_backend_rx) = mpsc::channel::<WsMessage>(100);

                self.ws_connections
                    .insert(connection_id.clone(), WsConnectionState { to_backend_tx });

                // Send success response
                if let Some(tx) = self.matrix_tx.read().await.as_ref() {
                    let response = StreamMessage {
                        message: Some(Message::WsOpenResponse(WebSocketOpenResponse {
                            connection_id: connection_id.clone(),
                            success: true,
                            error: String::new(),
                        })),
                    };
                    let _ = tx.send(response);
                }

                // Spawn task to forward messages FROM Strike48 TO Dioxus
                let conn_id_write = connection_id.clone();
                tokio::spawn(async move {
                    while let Some(msg) = to_backend_rx.recv().await {
                        if let Err(e) = ws_sink.send(msg).await {
                            tracing::error!("Error sending to backend WS {}: {}", conn_id_write, e);
                            break;
                        }
                    }
                });

                // Spawn task to forward messages FROM Dioxus TO Strike48
                let conn_id_read = connection_id.clone();
                let matrix_tx = Arc::clone(&self.matrix_tx);
                let ws_connections = self.ws_connections.clone();
                tokio::spawn(async move {
                    while let Some(msg_result) = ws_source.next().await {
                        match msg_result {
                            Ok(msg) => {
                                let (frame_type, data) = match msg {
                                    WsMessage::Text(text) => (
                                        WebSocketFrameType::WebsocketFrameTypeText,
                                        text.as_bytes().to_vec(),
                                    ),
                                    WsMessage::Binary(data) => (
                                        WebSocketFrameType::WebsocketFrameTypeBinary,
                                        data.to_vec(),
                                    ),
                                    WsMessage::Ping(data) => {
                                        (WebSocketFrameType::WebsocketFrameTypePing, data.to_vec())
                                    }
                                    WsMessage::Pong(data) => {
                                        (WebSocketFrameType::WebsocketFrameTypePong, data.to_vec())
                                    }
                                    WsMessage::Close(_) => {
                                        tracing::info!("Backend WS closed: {}", conn_id_read);
                                        break;
                                    }
                                    WsMessage::Frame(_) => continue,
                                };

                                // Encode as base64
                                let encoded_data = BASE64.encode(&data);

                                if let Some(tx) = matrix_tx.read().await.as_ref() {
                                    let frame = StreamMessage {
                                        message: Some(Message::WsFrame(WebSocketFrame {
                                            connection_id: conn_id_read.clone(),
                                            frame_type: frame_type as i32,
                                            data: encoded_data.into_bytes(),
                                        })),
                                    };
                                    if let Err(e) = tx.send(frame) {
                                        tracing::error!("Error sending frame to Strike48: {}", e);
                                        break;
                                    }
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
                if let Some(tx) = self.matrix_tx.read().await.as_ref() {
                    let response = StreamMessage {
                        message: Some(Message::WsOpenResponse(WebSocketOpenResponse {
                            connection_id,
                            success: false,
                            error: format!("Failed to connect: {}", e),
                        })),
                    };
                    let _ = tx.send(response);
                }
            }
        }
    }

    /// Handle WebSocket frame
    async fn handle_ws_frame(&self, frame: WebSocketFrame) {
        if let Some(conn) = self.ws_connections.get(&frame.connection_id) {
            // Decode base64 payload
            let decoded = match String::from_utf8(frame.data.clone()) {
                Ok(base64_str) => BASE64.decode(&base64_str).unwrap_or(frame.data),
                Err(_) => frame.data,
            };

            // Preserve frame type: text frames must arrive as WsMessage::Text
            // so the shell handler can parse JSON commands (input/resize)
            let msg = if frame.frame_type == WebSocketFrameType::WebsocketFrameTypeText as i32 {
                let text = String::from_utf8_lossy(&decoded).to_string();
                WsMessage::Text(text.into())
            } else {
                WsMessage::Binary(decoded.into())
            };

            if let Err(e) = conn.to_backend_tx.send(msg).await {
                tracing::error!("Error forwarding frame to backend: {}", e);
            }
        }
    }

    /// Handle WebSocket close
    fn handle_ws_close(&self, req: WebSocketCloseRequest) {
        tracing::info!("Closing WebSocket: {}", req.connection_id);
        self.ws_connections.remove(&req.connection_id);
    }

    /// Signal shutdown
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(handle) = &self.liveview_handle {
            handle.shutdown();
        }
        // Cleanup workspace
        if self.workspace_path.is_some() {
            workspace::cleanup_workspace(&self.config.instance_id);
        }
    }
}
