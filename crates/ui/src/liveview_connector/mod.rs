//! LiveView Connector with WebSocket Support and Scan State Tracking
//!
//! This module implements a connector that:
//! - Runs a Dioxus LiveView server internally
//! - Proxies HTTP requests to the LiveView server
//! - Proxies WebSocket connections for LiveView interactivity
//! - Executes tools via the tool registry
//! - Tracks active penetration testing scans with real-time state management
//! - Provides REST API for scan monitoring and aggression adjustment
//!
//! Uses the SDK's `ConnectorRunner` with a `PickConnector` (`BaseConnector` impl)
//! that handles tool execution, app proxying, and WebSocket relay. The runner
//! manages connection lifecycle, registration, heartbeat, OTT exchange, and
//! reconnection with exponential backoff.
//!
//! # Scan State Lifecycle
//!
//! Scan state is managed through event-driven updates:
//!
//! 1. **Initialization**: When `begin_scan` tool completes successfully, a `ScanState` is created
//!    containing the conversation ID, agent ID, start time, and current aggression level.
//!
//! 2. **Specialist Tracking**: When `spawn_specialist` tool completes successfully and a specialist
//!    is spawned, a `SpecialistInfo` entry is added to the scan's `active_specialists` map.
//!
//! 3. **Aggression Updates**: When aggression level is changed via REST API (`POST /api/aggression`),
//!    both the connector config and scan state are updated, and Matrix notifications are sent to
//!    active agents.
//!
//! 4. **Persistence**: Scan state is in-memory only and will be lost on connector restart.
//!    This is intentional for the current use case (local development, single sessions).
//!
//! # Thread Safety
//!
//! All shared state uses `Arc<RwLock<T>>` for thread-safe access:
//! - Multiple concurrent reads are allowed
//! - Writes block reads/writes (exclusive access)
//! - `try_write()` is used in event handlers to avoid blocking the event loop

mod api_routes;
mod auth;
mod injections;
pub mod llm_proxy;
mod pick_connector;
mod token_refresh;
mod tools;

use crate::liveview_server::{start_liveview_server, LiveViewConfig, LiveViewHandle};
use dashmap::DashMap;
use pentest_core::config::ConnectorConfig;
use pentest_core::state::ConnectorStatus;
use pentest_core::terminal::TerminalLine;
use pentest_core::tools::ToolRegistry;
use pentest_core::workspace;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message as WsMessage;

pub use self::injections::inject_websocket_shim;

use crate::components::ConnectingStep;

/// Default port for the internal Dioxus LiveView server
const DEFAULT_LIVEVIEW_PORT: u16 = 3030;

/// WebSocket connection state
pub(crate) struct WsConnectionState {
    to_backend_tx: mpsc::Sender<WsMessage>,
}

/// Information about a spawned specialist agent.
///
/// Tracks metadata for a domain-specific specialist agent (web-app, api, binary, ai-security)
/// that was spawned by the Red Team agent during a scan. This information is used to:
///
/// - Display active specialists in the UI and API (`GET /api/status`)
/// - Send aggression change notifications to all active specialists
/// - Track which targets each specialist is analyzing
///
/// # Fields
///
/// - `specialist_type`: Type of specialist (e.g., "web-app", "api", "binary")
/// - `agent_id`: Unique Strike48 agent ID for this specialist
/// - `agent_name`: Human-readable name (e.g., "pentest-connector-web-app")
/// - `targets`: List of URLs/endpoints/binaries this specialist is analyzing
/// - `spawned_at`: Timestamp when the specialist was spawned (serialized as human-readable time)
#[derive(Debug, Clone, serde::Serialize)]
pub struct SpecialistInfo {
    pub specialist_type: String,
    pub agent_id: String,
    pub agent_name: String,
    pub targets: Vec<String>,
    #[serde(with = "humantime_serde")]
    pub spawned_at: std::time::SystemTime,
}

/// Active scan state tracking.
///
/// Represents the state of an active penetration testing scan. This state is:
///
/// - **Created** when the `begin_scan` tool completes successfully
/// - **Updated** when specialists are spawned or aggression level changes
/// - **Queried** via `GET /api/status` for monitoring
/// - **In-memory only** (lost on connector restart)
///
/// # State Management
///
/// This struct is wrapped in `Arc<RwLock<Option<ScanState>>>` for thread-safe access:
///
/// - `None` = No active scan
/// - `Some(ScanState)` = Scan is active
///
/// # Fields
///
/// - `conversation_id`: Strike48 conversation ID (also called scan_id in begin_scan result)
/// - `agent_id`: Red Team agent ID that initiated the scan
/// - `started_at`: Monotonic timestamp for duration calculations (not serialized to JSON)
/// - `started_at_system`: Wall-clock timestamp for display (serialized as human-readable time)
/// - `current_aggression`: Current aggression level (updated via REST API)
/// - `active_specialists`: Map of specialist agent_id → SpecialistInfo for all spawned specialists
///
/// # Serialization
///
/// When serialized to JSON (for `GET /api/status`), timestamps are rendered as human-readable
/// strings using `humantime_serde` (e.g., "2026-04-25T23:45:00Z"). The `started_at` field is
/// skipped (not serializable, only used for duration calculations).
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
    /// Live progress from a running tool (e.g., webwright sidecar step updates).
    ToolProgress {
        tool_name: String,
        step: u32,
        message: String,
        /// Base64-encoded screenshot if available at this step.
        screenshot: Option<String>,
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
    /// SDK client for invoke_capability (artifact uploads, etc). Set when connected.
    pub(crate) event_tx: broadcast::Sender<ConnectorEvent>,
    pub(crate) shutdown: Arc<AtomicBool>,
    pub(crate) liveview_handle: Option<LiveViewHandle>,
    pub(crate) liveview_port: u16,
    /// Active scan state (if a scan is running)
    pub(crate) active_scan: Arc<RwLock<Option<ScanState>>>,
    /// Matrix HTTP client for sending system messages (aggression updates, etc.)
    pub(crate) matrix_client: Arc<RwLock<Option<pentest_core::matrix::MatrixChatClient>>>,
    /// Total specialists spawned across reconnects (persists across ScanState resets)
    pub(crate) total_specialists_spawned: Arc<AtomicUsize>,
    /// Shared handle to the SDK connector runner, populated in `connect_and_run`.
    /// Created up front (empty) so the `/health` route — built in
    /// `start_liveview_server`, BEFORE `connect_and_run` — can hold the SAME Arc and
    /// observe the runner once it exists. `None` until connected (reported as
    /// `status: "starting"`). See `api_routes::HealthState` (pick#295).
    pub(crate) runner: Arc<RwLock<Option<Arc<strike48_connector::ConnectorRunner>>>>,
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
            event_tx,
            shutdown: Arc::new(AtomicBool::new(false)),
            liveview_handle: None,
            liveview_port: DEFAULT_LIVEVIEW_PORT,
            active_scan: Arc::new(RwLock::new(None)),
            matrix_client: Arc::new(RwLock::new(None)),
            total_specialists_spawned: Arc::new(AtomicUsize::new(0)),
            runner: Arc::new(RwLock::new(None)),
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

                // Event-driven scan state tracking
                // When specific tools complete successfully, we update the scan state accordingly
                if *success {
                    // begin_scan completion → Initialize scan state
                    // This creates the root tracking object for the entire scan session
                    if tool_name == "begin_scan" {
                        // Extract conversation_id (scan_id) and agent_id from tool result
                        if let Ok(scan_result) =
                            serde_json::from_value::<serde_json::Value>(result.clone())
                        {
                            if let (Some(conv_id), Some(agent_id)) = (
                                scan_result.get("scan_id").and_then(|v| v.as_str()),
                                result.get("agent_id").and_then(|v| v.as_str()),
                            ) {
                                // Initialize scan state with current config values
                                let scan_state = ScanState {
                                    conversation_id: conv_id.to_string(),
                                    agent_id: agent_id.to_string(),
                                    started_at: std::time::Instant::now(),
                                    started_at_system: std::time::SystemTime::now(),
                                    current_aggression: self.config.aggression_level,
                                    active_specialists: std::collections::HashMap::new(),
                                };

                                // Use try_write() to avoid blocking the event loop
                                // Retry with exponential backoff to ensure scan state is initialized
                                // Spawn as task since send_event is not async
                                let active_scan = Arc::clone(&self.active_scan);
                                let conv_id = conv_id.to_string();
                                let total_specialists = Arc::clone(&self.total_specialists_spawned);
                                tokio::spawn(async move {
                                    let mut retry_count = 0;
                                    let max_retries = 10;
                                    let mut initialized = false;

                                    while retry_count < max_retries {
                                        if let Ok(mut scan_guard) = active_scan.try_write() {
                                            *scan_guard = Some(scan_state.clone());
                                            // Reset specialist counter when new scan starts
                                            total_specialists.store(0, Ordering::SeqCst);
                                            tracing::info!(
                                                "Scan state initialized: conversation={} agent={}",
                                                scan_state.conversation_id,
                                                scan_state.agent_id
                                            );
                                            initialized = true;
                                            break;
                                        } else {
                                            retry_count += 1;
                                            if retry_count < max_retries {
                                                tracing::debug!(
                                                    "Scan state init lock contention, retry {}/{}",
                                                    retry_count,
                                                    max_retries
                                                );
                                                // Exponential backoff: 2ms, 4ms, 8ms, 16ms, 32ms, ...
                                                tokio::time::sleep(
                                                    tokio::time::Duration::from_millis(
                                                        2 << retry_count,
                                                    ),
                                                )
                                                .await;
                                            }
                                        }
                                    }

                                    if !initialized {
                                        tracing::error!(
                                            "CRITICAL: Failed to initialize scan state after {} retries. \
                                             Scan {} will not be trackable via REST API.",
                                            max_retries,
                                            conv_id
                                        );
                                    }
                                });
                            }
                        }
                    // spawn_specialist completion → Track new specialist
                    // This adds the specialist to the scan's active_specialists map
                    } else if tool_name == "spawn_specialist" {
                        // Extract specialist information from tool result
                        if let Ok(spawn_result) =
                            serde_json::from_value::<serde_json::Value>(result.clone())
                        {
                            // Only track if spawn actually succeeded (spawned: true in result)
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
                                    // Defense against hostile agents: limit specialist tracking to prevent memory exhaustion
                                    const MAX_SPECIALISTS_PER_SCAN: usize = 50;
                                    const MAX_TARGETS_PER_SPECIALIST: usize = 1000;

                                    // Truncate target list if excessive (defense against compromised agents)
                                    let mut target_list: Vec<String> = targets
                                        .iter()
                                        .filter_map(|v| v.as_str().map(String::from))
                                        .collect();

                                    if target_list.len() > MAX_TARGETS_PER_SPECIALIST {
                                        tracing::warn!(
                                            "Specialist {} targets truncated from {} to {} (defensive limit)",
                                            agent_id,
                                            target_list.len(),
                                            MAX_TARGETS_PER_SPECIALIST
                                        );
                                        target_list.truncate(MAX_TARGETS_PER_SPECIALIST);
                                    }

                                    let specialist_info = SpecialistInfo {
                                        specialist_type: specialist_type.to_string(),
                                        agent_id: agent_id.to_string(),
                                        agent_name: agent_name.to_string(),
                                        targets: target_list,
                                        spawned_at: std::time::SystemTime::now(),
                                    };

                                    // Add specialist to active scan's specialist map
                                    // Use agent_id as key for easy lookup/updates
                                    // Retry with exponential backoff to ensure specialist is tracked
                                    // Spawn as task since send_event is not async
                                    let active_scan = Arc::clone(&self.active_scan);
                                    let total_specialists =
                                        Arc::clone(&self.total_specialists_spawned);
                                    let agent_id_owned = agent_id.to_string();
                                    tokio::spawn(async move {
                                        let mut retry_count = 0;
                                        let max_retries = 10;
                                        let mut tracked = false;

                                        while retry_count < max_retries {
                                            if let Ok(mut scan_guard) = active_scan.try_write() {
                                                if let Some(ref mut scan) = *scan_guard {
                                                    // Check global specialist limit (persists across reconnects)
                                                    let current_total =
                                                        total_specialists.load(Ordering::SeqCst);
                                                    if current_total >= MAX_SPECIALISTS_PER_SCAN {
                                                        tracing::warn!(
                                                            "Max specialists limit reached ({} total spawned). \
                                                             Specialist {} will not be tracked.",
                                                            current_total,
                                                            agent_id_owned
                                                        );
                                                        break;
                                                    }

                                                    scan.active_specialists.insert(
                                                        agent_id_owned.clone(),
                                                        specialist_info.clone(),
                                                    );
                                                    // Increment global counter (atomic)
                                                    total_specialists
                                                        .fetch_add(1, Ordering::SeqCst);
                                                    tracing::info!(
                                                        "Specialist tracked: type={} agent={} targets={} (total: {}/{})",
                                                        specialist_info.specialist_type,
                                                        agent_id_owned,
                                                        specialist_info.targets.len(),
                                                        current_total + 1,
                                                        MAX_SPECIALISTS_PER_SCAN
                                                    );
                                                    tracked = true;
                                                    break;
                                                } else {
                                                    tracing::warn!(
                                                        "Specialist spawned but no active scan found - specialist will not be tracked"
                                                    );
                                                    break;
                                                }
                                            } else {
                                                retry_count += 1;
                                                if retry_count < max_retries {
                                                    tracing::debug!(
                                                        "Specialist tracking lock contention, retry {}/{}",
                                                        retry_count,
                                                        max_retries
                                                    );
                                                    // Exponential backoff: 2ms, 4ms, 8ms, 16ms, 32ms, ...
                                                    tokio::time::sleep(
                                                        tokio::time::Duration::from_millis(
                                                            2 << retry_count,
                                                        ),
                                                    )
                                                    .await;
                                                }
                                            }
                                        }

                                        if !tracked {
                                            tracing::error!(
                                                "CRITICAL: Failed to track specialist {} after {} retries. \
                                                 Specialist will not appear in /api/status and won't receive aggression updates.",
                                                agent_id_owned,
                                                max_retries
                                            );
                                        }
                                    });
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

        // Unauthenticated /health route (pick#295). Built here so it can hold the
        // shared runner Arc; kept OFF the api router so it never inherits the
        // Bearer-token auth middleware (a readiness probe must work uncredentialed).
        let health_router = api_routes::create_health_route(api_routes::HealthState {
            runner: self.runner.clone(),
        });

        // Start LLM proxy on its own TCP port (webwright in proot needs TCP access).
        // Bind to port 0 to let the OS pick an available port, then store it.
        let llm_state = llm_proxy::LlmProxyState {
            matrix_client: self.matrix_client.clone(),
            conversations: Arc::new(RwLock::new(std::collections::HashMap::new())),
            agent_id: Arc::new(RwLock::new(None)),
            agent_upsert_lock: Arc::new(tokio::sync::Mutex::new(())),
        };
        let llm_proxy_router = llm_proxy::create_llm_proxy_routes(llm_state);
        let llm_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.ok();
        if let Some(listener) = llm_listener {
            let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
            // SAFETY: Called once at startup before any tool execution begins.
            // The webwright tool reads this via std::env::var to discover the proxy port.
            unsafe { std::env::set_var("PICK_LLM_PROXY_PORT", port.to_string()) };
            tracing::info!("LLM proxy listening on http://127.0.0.1:{}", port);
            tokio::spawn(async move {
                if let Err(e) = axum::serve(listener, llm_proxy_router).await {
                    tracing::error!("LLM proxy server error: {}", e);
                }
            });
        } else {
            tracing::warn!("Failed to start LLM proxy (could not bind TCP port)");
        }

        // Merge API routes + the health route with extra routes
        let combined_routes = extra_routes.merge(api_routes_router).merge(health_router);

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

    /// Connect to Strike48 and run the connector using the SDK's `ConnectorRunner`.
    ///
    /// The runner handles: connection, reconnection with exponential backoff,
    /// registration (built from `PickConnector`'s `BaseConnector` impl),
    /// keepalive heartbeats, OTT exchange (CredentialsIssued), session tokens,
    /// and message dispatch to `execute_with_context` / `handle_ws_*`.
    pub async fn connect_and_run(&mut self) -> Result<(), String> {
        use strike48_connector::ConnectorRunner;

        self.send_event(ConnectorEvent::StatusChanged(ConnectorStatus::Connecting));
        self.send_event(ConnectorEvent::StepChanged(ConnectingStep::Connecting));
        self.send_event(ConnectorEvent::Log(TerminalLine::info(format!(
            "Connecting to {}...",
            self.config.host
        ))));

        tracing::info!(
            "[ConnectAndRun] auth_token from config: len={} empty={}",
            self.config.auth_token.len(),
            self.config.auth_token.is_empty(),
        );

        // Pre-connect reachability probe: fast-fail on obviously bad URLs
        // (DNS miss, TLS refused, connect timeout) before the SDK spins up a
        // full runner + auto-reconnect loop. Without this, a typo like
        // `https://discoball.strike48.engineering/` leaves the UI stuck on
        // the connecting spinner with no feedback (pick#223). Returning Err
        // here lets the caller populate its `connect_error` banner; we skip
        // emitting a `Disconnected` status event so we don't race the
        // caller's `Error(_)` set that steers the UI back to the form.
        if let Err(e) = probe_host_reachable(&self.config.host).await {
            self.send_event(ConnectorEvent::Log(TerminalLine::error(e.clone())));
            return Err(e);
        }

        // Build the SDK config from our pentest_core config
        let mut sdk_config = self.config.to_sdk_config();

        // Report local host interfaces for infrastructure self-exclusion. The
        // orchestrator reads `host_interfaces` from the registration's
        // InstanceMetadata (the SDK forwards `config.metadata` there) so it
        // can exclude this connector's host from engagement scanning (#2274).
        // Previously injected in the hand-rolled registration message; the SDK
        // ConnectorRunner migration moved the injection point here.
        // `get_network_interfaces` is the cross-platform accessor on the
        // PlatformProvider abstraction (desktop/android/ios); the previous
        // desktop-only `desktop::get_local_ipv4_addresses` did not compile on
        // mobile. Filter to non-loopback IPv4 to match the exclusion set the
        // orchestrator expects.
        use pentest_platform::SystemInfo;
        let host_ips: Vec<String> = pentest_platform::get_platform()
            .get_network_interfaces()
            .await
            .unwrap_or_default()
            .into_iter()
            .flat_map(|iface| iface.ip_addresses)
            .filter(|ip| {
                ip.parse::<std::net::IpAddr>()
                    .map(|addr| addr.is_ipv4() && !addr.is_loopback())
                    .unwrap_or(false)
            })
            .collect();
        if !host_ips.is_empty() {
            tracing::info!("Reporting host interfaces for exclusion: {:?}", host_ips);
            sdk_config
                .metadata
                .insert("host_interfaces".to_string(), host_ips.join(","));
        }

        // Resolve the IPC address from the LiveView handle (if started)
        let ipc_addr: Arc<RwLock<Option<crate::ipc::IpcAddr>>> = Arc::new(RwLock::new(
            self.liveview_handle
                .as_ref()
                .and_then(|h| h.ipc_addr().cloned()),
        ));

        // Build the PickConnector that implements BaseConnector
        let pick_connector = Arc::new(pick_connector::PickConnector {
            tools: self.tools.clone(),
            workspace_path: self.workspace_path.clone(),
            event_tx: self.event_tx.clone(),
            ws_connections: self.ws_connections.clone(),
            matrix_client: self.matrix_client.clone(),
            connector_name: self.config.connector_name.clone(),
            instance_id: self.config.instance_id.clone(),
            aggression_level: Arc::new(RwLock::new(self.config.aggression_level)),
            ipc_addr: ipc_addr.clone(),
            // Share the SAME runner Arc the /health route holds (self.runner), so the
            // write below populates it for both PickConnector's invoke_capability AND
            // the health handler. Starts None → /health reports "starting" until set.
            runner: self.runner.clone(),
            matrix_api_url: self.derive_matrix_api_url(),
        });

        // Create the ConnectorRunner — it manages connection lifecycle, auth,
        // registration, keepalive, OTT exchange, and reconnection.
        let runner = Arc::new(ConnectorRunner::new(sdk_config, pick_connector.clone()));

        // Give the PickConnector a reference to the runner so execute_with_context
        // can call invoke_capability for artifact uploads.
        *pick_connector.runner.write().await = Some(runner.clone());

        // Get shutdown handle so we can stop the runner from our shutdown method
        let shutdown_handle = runner.shutdown_handle();
        let shutdown_flag = self.shutdown.clone();

        // Spawn a watcher that triggers the runner's shutdown when our local
        // shutdown flag is set (e.g. from LiveViewConnector::shutdown())
        tokio::spawn(async move {
            loop {
                if shutdown_flag.load(Ordering::SeqCst) {
                    shutdown_handle.shutdown();
                    break;
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });

        // Emit credentials event for UI if we already have an auth token
        if !self.config.auth_token.is_empty() {
            self.send_event(ConnectorEvent::CredentialsUpdated {
                auth_token: self.config.auth_token.clone(),
                api_url: self.derive_matrix_api_url(),
            });
        }

        // The SDK runner emits no user-facing events, so we emit Registered
        // once we see the first successful execute (or WS open). For now, emit
        // a best-effort Registered event after a short delay to indicate the
        // runner has started and is handling registration internally.
        //
        // We also probe the runner's `get_stats()` at that point and log a
        // clear verdict (search: "[Connector]") so an operator can tell "the
        // WS came up" from "still trying" without hunting for the SDK's own
        // `Registered successfully` line in a fast-scrolling log. `running`
        // plus a non-null `last_connected_at_ms` is the strongest cheap signal
        // that the transport actually established; `reconnection_attempts` and
        // `last_disconnect_reason` explain a stuck connector at a glance.
        let event_tx_clone = self.event_tx.clone();
        let runner_probe = runner.clone();
        tokio::spawn(async move {
            // Give the runner time to connect and register
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            let stats = runner_probe.get_stats().await;
            let running = stats
                .get("running")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let ever_connected = stats
                .get("last_connected_at_ms")
                .map(|v| !v.is_null())
                .unwrap_or(false);
            if running && ever_connected {
                tracing::info!(
                    "[Connector] transport up 3s after startup: reconnects={} disconnects={} \
                     heartbeat_rtt_last_ms={}",
                    stats
                        .get("reconnection_attempts")
                        .cloned()
                        .unwrap_or_default(),
                    stats.get("total_disconnects").cloned().unwrap_or_default(),
                    stats
                        .get("heartbeat_rtt_last_ms")
                        .cloned()
                        .unwrap_or_default(),
                );
            } else {
                tracing::warn!(
                    "[Connector] transport NOT established 3s after startup \
                     (running={} ever_connected={} last_disconnect_reason={}). Check host \
                     reachability, TLS/cert settings, and auth token; the runner keeps retrying \
                     with backoff.",
                    running,
                    ever_connected,
                    stats
                        .get("last_disconnect_reason")
                        .cloned()
                        .unwrap_or_default(),
                );
            }
            let _ = event_tx_clone.send(ConnectorEvent::StatusChanged(ConnectorStatus::Registered));
        });

        // One-time startup summary. The SDK runner logs its registration/OTT/
        // keepalive internals at debug and emits no user-facing events, so at
        // `info` there is no single line confirming *what* this connector is
        // trying to be. Emit a compact, greppable banner (search: "[Connector]")
        // so an operator staring at a fast-scrolling poll log can confirm the
        // host, tenant, identity, and whether an auth token is present without
        // reconstructing it from a dozen debug lines.
        tracing::info!(
            "[Connector] starting: host={} tenant={} instance_id={} connector_name={} \
             matrix_api_url={} auth_token={} aggression={:?}",
            self.config.host,
            self.config.tenant_id,
            self.config.instance_id,
            self.config.connector_name,
            self.derive_matrix_api_url(),
            if self.config.auth_token.is_empty() {
                "absent"
            } else {
                "present"
            },
            self.config.aggression_level,
        );

        // Run the connector — this blocks until shutdown or non-recoverable error
        match runner.run().await {
            Ok(()) => {
                tracing::info!("ConnectorRunner exited cleanly");
            }
            Err(e) => {
                tracing::error!("ConnectorRunner error: {}", e);
                self.send_event(ConnectorEvent::Log(TerminalLine::error(format!(
                    "Connector error: {}",
                    e
                ))));
            }
        }

        self.send_event(ConnectorEvent::StatusChanged(ConnectorStatus::Disconnected));
        Ok(())
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

/// Fast reachability check against the configured Strike48 host.
///
/// Bounded TCP connect so a typo like `wss://discoball.strike48.engineering`
/// fails immediately with a clear message instead of leaving the UI stuck on
/// the connecting spinner while the SDK retries (pick#223). TLS-level
/// failures still surface through the SDK's own WebSocket handshake, so we
/// deliberately don't re-probe TLS here — one round-trip, one error path.
async fn probe_host_reachable(host: &str) -> Result<(), String> {
    const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(6);

    let (hostname, port) = ConnectorConfig::split_authority(host)?;
    let target = format!("{}:{}", hostname, port);

    match tokio::time::timeout(CONNECT_TIMEOUT, tokio::net::TcpStream::connect(&target)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(format!(
            "Cannot reach {}: {}. Check the URL and your network connection.",
            target, e
        )),
        Err(_) => Err(format!(
            "Timed out connecting to {} after {}s. Verify the URL is reachable.",
            target,
            CONNECT_TIMEOUT.as_secs()
        )),
    }
}
