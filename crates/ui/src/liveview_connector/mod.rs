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

    /// Resolve the tenant a One-Time Token binds this connector to, performing the
    /// OTT exchange up-front so the tenant is known before registration.
    ///
    /// Returns `None` whenever there is nothing to adopt — no OTT in the
    /// environment, a cert-manager/direct-config deployment, or an exchange that
    /// yielded no usable tenant. Callers keep their existing `tenant_id` then, so
    /// the non-PLG paths (explicit `STRIKE48_TENANT`, k8s SA, post-approval) behave
    /// exactly as before.
    ///
    /// DELIBERATELY SCOPED TO THE `STRIKE48_REGISTRATION_TOKEN` ENV CARRIER.
    /// Exchanging here consumes the OTT (single-use), so the runner's own
    /// `initialize_auth` must not then exchange it a second time — it would get a
    /// 401 and abort a connector that is otherwise fine. The only way to suppress
    /// that second attempt is to unset the variable the SDK gates `has_ott()` on,
    /// which is possible for the env carrier and NOT for the file carriers
    /// (`STRIKE48_REGISTRATION_TOKEN_FILE`, `/var/run/secrets/matrix/...`, i.e. the
    /// chart/k8s flow). So a file-carried OTT is left entirely to the SDK: it hits
    /// the same upstream tenant bug, but those deployments pass an explicit tenant,
    /// and intervening without being able to neutralize the carrier would turn a
    /// working flow into a hard failure.
    async fn resolve_ott_tenant(connector_type: &str, instance_id: &str) -> Option<String> {
        use strike48_connector::OttProvider;

        // Read the OTT from the one carrier we can neutralize (see above). Absent
        // means "not the PLG flow" — nothing to do.
        let ott = match std::env::var("STRIKE48_REGISTRATION_TOKEN") {
            Ok(ott) => ott,
            // Distinguish the two VarError cases: absent is the ordinary
            // not-PLG case and stays silent, but non-UTF8 is a real
            // misconfiguration that would otherwise look identical.
            Err(std::env::VarError::NotPresent) => return None,
            Err(e) => {
                tracing::warn!("STRIKE48_REGISTRATION_TOKEN is set but unreadable ({e})");
                return None;
            }
        };
        let trimmed = ott.trim();
        if trimmed.is_empty() {
            return None;
        }
        // Normalize the carrier in place if it was padded. The SDK does NOT trim
        // this variable — load_ott passes it to parse_ott raw (ott_provider.rs:253),
        // unlike the FILE carrier, which is trimmed (:281). So a hand-edited
        // `.env.plg` with a stray space sends the padded token, 401s, and lands in
        // the saved-credentials fallback below looking like a routine spent-token
        // restart. Writing the trimmed value back means our exchange and the SDK's
        // (should it run) both see the same token.
        //
        // SAFETY: as with the remove_var calls below — this variable has no
        // concurrent reader.
        if trimmed.len() != ott.len() {
            tracing::warn!(
                "STRIKE48_REGISTRATION_TOKEN had surrounding whitespace; using the \
                 trimmed value (the SDK would otherwise send it padded and get a 401)"
            );
            unsafe { std::env::set_var("STRIKE48_REGISTRATION_TOKEN", trimmed) };
        }

        let mut provider = OttProvider::new(
            Some(connector_type.to_string()),
            Some(instance_id.to_string()),
        );

        // Priority 1 in the SDK is direct config (cert-manager). Defer to it and do
        // not consume the OTT, so that path is unchanged.
        if provider.has_direct_config() {
            // Both a direct config AND an OTT were supplied, which is
            // contradictory: the OTT will be ignored entirely. Say which one wins,
            // because the operator may not know a direct config is even present —
            // load_direct_config auto-discovers /var/run/secrets/matrix/*.pem with
            // no env var set (ott_provider.rs:148-165), so an OTT handed to a pod
            // that already has a mounted cert silently does nothing.
            tracing::warn!(
                "both a direct (cert-manager) config and STRIKE48_REGISTRATION_TOKEN \
                 are present; the direct config wins and the OTT will be ignored"
            );
            return None;
        }

        // A fresh OTT must still WIN over saved credentials, mirroring the SDK's own
        // precedence: re-attaching with a newly minted token is how an operator
        // rebinds this connector to a different tenant. Preferring the saved file
        // would silently keep the OLD tenant.
        match provider
            .register_with_ott(connector_type, Some(instance_id))
            .await
        {
            Ok(credentials) => {
                // Consumed — stop the runner from spending it again. Its
                // initialize_auth will fall through to the credentials just saved
                // by register_with_ott, which carry the same identity.
                //
                // SAFETY: no concurrent env access can interleave with this call.
                // set_var/remove_var mutate the shared `environ` array and race a
                // concurrent getenv on ANY variable — that is UB in every edition
                // (it is precisely why edition 2024 made these fns `unsafe`), so it
                // is NOT made safe by the fact that other readers touch a different
                // variable. What makes it safe here is the executor model: this runs
                // on Dioxus's single-threaded cooperative executor (the desktop
                // `spawn`), where the synchronous getenv/setenv can never interleave,
                // and the headless (`#[tokio::main]`) path spawns no concurrent env
                // reader during resolve_ott_tenant. This only becomes a real race if
                // these tasks are moved onto a multi-threaded executor alongside a
                // concurrent env reader.
                unsafe { std::env::remove_var("STRIKE48_REGISTRATION_TOKEN") };

                if credentials.tenant_id.trim().is_empty() {
                    // Unrecoverable, and loud on purpose. The exchange SUCCEEDED,
                    // so the OTT is spent and cannot be retried, and there is no
                    // tenant to adopt — the runner will register with the
                    // configured tenant, which on PLG is the "default" literal, and
                    // studio rejects that as :tenant_mismatch. A warn! here would
                    // bury the cause of a connector that never comes up.
                    tracing::error!(
                        "OTT exchange succeeded but returned no tenant_id (client_id={}); \
                         the token is now spent and registration will use the configured \
                         tenant, which studio rejects as :tenant_mismatch. Mint a new OTT \
                         and check the register-with-ott response.",
                        credentials.client_id,
                    );
                    return None;
                }
                tracing::info!(
                    "OTT exchange succeeded: client_id={} tenant_id={}",
                    credentials.client_id,
                    credentials.tenant_id,
                );
                Some(credentials.tenant_id)
            }
            Err(e) => {
                // The OTT is single-use with a short TTL, so the overwhelmingly
                // common failure is a RESTART: the token in the environment was
                // already spent by the previous run. The SDK treats that as fatal
                // (its OTT branch runs before saved credentials and propagates the
                // error), which bricks a `restart: unless-stopped` container until a
                // human mints a new token. Saved credentials from the earlier
                // exchange are still valid, so fall back to them and let the run
                // continue.
                match provider.load_saved_credentials(connector_type, Some(instance_id)) {
                    Some(credentials) => {
                        // Neutralize the token so the runner reaches the same saved
                        // credentials instead of re-failing on it. This is
                        // deliberately NOT conditional on the error variant, even
                        // though the SDK distinguishes them (ConnectionError for
                        // transport, InvalidConfig for a 401 — ott_provider.rs:358
                        // and :369). Keeping the carrier on a transport failure
                        // would hand it back to the runner, whose
                        // `register_with_ott(...).await?` (connector.rs:2116)
                        // propagates and returns BEFORE load_saved_credentials
                        // (:2139) — i.e. exactly the restart-brick this function
                        // exists to prevent, just triggered by a blip instead of a
                        // spent token. Nothing is lost: remove_var edits only this
                        // PROCESS's environment, and compose re-supplies the value
                        // from .env.plg on the next start, so a genuinely unspent
                        // token is still there to retry with.
                        //
                        // SAFETY: as above — this variable has no concurrent reader.
                        unsafe { std::env::remove_var("STRIKE48_REGISTRATION_TOKEN") };
                        // warn!, not info!: this run is NOT bound by the token the
                        // operator supplied. A 401 cannot distinguish "already
                        // spent" (routine restart) from "wrong or expired token",
                        // and a transport failure means it was never even sent — so
                        // if the intent was to REBIND to a new tenant, this run
                        // silently did not do that. Name the adopted tenant so that
                        // is checkable from the log alone.
                        tracing::warn!(
                            "OTT exchange failed ({e}); continuing on SAVED credentials \
                             for client_id={} tenant_id={}. This run is bound to the \
                             SAVED tenant, not to the supplied token: if you meant to \
                             rebind, mint a fresh OTT and confirm the tenant in \
                             StrikeHub -> Devices.",
                            credentials.client_id,
                            credentials.tenant_id,
                        );
                        (!credentials.tenant_id.trim().is_empty()).then_some(credentials.tenant_id)
                    }
                    None => {
                        // No prior credentials: this is a genuinely bad or expired
                        // first-attach token. Leave the variable in place so the SDK
                        // performs its own exchange and surfaces the error through
                        // its normal reporting path.
                        tracing::warn!(
                            "OTT exchange failed and no saved credentials are available: {e}"
                        );
                        None
                    }
                }
            }
        }
    }

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

        // PLG/StrikeHub (matrix#3519): adopt the tenant the OTT is bound to.
        //
        // The SDK runner does the OTT exchange itself (initialize_auth Priority 2)
        // but writes back ONLY auth_token — it never copies the returned
        // `Credentials.tenant_id` into its config. Registration therefore still
        // sends `config.tenant_id`, which on PLG is the "default" literal, because
        // no STRIKE48_TENANT is knowable ahead of time (the personal tenant is
        // minted at login). Studio compares the JWT's tenant against that
        // self-declared value and rejects the mismatch with
        // {:auth_invalid, :tenant_mismatch}, so the connector never registers even
        // though the exchange succeeded and issued correct credentials.
        //
        // Resolving it here — before the runner is constructed — is what makes the
        // tenant reach `build_register_request`. See `resolve_ott_tenant` for the
        // second defect this also closes (restart with a spent OTT).
        if let Some(tenant_id) =
            Self::resolve_ott_tenant(&self.config.connector_name, &self.config.instance_id).await
        {
            if tenant_id != sdk_config.tenant_id {
                tracing::info!(
                    "[Connector] adopting OTT-bound tenant: {} -> {}",
                    sdk_config.tenant_id,
                    tenant_id,
                );
            }
            sdk_config.tenant_id = tenant_id.clone();
            // Keep our own config in step, not just the SDK's copy. `self.config`
            // is what the "[Connector] starting:" banner reports and — more than
            // cosmetically — what `session::set_tenant_id` publishes for the Matrix
            // chat session (see `send_event`). Leaving it as the "default" literal
            // would make the banner misreport the tenant an operator is trying to
            // confirm, and point the chat session at the wrong one.
            self.config.tenant_id = tenant_id;
        }

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
            .flat_map(|iface| iface.ip_strings())
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

        // Load operator-provided test identities for differential-authz tools
        // (pick#162) once at startup. A missing file yields an empty store; a
        // malformed file is logged and treated as empty rather than blocking
        // connector startup (the operator can fix the file and reconnect).
        //
        // Resolve the path explicitly (rather than via `load_default_identities`)
        // so the chosen file is logged at startup. The precedence is
        // env `PICK_IDENTITIES_FILE` > a cwd `identities.json` > the settings
        // dir; preferring cwd is a launch-from-unexpected-directory foot-gun, so
        // making the resolved path auditable is deliberate (#317 finding #8).
        let identities_path = pentest_core::identity::identities_file_path();
        tracing::info!(
            "Resolved test-identities file path: {}",
            identities_path.display()
        );
        let loaded_identities =
            match pentest_core::identity::load_identities_from_file(&identities_path) {
                Ok(loaded) => {
                    if !loaded.store.is_empty() {
                        tracing::info!(
                            "Loaded {} operator identit{} for differential-authz testing",
                            loaded.store.len(),
                            if loaded.store.len() == 1 { "y" } else { "ies" }
                        );
                    }
                    loaded
                }
                Err(e) => {
                    // A malformed identities file (bad JSON, unknown role, or a
                    // non-anonymous identity with no credential) must NOT degrade
                    // to zero identities: specialists would still run the
                    // differential-authz prompts and report "no broken access
                    // control" when nothing was actually tested. Refuse to start
                    // (#317 review #3). A *missing* file is not an error -
                    // `load_identities_from_file` returns empty for NotFound - so
                    // only genuine corruption reaches this arm.
                    return Err(format!(
                        "refusing to start: identities file {} is unreadable or malformed: {e}. \
                         Fix or remove it (a missing file is fine and means no test identities).",
                        identities_path.display()
                    ));
                }
            };

        // Advertise the identity *references* (label/role/tenant only, no
        // secrets) to the Red Team orchestrator via InstanceMetadata, the same
        // mechanism as `host_interfaces` above (matrix#2274). The orchestrator
        // reads this to pass identities to spawn_specialist (matrix#3354). The
        // session material stays connector-side in the store below.
        if let Some(value) =
            pentest_core::identity::references_metadata_value(&loaded_identities.references)
        {
            sdk_config.metadata.insert(
                pentest_core::identity::IDENTITIES_METADATA_KEY.to_string(),
                value,
            );
        }

        let identities = loaded_identities.store;

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
            identities: Arc::new(identities),
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

        // Kick off on-device tool provisioning in the background (Android
        // downloads/extracts the BlackArch proot rootfs; no-op on other
        // platforms). Doing it here — at connect — means external tools are
        // ready by the time the user runs a scan, instead of triggering a
        // ~200MB download synchronously inside the first tool call's timeout
        // (which left Android advertising 114 tools that all failed to run).
        // Fire-and-forget; progress is observable via
        // pentest_platform::tools_provisioning_state().
        pentest_platform::provision_tools();

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

#[cfg(test)]
mod ott_tenant_tests {
    use super::*;

    /// `resolve_ott_tenant` reads and MUTATES process-global environment, and
    /// steers `OttProvider` by overriding `HOME` (the SDK hardcodes
    /// `$HOME/.strike48/credentials` with no injection point). Tests in one
    /// binary share that process, so they must not overlap.
    ///
    /// This is `tokio::sync::Mutex`, not `std::sync::Mutex`: the guard is held
    /// across the `.await` on `resolve_ott_tenant` (that await is exactly the
    /// window the env must stay stable through), which `clippy::await_holding_lock`
    /// correctly rejects for a blocking guard. The async mutex also has no
    /// poisoning to work around.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn env_lock() -> tokio::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().await
    }

    /// Saves every variable this code path touches and restores it on Drop, so a
    /// failing assertion cannot leak state into the next test.
    struct EnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        const VARS: [&'static str; 8] = [
            "STRIKE48_REGISTRATION_TOKEN",
            "STRIKE48_REGISTRATION_TOKEN_FILE",
            "STRIKE48_API_URL",
            "STRIKE48_CLIENT_ID",
            "STRIKE48_AUTH_URL",
            // Overriding HOME is NOT sufficient to contain the SDK's on-disk
            // writes: it reads STRIKE48_KEYS_DIR FIRST and only falls back to
            // `$HOME/.strike48/keys` (ott_provider.rs:99). A developer with that
            // var exported would have these tests generate and leave behind a real
            // EC keypair in their actual keys directory.
            "STRIKE48_KEYS_DIR",
            // Third leg of the direct-config (cert-manager) triple alongside
            // CLIENT_ID/AUTH_URL (ott_provider.rs:149). Clearing CLIENT_ID alone
            // already forces has_direct_config() to None, but this test module
            // deliberately EXERCISES that branch, so the var it keys on has to be
            // controllable rather than inherited from the shell.
            "STRIKE48_PRIVATE_KEY_PATH",
            "HOME",
        ];

        fn new() -> Self {
            let saved = Self::VARS
                .iter()
                .map(|k| (*k, std::env::var(k).ok()))
                .collect();
            // Start from a known-clean slate: a stray OTT or direct-config var in
            // the developer's shell would otherwise change which branch runs.
            for k in Self::VARS {
                unsafe { std::env::remove_var(k) };
            }
            Self { saved }
        }

        fn set(&self, key: &str, value: &str) {
            // SAFETY: all env access in these tests is serialized by ENV_LOCK,
            // and the values are restored by Drop.
            unsafe { std::env::set_var(key, value) };
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                match value {
                    Some(v) => unsafe { std::env::set_var(key, v) },
                    None => unsafe { std::env::remove_var(key) },
                }
            }
        }
    }

    const CONNECTOR_TYPE: &str = "pentest-connector";
    const INSTANCE_ID: &str = "pick-plg-test";
    const TENANT: &str = "019fd8c8-1fe0-723f-af59-d6da14eb15fe";

    /// Plant a saved-credentials file where `OttProvider` will look for it, i.e.
    /// `$HOME/.strike48/credentials/<connector_type>_<instance_id>.json`. Field
    /// names are the SDK's SERDE-RENAMED wire names (`keycloak_url`, not
    /// `auth_url`) — using the Rust field names would silently fail to parse and
    /// make the fallback look broken.
    fn plant_credentials(home: &std::path::Path, tenant_id: &str) {
        let dir = home.join(".strike48/credentials");
        std::fs::create_dir_all(&dir).expect("create credentials dir");
        let body = format!(
            r#"{{"client_id":"matrix:connector:local:{tenant_id}:{CONNECTOR_TYPE}:{INSTANCE_ID}",
                 "keycloak_url":"https://auth.invalid/realms/plg",
                 "tenant_id":"{tenant_id}"}}"#
        );
        std::fs::write(
            dir.join(format!("{CONNECTOR_TYPE}_{INSTANCE_ID}.json")),
            body,
        )
        .expect("write credentials");
    }

    /// An origin that is guaranteed to fail the OTT exchange fast, without
    /// reaching the network: port 0 is not connectable.
    const UNREACHABLE_API: &str = "http://127.0.0.1:0";

    /// Bug 3b regression guard: a SPENT OTT plus valid saved credentials must
    /// recover, not hard-fail.
    ///
    /// The SDK tries the OTT before saved credentials and propagates the error,
    /// so with `restart: unless-stopped` and a spent token left in `.env.plg`,
    /// every restart bricked the connector. Two assertions matter equally: the
    /// saved tenant is adopted, AND the spent carrier is REMOVED — without the
    /// removal the SDK runner would re-spend the same dead token and abort a
    /// connector that is otherwise fine.
    #[tokio::test]
    async fn spent_ott_falls_back_to_saved_credentials_and_clears_the_carrier() {
        let _lock = env_lock().await;
        let guard = EnvGuard::new();
        let home = tempfile::tempdir().expect("tempdir");
        plant_credentials(home.path(), TENANT);

        guard.set("HOME", home.path().to_str().expect("utf8 tempdir"));
        guard.set("STRIKE48_API_URL", UNREACHABLE_API);
        guard.set("STRIKE48_REGISTRATION_TOKEN", "ott_alreadyspent");

        let resolved = LiveViewConnector::resolve_ott_tenant(CONNECTOR_TYPE, INSTANCE_ID).await;

        assert_eq!(
            resolved.as_deref(),
            Some(TENANT),
            "a spent OTT with saved credentials on disk must adopt the saved tenant"
        );
        assert!(
            std::env::var("STRIKE48_REGISTRATION_TOKEN").is_err(),
            "the spent carrier must be removed so the SDK runner does not re-spend it"
        );
    }

    /// The other half of the same branch: exchange fails and there are NO saved
    /// credentials (a genuinely bad first-attach token). Then the variable must
    /// be LEFT IN PLACE, so the SDK performs its own exchange and reports the
    /// error through its normal path. Clearing it here would swallow the failure.
    #[tokio::test]
    async fn failed_exchange_without_saved_credentials_preserves_the_carrier() {
        let _lock = env_lock().await;
        let guard = EnvGuard::new();
        // Empty HOME: no credentials file to fall back to.
        let home = tempfile::tempdir().expect("tempdir");

        guard.set("HOME", home.path().to_str().expect("utf8 tempdir"));
        guard.set("STRIKE48_API_URL", UNREACHABLE_API);
        guard.set("STRIKE48_REGISTRATION_TOKEN", "ott_bogus");

        let resolved = LiveViewConnector::resolve_ott_tenant(CONNECTOR_TYPE, INSTANCE_ID).await;

        assert_eq!(
            resolved, None,
            "with no saved credentials there is no tenant to adopt"
        );
        assert_eq!(
            std::env::var("STRIKE48_REGISTRATION_TOKEN").as_deref(),
            Ok("ott_bogus"),
            "the carrier must survive so the SDK surfaces the real error itself"
        );
    }

    /// Non-PLG deployments (explicit `STRIKE48_TENANT`, k8s SA, post-approval)
    /// must be untouched: no OTT means return `None` immediately, before any
    /// provider is constructed or any credentials file is consulted. Saved
    /// credentials are planted here deliberately — returning `Some` would prove
    /// the function had adopted a tenant on a path that never asked for one.
    #[tokio::test]
    async fn no_ott_returns_none_without_consulting_credentials() {
        let _lock = env_lock().await;
        let guard = EnvGuard::new();
        let home = tempfile::tempdir().expect("tempdir");
        plant_credentials(home.path(), TENANT);

        guard.set("HOME", home.path().to_str().expect("utf8 tempdir"));

        let resolved = LiveViewConnector::resolve_ott_tenant(CONNECTOR_TYPE, INSTANCE_ID).await;

        assert_eq!(
            resolved, None,
            "absent an OTT this must be a no-op, even with credentials on disk"
        );
    }

    /// An empty or whitespace-only carrier is treated as absent. `env::var`
    /// returns `Ok("")` for `FOO=`, so a bare `.ok()?` would fall through and
    /// attempt an exchange with an empty token.
    #[tokio::test]
    async fn blank_ott_is_treated_as_absent() {
        let _lock = env_lock().await;
        let guard = EnvGuard::new();
        let home = tempfile::tempdir().expect("tempdir");
        plant_credentials(home.path(), TENANT);

        guard.set("HOME", home.path().to_str().expect("utf8 tempdir"));
        guard.set("STRIKE48_REGISTRATION_TOKEN", "   ");

        let resolved = LiveViewConnector::resolve_ott_tenant(CONNECTOR_TYPE, INSTANCE_ID).await;

        assert_eq!(
            resolved, None,
            "a blank carrier must not trigger an exchange"
        );
    }

    /// A FRESH OTT must WIN over saved credentials — the precedence that makes
    /// re-attaching with a newly minted token rebind this connector to a new
    /// tenant. Checking saved credentials first would silently keep the OLD
    /// tenant, and no other test in this module catches that: every other case
    /// drives the exchange to failure, where both orderings agree.
    ///
    /// Needs a real HTTP round trip (the SDK's `register_with_ott` has no seam),
    /// so serve one canned `register-with-ott` response from a local socket.
    #[tokio::test]
    async fn fresh_ott_wins_over_saved_credentials() {
        const NEW_TENANT: &str = "019fd999-aaaa-7000-bbbb-ccccddddeeee";

        // Bind first so the port is known before the env is set.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub");
        let port = listener.local_addr().expect("addr").port();

        let app = axum::Router::new().route(
            "/api/connectors/register-with-ott",
            axum::routing::post(move || async move {
                axum::Json(serde_json::json!({
                    "client_id": format!("matrix:connector:local:{NEW_TENANT}:{CONNECTOR_TYPE}:{INSTANCE_ID}"),
                    "keycloak_url": "https://auth.invalid/realms/plg",
                    "tenant_id": NEW_TENANT,
                }))
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        // The carrier must be sampled INSIDE the lock+guard scope: EnvGuard's Drop
        // restores the original value, so reading it after the block would observe
        // the restored state and assert nothing about what the function did.
        let (resolved, carrier_after) = {
            let _lock = env_lock().await;
            let guard = EnvGuard::new();
            let home = tempfile::tempdir().expect("tempdir");
            // Saved credentials for a DIFFERENT (old) tenant are present.
            plant_credentials(home.path(), TENANT);

            guard.set("HOME", home.path().to_str().expect("utf8 tempdir"));
            guard.set("STRIKE48_API_URL", &format!("http://127.0.0.1:{port}"));
            guard.set("STRIKE48_REGISTRATION_TOKEN", "ott_freshlyminted");

            let resolved = LiveViewConnector::resolve_ott_tenant(CONNECTOR_TYPE, INSTANCE_ID).await;
            (resolved, std::env::var("STRIKE48_REGISTRATION_TOKEN"))
        };
        server.abort();

        assert_eq!(
            resolved.as_deref(),
            Some(NEW_TENANT),
            "a fresh OTT must rebind to the exchanged tenant, not the saved one"
        );
        assert_ne!(
            resolved.as_deref(),
            Some(TENANT),
            "adopting the saved tenant means the OTT was not exchanged first"
        );
        // The SUCCESS path's carrier removal, which is the whole reason this
        // function is scoped to the env carrier: the exchange consumed the
        // single-use OTT, so if it were left set the SDK runner would spend it a
        // second time, get a 401, and abort a connector that had just registered
        // fine. Without this assertion, deleting that `remove_var` leaves every
        // other test in this module green.
        assert!(
            carrier_after.is_err(),
            "a CONSUMED OTT must be removed from the environment so the SDK runner \
             does not re-spend it (got {carrier_after:?})"
        );
    }

    /// Saved credentials that parse but carry an EMPTY tenant must not be
    /// adopted — `""` would overwrite a good configured tenant with nothing and
    /// then fail registration as `:tenant_mismatch`, the exact bug this closes.
    #[tokio::test]
    async fn saved_credentials_with_empty_tenant_are_not_adopted() {
        let _lock = env_lock().await;
        let guard = EnvGuard::new();
        let home = tempfile::tempdir().expect("tempdir");
        plant_credentials(home.path(), "");

        guard.set("HOME", home.path().to_str().expect("utf8 tempdir"));
        guard.set("STRIKE48_API_URL", UNREACHABLE_API);
        guard.set("STRIKE48_REGISTRATION_TOKEN", "ott_alreadyspent");

        let resolved = LiveViewConnector::resolve_ott_tenant(CONNECTOR_TYPE, INSTANCE_ID).await;

        assert_eq!(
            resolved, None,
            "an empty saved tenant must be rejected, not adopted"
        );
    }

    /// The cert-manager / direct-config path (SDK Priority 1) must be left
    /// completely alone: return `None` WITHOUT consuming the OTT, so the SDK
    /// handles that deployment exactly as it did before this change.
    ///
    /// A hand-edited `.env.plg` can leave whitespace around the token. The SDK
    /// does not trim THIS carrier (`ott_provider.rs:253` passes it to `parse_ott`
    /// raw, unlike the file carrier at `:281`), so a padded value would be sent
    /// padded and 401 — surfacing as a routine-looking spent-token fallback. The
    /// carrier must therefore be normalized in place.
    ///
    /// Asserted on the SUCCESS path so the exchange actually happens: the stub
    /// echoes back what it received, proving the padding is gone before the
    /// request, not merely tidied afterwards.
    #[tokio::test]
    async fn padded_ott_is_trimmed_before_the_exchange() {
        const PADDED_TENANT: &str = "019fd777-bbbb-7000-cccc-ddddeeeeffff";

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub");
        let port = listener.local_addr().expect("addr").port();

        // Capture the token the SDK actually transmitted.
        let seen: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
        let seen_for_route = seen.clone();
        let app = axum::Router::new().route(
            "/api/connectors/register-with-ott",
            axum::routing::post(
                move |axum::Json(body): axum::Json<serde_json::Value>| async move {
                    *seen_for_route.write().await = body
                        .get("token")
                        .and_then(|t| t.as_str())
                        .map(str::to_string);
                    axum::Json(serde_json::json!({
                        "client_id": format!("matrix:connector:local:{CONNECTOR_TYPE}:{INSTANCE_ID}"),
                        "keycloak_url": "https://auth.invalid/realms/plg",
                        "tenant_id": PADDED_TENANT,
                    }))
                },
            ),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let resolved = {
            let _lock = env_lock().await;
            let guard = EnvGuard::new();
            let home = tempfile::tempdir().expect("tempdir");

            guard.set("HOME", home.path().to_str().expect("utf8 tempdir"));
            guard.set("STRIKE48_API_URL", &format!("http://127.0.0.1:{port}"));
            guard.set("STRIKE48_REGISTRATION_TOKEN", "  ott_padded\n");

            LiveViewConnector::resolve_ott_tenant(CONNECTOR_TYPE, INSTANCE_ID).await
        };
        server.abort();

        assert_eq!(
            resolved.as_deref(),
            Some(PADDED_TENANT),
            "a padded but otherwise valid OTT must still complete the exchange"
        );
        assert_eq!(
            seen.read().await.as_deref(),
            Some("ott_padded"),
            "the token must reach the server TRIMMED; sending it padded is what \
             studio rejects with a 401"
        );
    }

    /// Saved credentials are planted deliberately, even though this path must
    /// never read them, because they are what makes the test DISCRIMINATE. With
    /// no credentials on disk, deleting the `has_direct_config()` guard still
    /// yields `None` with the carrier intact (the exchange fails against an
    /// unreachable origin and the no-credentials arm preserves the carrier on
    /// purpose) — so the test would pass against the broken code. With them
    /// planted, dropping the guard makes the fallback adopt `TENANT` and clear
    /// the carrier, and both assertions below fail.
    ///
    /// The SDK requires all three of `STRIKE48_PRIVATE_KEY_PATH` +
    /// `STRIKE48_CLIENT_ID` + `STRIKE48_AUTH_URL`, AND the key file to exist on
    /// disk (`ott_provider.rs:148-165`) — a nonexistent path yields `None` and
    /// would silently turn this into a duplicate of the bad-token test.
    #[tokio::test]
    async fn direct_config_defers_to_the_sdk_without_consuming_the_ott() {
        let _lock = env_lock().await;
        let guard = EnvGuard::new();
        let home = tempfile::tempdir().expect("tempdir");
        plant_credentials(home.path(), TENANT);

        // Contents are irrelevant — load_direct_config only checks existence.
        let key_path = home.path().join("connector-key.pem");
        std::fs::write(&key_path, b"not-a-real-key").expect("write key");

        guard.set("HOME", home.path().to_str().expect("utf8 tempdir"));
        guard.set(
            "STRIKE48_PRIVATE_KEY_PATH",
            key_path.to_str().expect("utf8 key path"),
        );
        guard.set("STRIKE48_CLIENT_ID", "matrix:connector:cert-manager");
        guard.set("STRIKE48_AUTH_URL", "https://auth.invalid/realms/non-prod");
        guard.set("STRIKE48_API_URL", UNREACHABLE_API);
        guard.set("STRIKE48_REGISTRATION_TOKEN", "ott_should_not_be_spent");

        let resolved = LiveViewConnector::resolve_ott_tenant(CONNECTOR_TYPE, INSTANCE_ID).await;

        assert_eq!(
            resolved, None,
            "a direct-config deployment must adopt nothing here, not even the \
             saved tenant on disk"
        );
        assert_eq!(
            std::env::var("STRIKE48_REGISTRATION_TOKEN").as_deref(),
            Ok("ott_should_not_be_spent"),
            "the direct-config path must NOT consume the OTT — the SDK owns it"
        );
    }

    /// An exchange that SUCCEEDS but returns a blank `tenant_id`. Distinct from
    /// `saved_credentials_with_empty_tenant_are_not_adopted`: that one blanks the
    /// SAVED file and exits via the `Err` arm, whereas this exits via the `Ok`
    /// arm, so neither test covers the other's line.
    ///
    /// This state is unrecoverable by design and the assertions pin both halves:
    /// nothing is adopted, and the carrier is gone (the OTT really was spent, so
    /// leaving it set would make the SDK re-spend a dead token). The code logs at
    /// `error!` here because registration will now proceed with the configured
    /// tenant and be rejected `:tenant_mismatch`.
    #[tokio::test]
    async fn exchange_returning_blank_tenant_adopts_nothing_and_clears_the_carrier() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub");
        let port = listener.local_addr().expect("addr").port();

        let app = axum::Router::new().route(
            "/api/connectors/register-with-ott",
            axum::routing::post(|| async {
                axum::Json(serde_json::json!({
                    "client_id": format!("matrix:connector:local:{CONNECTOR_TYPE}:{INSTANCE_ID}"),
                    "keycloak_url": "https://auth.invalid/realms/plg",
                    "tenant_id": "",
                }))
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let (resolved, carrier_after) = {
            let _lock = env_lock().await;
            let guard = EnvGuard::new();
            let home = tempfile::tempdir().expect("tempdir");

            guard.set("HOME", home.path().to_str().expect("utf8 tempdir"));
            guard.set("STRIKE48_API_URL", &format!("http://127.0.0.1:{port}"));
            guard.set("STRIKE48_REGISTRATION_TOKEN", "ott_freshlyminted");

            let resolved = LiveViewConnector::resolve_ott_tenant(CONNECTOR_TYPE, INSTANCE_ID).await;
            (resolved, std::env::var("STRIKE48_REGISTRATION_TOKEN"))
        };
        server.abort();

        assert_eq!(
            resolved, None,
            "a blank exchanged tenant must not be adopted"
        );
        assert!(
            carrier_after.is_err(),
            "the OTT was spent by the successful exchange, so it must be removed \
             even though there is no tenant to adopt (got {carrier_after:?})"
        );
    }
}
