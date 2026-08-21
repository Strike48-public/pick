use crate::auth::OttProvider;
use crate::client::{ClientOptions, ConnectorClient, InvokeOptions};
use crate::error::{ConnectorError, Result};
use crate::logger::Logger;
use crate::transport::TransportType;
use crate::types::*;
use crate::url_parser::parse_url;
use crate::utils::{deserialize_payload, error_response, sanitize_identifier, serialize_payload};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use strike48_proto::proto::StreamMessage as ProtoStreamMessage;
use tokio::sync::{RwLock, Semaphore};
use tokio::time::{Duration, Instant, sleep};

/// Build the registration metadata map for a connector, auto-injecting
/// behavior-specific required fields that the server validates on registration.
///
/// Currently this auto-derives `tool_schemas` from `BaseConnector::capabilities()`
/// when the connector advertises `ConnectorBehavior::Tool` and hasn't already
/// supplied `tool_schemas` in its `metadata()` map. The Matrix server requires
/// `metadata["tool_schemas"]` to be a JSON-stringified array of objects with at
/// least `name` and `description` fields when TOOL behavior is declared.
///
/// Always prefers user-supplied `tool_schemas` if present.
pub(crate) fn build_registration_metadata(
    connector: &dyn BaseConnector,
) -> HashMap<String, String> {
    let mut metadata = connector.metadata();

    let behaviors = connector.behaviors();
    let tool_declared = behaviors
        .iter()
        .any(|b| matches!(b, ConnectorBehavior::Tool));

    if tool_declared && !metadata.contains_key("tool_schemas") {
        let task_types = connector.capabilities();
        if !task_types.is_empty() {
            let schemas: Vec<serde_json::Value> = task_types
                .iter()
                .map(|tt| {
                    let parameters: serde_json::Value = serde_json::from_str(&tt.input_schema_json)
                        .unwrap_or(serde_json::Value::Null);
                    serde_json::json!({
                        "name":        tt.task_type_id,
                        "description": tt.description,
                        "parameters":  parameters,
                    })
                })
                .collect();
            if let Ok(json) = serde_json::to_string(&schemas) {
                metadata.insert("tool_schemas".to_string(), json);
            }
        }
    }

    metadata
}

/// Calculate reconnection delay with exponential backoff and jitter.
///
/// Formula: min(baseDelay * 2^attempt, maxDelay) + random(0, jitter)
///
/// This prevents the "thundering herd" problem where many clients
/// reconnect simultaneously after a server restart.
///
/// Once max delay is reached, continues retrying indefinitely with that delay + jitter.
fn calculate_reconnect_delay(
    attempt: u64,
    base_delay_ms: u64,
    max_delay_ms: u64,
    jitter_ms: u64,
) -> u64 {
    use rand::Rng;

    // Exponential backoff: baseDelay * 2^attempt
    let exponential_delay = base_delay_ms * 2_u64.pow(attempt.min(20) as u32); // Cap exponent to prevent overflow

    // Cap at maxDelay
    let capped_delay = exponential_delay.min(max_delay_ms);

    // Add random jitter to prevent thundering herd
    let mut rng = rand::thread_rng();
    let jitter = rng.gen_range(0..=jitter_ms);

    capped_delay + jitter
}

/// Get current timestamp in milliseconds since Unix epoch.
fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Check if a session token (format: base64url(JSON).base64url(HMAC)) is still valid.
/// Returns false if expired or unparseable. `buffer_secs` is subtracted from exp
/// so the token is considered expired slightly before its actual expiry.
fn is_session_token_valid(token: &str, buffer_secs: u64) -> bool {
    use base64::Engine;

    let payload_b64 = match token.split_once('.') {
        Some((p, _)) => p,
        None => return false,
    };

    let payload_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let claims: serde_json::Value = match serde_json::from_slice(&payload_bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let exp = match claims.get("exp").and_then(|v| v.as_u64()) {
        Some(e) => e,
        None => return false,
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    now < exp.saturating_sub(buffer_secs)
}

/// Rate-limited logger to avoid log spam during extended outages.
/// Logs detailed message on first occurrence, then only every `interval_ms`.
struct RateLimitedLogger {
    last_log_time: std::sync::Mutex<Option<Instant>>,
    interval: Duration,
}

impl RateLimitedLogger {
    fn new(interval_ms: u64) -> Self {
        Self {
            last_log_time: std::sync::Mutex::new(None),
            interval: Duration::from_millis(interval_ms),
        }
    }

    /// Log error message, rate-limited. Returns true if logged.
    fn log_error(&self, logger: &Logger, message: &str, detail: &str) -> bool {
        let mut last_time = self.last_log_time.lock().unwrap();
        let now = Instant::now();

        let should_log = match *last_time {
            None => true,
            Some(t) => now.duration_since(t) >= self.interval,
        };

        if should_log {
            logger.error(message, detail);
            *last_time = Some(now);
            true
        } else {
            // Log at debug level to avoid losing all visibility
            tracing::debug!("{}: {}", message, detail);
            false
        }
    }
}

/// Connector configuration
#[derive(Debug, Clone)]
pub struct ConnectorConfig {
    pub host: String,
    pub tenant_id: String,
    pub connector_type: String,
    pub instance_id: String,
    pub version: String,
    pub auth_token: String,
    pub use_tls: bool,
    pub transport_type: TransportType,
    pub max_concurrent_requests: usize,
    /// Enable automatic reconnection on disconnect (default: true)
    pub reconnect_enabled: bool,
    /// Base delay for reconnection backoff in ms (default: 500).
    /// Sequence: 500ms → 1s → 2s → 4s → 8s → 16s → 32s → 60s (cap).
    pub reconnect_delay_ms: u64,
    /// Maximum backoff delay in ms - retries indefinitely at this interval (default: 60000)
    pub max_backoff_delay_ms: u64,
    /// Jitter added to backoff to prevent thundering herd (default: 500)
    pub reconnect_jitter_ms: u64,

    // === Multi-instance routing metadata ===
    /// Human-readable display name for UI (defaults to instance_id if not set)
    pub display_name: Option<String>,
    /// Tags for grouping instances (e.g., ["prod", "us-east-1"])
    /// Used for tag-based routing: "run on all prod servers"
    pub tags: Vec<String>,
    /// Operator-defined key-value pairs for UI display
    /// Examples: {"location": "us-east-1", "owner": "platform-team"}
    pub metadata: std::collections::HashMap<String, String>,

    // === Metrics reporting ===
    /// Enable periodic metrics reporting to Strike48 (default: true)
    pub metrics_enabled: bool,
    /// Interval for sending metrics reports in ms (default: 30000 = 30s)
    pub metrics_interval_ms: u64,

    /// Outbound heartbeat interval. `None` (default) means use the SDK
    /// default of 30s, which matches the Matrix server's session-reaper
    /// expectation. Only tune this when running against a Matrix deployment
    /// with a non-default heartbeat configuration, or for flaky-network
    /// testing.
    pub heartbeat_interval: Option<Duration>,

    /// Heartbeat watchdog timeout. If no `HeartbeatResponse` arrives
    /// within this window the runner declares the stream dead and
    /// reconnects. `None` (default) means use the SDK default of 45s.
    pub heartbeat_timeout: Option<Duration>,
}

impl ConnectorConfig {
    /// Create configuration from environment variables.
    ///
    /// Reads from:
    /// - `STRIKE48_URL` or `MATRIX_HOST` or `STRIKE48_HOST`: Server address (auto-detects transport from scheme)
    /// - `TENANT_ID`: Tenant identifier
    /// - `AUTH_TOKEN`: Authentication token
    /// - `USE_TLS`: Whether to use TLS (auto-detected from URL scheme if using URLs)
    ///
    /// This is the recommended way to create a `ConnectorConfig` when using env vars.
    /// Use `Default::default()` for pure defaults without env var side effects.
    pub fn from_env() -> Self {
        // STRIKE48_URL takes priority, then MATRIX_HOST, then STRIKE48_HOST
        let strike48_url = std::env::var("STRIKE48_URL")
            .or_else(|_| std::env::var("MATRIX_HOST"))
            .ok();
        let strike48_host_env =
            std::env::var("STRIKE48_HOST").unwrap_or_else(|_| "localhost:50061".to_string());

        // Parse URL to get host, TLS settings, and transport type
        let (host, use_tls, transport_type) = if let Some(url) = strike48_url {
            match parse_url(&url) {
                Ok(parsed) => (parsed.host_port(), parsed.use_tls, parsed.transport),
                Err(_) => {
                    // Fall back to STRIKE48_HOST if URL parsing fails
                    let tls = std::env::var("USE_TLS")
                        .map(|v| v == "true")
                        .unwrap_or(false);
                    (strike48_host_env, tls, TransportType::Grpc)
                }
            }
        } else {
            // Try to parse STRIKE48_HOST as URL for auto-detection
            match parse_url(&strike48_host_env) {
                Ok(parsed) => (parsed.host_port(), parsed.use_tls, parsed.transport),
                Err(_) => {
                    // Simple host:port format - defaults to gRPC
                    let tls = std::env::var("USE_TLS")
                        .map(|v| v == "true")
                        .unwrap_or(false);
                    (strike48_host_env, tls, TransportType::Grpc)
                }
            }
        };

        Self {
            host,
            tenant_id: std::env::var("TENANT_ID").unwrap_or_else(|_| "default".to_string()),
            connector_type: "unknown".to_string(),
            instance_id: std::env::var("INSTANCE_ID").unwrap_or_else(|_| {
                format!("{}-{}", "unknown", chrono::Utc::now().timestamp_millis())
            }),
            version: "1.0.0".to_string(),
            auth_token: std::env::var("AUTH_TOKEN").unwrap_or_else(|_| String::new()),
            use_tls,
            transport_type,
            max_concurrent_requests: 1000,
            reconnect_enabled: true,
            reconnect_delay_ms: 500,
            max_backoff_delay_ms: 60000,
            reconnect_jitter_ms: 500,
            display_name: std::env::var("CONNECTOR_DISPLAY_NAME").ok(),
            tags: std::env::var("CONNECTOR_TAGS")
                .map(|s| s.split(',').map(|t| t.trim().to_string()).collect())
                .unwrap_or_default(),
            metadata: std::collections::HashMap::new(),
            metrics_enabled: std::env::var("STRIKE48_METRICS_ENABLED")
                .map(|v| v != "false" && v != "0")
                .unwrap_or(true),
            metrics_interval_ms: std::env::var("STRIKE48_METRICS_INTERVAL_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(30000),
            heartbeat_interval: None,
            heartbeat_timeout: None,
        }
    }

    /// Override the heartbeat interval and watchdog timeout. Defaults are
    /// **30s interval / 45s timeout** (the Matrix server's defaults). Only
    /// tune this when running against a Matrix deployment with a non-default
    /// heartbeat configuration, or for flaky-network testing.
    ///
    /// Emits a `tracing::warn!` when `timeout < interval` because that
    /// misconfigures the watchdog (the very first tick can fire before
    /// any reply has had a chance to arrive); the values are still
    /// applied — the runner uses whatever is configured.
    pub fn with_heartbeat(mut self, interval: Duration, timeout: Duration) -> Self {
        if timeout < interval {
            tracing::warn!(
                target: "strike48_connector::heartbeat",
                interval_ms = interval.as_millis() as u64,
                timeout_ms = timeout.as_millis() as u64,
                "heartbeat_timeout < heartbeat_interval; the watchdog can fire before the first heartbeat reply has a chance to arrive"
            );
        }
        self.heartbeat_interval = Some(interval);
        self.heartbeat_timeout = Some(timeout);
        self
    }

    /// Set human-readable display name for UI.
    /// Defaults to instance_id if not set.
    ///
    /// # Example
    /// ```ignore
    /// config.display_name("Production Server 1");
    /// ```
    pub fn display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = Some(name.into());
        self
    }

    /// Add a tag for instance grouping.
    /// Tags enable routing like "run on all prod servers".
    ///
    /// # Example
    /// ```ignore
    /// config.tag("prod").tag("us-east-1");
    /// ```
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add multiple tags at once.
    ///
    /// # Example
    /// ```ignore
    /// config.tags(["prod", "us-east-1", "high-memory"]);
    /// ```
    pub fn tags(mut self, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tags.extend(tags.into_iter().map(|t| t.into()));
        self
    }

    /// Add operator metadata for UI display.
    ///
    /// # Example
    /// ```ignore
    /// config.with_metadata("location", "AWS US-East-1")
    ///       .with_metadata("owner", "platform-team");
    /// ```
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Load metadata from environment variables with a prefix.
    ///
    /// # Example
    /// ```ignore
    /// // Reads CONNECTOR_LOCATION, CONNECTOR_OWNER, etc.
    /// config.metadata_from_env("CONNECTOR_");
    /// ```
    pub fn metadata_from_env(mut self, prefix: &str) -> Self {
        for (key, value) in std::env::vars() {
            if key.starts_with(prefix) {
                let meta_key = key.strip_prefix(prefix).unwrap().to_lowercase();
                self.metadata.insert(meta_key, value);
            }
        }
        self
    }
}

impl Default for ConnectorConfig {
    /// Create a pure default configuration without reading environment variables.
    ///
    /// For env-based configuration, use `ConnectorConfig::from_env()` instead.
    fn default() -> Self {
        Self {
            host: "localhost:50061".to_string(),
            tenant_id: "default".to_string(),
            connector_type: "unknown".to_string(),
            instance_id: format!("{}-{}", "unknown", chrono::Utc::now().timestamp_millis()),
            version: "1.0.0".to_string(),
            auth_token: String::new(),
            use_tls: false,
            transport_type: TransportType::Grpc,
            max_concurrent_requests: 1000,
            reconnect_enabled: true,
            reconnect_delay_ms: 500,
            max_backoff_delay_ms: 60000,
            reconnect_jitter_ms: 500,
            display_name: None,
            tags: Vec::new(),
            metadata: std::collections::HashMap::new(),
            metrics_enabled: true,
            metrics_interval_ms: 30000,
            heartbeat_interval: None,
            heartbeat_timeout: None,
        }
    }
}

/// Handle for communicating with the Matrix server from connector callbacks.
///
/// Provided to connector implementations through `BaseConnector` callback methods
/// (e.g., `handle_ws_open`, `handle_ws_frame`). Cannot be constructed directly --
/// only `ConnectorRunner` creates instances internally.
///
/// Only typed, safe operations are exposed. Raw proto message sending is
/// intentionally restricted to prevent injection of arbitrary stream messages
/// (e.g., fake registrations or spoofed responses).
///
/// # Example
///
/// ```rust,ignore
/// fn handle_ws_frame(
///     &self,
///     frame: WsFrame,
///     handle: ConnectorHandle,
/// ) -> Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
///     Box::pin(async move {
///         // Forward frame to backend, then relay response back
///         let response_data = self.backend.send(frame.data).await?;
///         handle.send_ws_frame(&frame.connection_id, WsFrameType::Text, response_data).await
///     })
/// }
/// ```
#[derive(Clone)]
pub struct ConnectorHandle {
    inner: HandleInner,
}

/// Two backends:
/// - `Single`: the original `ConnectorRunner` path; sends through the lazily-
///   reconnected `ConnectorClient`.
/// - `Multi`: the `MultiConnectorRunner` path; sends through a per-registration
///   `mpsc::Sender<StreamMessage>`. `invoke_capability` is not supported here
///   today (multi-runner doesn't track pending-invokes), so the call returns
///   `ConnectorError::Unsupported`.
#[derive(Clone)]
enum HandleInner {
    Single(Arc<RwLock<Option<ConnectorClient>>>),
    Multi(tokio::sync::mpsc::Sender<ProtoStreamMessage>),
}

impl std::fmt::Debug for ConnectorHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectorHandle")
            .field("connected", &self.is_connected())
            .finish()
    }
}

impl ConnectorHandle {
    pub(crate) fn new(client: Arc<RwLock<Option<ConnectorClient>>>) -> Self {
        Self {
            inner: HandleInner::Single(client),
        }
    }

    /// Construct a handle that sends through a multi-runner per-registration
    /// outbound channel. Used by `MultiConnectorRunner` when dispatching
    /// `WsOpenRequest` / `WsFrame` to a `BaseConnector`.
    pub(crate) fn from_sender(tx: tokio::sync::mpsc::Sender<ProtoStreamMessage>) -> Self {
        Self {
            inner: HandleInner::Multi(tx),
        }
    }

    /// Send a raw protobuf message on the underlying stream.
    ///
    /// Clones the channel sender under the lock, then drops the lock before
    /// the actual send, so reconnection (which needs a write lock) is never
    /// blocked by an in-flight send.
    async fn send_raw(&self, message: ProtoStreamMessage) -> Result<()> {
        match &self.inner {
            HandleInner::Single(client) => {
                let tx = {
                    let guard = client.read().await;
                    let client = guard.as_ref().ok_or(ConnectorError::NotConnected)?;
                    client.clone_message_tx().await?
                };
                tx.send(message).map_err(|e| {
                    ConnectorError::StreamError(format!("Failed to send message: {e}"))
                })?;
            }
            HandleInner::Multi(tx) => {
                tx.send(message).await.map_err(|e| {
                    ConnectorError::StreamError(format!("Failed to send message: {e}"))
                })?;
            }
        }
        Ok(())
    }

    /// Send a WebSocket frame to a proxied client connection.
    pub async fn send_ws_frame(
        &self,
        connection_id: &str,
        frame_type: WsFrameType,
        data: Vec<u8>,
    ) -> Result<()> {
        let message = ProtoStreamMessage {
            message: Some(proto::stream_message::Message::WsFrame(
                proto::WebSocketFrame {
                    connection_id: connection_id.to_string(),
                    frame_type: frame_type as i32,
                    data,
                },
            )),
        };
        self.send_raw(message).await
    }

    /// Send a WebSocket open response confirming a backend connection was established.
    pub async fn send_ws_open_response(
        &self,
        connection_id: &str,
        success: bool,
        error: &str,
    ) -> Result<()> {
        let message = ProtoStreamMessage {
            message: Some(proto::stream_message::Message::WsOpenResponse(
                proto::WebSocketOpenResponse {
                    connection_id: connection_id.to_string(),
                    success,
                    error: error.to_string(),
                },
            )),
        };
        self.send_raw(message).await
    }

    /// Invoke a capability on another connector through Matrix routing.
    ///
    /// Returns `None` for fire-and-forget invocations.
    ///
    /// The client lock is held only long enough to register the pending
    /// request and send the message. The (potentially long) wait for the
    /// response happens outside the lock so reconnection is never blocked.
    pub async fn invoke_capability(
        &self,
        target_address: &str,
        payload: Vec<u8>,
        options: InvokeOptions,
    ) -> Result<Option<InvokeCapabilityResponse>> {
        let client = match &self.inner {
            HandleInner::Single(c) => c,
            HandleInner::Multi(_) => {
                // Multi-runner currently has no pending-invoke registry, so
                // we can't correlate responses. Surface explicitly rather
                // than silently dropping the call.
                return Err(ConnectorError::NotImplemented(
                    "invoke_capability is not yet supported on MultiConnectorRunner handles"
                        .to_string(),
                ));
            }
        };
        let mut started = {
            let guard = client.read().await;
            let client = guard.as_ref().ok_or(ConnectorError::NotConnected)?;
            client
                .start_invoke(target_address, payload, options)
                .await?
        };

        let rx = match started.receiver.take() {
            None => return Ok(None),
            Some(rx) => rx,
        };

        match tokio::time::timeout(Duration::from_millis(started.timeout_ms), rx).await {
            Ok(Ok(response)) => Ok(Some(response)),
            Ok(Err(_)) => {
                started.cancel().await;
                Err(ConnectorError::StreamError(
                    "Response channel closed".to_string(),
                ))
            }
            Err(_) => {
                started.cancel().await;
                Err(ConnectorError::Timeout(format!(
                    "Invoke request {} timed out after {}ms",
                    started.request_id, started.timeout_ms
                )))
            }
        }
    }

    /// Check if the underlying connection is active.
    ///
    /// **Best-effort, racy.** This is a hint for diagnostics or coarse
    /// circuit-breaker logic — never the basis for "should I send" decisions.
    /// Always handle the `Result` of `send_ws_frame` / `send_ws_open_response`
    /// / `send_*` calls and treat a send error as the canonical signal that
    /// the connection is gone. A `true` return here can flip to a closed
    /// channel before the next `.await` completes; an `Err` from the send
    /// itself cannot.
    ///
    /// Uses a non-blocking `try_read` on the internal lock. Under heavy write
    /// contention (e.g., during reconnection) this may return `false` even
    /// when the client is connected.
    ///
    /// # `HandleInner::Multi` caveat
    ///
    /// For handles obtained via `ConnectorHandle::from_sender` (i.e. from
    /// `MultiConnectorRunner` WS dispatch), this returns `true` as long as
    /// the receiving side of the per-registration outbound channel is alive.
    /// That is *not* the same as "the underlying tunnel is up": during a
    /// reconnect the runner may be in the middle of swapping streams while
    /// the previous channel is still draining, and a connector's
    /// `handle_ws_*` task may observe `is_connected() == true` and then
    /// fail on the next `send_ws_frame` with a closed-channel error. The
    /// runner aborts WS pump tasks on stream teardown (see
    /// `RegistrationRunner::drive_stream`) so this is bounded — but
    /// `is_connected` is still racy with that abort.
    pub fn is_connected(&self) -> bool {
        match &self.inner {
            HandleInner::Single(client) => client
                .try_read()
                .map(|guard| guard.as_ref().is_some_and(|c| c.is_connected()))
                .unwrap_or(false),
            HandleInner::Multi(tx) => !tx.is_closed(),
        }
    }
}

/// Base connector trait — the low-level surface every runner consumes.
///
/// # Note
///
/// For tool connectors prefer [`crate::ToolConnector`] wrapped in
/// [`crate::ToolAdapter`]; for request/response connectors prefer
/// [`crate::SimpleConnector`]. Implement `BaseConnector` directly only when
/// you need raw stream callbacks (e.g. App connectors that proxy WebSocket
/// frames via [`Self::handle_ws_open`] / [`Self::handle_ws_frame`] /
/// [`Self::handle_ws_close`]).
pub trait BaseConnector: Send + Sync {
    /// Connector type identifier
    fn connector_type(&self) -> &str;

    /// Connector version
    fn version(&self) -> &str;

    /// Execute operation (implemented by subclasses).
    ///
    /// This is the required execution entry point for every connector.
    /// For context-aware operation (e.g. multi-tenant deployments that need
    /// the caller's `tenant_id`), override [`Self::execute_with_context`]
    /// instead — the SDK runners always invoke the context-aware variant
    /// and the default implementation of `execute_with_context` delegates
    /// here.
    fn execute(
        &self,
        request: serde_json::Value,
        capability_id: Option<&str>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + '_>>;

    /// Execute with full server-supplied per-request context.
    ///
    /// The wire-level [`crate::types::ExecuteRequest`] carries a `context`
    /// map populated by the server with caller metadata (tenant identity,
    /// subject, attributes). Override this method when your connector needs
    /// that metadata. The default implementation discards `context` and
    /// delegates to [`Self::execute`] for backward compatibility —
    /// connectors that only implement `execute` continue to work unchanged.
    ///
    /// Well-known context keys (server-defined, not enforced by the SDK):
    ///
    /// - `tenant_id` — caller tenant identifier (multi-tenant
    ///   deployments).
    /// - `user_id` — caller subject (audit / policy).
    /// - `agent_execution` — `"true"` / `"false"` string flag.
    /// - `agent_context` — JSON-encoded string (decoded form lives at
    ///   `params["metadata"]["agent_context"]`).
    ///
    /// See [`crate::context::keys`] for the well-known key constants.
    ///
    /// Note: `context` and `request["metadata"]` are two parallel views of
    /// the same caller metadata. `context` is a flat
    /// `HashMap<String, String>` (complex values arrive as JSON-encoded
    /// strings); `request["metadata"]` carries the same data with values
    /// already decoded as JSON. For complex keys (e.g. `agent_context`)
    /// prefer the metadata path. For tool connectors specifically, the
    /// invoked tool's arguments live at `request["parameters"]`.
    ///
    /// # Note
    ///
    /// `execute` remains the required method on this trait. If you override
    /// `execute_with_context`, you still must provide an `execute` impl —
    /// a common pattern is to share a private helper, or have `execute`
    /// call `execute_with_context(req, cap, &HashMap::new())` (only safe
    /// if you've also overridden `execute_with_context` — without an
    /// override this calls back into the default impl and recurses).
    /// Calling `self.execute(...)` from your override discards context for
    /// the actual work — only do it if you've already consumed `context`
    /// for something else (e.g. tenant-tagged logging) and want the legacy
    /// execution path.
    ///
    /// # Debug-build tripwire
    ///
    /// In debug builds (`#[cfg(debug_assertions)]`) the default impl emits a
    /// `tracing::warn!` on the
    /// `strike48_connector::context_drop` target whenever a non-empty
    /// `context` is dropped — i.e. the SDK delivered caller metadata that
    /// the connector has not opted into. Silence with
    /// `RUST_LOG=strike48_connector::context_drop=off`. Production
    /// (`--release`) builds keep zero overhead.
    fn execute_with_context<'a>(
        &'a self,
        request: serde_json::Value,
        capability_id: Option<&'a str>,
        context: &'a HashMap<String, String>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + 'a>>
    {
        #[cfg(debug_assertions)]
        if !context.is_empty() {
            tracing::warn!(
                target: "strike48_connector::context_drop",
                context_keys = ?context.keys().collect::<Vec<_>>(),
                "BaseConnector::execute_with_context default impl is dropping non-empty context. \
                 Override execute_with_context (not execute) if your connector or wrapper needs caller \
                 metadata (tenant_id, user_id, etc.)."
            );
        }
        #[cfg(not(debug_assertions))]
        let _ = context;
        self.execute(request, capability_id)
    }

    /// Get connector behavior
    fn behavior(&self) -> ConnectorBehavior {
        ConnectorBehavior::RequestResponse
    }

    /// Get connector behaviors (supports registering multiple).
    /// Default wraps the single behavior() return in a vec.
    fn behaviors(&self) -> Vec<ConnectorBehavior> {
        vec![self.behavior()]
    }

    /// Get supported encodings
    fn supported_encodings(&self) -> Vec<PayloadEncoding> {
        vec![PayloadEncoding::Json, PayloadEncoding::RawBytes]
    }

    /// Get connector metadata
    fn metadata(&self) -> HashMap<String, String> {
        HashMap::new()
    }

    /// Get connector capabilities (tools/tasks)
    fn capabilities(&self) -> Vec<TaskTypeSchema> {
        Vec::new()
    }

    /// Get timeout in milliseconds
    fn timeout_ms(&self) -> u64 {
        30000 // 30 seconds default
    }

    /// Handle WebSocket open request from the server.
    ///
    /// App connectors that proxy WebSocket connections (e.g., LiveView) should
    /// override this to open a backend WebSocket and relay frames. The default
    /// implementation does nothing.
    fn handle_ws_open(
        &self,
        _req: WsOpenRequest,
        _handle: ConnectorHandle,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }

    /// Handle an incoming WebSocket frame from the server.
    ///
    /// Override this to forward frames to a backend WebSocket. The default
    /// implementation does nothing.
    fn handle_ws_frame(
        &self,
        _frame: WsFrame,
        _handle: ConnectorHandle,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + '_>> {
        Box::pin(async { Ok(()) })
    }

    /// Handle a WebSocket close request from the server.
    ///
    /// Override this to tear down the backend WebSocket. The default
    /// implementation does nothing.
    fn handle_ws_close(&self, _req: WsCloseRequest) {}
}

/// Handle for triggering shutdown from signal handlers or other contexts.
///
/// This handle can be cloned and used to trigger shutdown without needing
/// a mutable reference to the ConnectorRunner.
#[derive(Clone)]
pub struct ShutdownHandle {
    shutdown_requested: Arc<AtomicBool>,
}

impl ShutdownHandle {
    /// Trigger shutdown of the connector.
    ///
    /// This is safe to call from signal handlers or other async contexts.
    /// Uses atomic operations for lock-free, immediate shutdown signaling.
    pub fn shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
    }

    /// Construct a handle that drives an externally-owned shutdown flag.
    ///
    /// Used by [`crate::MultiConnectorRunner`] (and other future runners) to
    /// expose shutdown over the same `ShutdownHandle` type without coupling
    /// to `ConnectorRunner`'s internals.
    pub(crate) fn from_flag(flag: Arc<AtomicBool>) -> Self {
        Self {
            shutdown_requested: flag,
        }
    }
}

/// Connector runner that manages lifecycle
pub struct ConnectorRunner {
    config: Arc<RwLock<ConnectorConfig>>,
    /// The connector implementation
    pub connector: Arc<dyn BaseConnector>,
    client: Arc<RwLock<Option<ConnectorClient>>>,
    metrics: Arc<RwLock<ConnectorMetrics>>,
    /// Atomic flag for running state (lock-free)
    running: Arc<AtomicBool>,
    /// Atomic flag for lock-free shutdown signaling
    shutdown_requested: Arc<AtomicBool>,
    logger: Logger,
    start_time: Arc<RwLock<Option<Instant>>>,
    ott_provider: Arc<RwLock<Option<OttProvider>>>,
    /// Atomic flag for JWT reconnect state (lock-free)
    reconnect_with_jwt: Arc<AtomicBool>,
    /// Semaphore to limit concurrent request handlers (prevents OOM under load)
    request_semaphore: Arc<Semaphore>,
    /// Track reconnection attempts for exponential backoff
    reconnect_attempts: Arc<AtomicU64>,
    /// Rate-limited logger for connection errors (logs every 60s during outage)
    error_logger: RateLimitedLogger,
    /// Connector ARN assigned after registration (format: strike48:tenant:type:instance)
    connector_arn: Arc<RwLock<Option<String>>>,
    /// Session token from server, persisted across reconnections for lighter re-auth
    session_token: Arc<RwLock<Option<String>>>,
    /// OIDC config from server for OAuth desktop flow (when provided)
    oidc_config: Arc<RwLock<Option<strike48_proto::proto::OidcConfig>>>,
    /// Flag to prevent spawning multiple metrics reporters on reconnection
    metrics_reporter_running: Arc<AtomicBool>,
    /// Shared storage for the `metrics` crate recorder (connector-defined metrics)
    metrics_storage: crate::metrics_recorder::MetricsStorage,
    /// Consecutive auth failures without a successful registration in between.
    /// Used to detect livelock when the server persistently rejects registrations
    /// after credentials have already been cleared (e.g. Keycloak client deleted,
    /// future-dated JWT, server misconfiguration).
    consecutive_auth_failures: Arc<AtomicU64>,
}

impl ConnectorRunner {
    pub fn new(config: ConnectorConfig, connector: Arc<dyn BaseConnector>) -> Self {
        let logger = Logger::new("connector");
        let max_concurrent = config.max_concurrent_requests;
        let metrics_storage = crate::metrics_recorder::install();
        Self {
            config: Arc::new(RwLock::new(config)),
            connector,
            client: Arc::new(RwLock::new(None)),
            metrics: Arc::new(RwLock::new(ConnectorMetrics::default())),
            running: Arc::new(AtomicBool::new(false)),
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            logger,
            start_time: Arc::new(RwLock::new(None)),
            ott_provider: Arc::new(RwLock::new(None)),
            reconnect_with_jwt: Arc::new(AtomicBool::new(false)),
            request_semaphore: Arc::new(Semaphore::new(max_concurrent)),
            reconnect_attempts: Arc::new(AtomicU64::new(0)),
            error_logger: RateLimitedLogger::new(60000),
            connector_arn: Arc::new(RwLock::new(None)),
            session_token: Arc::new(RwLock::new(None)),
            oidc_config: Arc::new(RwLock::new(None)),
            metrics_reporter_running: Arc::new(AtomicBool::new(false)),
            metrics_storage,
            consecutive_auth_failures: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get OIDC config from the last successful registration (if provided by server).
    pub fn oidc_config(&self) -> Arc<RwLock<Option<strike48_proto::proto::OidcConfig>>> {
        Arc::clone(&self.oidc_config)
    }

    /// Clear all cached credentials (session token, OTT provider state, and saved
    /// credentials file).  Used when the server signals that the connector's identity
    /// is no longer valid (admin de-registration, rejection, forced reconnect).
    async fn clear_credentials(&self) {
        *self.session_token.write().await = None;
        let mut ott_guard = self.ott_provider.write().await;
        if let Some(ref mut ott) = *ott_guard {
            ott.delete_saved_credentials();
            ott.reset();
        }
    }

    /// Get a shutdown handle that can be used to trigger shutdown from signal handlers.
    ///
    /// This handle can be cloned and passed to signal handlers or other async contexts
    /// without needing to hold a reference to the ConnectorRunner.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let runner = ConnectorRunner::new(config, connector);
    /// let shutdown_handle = runner.shutdown_handle();
    ///
    /// // In signal handler
    /// tokio::spawn(async move {
    ///     tokio::signal::ctrl_c().await.unwrap();
    ///     shutdown_handle.shutdown();
    /// });
    ///
    /// runner.run().await?;
    /// ```
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            shutdown_requested: self.shutdown_requested.clone(),
        }
    }

    /// Run the connector
    pub async fn run(&self) -> Result<()> {
        // Use compare_exchange to atomically check and set running state
        if self
            .running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(ConnectorError::AlreadyRunning);
        }
        *self.start_time.write().await = Some(Instant::now());

        self.logger.info(&format!(
            "Starting {} connector",
            self.connector.connector_type()
        ));

        // Validate configuration
        self.validate_config().await?;

        // Initialize authentication
        self.initialize_auth().await?;

        // Connection loop
        while !self.shutdown_requested.load(Ordering::SeqCst) {
            // Reset reconnection flag at start of each iteration
            self.reconnect_with_jwt.store(false, Ordering::SeqCst);

            // Refresh token before (re)connecting to ensure it's not expired
            // The get_token() call checks expiry with 30s buffer and fetches fresh if needed
            if let Some(ref mut ott) = *self.ott_provider.write().await {
                match ott.get_token().await {
                    Ok(fresh_token) => {
                        self.config.write().await.auth_token = fresh_token;
                        self.logger.debug("Token refreshed before connection");
                    }
                    Err(e) => {
                        let err_str = e.to_string();
                        let is_auth_failure = err_str.contains("401")
                            || err_str.contains("invalid_client")
                            || err_str.contains("Unauthorized");

                        if is_auth_failure {
                            // Auth failure (e.g. 401 after de-registration) — clear
                            // auth_token so registration falls back to token-less
                            // pending-approval flow instead of sending a stale JWT.
                            self.config.write().await.auth_token = String::new();
                            self.logger.warn(&format!(
                                "Token refresh auth failure, cleared auth_token: {e}"
                            ));
                        } else {
                            // Network/transient error — keep auth_token, it may
                            // still be valid. The existing cached token will be
                            // used for registration.
                            self.logger
                                .debug(&format!("Token refresh skipped (transient): {e}"));
                        }
                    }
                }
            }

            let config = self.config.read().await.clone();

            // Build URL with proper scheme from transport type for auto-detection
            let url = match config.transport_type {
                TransportType::WebSocket => {
                    if config.use_tls {
                        format!("wss://{}", config.host)
                    } else {
                        format!("ws://{}", config.host)
                    }
                }
                TransportType::Grpc => {
                    if config.use_tls {
                        format!("grpcs://{}", config.host)
                    } else {
                        format!("grpc://{}", config.host)
                    }
                }
            };

            // Create client with URL-based transport auto-detection
            #[allow(deprecated)]
            let mut client = ConnectorClient::with_options(ClientOptions {
                url: Some(url),
                host: None,
                use_tls: None,
                transport: None,
                default_timeout_ms: Some(30000),
            });
            if let Some(hb) = config.heartbeat_interval {
                client.set_keepalive_interval(hb);
            }

            match client.connect_channel().await {
                Ok(_) => {
                    self.logger.debug("Connected to Strike48 server");

                    // Store client before starting stream
                    *self.client.write().await = Some(client);

                    self.logger
                        .debug("Starting bidirectional stream with registration...");

                    // Build registration request message
                    let config = self.config.read().await.clone();

                    let stored_session_token = {
                        let token = self.session_token.read().await.clone().unwrap_or_default();
                        if !token.is_empty() && !is_session_token_valid(&token, 30) {
                            tracing::debug!("Session token expired, clearing for JWT fallback");
                            *self.session_token.write().await = None;
                            String::new()
                        } else {
                            token
                        }
                    };

                    let has_session_token = !stored_session_token.is_empty();
                    let has_jwt = !config.auth_token.is_empty();
                    if has_session_token {
                        self.logger
                            .debug("Registering with session token (reconnection)");
                    } else if has_jwt {
                        self.logger.debug("Registering with JWT authentication");
                    } else {
                        self.logger
                            .info("Registering without JWT (pending approval flow)");
                    }

                    let jwt = if has_jwt {
                        config.auth_token.as_str()
                    } else {
                        ""
                    };
                    let registration_message =
                        self.build_register_request(&config, jwt, &stored_session_token);

                    // Start stream with registration message included.
                    // Treat stream-start failures as recoverable connection errors —
                    // the server may have dropped the connection immediately after the
                    // TCP accept (e.g. during a rolling restart). Use the same
                    // exponential backoff path as connect_channel failures.
                    let (_tx, mut rx) = {
                        let mut client_guard = self.client.write().await;
                        match client_guard.as_mut() {
                            None => {
                                drop(client_guard);
                                let attempt =
                                    self.reconnect_attempts.fetch_add(1, Ordering::SeqCst);
                                let cfg = self.config.read().await.clone();
                                let delay = calculate_reconnect_delay(
                                    attempt,
                                    cfg.reconnect_delay_ms,
                                    cfg.max_backoff_delay_ms,
                                    cfg.reconnect_jitter_ms,
                                );
                                self.logger.warn(&format!(
                                    "Client disappeared before stream start, retrying in {delay}ms"
                                ));
                                let mut remaining = delay;
                                while remaining > 0
                                    && !self.shutdown_requested.load(Ordering::SeqCst)
                                {
                                    let wait = std::cmp::min(remaining, 100);
                                    sleep(Duration::from_millis(wait)).await;
                                    remaining = remaining.saturating_sub(wait);
                                }
                                continue;
                            }
                            Some(client_ref) => {
                                match client_ref
                                    .start_stream_with_registration(registration_message)
                                    .await
                                {
                                    Ok(streams) => streams,
                                    Err(e) => {
                                        drop(client_guard);
                                        let attempt =
                                            self.reconnect_attempts.fetch_add(1, Ordering::SeqCst);
                                        let cfg = self.config.read().await.clone();
                                        let delay = calculate_reconnect_delay(
                                            attempt,
                                            cfg.reconnect_delay_ms,
                                            cfg.max_backoff_delay_ms,
                                            cfg.reconnect_jitter_ms,
                                        );
                                        self.error_logger.log_error(
                                            &self.logger,
                                            "Stream start failed, retrying",
                                            &format!("{e} (backoff {delay}ms)"),
                                        );
                                        let mut remaining = delay;
                                        while remaining > 0
                                            && !self.shutdown_requested.load(Ordering::SeqCst)
                                        {
                                            let wait = std::cmp::min(remaining, 100);
                                            sleep(Duration::from_millis(wait)).await;
                                            remaining = remaining.saturating_sub(wait);
                                        }
                                        continue;
                                    }
                                }
                            }
                        }
                    };

                    self.logger
                        .debug("Stream started with registration, waiting for response...");

                    // Wait for registration response and handle messages
                    let mut registered = false;
                    let mut auth_reset = false;
                    let client_for_sending = self.client.clone();

                    // Track proto-level heartbeat responses. The keepalive
                    // task sends HeartbeatRequest every 30s through the
                    // channel. If the server-side channel process is dead
                    // (e.g. admin removed the connector), no HeartbeatResponse
                    // comes back. We detect this and break the loop.
                    let mut last_heartbeat_response = Instant::now();
                    let heartbeat_timeout: Duration =
                        config.heartbeat_timeout.unwrap_or(Duration::from_secs(45));

                    // Grab the heartbeat send timestamp for RTT calculation
                    let heartbeat_sent_at_nanos = {
                        let guard = self.client.read().await;
                        guard.as_ref().map(|c| c.heartbeat_sent_at_nanos().clone())
                    };

                    while !self.shutdown_requested.load(Ordering::SeqCst) {
                        tokio::select! {
                            msg_opt = rx.recv() => {
                                let Some(msg) = msg_opt else {
                                    // Stream closed by server
                                    self.logger.warn("Stream closed by server, will reconnect");
                                    break;
                                };

                                if let Some(proto::stream_message::Message::RegisterResponse(resp)) = msg.message.as_ref() {
                                    if resp.success {
                                        self.logger.info(&format!(
                                            "Registered successfully: {}",
                                            resp.connector_arn
                                        ));
                                        registered = true;

                                        if let Some(client) = client_for_sending.read().await.as_ref() {
                                            client.mark_registered();
                                        }

                                        // Store connector ARN for metrics reporting
                                        *self.connector_arn.write().await = Some(resp.connector_arn.clone());

                                        // Track successful connection in metrics
                                        {
                                            let mut metrics = self.metrics.write().await;
                                            let attempts = self.reconnect_attempts.load(Ordering::SeqCst);
                                            if attempts > 0 {
                                                metrics.successful_reconnects += 1;
                                            }
                                            metrics.last_connected_at_ms = Some(current_time_ms());
                                            metrics.current_backoff_ms = 0;
                                        }

                                        // Reset reconnect attempts and auth failure counter on success
                                        self.reconnect_attempts.store(0, Ordering::SeqCst);
                                        self.consecutive_auth_failures.store(0, Ordering::SeqCst);

                                        // Persist session token for reconnection
                                        if !resp.session_token.is_empty() {
                                            *self.session_token.write().await = Some(resp.session_token.clone());
                                            if let Some(client) = client_for_sending.read().await.as_ref() {
                                                client.set_session_token(resp.session_token.clone()).await;
                                            }
                                        }

                                        // Store OIDC config if provided
                                        if resp.oidc_config.is_some() {
                                            *self.oidc_config.write().await = resp.oidc_config.clone();
                                        }

                                        // Start metrics reporter if enabled
                                        let config = self.config.read().await;
                                        if config.metrics_enabled {
                                            let metrics_interval = config.metrics_interval_ms;
                                            drop(config);
                                            self.start_metrics_reporter(
                                                resp.connector_arn.clone(),
                                                metrics_interval,
                                                client_for_sending.clone(),
                                            );
                                        }
                                        // Continue handling messages - don't break!
                                    } else {
                                        let error_lower = resp.error.to_lowercase();

                                        // Token-level errors: the JWT itself is bad (expired,
                                        // malformed, clock skew) but the credentials (client_id,
                                        // key pair) are fine. Clear cached token and fetch a
                                        // fresh one on reconnect — no approval flow needed.
                                        let is_token_error = error_lower.contains("expired")
                                            || error_lower.contains("jwt_invalid")
                                            || error_lower.contains("jwt_decode")
                                            || error_lower.contains("invalid_token")
                                            || error_lower.contains("token_expired")
                                            || error_lower.contains("invalid token");

                                        // Identity-level errors: the connector's identity
                                        // itself is rejected (de-registered, Keycloak client
                                        // deleted). Full credential wipe needed.
                                        let is_identity_error =
                                            error_lower.contains("auth_invalid")
                                                || error_lower.contains("unauthorized")
                                                || error_lower.contains("unauthenticated");

                                        let is_auth_error = is_token_error || is_identity_error;

                                        // Always clear session token on registration failure
                                        *self.session_token.write().await = None;

                                        if is_auth_error {
                                            let failures = self
                                                .consecutive_auth_failures
                                                .fetch_add(1, Ordering::SeqCst)
                                                + 1;

                                            if is_identity_error {
                                                // Identity rejected — wipe everything, will
                                                // enter pending-approval flow on reconnect.
                                                self.clear_credentials().await;
                                                tracing::warn!(
                                                    "Identity rejected (attempt {}), cleared all \
                                                     credentials — will require re-approval: {}",
                                                    failures,
                                                    resp.error
                                                );
                                            } else {
                                                // Token-level error — clear only the cached
                                                // token so a fresh JWT is fetched using the
                                                // existing credentials and key pair.
                                                {
                                                    let mut ott_guard =
                                                        self.ott_provider.write().await;
                                                    if let Some(ref mut ott) = *ott_guard {
                                                        ott.clear_token_cache();
                                                    }
                                                }
                                                self.config.write().await.auth_token =
                                                    String::new();

                                                if failures >= 5 {
                                                    tracing::error!(
                                                        "Persistent token rejection ({} consecutive \
                                                         failures). Credentials intact but server keeps \
                                                         rejecting fresh JWTs. Possible causes: clock \
                                                         skew, Keycloak misconfiguration, future-dated \
                                                         tokens. Last error: {}",
                                                        failures,
                                                        resp.error
                                                    );
                                                } else {
                                                    tracing::warn!(
                                                        "Token error during registration (attempt {}), \
                                                         cleared cached token and will fetch fresh JWT: {}",
                                                        failures,
                                                        resp.error
                                                    );
                                                }
                                            }

                                            // Break out of the message loop — the outer loop
                                            // will reconnect with backoff and either fetch a
                                            // fresh JWT (token error) or enter pending-approval
                                            // flow (identity error).
                                            auth_reset = true;
                                            break;
                                        }

                                        // Non-auth registration failure (e.g. server still
                                        // starting after a restart). Break out of the message
                                        // loop so the outer reconnect logic retries with
                                        // exponential backoff via the !registered path.
                                        self.logger.warn(&format!(
                                            "Registration failed (will retry): {}",
                                            resp.error
                                        ));
                                        break;
                                    }
                                } else if let Some(proto::stream_message::Message::ExecuteRequest(req)) = msg.message.as_ref() {
                                    // Handle execute request
                                    let request = ExecuteRequest {
                                        request_id: req.request_id.clone(),
                                        payload: req.payload.clone(),
                                        payload_encoding: PayloadEncoding::from(req.payload_encoding),
                                        context: req.context.clone(),
                                        capability_id: if req.capability_id.is_empty() {
                                            None
                                        } else {
                                            Some(req.capability_id.clone())
                                        },
                                    };

                                    // Handle request in background with concurrency limiting
                                    // Semaphore enforces max_concurrent_requests to prevent OOM
                                    let connector = self.connector.clone();
                                    let metrics = self.metrics.clone();
                                    let client_clone = self.client.clone();
                                    let logger = Logger::new("connector");
                                    let semaphore = self.request_semaphore.clone();

                                    tokio::spawn(async move {
                                        // Acquire permit - blocks if at max concurrency
                                        // Permit is released when dropped at end of scope
                                        let _permit = match semaphore.acquire().await {
                                            Ok(permit) => permit,
                                            Err(_) => {
                                                tracing::error!("Request semaphore closed");
                                                return;
                                            }
                                        };

                                        if let Err(e) = Self::handle_request(
                                            connector,
                                            request,
                                            client_clone,
                                            metrics,
                                            logger,
                                        ).await {
                                            tracing::error!("Error handling request: {}", e);
                                        }
                                    });
                                } else if let Some(proto::stream_message::Message::InvokeResponse(resp)) = msg.message.as_ref() {
                                    // Handle invoke response
                                    if let Some(client) = client_for_sending.read().await.as_ref() {
                                        client.handle_invoke_response(resp.clone()).await;
                                    }
                                } else if let Some(proto::stream_message::Message::CredentialsIssued(creds)) = msg.message.as_ref() {
                                    // Handle credentials_issued message (post-approval flow)
                                    self.handle_credentials_issued(creds.clone()).await;

                                    // If reconnect_with_jwt was set, break out of the loop to reconnect
                                    if self.reconnect_with_jwt.load(Ordering::SeqCst) {
                                        self.logger.debug("Breaking message loop to reconnect with JWT");
                                        break;
                                    }
                                } else if let Some(proto::stream_message::Message::ApprovalNotification(notif)) = msg.message.as_ref() {
                                    // Handle admin approval/rejection notifications
                                    let status = proto::RegistrationStatus::try_from(notif.status);
                                    match status {
                                        Ok(proto::RegistrationStatus::Rejected) => {
                                            self.logger.warn(&format!(
                                                "Registration rejected by admin: {}",
                                                if notif.message.is_empty() { "no reason given" } else { &notif.message }
                                            ));

                                            // Clear credentials — admin rejected, so any
                                            // saved state is invalid for this identity.
                                            self.clear_credentials().await;

                                            // Break to outer loop — will reconnect with
                                            // backoff and go through pending approval again.
                                            auth_reset = true;
                                            break;
                                        }
                                        Ok(proto::RegistrationStatus::Approved) => {
                                            self.logger.info("Registration approved by admin");
                                            // CredentialsIssued should follow shortly
                                        }
                                        Ok(proto::RegistrationStatus::Pending) => {
                                            self.logger.info(&format!(
                                                "Registration pending approval: {}",
                                                if notif.message.is_empty() { "awaiting admin" } else { &notif.message }
                                            ));
                                        }
                                        _ => {
                                            self.logger.debug(&format!(
                                                "ApprovalNotification with status={}: {}",
                                                notif.status, notif.message
                                            ));
                                        }
                                    }
                                } else if let Some(proto::stream_message::Message::WsOpenRequest(req)) = msg.message.as_ref() {
                                    let ws_req = WsOpenRequest {
                                        connection_id: req.connection_id.clone(),
                                        path: req.path.clone(),
                                        query_string: req.query_string.clone(),
                                        headers: req.headers.clone(),
                                    };
                                    let connector = self.connector.clone();
                                    let handle = ConnectorHandle::new(self.client.clone());
                                    tokio::spawn(async move {
                                        if let Err(e) = connector.handle_ws_open(ws_req, handle).await {
                                            tracing::error!("Error handling WsOpenRequest: {}", e);
                                        }
                                    });
                                } else if let Some(proto::stream_message::Message::WsFrame(frame)) = msg.message.as_ref() {
                                    let ws_frame = WsFrame {
                                        connection_id: frame.connection_id.clone(),
                                        frame_type: WsFrameType::from(frame.frame_type),
                                        data: frame.data.clone(),
                                    };
                                    let connector = self.connector.clone();
                                    let handle = ConnectorHandle::new(self.client.clone());
                                    tokio::spawn(async move {
                                        if let Err(e) = connector.handle_ws_frame(ws_frame, handle).await {
                                            tracing::error!("Error handling WsFrame: {}", e);
                                        }
                                    });
                                } else if let Some(proto::stream_message::Message::WsCloseRequest(req)) = msg.message.as_ref() {
                                    let ws_req = WsCloseRequest {
                                        connection_id: req.connection_id.clone(),
                                        code: req.code,
                                        reason: req.reason.clone(),
                                    };
                                    self.connector.handle_ws_close(ws_req);
                                } else if let Some(proto::stream_message::Message::HeartbeatResponse(_)) = msg.message.as_ref() {
                                    last_heartbeat_response = Instant::now();

                                    if let Some(ref sent_at) = heartbeat_sent_at_nanos {
                                        let sent_nanos = sent_at.load(Ordering::Acquire);
                                        if sent_nanos > 0 {
                                            let now_nanos = SystemTime::now()
                                                .duration_since(UNIX_EPOCH)
                                                .unwrap_or_default()
                                                .as_nanos() as u64;
                                            let rtt_ms = (now_nanos.saturating_sub(sent_nanos)) as f64 / 1_000_000.0;
                                            self.metrics.write().await.record_heartbeat_rtt(rtt_ms);
                                        }
                                    }
                                }
                            }
                            _ = sleep(Duration::from_millis(100)) => {
                                // Shutdown poll interval + heartbeat liveness check.
                                // If no HeartbeatResponse has arrived within the
                                // timeout, the server-side channel process is likely
                                // dead (e.g. admin removed the connector). Break to
                                // trigger reconnect.
                                if registered && last_heartbeat_response.elapsed() > heartbeat_timeout {
                                    self.logger.warn(&format!(
                                        "No heartbeat response for {}s, connection presumed dead",
                                        last_heartbeat_response.elapsed().as_secs()
                                    ));
                                    break;
                                }
                            }
                        }
                    }

                    // After loop exits (stream closed, shutdown, or auth reset)
                    if !registered && !auth_reset {
                        // Registration did not succeed. This covers two cases:
                        // 1. Server closed the stream before sending a RegisterResponse
                        // 2. Server responded with a non-auth registration failure
                        //    (e.g. server still starting during a rolling restart)
                        // Treat as transient and retry with backoff.
                        if self.shutdown_requested.load(Ordering::SeqCst) {
                            break;
                        }
                        let attempt = self.reconnect_attempts.fetch_add(1, Ordering::SeqCst);
                        let cfg = self.config.read().await.clone();
                        let delay = calculate_reconnect_delay(
                            attempt,
                            cfg.reconnect_delay_ms,
                            cfg.max_backoff_delay_ms,
                            cfg.reconnect_jitter_ms,
                        );
                        self.error_logger.log_error(
                            &self.logger,
                            "Stream closed before registration completed, retrying",
                            &format!("backoff {delay}ms"),
                        );
                        let mut remaining = delay;
                        while remaining > 0 && !self.shutdown_requested.load(Ordering::SeqCst) {
                            let wait = std::cmp::min(remaining, 100);
                            sleep(Duration::from_millis(wait)).await;
                            remaining = remaining.saturating_sub(wait);
                        }
                        continue;
                    }

                    // Auth reset: either token was bad (credentials kept, will fetch
                    // fresh JWT) or identity was rejected (credentials wiped, will
                    // enter pending-approval flow). Reconnect with backoff.
                    if auth_reset {
                        self.logger
                            .info("Auth failure handled, reconnecting with backoff...");
                        let attempt = self.reconnect_attempts.fetch_add(1, Ordering::SeqCst);
                        let config = self.config.read().await.clone();
                        let delay = calculate_reconnect_delay(
                            attempt,
                            config.reconnect_delay_ms,
                            config.max_backoff_delay_ms,
                            config.reconnect_jitter_ms,
                        );
                        let mut remaining = delay;
                        while remaining > 0 && !self.shutdown_requested.load(Ordering::SeqCst) {
                            let wait = std::cmp::min(remaining, 100);
                            sleep(Duration::from_millis(wait)).await;
                            remaining = remaining.saturating_sub(wait);
                        }
                        if self.shutdown_requested.load(Ordering::SeqCst) {
                            break;
                        }
                        continue;
                    }

                    self.logger.info("Connection ended, checking reconnect...");

                    // If reconnect_with_jwt was set, loop back to reconnect with JWT
                    if self.reconnect_with_jwt.load(Ordering::SeqCst) {
                        self.logger.debug("Reconnecting with JWT authentication...");
                        // Reset the flag so we don't keep reconnecting
                        self.reconnect_with_jwt.store(false, Ordering::SeqCst);
                        sleep(Duration::from_millis(100)).await;
                        continue;
                    }

                    // Stream closed after successful registration.
                    // The server just drops the connection (GenServer.stop) —
                    // no special close reason is sent. We can't distinguish
                    // admin de-registration from a server restart here.
                    //
                    // Strategy: keep credentials, quick reconnect. If the
                    // connector was de-registered, the Keycloak client is
                    // deleted, so the next token refresh (top of loop) will
                    // fail with 401 → auth_token cleared → registers without
                    // JWT → enters pending-approval flow.
                    let config = self.config.read().await.clone();
                    if config.reconnect_enabled && !self.shutdown_requested.load(Ordering::SeqCst) {
                        // Track disconnect in metrics
                        {
                            let mut metrics = self.metrics.write().await;
                            metrics.total_disconnects += 1;
                            metrics.last_disconnect_reason = Some("stream closed".to_string());
                            metrics.last_disconnected_at_ms = Some(current_time_ms());
                            metrics.reconnection_attempts += 1;
                        }

                        self.reconnect_attempts.store(0, Ordering::SeqCst);
                        self.logger.info("Stream closed, reconnecting...");
                        sleep(Duration::from_millis(100)).await;
                    }
                }
                Err(e) => {
                    // Check if this is a reconnection request (from credentials_issued flow)
                    if e.code() == "RECONNECT_REQUIRED" {
                        self.logger.debug("Reconnecting with JWT authentication...");
                        sleep(Duration::from_millis(100)).await;
                        continue;
                    }

                    // Track disconnect in metrics
                    {
                        let mut metrics = self.metrics.write().await;
                        metrics.total_disconnects += 1;
                        metrics.last_disconnect_reason = Some(e.to_string());
                        metrics.last_disconnected_at_ms = Some(current_time_ms());
                    }

                    // Use rate-limited logging to avoid spam during extended outages
                    self.error_logger
                        .log_error(&self.logger, "Connection failed", &e.to_string());

                    let config = self.config.read().await.clone();
                    if config.reconnect_enabled && e.is_recoverable() {
                        // Calculate delay with exponential backoff and jitter
                        // Retries indefinitely at max backoff delay
                        let attempt = self.reconnect_attempts.fetch_add(1, Ordering::SeqCst);
                        let delay = calculate_reconnect_delay(
                            attempt,
                            config.reconnect_delay_ms,
                            config.max_backoff_delay_ms,
                            config.reconnect_jitter_ms,
                        );

                        // Track metrics
                        {
                            let mut metrics = self.metrics.write().await;
                            metrics.reconnection_attempts += 1;
                            metrics.current_backoff_ms = delay;
                        }

                        self.logger.warn(&format!(
                            "Reconnecting in {}ms (attempt {}, max_backoff: {}ms)...",
                            delay,
                            attempt + 1,
                            config.max_backoff_delay_ms
                        ));

                        // Interruptible sleep - check for shutdown every 100ms
                        let mut remaining = delay;
                        while remaining > 0 && !self.shutdown_requested.load(Ordering::SeqCst) {
                            let wait = std::cmp::min(remaining, 100);
                            sleep(Duration::from_millis(wait)).await;
                            remaining = remaining.saturating_sub(wait);
                        }
                        if self.shutdown_requested.load(Ordering::SeqCst) {
                            break;
                        }
                        continue;
                    } else {
                        if !e.is_recoverable() {
                            self.logger.error(
                                "Non-recoverable error, stopping reconnection",
                                &e.to_string(),
                            );
                        }
                        return Err(e);
                    }
                }
            }
        }

        self.cleanup().await;
        Ok(())
    }

    /// Handle a single request
    async fn handle_request(
        connector: Arc<dyn BaseConnector>,
        request: ExecuteRequest,
        client: Arc<RwLock<Option<ConnectorClient>>>,
        metrics: Arc<RwLock<ConnectorMetrics>>,
        logger: Logger,
    ) -> Result<()> {
        let start_time = Instant::now();
        let mut metrics_guard = metrics.write().await;
        metrics_guard.requests_received += 1;
        metrics_guard.bytes_received += request.payload.len() as u64;
        metrics_guard.last_request_at_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;
        drop(metrics_guard);

        let response = match deserialize_payload::<serde_json::Value>(
            &request.payload,
            request.payload_encoding,
        ) {
            Ok(request_data) => {
                match connector
                    .execute_with_context(
                        request_data,
                        request.capability_id.as_deref(),
                        &request.context,
                    )
                    .await
                {
                    Ok(response_data) => {
                        match serialize_payload(&response_data, PayloadEncoding::Json) {
                            Ok(payload) => {
                                let duration_ms = start_time.elapsed().as_millis() as u64;
                                let mut metrics_guard = metrics.write().await;
                                metrics_guard.requests_processed += 1;
                                metrics_guard.bytes_sent += payload.len() as u64;
                                metrics_guard.total_duration_ms += duration_ms;
                                drop(metrics_guard);

                                ExecuteResponse {
                                    request_id: request.request_id,
                                    success: true,
                                    payload,
                                    payload_encoding: PayloadEncoding::Json,
                                    error: String::new(),
                                    duration_ms,
                                }
                            }
                            Err(e) => {
                                logger.error("Serialization failed", &e.to_string());
                                let mut metrics_guard = metrics.write().await;
                                metrics_guard.requests_failed += 1;
                                drop(metrics_guard);

                                ExecuteResponse {
                                    request_id: request.request_id,
                                    success: false,
                                    payload: error_response(&e.to_string()).unwrap_or_default(),
                                    payload_encoding: PayloadEncoding::Json,
                                    error: e.to_string(),
                                    duration_ms: start_time.elapsed().as_millis() as u64,
                                }
                            }
                        }
                    }
                    Err(e) => {
                        logger.error("Execution failed", &e.to_string());
                        let mut metrics_guard = metrics.write().await;
                        metrics_guard.requests_failed += 1;
                        drop(metrics_guard);

                        ExecuteResponse {
                            request_id: request.request_id,
                            success: false,
                            payload: error_response(&e.to_string()).unwrap_or_default(),
                            payload_encoding: PayloadEncoding::Json,
                            error: e.to_string(),
                            duration_ms: start_time.elapsed().as_millis() as u64,
                        }
                    }
                }
            }
            Err(e) => {
                logger.error("Deserialization failed", &e.to_string());
                let mut metrics_guard = metrics.write().await;
                metrics_guard.requests_failed += 1;
                drop(metrics_guard);

                ExecuteResponse {
                    request_id: request.request_id,
                    success: false,
                    payload: error_response(&e.to_string()).unwrap_or_default(),
                    payload_encoding: PayloadEncoding::Json,
                    error: e.to_string(),
                    duration_ms: start_time.elapsed().as_millis() as u64,
                }
            }
        };

        // Send response -- clone sender under lock, drop lock, then send
        let tx = {
            let client_guard = client.read().await;
            match client_guard.as_ref() {
                Some(c) => Some(c.clone_message_tx().await?),
                None => None,
            }
        };
        if let Some(tx) = tx {
            let message = ProtoStreamMessage {
                message: Some(
                    strike48_proto::proto::stream_message::Message::ExecuteResponse(
                        strike48_proto::proto::ExecuteResponse {
                            request_id: response.request_id,
                            success: response.success,
                            payload: response.payload,
                            payload_encoding: response.payload_encoding as i32,
                            error: response.error,
                            duration_ms: response.duration_ms as i64,
                        },
                    ),
                ),
            };
            tx.send(message).map_err(|e| {
                ConnectorError::StreamError(format!("Failed to send response: {e}"))
            })?;
        }

        Ok(())
    }

    /// Validate configuration
    async fn validate_config(&self) -> Result<()> {
        let config = self.config.read().await;
        if config.host.is_empty() {
            return Err(ConnectorError::InvalidConfig(
                "host is required".to_string(),
            ));
        }

        if config.tenant_id.is_empty() {
            return Err(ConnectorError::InvalidConfig(
                "tenant_id is required".to_string(),
            ));
        }

        if config.max_concurrent_requests < 1 {
            return Err(ConnectorError::InvalidConfig(
                "max_concurrent_requests must be >= 1".to_string(),
            ));
        }

        Ok(())
    }

    /// Shutdown the connector
    pub fn shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        self.logger.info("Shutting down connector");
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> ConnectorMetrics {
        self.metrics.read().await.clone()
    }

    /// Get detailed statistics
    pub async fn get_stats(&self) -> serde_json::Value {
        let metrics = self.metrics.read().await;
        let uptime_ms = if let Some(start) = *self.start_time.read().await {
            start.elapsed().as_millis() as u64
        } else {
            0
        };
        let avg_duration = if metrics.requests_processed > 0 {
            metrics.total_duration_ms as f64 / metrics.requests_processed as f64
        } else {
            0.0
        };
        let config = self.config.read().await;
        let instance_id = config.instance_id.clone();
        let host = config.host.clone();
        let tenant_id = config.tenant_id.clone();
        let use_tls = config.use_tls;
        let transport_type = format!("{:?}", config.transport_type);
        drop(config);

        serde_json::json!({
            // Request metrics
            "requests_received": metrics.requests_received,
            "requests_processed": metrics.requests_processed,
            "requests_failed": metrics.requests_failed,
            "avg_latency_ms": avg_duration,
            "total_duration_ms": metrics.total_duration_ms,
            "bytes_received": metrics.bytes_received,
            "bytes_sent": metrics.bytes_sent,
            // Uptime
            "uptime_ms": uptime_ms,
            "uptime_seconds": uptime_ms / 1000,
            // Connection state
            "running": self.running.load(Ordering::SeqCst),
            "connector_type": self.connector.connector_type(),
            "instance_id": instance_id,
            "version": self.connector.version(),
            "host": host,
            "tenant_id": tenant_id,
            "use_tls": use_tls,
            "transport_type": transport_type,
            // Resilience metrics
            "reconnection_attempts": metrics.reconnection_attempts,
            "total_disconnects": metrics.total_disconnects,
            "successful_reconnects": metrics.successful_reconnects,
            "last_disconnect_reason": metrics.last_disconnect_reason,
            "last_connected_at_ms": metrics.last_connected_at_ms,
            "last_disconnected_at_ms": metrics.last_disconnected_at_ms,
            "current_backoff_ms": metrics.current_backoff_ms,
            "last_request_at_ms": metrics.last_request_at_ms,
            // Heartbeat RTT
            "heartbeat_rtt_avg_ms": metrics.heartbeat_rtt_avg_ms(),
            "heartbeat_rtt_last_ms": metrics.heartbeat_rtt_last_ms,
            "heartbeat_rtt_min_ms": metrics.heartbeat_rtt_min_ms,
            "heartbeat_rtt_max_ms": metrics.heartbeat_rtt_max_ms,
            "heartbeat_rtt_count": metrics.heartbeat_rtt_count,
        })
    }

    /// Start the metrics reporter background task.
    /// Sends MetricsReport to Strike48 every `interval_ms` milliseconds.
    /// Only spawns one reporter - subsequent calls are no-ops.
    fn start_metrics_reporter(
        &self,
        connector_arn: String,
        interval_ms: u64,
        client: Arc<RwLock<Option<ConnectorClient>>>,
    ) {
        // Use compare_exchange to ensure only one reporter runs
        // If already running (true), return early
        if self
            .metrics_reporter_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            // Already running, skip
            return;
        }

        let running = self.running.clone();
        let metrics = self.metrics.clone();
        let start_time = self.start_time.clone();
        let metrics_storage = self.metrics_storage.clone();
        let metrics_reporter_running = self.metrics_reporter_running.clone();
        let logger = Logger::new("metrics");

        tokio::spawn(async move {
            logger.debug(&format!(
                "Metrics reporter started (interval: {interval_ms}ms)"
            ));

            loop {
                tokio::time::sleep(tokio::time::Duration::from_millis(interval_ms)).await;

                // Check if still running
                if !running.load(Ordering::SeqCst) {
                    logger.debug("Metrics reporter stopping (connector not running)");
                    break;
                }

                // Build and send metrics report
                if let Err(e) = Self::send_metrics_report(
                    &connector_arn,
                    &metrics,
                    &start_time,
                    &client,
                    &metrics_storage,
                    &logger,
                )
                .await
                {
                    logger.debug(&format!("Failed to send metrics: {e}"));
                }
            }

            // Reset flag so reporter can be restarted on next connection
            metrics_reporter_running.store(false, Ordering::SeqCst);
        });
    }

    /// Build and send a MetricsReport message to Strike48.
    async fn send_metrics_report(
        connector_arn: &str,
        metrics: &Arc<RwLock<ConnectorMetrics>>,
        start_time: &Arc<RwLock<Option<Instant>>>,
        client: &Arc<RwLock<Option<ConnectorClient>>>,
        metrics_storage: &crate::metrics_recorder::MetricsStorage,
        logger: &Logger,
    ) -> Result<()> {
        let metrics_snapshot = metrics.read().await;
        let uptime_seconds = if let Some(start) = *start_time.read().await {
            start.elapsed().as_secs_f64()
        } else {
            0.0
        };

        let avg_latency_ms = if metrics_snapshot.requests_processed > 0 {
            metrics_snapshot.total_duration_ms as f64 / metrics_snapshot.requests_processed as f64
        } else {
            0.0
        };

        // Merge: connector metrics (from `metrics` crate) first,
        // then SDK metrics (system resources, RTT) — SDK wins on collision
        let mut custom_metrics = metrics_storage.snapshot();
        custom_metrics.extend(metrics_snapshot.sdk_custom_metrics());

        let report = proto::MetricsReport {
            connector_arn: connector_arn.to_string(),
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            requests_received: metrics_snapshot.requests_received as i64,
            requests_processed: metrics_snapshot.requests_processed as i64,
            requests_failed: metrics_snapshot.requests_failed as i64,
            avg_latency_ms,
            total_duration_ms: metrics_snapshot.total_duration_ms as f64,
            bytes_received: metrics_snapshot.bytes_received as i64,
            bytes_sent: metrics_snapshot.bytes_sent as i64,
            reconnection_attempts: metrics_snapshot.reconnection_attempts as i64,
            total_disconnects: metrics_snapshot.total_disconnects as i64,
            successful_reconnects: metrics_snapshot.successful_reconnects as i64,
            uptime_seconds,
            last_request_at_ms: metrics_snapshot.last_request_at_ms as i64,
            custom_metrics,
        };

        drop(metrics_snapshot);

        // Clone sender under lock, drop lock, then send
        let tx = {
            let client_guard = client.read().await;
            match client_guard.as_ref() {
                Some(c) => Some(c.clone_message_tx().await?),
                None => None,
            }
        };
        if let Some(tx) = tx {
            let message = proto::StreamMessage {
                message: Some(proto::stream_message::Message::MetricsReport(report)),
            };
            tx.send(message)
                .map_err(|e| ConnectorError::StreamError(format!("Failed to send metrics: {e}")))?;
            logger.debug(&format!(
                "Sent metrics (requests={}, uptime={:.0}s)",
                metrics.read().await.requests_processed,
                uptime_seconds
            ));
        }

        Ok(())
    }

    /// Invoke a capability on another connector through Strike48 routing.
    /// High-level helper that handles JSON serialization/deserialization.
    pub async fn invoke_capability(
        &self,
        target_address: &str,
        payload: serde_json::Value,
        options: InvokeCapabilityOptions,
    ) -> Result<Option<serde_json::Value>> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(ConnectorError::NotRunning);
        }

        let timeout_ms = options.timeout_ms.unwrap_or(self.connector.timeout_ms());
        let payload_bytes = serialize_payload(&payload, PayloadEncoding::Json)?;

        let handle = ConnectorHandle::new(self.client.clone());
        let invoke_options = InvokeOptions {
            payload_encoding: Some(PayloadEncoding::Json),
            capability_id: options.capability_id,
            timeout_ms: Some(timeout_ms),
            fire_and_forget: options.fire_and_forget,
            context: options.context,
        };

        let response = handle
            .invoke_capability(target_address, payload_bytes, invoke_options)
            .await?;

        match response {
            None => Ok(None),
            Some(invoke_response) => {
                if !invoke_response.success {
                    return Err(ConnectorError::InvokeFailed(invoke_response.error));
                }

                if !invoke_response.payload.is_empty() {
                    let response_data: serde_json::Value = deserialize_payload(
                        &invoke_response.payload,
                        invoke_response.payload_encoding,
                    )?;
                    Ok(Some(response_data))
                } else {
                    Ok(Some(serde_json::json!({})))
                }
            }
        }
    }

    /// Cleanup resources
    async fn cleanup(&self) {
        self.logger.debug("Cleaning up");
        let mut client_guard = self.client.write().await;
        if let Some(mut client) = client_guard.take() {
            client.disconnect().await;
        }
        self.running.store(false, Ordering::SeqCst);
        self.logger.info("Shutdown complete");
    }

    /// Initialize authentication by loading persisted credentials and fetching JWT
    async fn initialize_auth(&self) -> Result<()> {
        let instance_id = {
            let config = self.config.read().await;
            config.instance_id.clone()
        };
        let mut ott_provider = OttProvider::new(
            Some(self.connector.connector_type().to_string()),
            Some(instance_id.clone()),
        );

        // Priority 1: Check for direct configuration (cert-manager / direct auth)
        if ott_provider.has_direct_config() {
            self.logger
                .debug("Direct configuration detected (cert-manager/direct auth mode)");
            let credentials = ott_provider.initialize_from_direct_config()?;
            self.logger.debug(&format!(
                "Direct config initialized: {}",
                credentials.client_id
            ));
            *self.ott_provider.write().await = Some(ott_provider);

            // Get token immediately
            let mut ott_guard = self.ott_provider.write().await;
            if let Some(ref mut ott) = *ott_guard {
                let auth_token = ott.get_token().await?;
                self.config.write().await.auth_token = auth_token;
            }
            return Ok(());
        }

        // Priority 2: Check for OTT (pre-approval flow)
        if ott_provider.has_ott() {
            self.logger
                .debug("OTT detected, attempting pre-approval registration");
            let credentials = ott_provider
                .register_with_ott(self.connector.connector_type(), Some(&instance_id))
                .await?;
            self.logger.debug(&format!(
                "OTT registration successful: {}",
                credentials.client_id
            ));
            *self.ott_provider.write().await = Some(ott_provider);

            // Get token immediately
            let mut ott_guard = self.ott_provider.write().await;
            if let Some(ref mut ott) = *ott_guard {
                let auth_token = ott.get_token().await?;
                self.config.write().await.auth_token = auth_token;
            }
            return Ok(());
        }

        // Priority 3: Check for saved OTT credentials
        self.logger.debug(&format!(
            "Checking for saved credentials: connector_type={}, instance_id={}",
            self.connector.connector_type(),
            instance_id
        ));
        if let Some(saved_creds) =
            ott_provider.load_saved_credentials(self.connector.connector_type(), Some(&instance_id))
        {
            self.logger.debug(&format!(
                "Loaded saved credentials for client_id: {}",
                saved_creds.client_id
            ));
            *self.ott_provider.write().await = Some(ott_provider);

            // Get token
            let mut ott_guard = self.ott_provider.write().await;
            if let Some(ref mut ott) = *ott_guard {
                match ott.get_token().await {
                    Ok(auth_token) => {
                        self.logger
                            .debug("Successfully fetched JWT from saved credentials");
                        self.config.write().await.auth_token = auth_token;
                    }
                    Err(e) => {
                        self.logger
                            .error("Failed to get JWT from saved credentials", &e.to_string());
                        // Fall through to post-approval flow
                        return Ok(());
                    }
                }
            }
            return Ok(());
        }

        // Priority 4: No auth available, will use post-approval flow
        self.logger
            .debug("No saved credentials found, will use post-approval flow");
        Ok(())
    }

    /// Build a RegisterRequest StreamMessage from current connector config and capabilities.
    /// Used for both initial registration and in-stream re-registration after JWT acquisition.
    fn build_register_request(
        &self,
        config: &ConnectorConfig,
        jwt_token: &str,
        session_token: &str,
    ) -> proto::StreamMessage {
        let capabilities_proto = proto::ConnectorCapabilities {
            connector_type: self.connector.connector_type().to_string(),
            version: self.connector.version().to_string(),
            supported_encodings: self
                .connector
                .supported_encodings()
                .iter()
                .map(|e| *e as i32)
                .collect(),
            behaviors: self
                .connector
                .behaviors()
                .iter()
                .map(|b| *b as i32)
                .collect(),
            metadata: build_registration_metadata(self.connector.as_ref()),
            task_types: {
                let caps = self.connector.capabilities();
                if caps.is_empty() {
                    Vec::new()
                } else {
                    caps.iter()
                        .map(|tt| proto::TaskTypeSchema {
                            task_type_id: tt.task_type_id.clone(),
                            name: tt.name.clone(),
                            description: tt.description.clone(),
                            category: tt.category.clone(),
                            icon: tt.icon.clone(),
                            input_schema_json: tt.input_schema_json.clone(),
                            output_schema_json: tt.output_schema_json.clone(),
                        })
                        .collect()
                }
            },
        };

        let sanitized_instance_id = sanitize_identifier(&config.instance_id);

        let mut metadata = config.metadata.clone();
        crate::sdk_metadata::merge_into(
            &mut metadata,
            &config.transport_type.to_string(),
            config.use_tls,
        );

        let instance_metadata = Some(proto::InstanceMetadata {
            display_name: config
                .display_name
                .clone()
                .unwrap_or_else(|| sanitized_instance_id.clone()),
            tags: config.tags.clone(),
            metadata,
        });

        let register_request = proto::RegisterConnectorRequest {
            tenant_id: sanitize_identifier(&config.tenant_id),
            connector_type: sanitize_identifier(self.connector.connector_type()),
            instance_id: sanitized_instance_id,
            capabilities: Some(capabilities_proto),
            jwt_token: jwt_token.to_string(),
            session_token: session_token.to_string(),
            scope: 0,
            instance_metadata,
        };

        proto::StreamMessage {
            message: Some(proto::stream_message::Message::RegisterRequest(
                register_request,
            )),
        }
    }

    /// Handle credentials_issued message from server (post-approval flow)
    async fn handle_credentials_issued(&self, creds: crate::client::proto::CredentialsIssued) {
        self.logger
            .debug("Received credentials_issued message from server (post-approval)");

        if creds.ott.is_empty() {
            self.logger
                .error("No OTT in credentials_issued message", "");
            return;
        }

        // [STRIKE48-PATCH connector-owns-callback-origin]
        // `creds.matrix_api_url` is advisory, not authoritative. In a
        // multi-tenant studio it is a single global fallback that cannot name
        // each tenant's host, and it degrades to a localhost placeholder when
        // the deployment has not configured one. The connector already knows
        // which host it dialed, so it resolves its own callback base — and an
        // empty server value is therefore no longer fatal.
        let (instance_id, dialed_host, use_tls) = {
            let config = self.config.read().await;
            (
                config.instance_id.clone(),
                config.host.clone(),
                config.use_tls,
            )
        };

        let configured_api_url = std::env::var("STRIKE48_API_URL").ok();
        let Some(api_base) = OttProvider::resolve_register_base(
            configured_api_url.as_deref(),
            Some(&dialed_host),
            use_tls,
            &creds.matrix_api_url,
        ) else {
            self.logger.error(
                "Cannot resolve an OTT registration URL: STRIKE48_API_URL unset, no dialed host, \
                 and the server supplied none",
                "",
            );
            return;
        };

        if creds.matrix_api_url.trim().trim_end_matches('/') != api_base {
            self.logger.debug(&format!(
                "OTT callback base overridden: server advertised {:?}, using {:?}",
                creds.matrix_api_url, api_base
            ));
        }
        let mut ott_provider = OttProvider::new(
            Some(self.connector.connector_type().to_string()),
            Some(instance_id.clone()),
        );

        // Register public key with OTT
        match ott_provider
            .register_public_key_with_ott_data(
                &creds.ott,
                &api_base,
                &creds.register_url,
                self.connector.connector_type(),
                Some(&instance_id),
            )
            .await
        {
            Ok(response) => {
                self.logger.debug(&format!(
                    "Registered public key with OTT. Client ID: {}",
                    response.client_id
                ));

                // Get JWT using private_key_jwt
                match ott_provider.get_token().await {
                    Ok(jwt_token) => {
                        self.logger
                            .debug("Fetched JWT using private_key_jwt, upgrading session in-place");
                        self.config.write().await.auth_token = jwt_token.clone();
                        *self.ott_provider.write().await = Some(ott_provider);

                        // Re-register on the existing stream with the JWT instead of
                        // disconnecting. The server validates the JWT, starts a ConnectorSession,
                        // and responds with APPROVED + session_token. The existing message loop
                        // handles the RegisterResponse, so no reconnect cycle is needed.
                        let config = self.config.read().await.clone();
                        let register_msg = self.build_register_request(&config, &jwt_token, "");
                        let send_result = {
                            let client_guard = self.client.read().await;
                            if let Some(ref client) = *client_guard {
                                client.send_message(register_msg).await
                            } else {
                                Err(ConnectorError::NotConnected)
                            }
                        };
                        match send_result {
                            Ok(()) => {
                                self.logger.info(
                                    "Sent JWT re-registration on existing stream (no disconnect)",
                                );
                            }
                            Err(e) => {
                                // Fallback: disconnect to trigger the reconnection path.
                                // JWT is already stored in config so the next connection uses it.
                                self.logger.warn(&format!(
                                    "In-stream re-register failed: {}, falling back to reconnect",
                                    e
                                ));
                                self.reconnect_with_jwt.store(true, Ordering::SeqCst);
                                let mut client_guard = self.client.write().await;
                                if let Some(ref mut client) = *client_guard {
                                    client.disconnect().await;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        self.logger
                            .error("Failed to get JWT using private_key_jwt", &e.to_string());
                    }
                }
            }
            Err(e) => {
                self.logger
                    .error("Failed to complete OTT registration", &e.to_string());
            }
        }
    }
}

/// Options for invoking a capability on another connector via
/// [`ConnectorRunner::invoke_capability`].
///
/// All fields are optional and use sensible defaults when omitted.
#[derive(Debug, Clone, Default)]
pub struct InvokeCapabilityOptions {
    /// Target capability to invoke. If `None`, the default capability is used.
    pub capability_id: Option<String>,
    /// Request timeout in milliseconds. Defaults to the connector's configured timeout.
    pub timeout_ms: Option<u64>,
    /// If `true`, send the request without waiting for a response.
    pub fire_and_forget: Option<bool>,
    /// Arbitrary key-value context forwarded with the request.
    pub context: Option<HashMap<String, String>>,
}

pub(crate) use strike48_proto::proto;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_heartbeat_roundtrip() {
        let cfg = ConnectorConfig::default()
            .with_heartbeat(Duration::from_secs(7), Duration::from_secs(20));
        assert_eq!(cfg.heartbeat_interval, Some(Duration::from_secs(7)));
        assert_eq!(cfg.heartbeat_timeout, Some(Duration::from_secs(20)));
    }

    #[test]
    fn test_with_heartbeat_misordered_pair_is_still_applied() {
        // Validation only emits a tracing::warn!; the values are still
        // applied so operators can opt into aggressive timeouts knowingly.
        let cfg = ConnectorConfig::default()
            .with_heartbeat(Duration::from_secs(30), Duration::from_secs(10));
        assert_eq!(cfg.heartbeat_interval, Some(Duration::from_secs(30)));
        assert_eq!(cfg.heartbeat_timeout, Some(Duration::from_secs(10)));
    }

    #[test]
    fn test_default_heartbeat_is_none() {
        let cfg = ConnectorConfig::default();
        assert!(cfg.heartbeat_interval.is_none());
        assert!(cfg.heartbeat_timeout.is_none());
    }

    #[test]
    fn test_display_name() {
        let config = ConnectorConfig::default().display_name("My Server");

        assert_eq!(config.display_name, Some("My Server".to_string()));
    }

    #[test]
    fn test_single_tag() {
        let config = ConnectorConfig::default().tag("prod");

        assert_eq!(config.tags, vec!["prod"]);
    }

    #[test]
    fn test_multiple_tags() {
        let config = ConnectorConfig::default()
            .tag("prod")
            .tag("us-east-1")
            .tags(["high-memory", "ssd"]);

        assert_eq!(config.tags, vec!["prod", "us-east-1", "high-memory", "ssd"]);
    }

    #[test]
    fn test_metadata() {
        let config = ConnectorConfig::default()
            .with_metadata("location", "us-east-1")
            .with_metadata("owner", "platform");

        assert_eq!(
            config.metadata.get("location"),
            Some(&"us-east-1".to_string())
        );
        assert_eq!(config.metadata.get("owner"), Some(&"platform".to_string()));
    }

    #[test]
    fn test_metadata_from_env() {
        // Set test env vars
        // SAFETY: test-only; we accept the risk of concurrent env mutation in tests.
        unsafe {
            std::env::set_var("TESTMETA_LOCATION", "us-east-1");
            std::env::set_var("TESTMETA_OWNER", "platform");
        }

        let config = ConnectorConfig::default().metadata_from_env("TESTMETA_");

        assert_eq!(
            config.metadata.get("location"),
            Some(&"us-east-1".to_string())
        );
        assert_eq!(config.metadata.get("owner"), Some(&"platform".to_string()));

        // Clean up
        // SAFETY: test-only cleanup.
        unsafe {
            std::env::remove_var("TESTMETA_LOCATION");
            std::env::remove_var("TESTMETA_OWNER");
        }
    }

    #[test]
    fn test_config_defaults_no_metadata() {
        let config = ConnectorConfig::default();

        assert_eq!(config.display_name, None);
        assert!(config.tags.is_empty());
        assert!(config.metadata.is_empty());
    }

    #[test]
    fn test_builder_chain() {
        let config = ConnectorConfig::default()
            .display_name("Production Server 1")
            .tag("prod")
            .tag("us-east-1")
            .with_metadata("owner", "platform-team")
            .with_metadata("cost-center", "engineering");

        assert_eq!(config.display_name, Some("Production Server 1".to_string()));
        assert_eq!(config.tags, vec!["prod", "us-east-1"]);
        assert_eq!(config.metadata.len(), 2);
    }

    #[test]
    fn test_metrics_config_defaults() {
        let config = ConnectorConfig::default();
        assert!(config.metrics_enabled);
        assert_eq!(config.metrics_interval_ms, 30000);
    }

    #[test]
    fn test_metrics_config_from_env() {
        // SAFETY: test-only; we accept the risk of concurrent env mutation in tests.
        unsafe {
            std::env::set_var("STRIKE48_METRICS_ENABLED", "false");
            std::env::set_var("STRIKE48_METRICS_INTERVAL_MS", "15000");
        }

        let config = ConnectorConfig::from_env();
        assert!(!config.metrics_enabled);
        assert_eq!(config.metrics_interval_ms, 15000);

        // Test "0" also disables metrics
        // SAFETY: test-only.
        unsafe {
            std::env::set_var("STRIKE48_METRICS_ENABLED", "0");
        }
        let config2 = ConnectorConfig::from_env();
        assert!(!config2.metrics_enabled);

        // Test any other value enables metrics
        // SAFETY: test-only.
        unsafe {
            std::env::set_var("STRIKE48_METRICS_ENABLED", "true");
        }
        let config3 = ConnectorConfig::from_env();
        assert!(config3.metrics_enabled);

        // Clean up
        // SAFETY: test-only cleanup.
        unsafe {
            std::env::remove_var("STRIKE48_METRICS_ENABLED");
            std::env::remove_var("STRIKE48_METRICS_INTERVAL_MS");
        }
    }

    // =========================================================================
    // Session token validation (is_session_token_valid)
    // =========================================================================

    /// Helper: build a session token with the given exp claim.
    fn make_session_token(exp: u64) -> String {
        use base64::Engine;
        let payload = serde_json::json!({ "exp": exp, "sub": "test" });
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        // Fake signature part — only the payload matters for validation
        format!("{payload_b64}.fakesig")
    }

    #[test]
    fn test_session_token_valid_future_exp() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = make_session_token(now + 3600); // expires in 1 hour
        assert!(is_session_token_valid(&token, 30));
    }

    #[test]
    fn test_session_token_expired() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = make_session_token(now - 60); // expired 1 minute ago
        assert!(!is_session_token_valid(&token, 30));
    }

    #[test]
    fn test_session_token_within_buffer() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Expires in 20s, but buffer is 30s — should be considered expired
        let token = make_session_token(now + 20);
        assert!(!is_session_token_valid(&token, 30));
    }

    #[test]
    fn test_session_token_exactly_at_buffer_boundary() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Expires in exactly 30s with 30s buffer — now == exp - buffer, so invalid (not <)
        let token = make_session_token(now + 30);
        assert!(!is_session_token_valid(&token, 30));
    }

    #[test]
    fn test_session_token_just_past_buffer() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Expires in 31s with 30s buffer — should be valid
        let token = make_session_token(now + 31);
        assert!(is_session_token_valid(&token, 30));
    }

    #[test]
    fn test_session_token_zero_buffer() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = make_session_token(now + 1);
        assert!(is_session_token_valid(&token, 0));
    }

    #[test]
    fn test_session_token_invalid_no_dot() {
        assert!(!is_session_token_valid("nodottoken", 30));
    }

    #[test]
    fn test_session_token_invalid_bad_base64() {
        assert!(!is_session_token_valid("!!!invalid!!!.fakesig", 30));
    }

    #[test]
    fn test_session_token_invalid_not_json() {
        use base64::Engine;
        let not_json = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"not json");
        assert!(!is_session_token_valid(&format!("{not_json}.sig"), 30));
    }

    #[test]
    fn test_session_token_missing_exp_claim() {
        use base64::Engine;
        let payload = serde_json::json!({ "sub": "test" }); // no exp
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        assert!(!is_session_token_valid(&format!("{b64}.sig"), 30));
    }

    #[test]
    fn test_session_token_empty_string() {
        assert!(!is_session_token_valid("", 30));
    }

    // =========================================================================
    // Reconnect delay calculation
    // =========================================================================

    #[test]
    fn test_reconnect_delay_first_attempt() {
        // attempt=0: base_delay * 2^0 = 500
        // jitter is random 0..=500, so result is in [500, 1000]
        let delay = calculate_reconnect_delay(0, 500, 60000, 500);
        assert!((500..=1000).contains(&delay), "delay={delay}");
    }

    #[test]
    fn test_reconnect_delay_exponential_growth() {
        // attempt=1: 500 * 2^1 = 1000, + jitter 0..=500 → [1000, 1500]
        let delay = calculate_reconnect_delay(1, 500, 60000, 500);
        assert!((1000..=1500).contains(&delay), "delay={delay}");

        // attempt=2: 500 * 2^2 = 2000, + jitter → [2000, 2500]
        let delay = calculate_reconnect_delay(2, 500, 60000, 500);
        assert!((2000..=2500).contains(&delay), "delay={delay}");

        // attempt=3: 500 * 2^3 = 4000, + jitter → [4000, 4500]
        let delay = calculate_reconnect_delay(3, 500, 60000, 500);
        assert!((4000..=4500).contains(&delay), "delay={delay}");
    }

    #[test]
    fn test_reconnect_delay_caps_at_max() {
        // attempt=20: would be 500 * 2^20 = huge, but capped at 60000
        let delay = calculate_reconnect_delay(20, 500, 60000, 500);
        assert!((60000..=60500).contains(&delay), "delay={delay}");
    }

    #[test]
    fn test_reconnect_delay_stays_at_max_for_high_attempts() {
        // Even at attempt 100, stays at max
        let delay = calculate_reconnect_delay(100, 500, 60000, 500);
        assert!((60000..=60500).contains(&delay), "delay={delay}");
    }

    #[test]
    fn test_reconnect_delay_zero_jitter() {
        let delay = calculate_reconnect_delay(0, 500, 60000, 0);
        assert_eq!(delay, 500);

        let delay = calculate_reconnect_delay(3, 500, 60000, 0);
        assert_eq!(delay, 4000);
    }

    #[test]
    fn test_reconnect_delay_zero_base() {
        let delay = calculate_reconnect_delay(5, 0, 60000, 0);
        assert_eq!(delay, 0);
    }

    #[test]
    fn test_reconnect_delay_overflow_protection() {
        // Very high attempt number should not panic due to overflow
        let delay = calculate_reconnect_delay(u64::MAX, 500, 60000, 500);
        assert!((60000..=60500).contains(&delay), "delay={delay}");
    }

    // =========================================================================
    // build_register_request
    // =========================================================================

    struct DummyConnector;
    impl BaseConnector for DummyConnector {
        fn connector_type(&self) -> &str {
            "test-type"
        }
        fn version(&self) -> &str {
            "1.0.0"
        }
        fn execute(
            &self,
            _request: serde_json::Value,
            _capability_id: Option<&str>,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<serde_json::Value>> + Send + '_>,
        > {
            Box::pin(async { Ok(serde_json::json!({})) })
        }
    }

    #[cfg(debug_assertions)]
    #[tokio::test]
    async fn execute_with_context_default_impl_delegates_and_does_not_panic() {
        // Behavioral contract for the debug-build context-drop tripwire:
        // calling the default `execute_with_context` with a non-empty
        // context must (a) NOT panic, (b) return the value `execute`
        // produced. The tracing::warn! side-effect is documented in the
        // rustdoc; we don't assert log capture here (no tracing-test dep).
        let conn = DummyConnector;
        let mut ctx: HashMap<String, String> = HashMap::new();
        ctx.insert("tenant_id".into(), "tenant-acme".into());
        ctx.insert("user_id".into(), "user-42".into());
        let resp = conn
            .execute_with_context(serde_json::json!({"k": "v"}), None, &ctx)
            .await
            .expect("default execute_with_context must delegate to execute and succeed");
        assert_eq!(resp, serde_json::json!({}));
    }

    #[test]
    fn test_build_register_request_with_jwt() {
        let config = ConnectorConfig {
            tenant_id: "my-tenant".to_string(),
            instance_id: "my-instance".to_string(),
            ..Default::default()
        };
        let connector = Arc::new(DummyConnector);
        let runner = ConnectorRunner::new(config.clone(), connector);

        let msg = runner.build_register_request(&config, "my-jwt-token", "");

        match msg.message {
            Some(proto::stream_message::Message::RegisterRequest(req)) => {
                assert_eq!(req.tenant_id, "my-tenant");
                assert_eq!(req.connector_type, "test-type");
                assert_eq!(req.instance_id, "my-instance");
                assert_eq!(req.jwt_token, "my-jwt-token");
                assert!(req.session_token.is_empty());
                assert!(req.capabilities.is_some());
            }
            other => panic!("Expected RegisterRequest, got {:?}", other),
        }
    }

    #[test]
    fn test_build_register_request_with_session_token() {
        let config = ConnectorConfig {
            tenant_id: "t".to_string(),
            instance_id: "i".to_string(),
            ..Default::default()
        };
        let connector = Arc::new(DummyConnector);
        let runner = ConnectorRunner::new(config.clone(), connector);

        let msg = runner.build_register_request(&config, "", "session-abc");

        match msg.message {
            Some(proto::stream_message::Message::RegisterRequest(req)) => {
                assert!(req.jwt_token.is_empty());
                assert_eq!(req.session_token, "session-abc");
            }
            other => panic!("Expected RegisterRequest, got {:?}", other),
        }
    }

    #[test]
    fn test_build_register_request_no_auth() {
        let config = ConnectorConfig {
            tenant_id: "t".to_string(),
            instance_id: "i".to_string(),
            ..Default::default()
        };
        let connector = Arc::new(DummyConnector);
        let runner = ConnectorRunner::new(config.clone(), connector);

        let msg = runner.build_register_request(&config, "", "");

        match msg.message {
            Some(proto::stream_message::Message::RegisterRequest(req)) => {
                assert!(req.jwt_token.is_empty());
                assert!(req.session_token.is_empty());
            }
            other => panic!("Expected RegisterRequest, got {:?}", other),
        }
    }

    #[test]
    fn test_build_register_request_includes_instance_metadata() {
        let config = ConnectorConfig {
            tenant_id: "t".to_string(),
            instance_id: "i".to_string(),
            display_name: Some("My Display Name".to_string()),
            tags: vec!["prod".to_string(), "us-east-1".to_string()],
            ..Default::default()
        };
        let connector = Arc::new(DummyConnector);
        let runner = ConnectorRunner::new(config.clone(), connector);

        let msg = runner.build_register_request(&config, "", "");

        match msg.message {
            Some(proto::stream_message::Message::RegisterRequest(req)) => {
                let meta = req.instance_metadata.unwrap();
                assert_eq!(meta.display_name, "My Display Name");
                assert_eq!(meta.tags, vec!["prod", "us-east-1"]);
            }
            other => panic!("Expected RegisterRequest, got {:?}", other),
        }
    }

    #[test]
    fn test_build_register_request_display_name_defaults_to_instance_id() {
        let config = ConnectorConfig {
            tenant_id: "t".to_string(),
            instance_id: "my-instance-123".to_string(),
            display_name: None, // not set
            ..Default::default()
        };
        let connector = Arc::new(DummyConnector);
        let runner = ConnectorRunner::new(config.clone(), connector);

        let msg = runner.build_register_request(&config, "", "");

        match msg.message {
            Some(proto::stream_message::Message::RegisterRequest(req)) => {
                let meta = req.instance_metadata.unwrap();
                assert_eq!(meta.display_name, "my-instance-123");
            }
            other => panic!("Expected RegisterRequest, got {:?}", other),
        }
    }

    #[test]
    fn test_build_register_request_capabilities() {
        let config = ConnectorConfig::default();
        let connector = Arc::new(DummyConnector);
        let runner = ConnectorRunner::new(config.clone(), connector);

        let msg = runner.build_register_request(&config, "", "");

        match msg.message {
            Some(proto::stream_message::Message::RegisterRequest(req)) => {
                let caps = req.capabilities.unwrap();
                assert_eq!(caps.connector_type, "test-type");
                assert_eq!(caps.version, "1.0.0");
                // Default behavior is RequestResponse
                assert!(!caps.behaviors.is_empty());
            }
            other => panic!("Expected RegisterRequest, got {:?}", other),
        }
    }
}
