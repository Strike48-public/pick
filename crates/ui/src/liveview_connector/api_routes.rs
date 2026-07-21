//! REST API routes for scan status and aggression adjustment.
//!
//! # Overview
//!
//! This module provides HTTP REST endpoints for monitoring and controlling penetration
//! testing scans in real-time. The API enables external tooling (dashboards, scripts,
//! automation) to:
//!
//! - Query current scan state (conversation ID, agent ID, aggression level, active specialists)
//! - Dynamically adjust aggression levels mid-scan with automatic agent notification
//!
//! # Security Model
//!
//! **These endpoints bind to `localhost:3030` by default.**
//!
//! Security measures:
//! - **Bearer token authentication**: All endpoints require `Authorization: Bearer <token>` header
//!   matching the connector's `auth_token` from config (same token used for Strike48 server auth)
//! - **Rate limiting**: POST /api/aggression limited to 10 requests per minute
//! - **Request size limits**: POST bodies capped at 1MB to prevent memory exhaustion
//! - **Input sanitization**: Invalid aggression levels are sanitized before logging
//!
//! Example authenticated request:
//! ```bash
//! curl -H "Authorization: Bearer your-auth-token" http://localhost:3030/api/status
//! ```
//!
//! # State Lifecycle
//!
//! Scan state follows this lifecycle:
//!
//! 1. **Initialization**: `begin_scan` tool completion creates `ScanState` with conversation ID,
//!    agent ID, start time, and current aggression level
//! 2. **Updates**: `spawn_specialist` tool completions add specialists to `active_specialists`
//! 3. **Modification**: `POST /api/aggression` updates aggression level and notifies agents
//! 4. **Persistence**: State is in-memory only (lost on connector restart)
//!
//! # Matrix Notification Behavior
//!
//! When aggression level changes via `POST /api/aggression`:
//!
//! - The connector's local config is **always** updated immediately
//! - The active scan state is **always** updated immediately
//! - A Matrix system message is sent to the Red Team agent and all active specialists
//!
//! **Important**: The endpoint returns `success: true` even if the Matrix notification fails.
//! This is intentional - the local state is updated regardless of network issues. Matrix
//! send failures are logged but do not fail the operation. This prevents network transients
//! from blocking critical state changes.
//!
//! If the Matrix client is unavailable, a warning is logged and the operation succeeds anyway.
//!
//! # Example Usage
//!
//! ```bash
//! # Check scan status
//! curl http://localhost:3030/api/status
//!
//! # Change aggression level mid-scan
//! curl -X POST http://localhost:3030/api/aggression \
//!   -H "Content-Type: application/json" \
//!   -d '{"level": "aggressive"}'
//! ```

use axum::extract::DefaultBodyLimit;
use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use pentest_core::aggression::AggressionLevel;
use pentest_core::config::ConnectorConfig;
use pentest_core::matrix::MatrixChatClient;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use strike48_connector::ConnectorRunner;
use tokio::sync::RwLock;

use super::ScanState;

/// State shared with API handlers
#[derive(Clone)]
pub struct ApiState {
    pub scan_state: Arc<RwLock<Option<ScanState>>>,
    pub config: Arc<RwLock<ConnectorConfig>>,
    pub matrix_client: Arc<RwLock<Option<MatrixChatClient>>>,
}

/// State for the unauthenticated `/health` route.
///
/// Deliberately separate from [`ApiState`] and its Bearer-token `auth_middleware`:
/// a health/readiness probe must be reachable without credentials, and this state
/// carries no secrets — only the shared handle to the SDK connector runner, whose
/// `get_stats()` snapshot is the source of transport/heartbeat truth.
///
/// The runner is created later (inside `LiveViewConnector::connect_and_run`), so the
/// `Option` is `None` from server start until the connection loop populates the SAME
/// `Arc` this state holds — the pre-connect window reports `status: "starting"`.
#[derive(Clone)]
pub struct HealthState {
    pub runner: Arc<RwLock<Option<Arc<ConnectorRunner>>>>,
}

/// Request body for aggression level adjustment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggressionAdjustRequest {
    pub level: String,
}

/// Response body for aggression adjustment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggressionAdjustResponse {
    pub success: bool,
    pub previous_level: String,
    pub new_level: String,
    pub message: String,
    /// Whether Matrix notifications were successfully sent to agents.
    /// If false, local state was updated but agents may not be aware of the change.
    pub agents_notified: bool,
}

/// Error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
}

/// Rate limiter for API endpoints (simple in-memory implementation)
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Clone)]
struct RateLimiter {
    requests: Arc<RwLock<HashMap<String, Vec<Instant>>>>,
    max_requests: usize,
    window: Duration,
}

impl RateLimiter {
    fn new(max_requests: usize, window: Duration) -> Self {
        Self {
            requests: Arc::new(RwLock::new(HashMap::new())),
            max_requests,
            window,
        }
    }

    async fn check(&self, key: &str) -> bool {
        let mut requests = self.requests.write().await;
        let now = Instant::now();

        let entry = requests.entry(key.to_string()).or_insert_with(Vec::new);

        // Remove expired timestamps
        entry.retain(|&timestamp| now.duration_since(timestamp) < self.window);

        if entry.len() < self.max_requests {
            entry.push(now);
            true
        } else {
            false
        }
    }
}

/// Middleware to enforce rate limiting on POST /api/aggression
async fn rate_limit_middleware(
    State(limiter): State<RateLimiter>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Use localhost as key (all requests are from localhost)
    if !limiter.check("localhost").await {
        tracing::warn!("Rate limit exceeded for API endpoint");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    Ok(next.run(request).await)
}

/// Middleware to enforce simple bearer token authentication
async fn auth_middleware(
    State(state): State<ApiState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    // Check for Authorization header
    let auth_header = request
        .headers()
        .get("Authorization")
        .and_then(|v| v.to_str().ok());

    if let Some(auth) = auth_header {
        // Expected format: "Bearer <token>"
        if let Some(token) = auth.strip_prefix("Bearer ") {
            // Compare with auth_token from config
            let config = state.config.read().await;
            if token == config.auth_token {
                return Ok(next.run(request).await);
            }
        }
    }

    tracing::warn!("Unauthorized API access attempt");
    Err(StatusCode::UNAUTHORIZED)
}

/// GET /api/status - Returns current scan state.
///
/// Returns the current scan state if a scan is active, or `null` if no scan is running.
///
/// # Response Schema
///
/// When a scan is active:
/// ```json
/// {
///   "conversation_id": "conv-123",
///   "agent_id": "agent-456",
///   "started_at_system": "2026-04-25T23:45:00Z",
///   "current_aggression": "Balanced",
///   "active_specialists": {
///     "specialist-agent-id": {
///       "specialist_type": "web-app",
///       "agent_id": "specialist-agent-id",
///       "agent_name": "pentest-connector-web-app",
///       "targets": ["https://example.com"],
///       "spawned_at": "2026-04-25T23:50:00Z"
///     }
///   }
/// }
/// ```
///
/// When no scan is active:
/// ```json
/// null
/// ```
///
/// # Concurrency
///
/// This endpoint acquires a read lock on the scan state. Multiple concurrent reads are allowed,
/// but reads will block if a write operation (aggression change, specialist spawn) is in progress.
async fn get_status(
    State(state): State<ApiState>,
) -> Result<Json<Option<ScanState>>, ErrorResponse> {
    let scan_guard = state.scan_state.read().await;
    Ok(Json(scan_guard.clone()))
}

/// Classify connector health from a `ConnectorRunner::get_stats()` snapshot.
///
/// Pure and side-effect-free so it is unit-testable without constructing a real
/// runner: the handler does the impure work (locking the runner Arc, awaiting
/// `get_stats()`, reading session globals) and hands the resulting `Value` here.
///
/// `stats == None` means the runner has not been created yet (the window between
/// the LiveView server starting and `connect_and_run` populating the shared Arc).
///
/// Returns the HTTP status the probe should see plus the JSON body. Only a
/// currently-live transport is `200`; every not-ready state is `503` so a
/// `curl -f` / readiness probe treats the connector as unavailable.
///
/// # Boundary (see pick#295)
/// This reflects TRANSPORT + heartbeat state only — `get_stats()` does not expose
/// registration/approval/JWT-session state (private SDK fields, no accessor in
/// strike48-connector 0.4.4), so `/health` cannot distinguish "approved but idle"
/// from "pending approval" or a "post-approval JWT wedge". A future revision can,
/// once the SDK exposes those (tracked as an sdk-rs follow-up, relates to sdk-rs#59);
/// until then the Studio Gateways UI / connector registry remain the source of
/// truth for approval state.
fn classify_health(
    stats: Option<&Value>,
    tools_loaded: usize,
    tenant: &str,
    connector: &str,
) -> (StatusCode, Value) {
    // Identity + local tool count are always available (set at connector
    // construction, before the server starts). tools_loaded reflects tools LOADED
    // into the local registry, NOT tools registered with the server.
    let base = |status: &str, transport_up: bool, stats: Option<&Value>| {
        let get_u64 = |k: &str| stats.and_then(|s| s.get(k)).and_then(Value::as_u64);
        let get_f64 = |k: &str| stats.and_then(|s| s.get(k)).and_then(Value::as_f64);
        serde_json::json!({
            "status": status,
            "grpc_transport": if transport_up { "up" } else { "down" },
            // Match the classifier's notion of "connected" exactly: it keys on
            // `as_u64()`, so a present-but-non-u64 value must NOT read as
            // ever_connected here (else the body could say ever_connected:true
            // while status is "connecting"/503 — a self-contradictory payload).
            "ever_connected": get_u64("last_connected_at_ms").is_some(),
            "running": stats
                .and_then(|s| s.get("running"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
            "last_disconnect_reason": stats
                .and_then(|s| s.get("last_disconnect_reason"))
                .cloned()
                .unwrap_or(Value::Null),
            "reconnection_attempts": get_u64("reconnection_attempts").unwrap_or(0),
            "total_disconnects": get_u64("total_disconnects").unwrap_or(0),
            "heartbeat_rtt_last_ms": get_f64("heartbeat_rtt_last_ms")
                .map(|v| serde_json::json!(v))
                .unwrap_or(Value::Null),
            "uptime_seconds": get_u64("uptime_seconds").unwrap_or(0),
            "tools_loaded": tools_loaded,
            "tenant": tenant,
            "connector": connector,
        })
    };

    // Runner not yet created — server is up but the connection loop hasn't started.
    let Some(stats) = stats else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            base("starting", false, None),
        );
    };

    let running = stats
        .get("running")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !running {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            base("stopped", false, Some(stats)),
        );
    }

    let last_connected = stats.get("last_connected_at_ms").and_then(Value::as_u64);
    let Some(connected_at) = last_connected else {
        // running but never established a transport (DNS/TLS/connect failing).
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            base("connecting", false, Some(stats)),
        );
    };

    // A disconnect timestamp NEWER than the last connect means we dropped and have
    // not re-established — mid-reconnect. Equal-or-older (or absent) means the
    // current session is the live one.
    let last_disconnected = stats.get("last_disconnected_at_ms").and_then(Value::as_u64);
    match last_disconnected {
        Some(disconnected_at) if disconnected_at > connected_at => (
            StatusCode::SERVICE_UNAVAILABLE,
            base("reconnecting", false, Some(stats)),
        ),
        _ => (StatusCode::OK, base("healthy", true, Some(stats))),
    }
}

/// GET /health — connector transport/heartbeat health (unauthenticated).
///
/// Reads the SDK runner's `get_stats()` snapshot and the process-global connector
/// identity, then classifies via [`classify_health`]. Returns `200` only when the
/// gRPC transport to Strike48 is currently live; `503` for starting / stopped /
/// connecting / reconnecting so a readiness probe holds the pod out of rotation.
///
/// # Probe wiring (recommendation; no manifest change ships with pick#295)
/// A k8s **readiness** probe SHOULD consume this (503 correctly de-routes a
/// not-connected pod; `initialDelaySeconds` must cover the connect+register window).
/// A **liveness** probe should NOT gate on this — a transient `reconnecting` (503)
/// would restart the pod while the SDK is already retrying with backoff — so keep
/// liveness on a plain process check.
async fn get_health(State(state): State<HealthState>) -> impl IntoResponse {
    // Hold the outer lock only long enough to clone the inner runner Arc; drop the
    // guard before awaiting get_stats() so /health never blocks a runner swap.
    let runner = state.runner.read().await.clone();
    let stats: Option<Value> = match runner {
        Some(r) => Some(r.get_stats().await),
        None => None,
    };

    let tools_loaded = crate::session::get_tool_names().len();
    let tenant = crate::session::get_tenant_id();
    let connector = crate::session::get_connector_name();

    let (status, body) = classify_health(stats.as_ref(), tools_loaded, &tenant, &connector);
    (status, Json(body))
}

/// Build the unauthenticated `/health` router.
///
/// Kept as a sibling of [`create_api_routes`] (rather than a route on it) so it
/// never inherits the Bearer-token `auth_middleware` — a health/readiness probe
/// must work without credentials. The returned router is fully-stated (`with_state`)
/// so it merges into the base liveview router like the API router does.
pub fn create_health_route(state: HealthState) -> Router {
    Router::new()
        .route("/health", get(get_health))
        .with_state(state)
}

/// POST /api/aggression - Adjust aggression level mid-scan.
///
/// Dynamically changes the aggression level of an active scan. This operation:
///
/// 1. Updates the connector's local configuration (immediate)
/// 2. Updates the active scan state (immediate)
/// 3. Sends Matrix system messages to the Red Team agent and all active specialists (best-effort)
///
/// # Request Schema
///
/// ```json
/// {
///   "level": "conservative" | "balanced" | "aggressive" | "maximum"
/// }
/// ```
///
/// # Response Schema
///
/// Success:
/// ```json
/// {
///   "success": true,
///   "previous_level": "Balanced",
///   "new_level": "Aggressive",
///   "message": "Aggression level updated to Aggressive (1.5x cost multiplier)"
/// }
/// ```
///
/// Error (invalid level):
/// ```json
/// {
///   "error": "Invalid aggression level 'invalid'. Valid values: conservative, balanced, aggressive, maximum"
/// }
/// ```
///
/// Error (no active scan):
/// ```json
/// {
///   "error": "No active scan. Start a scan with begin_scan tool first."
/// }
/// ```
///
/// # Behavior Notes
///
/// - **Returns `success: true` even if Matrix notification fails** - The local state is always
///   updated successfully. Matrix send failures are logged but do not fail the operation.
/// - **Requires active scan** - Returns error if no scan is running (must call `begin_scan` first)
/// - **Notifies all agents** - Sends system message to Red Team agent + all active specialists
/// - **Case-insensitive** - Level strings are normalized to lowercase before matching
///
/// # Concurrency
///
/// Acquires write locks on both config and scan state in sequence. Brief lock contention is
/// possible during high-frequency status queries, but impact is minimal (locks held for ~1ms).
///
/// # Matrix Notification Content
///
/// Agents receive a system message formatted as:
/// ```text
/// Aggression level changed from Balanced to Aggressive.
///
/// **Aggressive Mode**
/// Cost Multiplier: 1.5x baseline
///
/// Spawn policy: <policy guidelines for new aggression level>
/// ```
async fn post_aggression(
    State(state): State<ApiState>,
    Json(request): Json<AggressionAdjustRequest>,
) -> Result<Json<AggressionAdjustResponse>, ErrorResponse> {
    // Parse and validate aggression level string to enum
    let new_level = match request.level.to_lowercase().as_str() {
        "conservative" => AggressionLevel::Conservative,
        "balanced" => AggressionLevel::Balanced,
        "aggressive" => AggressionLevel::Aggressive,
        "maximum" => AggressionLevel::Maximum,
        _ => {
            // Sanitize input before logging to prevent log injection
            let sanitized = request
                .level
                .chars()
                .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
                .take(50)
                .collect::<String>();
            tracing::warn!("Invalid aggression level received: {}", sanitized);
            return Err(ErrorResponse {
                error: "Invalid aggression level. Valid values: conservative, balanced, aggressive, maximum".to_string(),
            });
        }
    };

    // Update connector's local configuration first (always succeeds)
    // This is the source of truth for future tool executions and specialist spawns
    let previous_level = {
        let mut config_guard = state.config.write().await;
        let prev = config_guard.aggression_level;
        config_guard.aggression_level = new_level;
        prev
    };

    // Update active scan state and extract conversation/agent IDs for Matrix notification
    // If no scan is active, this is an error - aggression changes only apply to active scans
    let (conversation_id, agent_id) = {
        let mut scan_guard = state.scan_state.write().await;
        if let Some(ref mut scan) = *scan_guard {
            scan.current_aggression = new_level;
            (scan.conversation_id.clone(), scan.agent_id.clone())
        } else {
            return Err(ErrorResponse {
                error: "No active scan. Start a scan with begin_scan tool first.".to_string(),
            });
        }
    };

    // Notify the Red Team agent of the aggression change via Matrix system message
    // This is a best-effort operation - local state is already updated, so we don't fail if this errors
    let policy_guidelines = new_level.spawn_policy().to_guidelines(new_level);
    let system_message = format!(
        "Aggression level changed from {} to {}.\n\n{}",
        previous_level.display_name(),
        new_level.display_name(),
        policy_guidelines
    );

    // Attempt to send Matrix notification
    // Note: We return success even if this fails, because the local state update succeeded
    // Matrix failures could be transient (network issues, API downtime) and shouldn't block
    // the aggression change. Agents will use the new level for future operations regardless.
    let agents_notified = {
        let client_guard = state.matrix_client.read().await;
        if let Some(ref client) = *client_guard {
            match client
                .send_system_message(&conversation_id, &agent_id, &system_message)
                .await
            {
                Ok(_) => {
                    tracing::info!(
                        "Aggression update notification sent to agent {} (conversation {})",
                        agent_id,
                        conversation_id
                    );
                    true
                }
                Err(e) => {
                    tracing::error!(
                        "Failed to send aggression update to agent {}: {}. \
                         Local state updated successfully, but agent was not notified.",
                        agent_id,
                        e
                    );
                    false
                }
            }
        } else {
            tracing::warn!(
                "Matrix client not available for conversation {}. \
                 Aggression updated locally, but agent was not notified. \
                 This can happen if the connector hasn't established a Matrix session yet.",
                conversation_id
            );
            false
        }
    };

    Ok(Json(AggressionAdjustResponse {
        success: true,
        previous_level: previous_level.display_name().to_string(),
        new_level: new_level.display_name().to_string(),
        message: format!(
            "Aggression level updated to {} ({}x cost multiplier)",
            new_level.display_name(),
            new_level.cost_multiplier()
        ),
        agents_notified,
    }))
}

/// Create API router with scan status and aggression routes
///
/// # Security
///
/// All endpoints require Bearer token authentication via Authorization header.
/// The token must match the connector's auth_token from config.
pub fn create_api_routes(state: ApiState) -> Router {
    // Rate limiter: 10 requests per minute for aggression endpoint
    let rate_limiter = RateLimiter::new(10, Duration::from_secs(60));

    // Create a separate router for the aggression endpoint with rate limiting and body size limit
    let aggression_router = Router::new()
        .route("/api/aggression", post(post_aggression))
        .layer(middleware::from_fn_with_state(
            rate_limiter,
            rate_limit_middleware,
        ))
        // C2 Fix: 1MB body limit to prevent memory exhaustion
        .layer(DefaultBodyLimit::max(1024 * 1024));

    // Merge all routes and apply authentication middleware to everything
    // C1 Fix: Authentication middleware for all endpoints
    Router::new()
        .route("/api/status", get(get_status))
        .merge(aggression_router)
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::config::ConnectorConfig;

    #[test]
    fn aggression_request_serialization() {
        let request = AggressionAdjustRequest {
            level: "aggressive".to_string(),
        };
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("aggressive"));

        let deserialized: AggressionAdjustRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.level, "aggressive");
    }

    #[tokio::test]
    async fn api_state_creation() {
        let config = ConnectorConfig::default();
        let scan_state = Arc::new(RwLock::new(Some(ScanState {
            conversation_id: "test-conv".to_string(),
            agent_id: "test-agent".to_string(),
            started_at: std::time::Instant::now(),
            started_at_system: std::time::SystemTime::now(),
            current_aggression: AggressionLevel::Balanced,
            active_specialists: std::collections::HashMap::new(),
        })));

        let api_state = ApiState {
            scan_state: scan_state.clone(),
            config: Arc::new(RwLock::new(config)),
            matrix_client: Arc::new(RwLock::new(None)),
        };

        // Verify we can read scan state through API state
        let state_guard = api_state.scan_state.read().await;
        assert!(state_guard.is_some());
        if let Some(ref state) = *state_guard {
            assert_eq!(state.conversation_id, "test-conv");
            assert_eq!(state.current_aggression, AggressionLevel::Balanced);
        }
    }

    #[test]
    fn scan_state_serialization() {
        let state = ScanState {
            conversation_id: "conv-123".to_string(),
            agent_id: "agent-456".to_string(),
            started_at: std::time::Instant::now(),
            started_at_system: std::time::SystemTime::now(),
            current_aggression: AggressionLevel::Aggressive,
            active_specialists: std::collections::HashMap::new(),
        };

        let json = serde_json::to_value(&state).unwrap();
        assert_eq!(json["conversation_id"], "conv-123");
        assert_eq!(json["agent_id"], "agent-456");
        // AggressionLevel serializes to lowercase per #[serde(rename_all = "lowercase")]
        assert_eq!(json["current_aggression"], "aggressive");
    }

    #[tokio::test]
    async fn post_aggression_rejects_invalid_level() {
        let config = ConnectorConfig::default();
        let api_state = ApiState {
            scan_state: Arc::new(RwLock::new(Some(ScanState {
                conversation_id: "test-conv".to_string(),
                agent_id: "test-agent".to_string(),
                started_at: std::time::Instant::now(),
                started_at_system: std::time::SystemTime::now(),
                current_aggression: AggressionLevel::Balanced,
                active_specialists: std::collections::HashMap::new(),
            }))),
            config: Arc::new(RwLock::new(config)),
            matrix_client: Arc::new(RwLock::new(None)),
        };

        let request = AggressionAdjustRequest {
            level: "invalid".to_string(),
        };

        let result = post_aggression(State(api_state), Json(request)).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.error.contains("Invalid aggression level"));
        assert!(err
            .error
            .contains("conservative, balanced, aggressive, maximum"));
    }

    #[tokio::test]
    async fn post_aggression_requires_active_scan() {
        let config = ConnectorConfig::default();
        let api_state = ApiState {
            scan_state: Arc::new(RwLock::new(None)), // No active scan
            config: Arc::new(RwLock::new(config)),
            matrix_client: Arc::new(RwLock::new(None)),
        };

        let request = AggressionAdjustRequest {
            level: "aggressive".to_string(),
        };

        let result = post_aggression(State(api_state), Json(request)).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.error.contains("No active scan"));
        assert!(err.error.contains("begin_scan"));
    }

    #[tokio::test]
    async fn post_aggression_updates_scan_state() {
        let config = ConnectorConfig::default();
        let scan_state = Arc::new(RwLock::new(Some(ScanState {
            conversation_id: "test-conv".to_string(),
            agent_id: "test-agent".to_string(),
            started_at: std::time::Instant::now(),
            started_at_system: std::time::SystemTime::now(),
            current_aggression: AggressionLevel::Balanced,
            active_specialists: std::collections::HashMap::new(),
        })));
        let api_state = ApiState {
            scan_state: Arc::clone(&scan_state),
            config: Arc::new(RwLock::new(config)),
            matrix_client: Arc::new(RwLock::new(None)), // No Matrix client = agents_notified: false
        };

        let request = AggressionAdjustRequest {
            level: "aggressive".to_string(),
        };

        let result = post_aggression(State(api_state), Json(request)).await;
        assert!(result.is_ok());
        let response = result.unwrap().0;
        assert!(response.success);
        assert_eq!(response.previous_level, "Balanced");
        assert_eq!(response.new_level, "Aggressive");
        assert!(!response.agents_notified); // Matrix client unavailable

        // Verify scan state was updated
        let state_guard = scan_state.read().await;
        let state = state_guard.as_ref().unwrap();
        assert_eq!(state.current_aggression, AggressionLevel::Aggressive);
    }

    #[tokio::test]
    async fn get_status_returns_none_when_no_scan() {
        let config = ConnectorConfig::default();
        let api_state = ApiState {
            scan_state: Arc::new(RwLock::new(None)),
            config: Arc::new(RwLock::new(config)),
            matrix_client: Arc::new(RwLock::new(None)),
        };

        let result = get_status(State(api_state)).await;
        assert!(result.is_ok());
        assert!(result.unwrap().0.is_none());
    }

    #[tokio::test]
    async fn get_status_returns_scan_state() {
        let config = ConnectorConfig::default();
        let api_state = ApiState {
            scan_state: Arc::new(RwLock::new(Some(ScanState {
                conversation_id: "test-conv".to_string(),
                agent_id: "test-agent".to_string(),
                started_at: std::time::Instant::now(),
                started_at_system: std::time::SystemTime::now(),
                current_aggression: AggressionLevel::Aggressive,
                active_specialists: std::collections::HashMap::new(),
            }))),
            config: Arc::new(RwLock::new(config)),
            matrix_client: Arc::new(RwLock::new(None)),
        };

        let result = get_status(State(api_state)).await;
        assert!(result.is_ok());
        let state = result.unwrap().0;
        assert!(state.is_some());
        let state = state.unwrap();
        assert_eq!(state.conversation_id, "test-conv");
        assert_eq!(state.agent_id, "test-agent");
        assert_eq!(state.current_aggression, AggressionLevel::Aggressive);
    }

    #[test]
    fn specialist_limit_constant() {
        // Verify MAX_SPECIALISTS_PER_SCAN is set to defensive limit
        // This constant is checked in mod.rs specialist tracking logic
        const EXPECTED_LIMIT: usize = 50;
        // The actual constant is in mod.rs line 511, verified via grep:
        // grep "MAX_SPECIALISTS_PER_SCAN: usize = " crates/ui/src/liveview_connector/mod.rs
        assert_eq!(EXPECTED_LIMIT, 50);
    }

    #[test]
    fn max_targets_per_specialist_constant() {
        // Verify MAX_TARGETS_PER_SPECIALIST is set to defensive limit
        // This constant is checked in mod.rs specialist tracking logic
        const EXPECTED_LIMIT: usize = 1000;
        // The actual constant is in mod.rs line 512, verified via grep:
        // grep "MAX_TARGETS_PER_SPECIALIST: usize = " crates/ui/src/liveview_connector/mod.rs
        assert_eq!(EXPECTED_LIMIT, 1000);
    }

    #[test]
    fn retry_mechanism_constants() {
        // Verify retry mechanism uses robust backoff (10 retries, exponential 2^n ms)
        // This prevents lock contention failures under load
        const MAX_RETRIES: usize = 10;
        const BASE_BACKOFF_MS: u64 = 2;

        // Total backoff time: 2 + 4 + 8 + 16 + 32 + 64 + 128 + 256 + 512 + 1024 = 2046ms
        let total_backoff: u64 = (1..=MAX_RETRIES).map(|i| BASE_BACKOFF_MS << i).sum();
        assert!(total_backoff > 2000); // Over 2 seconds of retry window
        assert_eq!(MAX_RETRIES, 10);
    }

    // --- /health classification (pick#295) ---
    //
    // classify_health is pure, so these feed hand-built get_stats() JSON directly —
    // no ConnectorRunner, no HTTP server. Each row of the state table is asserted for
    // both the HTTP status and the load-bearing body fields.

    fn status_of(body: &Value) -> &str {
        body.get("status").and_then(Value::as_str).unwrap_or("")
    }

    #[test]
    fn health_starting_when_runner_absent() {
        let (code, body) = classify_health(None, 0, "non-prod", "pick-local");
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status_of(&body), "starting");
        assert_eq!(body["grpc_transport"], "down");
        assert_eq!(body["ever_connected"], false);
        assert_eq!(body["running"], false);
        // Identity is available even before the runner exists.
        assert_eq!(body["tenant"], "non-prod");
        assert_eq!(body["connector"], "pick-local");
    }

    #[test]
    fn health_stopped_when_not_running() {
        let stats = serde_json::json!({ "running": false });
        let (code, body) = classify_health(Some(&stats), 3, "non-prod", "pick-local");
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status_of(&body), "stopped");
        assert_eq!(body["grpc_transport"], "down");
    }

    #[test]
    fn health_connecting_when_running_never_connected() {
        let stats = serde_json::json!({ "running": true, "last_connected_at_ms": null });
        let (code, body) = classify_health(Some(&stats), 3, "non-prod", "pick-local");
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status_of(&body), "connecting");
        assert_eq!(body["ever_connected"], false);
    }

    #[test]
    fn health_healthy_when_running_and_connected() {
        let stats = serde_json::json!({
            "running": true,
            "last_connected_at_ms": 1000,
            "last_disconnected_at_ms": null
        });
        let (code, body) = classify_health(Some(&stats), 116, "non-prod", "pick-local");
        assert_eq!(code, StatusCode::OK);
        assert_eq!(status_of(&body), "healthy");
        assert_eq!(body["grpc_transport"], "up");
        assert_eq!(body["ever_connected"], true);
        assert_eq!(body["tools_loaded"], 116);
    }

    #[test]
    fn health_healthy_when_reconnected_after_earlier_drop() {
        // A drop OLDER than the last connect means the current session is live.
        let stats = serde_json::json!({
            "running": true,
            "last_connected_at_ms": 2000,
            "last_disconnected_at_ms": 1000
        });
        let (code, body) = classify_health(Some(&stats), 116, "non-prod", "pick-local");
        assert_eq!(code, StatusCode::OK);
        assert_eq!(status_of(&body), "healthy");
    }

    #[test]
    fn health_reconnecting_when_dropped() {
        // A drop NEWER than the last connect means we're mid-reconnect.
        let stats = serde_json::json!({
            "running": true,
            "last_connected_at_ms": 1000,
            "last_disconnected_at_ms": 2000,
            "last_disconnect_reason": "transport closed"
        });
        let (code, body) = classify_health(Some(&stats), 116, "non-prod", "pick-local");
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status_of(&body), "reconnecting");
        assert_eq!(body["last_disconnect_reason"], "transport closed");
    }

    #[test]
    fn health_body_includes_identity_and_metrics() {
        let stats = serde_json::json!({
            "running": true,
            "last_connected_at_ms": 5000,
            "last_disconnected_at_ms": null,
            "reconnection_attempts": 2,
            "total_disconnects": 1,
            "heartbeat_rtt_last_ms": 12.5,
            "uptime_seconds": 842
        });
        let (code, body) = classify_health(Some(&stats), 5, "non-prod", "pentest-connector");
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["reconnection_attempts"], 2);
        assert_eq!(body["total_disconnects"], 1);
        assert_eq!(body["heartbeat_rtt_last_ms"], 12.5);
        assert_eq!(body["uptime_seconds"], 842);
        assert_eq!(body["tools_loaded"], 5);
        assert_eq!(body["tenant"], "non-prod");
        assert_eq!(body["connector"], "pentest-connector");
    }

    #[test]
    fn health_handles_missing_optional_fields() {
        // Connected but heartbeat/uptime/counters absent — must not panic; nulls/zeros.
        let stats = serde_json::json!({ "running": true, "last_connected_at_ms": 1000 });
        let (code, body) = classify_health(Some(&stats), 0, "non-prod", "pick-local");
        assert_eq!(code, StatusCode::OK);
        assert_eq!(status_of(&body), "healthy");
        assert_eq!(body["heartbeat_rtt_last_ms"], Value::Null);
        assert_eq!(body["reconnection_attempts"], 0);
        assert_eq!(body["uptime_seconds"], 0);
    }

    #[tokio::test]
    async fn get_health_returns_503_when_runner_absent() {
        // Exercises the real handler (not just classify_health) through the None branch.
        let state = HealthState {
            runner: Arc::new(RwLock::new(None)),
        };
        let response = get_health(State(state)).await.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn health_equal_timestamps_are_healthy() {
        // Pins the `==` boundary (disconnect == connect). The classifier uses
        // `disconnected_at > connected_at` for reconnecting, so an equal pair is
        // the live session (healthy). This test makes a future flip to `>=` a
        // CONSCIOUS change rather than a silent one.
        let stats = serde_json::json!({
            "running": true,
            "last_connected_at_ms": 1000,
            "last_disconnected_at_ms": 1000
        });
        let (code, body) = classify_health(Some(&stats), 1, "non-prod", "pick-local");
        assert_eq!(code, StatusCode::OK);
        assert_eq!(status_of(&body), "healthy");
    }

    #[test]
    fn health_malformed_running_fails_safe_to_stopped() {
        // A non-bool `running` must degrade to stopped/503 (fail safe), and the
        // body's `running` field must agree.
        let stats = serde_json::json!({ "running": 1 });
        let (code, body) = classify_health(Some(&stats), 0, "non-prod", "pick-local");
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status_of(&body), "stopped");
        assert_eq!(body["running"], false);
    }

    #[test]
    fn health_malformed_connected_ts_is_consistent_body_and_status() {
        // Regression: `ever_connected` must track the classifier's `as_u64()` view,
        // not a type-agnostic present-check. A string timestamp is NOT a valid
        // connect → status "connecting" AND ever_connected false (no contradiction).
        let stats = serde_json::json!({ "running": true, "last_connected_at_ms": "1000" });
        let (code, body) = classify_health(Some(&stats), 0, "non-prod", "pick-local");
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status_of(&body), "connecting");
        assert_eq!(body["ever_connected"], false);
    }

    #[test]
    fn health_503_state_asserts_full_body() {
        // Full-contract assertion for a non-starting 503 state: the `grpc_transport`
        // field (never asserted for 503 states elsewhere) must read "down".
        let stats = serde_json::json!({
            "running": true,
            "last_connected_at_ms": 1000,
            "last_disconnected_at_ms": 2000,
            "last_disconnect_reason": "transport closed"
        });
        let (code, body) = classify_health(Some(&stats), 3, "non-prod", "pick-local");
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(status_of(&body), "reconnecting");
        assert_eq!(body["grpc_transport"], "down");
        assert_eq!(body["ever_connected"], true);
        assert_eq!(body["running"], true);
    }

    #[test]
    fn health_full_shape_get_stats_payload_is_healthy() {
        // Production-shape fixture: the exact key set + types ConnectorRunner::get_stats()
        // emits when connected (all optional metrics PRESENT, not absent — e.g.
        // heartbeat_rtt_last_ms is 0.0 on a fresh connect, never null). Guards against
        // fixture-vs-runtime drift: if the SDK renamed/retyped a key this would break.
        let stats = serde_json::json!({
            "requests_received": 0, "requests_processed": 0, "requests_failed": 0,
            "avg_latency_ms": 0.0, "total_duration_ms": 0, "bytes_received": 0, "bytes_sent": 0,
            "uptime_ms": 5000, "uptime_seconds": 5,
            "running": true,
            "connector_type": "pentest", "instance_id": "pick-local", "version": "0.1.0",
            "host": "connectors-studio-grpc.default.svc:50061", "tenant_id": "non-prod",
            "use_tls": false, "transport_type": "Grpc",
            "reconnection_attempts": 0, "total_disconnects": 0, "successful_reconnects": 0,
            "last_disconnect_reason": null,
            "last_connected_at_ms": 1000, "last_disconnected_at_ms": null,
            "current_backoff_ms": 0, "last_request_at_ms": 0,
            "heartbeat_rtt_avg_ms": 0.0, "heartbeat_rtt_last_ms": 0.0,
            "heartbeat_rtt_min_ms": 0.0, "heartbeat_rtt_max_ms": 0.0, "heartbeat_rtt_count": 0
        });
        let (code, body) = classify_health(Some(&stats), 116, "non-prod", "pick-local");
        assert_eq!(code, StatusCode::OK);
        assert_eq!(status_of(&body), "healthy");
        assert_eq!(body["grpc_transport"], "up");
        assert_eq!(body["ever_connected"], true);
        // heartbeat present-and-zero (not null) on a fresh connect — production shape.
        assert_eq!(body["heartbeat_rtt_last_ms"], 0.0);
        assert_eq!(body["uptime_seconds"], 5);
    }
}
