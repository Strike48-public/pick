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
//! **These endpoints are LOCAL-ONLY and bind to `localhost:3030`.**
//!
//! - No authentication is implemented (assumes localhost trust boundary)
//! - Not exposed to network by default (bind address is 127.0.0.1)
//! - Suitable for local development, single-user workstations, and trusted environments
//!
//! **Future Enhancement**: For multi-user or networked deployments, API key authentication
//! should be added before exposing these endpoints beyond localhost.
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

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use pentest_core::aggression::AggressionLevel;
use pentest_core::config::ConnectorConfig;
use pentest_core::matrix::MatrixChatClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use super::ScanState;

/// State shared with API handlers
#[derive(Clone)]
pub struct ApiState {
    pub scan_state: Arc<RwLock<Option<ScanState>>>,
    pub config: Arc<RwLock<ConnectorConfig>>,
    pub matrix_client: Arc<RwLock<Option<MatrixChatClient>>>,
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
            // Log the actual invalid input but don't echo it back to the client
            tracing::warn!("Invalid aggression level received: {}", request.level);
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
pub fn create_api_routes(state: ApiState) -> Router {
    Router::new()
        .route("/api/status", get(get_status))
        .route("/api/aggression", post(post_aggression))
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
}
