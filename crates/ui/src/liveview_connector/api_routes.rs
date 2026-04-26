//! REST API routes for scan status and aggression adjustment

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

/// GET /api/status - Returns current scan state
async fn get_status(
    State(state): State<ApiState>,
) -> Result<Json<Option<ScanState>>, ErrorResponse> {
    let scan_guard = state.scan_state.read().await;
    Ok(Json(scan_guard.clone()))
}

/// POST /api/aggression - Adjust aggression level mid-scan
async fn post_aggression(
    State(state): State<ApiState>,
    Json(request): Json<AggressionAdjustRequest>,
) -> Result<Json<AggressionAdjustResponse>, ErrorResponse> {
    // Parse aggression level
    let new_level = match request.level.to_lowercase().as_str() {
        "conservative" => AggressionLevel::Conservative,
        "balanced" => AggressionLevel::Balanced,
        "aggressive" => AggressionLevel::Aggressive,
        "maximum" => AggressionLevel::Maximum,
        _ => {
            return Err(ErrorResponse {
                error: format!(
                    "Invalid aggression level '{}'. Valid values: conservative, balanced, aggressive, maximum",
                    request.level
                ),
            });
        }
    };

    // Get current level and update config
    let previous_level = {
        let mut config_guard = state.config.write().await;
        let prev = config_guard.aggression_level.clone();
        config_guard.aggression_level = new_level.clone();
        prev
    };

    // Check if scan is active and update scan state
    let (conversation_id, agent_id) = {
        let mut scan_guard = state.scan_state.write().await;
        if let Some(ref mut scan) = *scan_guard {
            scan.current_aggression = new_level.clone();
            (scan.conversation_id.clone(), scan.agent_id.clone())
        } else {
            return Err(ErrorResponse {
                error: "No active scan. Start a scan with begin_scan tool first.".to_string(),
            });
        }
    };

    // Send system message to agent with new policy guidelines
    let policy_guidelines = new_level.spawn_policy().to_guidelines(new_level.clone());
    let system_message = format!(
        "Aggression level changed from {} to {}.\n\n{}",
        previous_level.display_name(),
        new_level.display_name(),
        policy_guidelines
    );

    // Attempt to send system message
    {
        let client_guard = state.matrix_client.read().await;
        if let Some(ref client) = *client_guard {
            if let Err(e) = client
                .send_system_message(&conversation_id, &agent_id, &system_message)
                .await
            {
                tracing::error!("Failed to send aggression update to agent: {}", e);
                // Continue anyway - config is updated locally
            }
        } else {
            tracing::warn!("Matrix client not available, aggression update not sent to agent");
        }
    }

    Ok(Json(AggressionAdjustResponse {
        success: true,
        previous_level: previous_level.display_name().to_string(),
        new_level: new_level.display_name().to_string(),
        message: format!(
            "Aggression level updated to {} ({}x cost multiplier)",
            new_level.display_name(),
            new_level.cost_multiplier()
        ),
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
        assert_eq!(json["current_aggression"], "Aggressive");
    }
}
