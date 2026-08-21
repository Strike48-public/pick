use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Payload encoding types (matches protobuf enum)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum PayloadEncoding {
    Unspecified = 0,
    Json = 1,
    RawBytes = 2,
    ArrowIpc = 3,
    JsonLines = 4,
    Protobuf = 5,
    Msgpack = 6,
    Parquet = 7,
}

impl From<i32> for PayloadEncoding {
    fn from(value: i32) -> Self {
        match value {
            1 => PayloadEncoding::Json,
            2 => PayloadEncoding::RawBytes,
            3 => PayloadEncoding::ArrowIpc,
            4 => PayloadEncoding::JsonLines,
            5 => PayloadEncoding::Protobuf,
            6 => PayloadEncoding::Msgpack,
            7 => PayloadEncoding::Parquet,
            _ => PayloadEncoding::Unspecified,
        }
    }
}

impl From<PayloadEncoding> for i32 {
    fn from(encoding: PayloadEncoding) -> Self {
        encoding as i32
    }
}

/// Connector behavior patterns
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum ConnectorBehavior {
    Unspecified = 0,
    Source = 1,
    Sink = 2,
    Tool = 3,
    Pubsub = 4,
    RequestResponse = 5,
    App = 6,
}

impl From<i32> for ConnectorBehavior {
    fn from(value: i32) -> Self {
        match value {
            1 => ConnectorBehavior::Source,
            2 => ConnectorBehavior::Sink,
            3 => ConnectorBehavior::Tool,
            4 => ConnectorBehavior::Pubsub,
            5 => ConnectorBehavior::RequestResponse,
            6 => ConnectorBehavior::App,
            _ => ConnectorBehavior::Unspecified,
        }
    }
}

impl From<ConnectorBehavior> for i32 {
    fn from(behavior: ConnectorBehavior) -> Self {
        behavior as i32
    }
}

/// Registration status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum RegistrationStatus {
    Unspecified = 0,
    Pending = 1,
    Approved = 2,
    Rejected = 3,
}

impl From<i32> for RegistrationStatus {
    fn from(value: i32) -> Self {
        match value {
            1 => RegistrationStatus::Pending,
            2 => RegistrationStatus::Approved,
            3 => RegistrationStatus::Rejected,
            _ => RegistrationStatus::Unspecified,
        }
    }
}

/// Task type schema for registering capabilities (a.k.a. a "tool" the
/// connector exposes to LLM agents).
///
/// Construct directly with a struct literal for backward compatibility, or use
/// the chainable builder for ergonomics:
///
/// ```rust,ignore
/// use serde_json::json;
/// use strike48_connector::TaskTypeSchema;
///
/// let schema = TaskTypeSchema::new("add", "Add", "Add two numbers")
///     .category("math")
///     .icon("calculator")
///     .input_schema(json!({
///         "type": "object",
///         "properties": {
///             "a": {"type": "number"},
///             "b": {"type": "number"}
///         },
///         "required": ["a", "b"]
///     }))
///     .output_schema(json!({
///         "type": "object",
///         "properties": {"result": {"type": "number"}},
///         "required": ["result"]
///     }));
/// ```
///
/// `category` and `icon` default to empty strings (server treats them as
/// optional). `input_schema_json` / `output_schema_json` default to `"{}"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskTypeSchema {
    pub task_type_id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub icon: String,
    pub input_schema_json: String,
    pub output_schema_json: String,
}

impl Default for TaskTypeSchema {
    fn default() -> Self {
        Self {
            task_type_id: String::new(),
            name: String::new(),
            description: String::new(),
            category: String::new(),
            icon: String::new(),
            input_schema_json: "{}".to_string(),
            output_schema_json: "{}".to_string(),
        }
    }
}

impl TaskTypeSchema {
    /// Create a new task-type/tool schema with sensible defaults.
    ///
    /// Defaults: `category=""`, `icon=""`, `input_schema_json="{}"`,
    /// `output_schema_json="{}"`. Use the builder methods to populate.
    pub fn new(
        task_type_id: impl Into<String>,
        name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            task_type_id: task_type_id.into(),
            name: name.into(),
            description: description.into(),
            ..Self::default()
        }
    }

    /// Set the category label (free-form; used by the admin UI for grouping).
    pub fn category(mut self, c: impl Into<String>) -> Self {
        self.category = c.into();
        self
    }

    /// Set the icon name (free-form; used by the admin UI).
    pub fn icon(mut self, i: impl Into<String>) -> Self {
        self.icon = i.into();
        self
    }

    /// Set the input JSON Schema as a [`serde_json::Value`]. The SDK
    /// stringifies it for transport; the Matrix server validates input
    /// payloads against this on invocation.
    pub fn input_schema(mut self, schema: serde_json::Value) -> Self {
        self.input_schema_json =
            serde_json::to_string(&schema).unwrap_or_else(|_| "{}".to_string());
        self
    }

    /// Set the output JSON Schema as a [`serde_json::Value`].
    pub fn output_schema(mut self, schema: serde_json::Value) -> Self {
        self.output_schema_json =
            serde_json::to_string(&schema).unwrap_or_else(|_| "{}".to_string());
        self
    }

    /// Set the input schema directly as a JSON string (escape hatch for
    /// callers that already have a stringified schema).
    pub fn input_schema_str(mut self, json: impl Into<String>) -> Self {
        self.input_schema_json = json.into();
        self
    }

    /// Set the output schema directly as a JSON string.
    pub fn output_schema_str(mut self, json: impl Into<String>) -> Self {
        self.output_schema_json = json.into();
        self
    }
}

/// Connector capabilities
#[derive(Debug, Clone)]
pub struct ConnectorCapabilities {
    pub connector_type: String,
    pub version: String,
    pub supported_encodings: Vec<PayloadEncoding>,
    pub behaviors: Vec<ConnectorBehavior>,
    pub metadata: HashMap<String, String>,
    pub task_types: Option<Vec<TaskTypeSchema>>,
}

/// Register connector response
#[derive(Debug, Clone)]
pub struct RegisterConnectorResponse {
    pub success: bool,
    pub address: String,
    pub connector_arn: String,
    pub error: String,
    pub status: RegistrationStatus,
    pub session_token: Option<String>,
}

/// Execute request
#[derive(Debug, Clone)]
pub struct ExecuteRequest {
    pub request_id: String,
    pub payload: Vec<u8>,
    pub payload_encoding: PayloadEncoding,
    pub context: HashMap<String, String>,
    pub capability_id: Option<String>,
}

/// Execute response
#[derive(Debug, Clone)]
pub struct ExecuteResponse {
    pub request_id: String,
    pub success: bool,
    pub payload: Vec<u8>,
    pub payload_encoding: PayloadEncoding,
    pub error: String,
    pub duration_ms: u64,
}

/// Connector scope - determines tenant visibility
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(i32)]
pub enum ConnectorScope {
    Unspecified = 0, // Infer from tenant_id (backward compatible)
    Tenant = 1,      // Tenant-scoped
    Global = 2,      // Global (accessible by all)
}

impl From<i32> for ConnectorScope {
    fn from(value: i32) -> Self {
        match value {
            1 => ConnectorScope::Tenant,
            2 => ConnectorScope::Global,
            _ => ConnectorScope::Unspecified,
        }
    }
}

impl From<ConnectorScope> for i32 {
    fn from(scope: ConnectorScope) -> Self {
        scope as i32
    }
}

/// Authentication error codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum AuthError {
    Unspecified = 0,
    InvalidToken = 1,
    ExpiredToken = 2,
    UntrustedIssuer = 3,
    MissingTenantId = 4,
}

impl From<i32> for AuthError {
    fn from(value: i32) -> Self {
        match value {
            1 => AuthError::InvalidToken,
            2 => AuthError::ExpiredToken,
            3 => AuthError::UntrustedIssuer,
            4 => AuthError::MissingTenantId,
            _ => AuthError::Unspecified,
        }
    }
}

/// Invoke capability request - allows connector-to-connector invocation
#[derive(Debug, Clone)]
pub struct InvokeCapabilityRequest {
    pub request_id: String,
    pub target_address: String,
    pub capability_id: Option<String>,
    pub payload: Vec<u8>,
    pub payload_encoding: PayloadEncoding,
    pub context: HashMap<String, String>,
    pub timeout_ms: Option<u64>,
    pub fire_and_forget: bool,
}

/// Invoke capability response
#[derive(Debug, Clone)]
pub struct InvokeCapabilityResponse {
    pub request_id: String,
    pub success: bool,
    pub payload: Vec<u8>,
    pub payload_encoding: PayloadEncoding,
    pub error: String,
    pub duration_ms: u64,
    pub context: Option<HashMap<String, String>>,
    pub error_details: Option<HashMap<String, String>>,
}

/// WebSocket frame type (matches protobuf enum)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum WsFrameType {
    Unspecified = 0,
    Text = 1,
    Binary = 2,
    Ping = 3,
    Pong = 4,
}

impl From<i32> for WsFrameType {
    fn from(value: i32) -> Self {
        match value {
            1 => WsFrameType::Text,
            2 => WsFrameType::Binary,
            3 => WsFrameType::Ping,
            4 => WsFrameType::Pong,
            _ => WsFrameType::Unspecified,
        }
    }
}

/// Request from server to open a WebSocket connection to a backend
#[derive(Debug, Clone)]
pub struct WsOpenRequest {
    pub connection_id: String,
    pub path: String,
    pub query_string: String,
    pub headers: HashMap<String, String>,
}

/// Response confirming WebSocket connection was opened (or failed)
#[derive(Debug, Clone)]
pub struct WsOpenResponse {
    pub connection_id: String,
    pub success: bool,
    pub error: String,
}

/// A WebSocket frame flowing bidirectionally
#[derive(Debug, Clone)]
pub struct WsFrame {
    pub connection_id: String,
    pub frame_type: WsFrameType,
    pub data: Vec<u8>,
}

/// Request from server to close a WebSocket connection
#[derive(Debug, Clone)]
pub struct WsCloseRequest {
    pub connection_id: String,
    pub code: i32,
    pub reason: String,
}

/// Event message for SOURCE connectors
#[derive(Debug, Clone)]
pub struct EventMessage {
    pub event_id: String,
    pub payload: Vec<u8>,
    pub payload_encoding: PayloadEncoding,
    pub timestamp: String,
}

/// Batch message for batch event sending
#[derive(Debug, Clone)]
pub struct BatchMessage {
    pub batch_id: String,
    pub events: Vec<EventMessage>,
    pub event_count: usize,
}

/// Connector metrics
#[derive(Debug, Clone, Default)]
pub struct ConnectorMetrics {
    pub requests_received: u64,
    pub requests_processed: u64,
    pub requests_failed: u64,
    pub total_duration_ms: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    /// Timestamp of last request received (Unix ms, 0 if none)
    pub last_request_at_ms: u64,
    // Resilience metrics
    pub reconnection_attempts: u64,
    pub total_disconnects: u64,
    pub successful_reconnects: u64,
    pub last_disconnect_reason: Option<String>,
    pub last_connected_at_ms: Option<u64>,
    pub last_disconnected_at_ms: Option<u64>,
    pub current_backoff_ms: u64,
    // Heartbeat RTT metrics
    pub heartbeat_rtt_total_ms: f64,
    pub heartbeat_rtt_count: u64,
    pub heartbeat_rtt_last_ms: f64,
    pub heartbeat_rtt_min_ms: f64,
    pub heartbeat_rtt_max_ms: f64,
}

impl ConnectorMetrics {
    /// Record a heartbeat round-trip time measurement.
    pub fn record_heartbeat_rtt(&mut self, rtt_ms: f64) {
        self.heartbeat_rtt_total_ms += rtt_ms;
        self.heartbeat_rtt_count += 1;
        self.heartbeat_rtt_last_ms = rtt_ms;
        if self.heartbeat_rtt_count == 1 || rtt_ms < self.heartbeat_rtt_min_ms {
            self.heartbeat_rtt_min_ms = rtt_ms;
        }
        if rtt_ms > self.heartbeat_rtt_max_ms {
            self.heartbeat_rtt_max_ms = rtt_ms;
        }
    }

    /// Average heartbeat RTT in milliseconds, or 0.0 if no samples.
    pub fn heartbeat_rtt_avg_ms(&self) -> f64 {
        if self.heartbeat_rtt_count == 0 {
            0.0
        } else {
            self.heartbeat_rtt_total_ms / self.heartbeat_rtt_count as f64
        }
    }

    /// Collect SDK-level metrics for inclusion in `MetricsReport.custom_metrics`.
    /// All keys are `sdk.*` prefixed to avoid collision with connector-defined metrics.
    pub fn sdk_custom_metrics(&self) -> std::collections::HashMap<String, f64> {
        let mut m = crate::system_metrics::collect();

        if self.heartbeat_rtt_count > 0 {
            m.insert(
                "sdk.heartbeat_rtt_avg_ms".to_string(),
                self.heartbeat_rtt_avg_ms(),
            );
            m.insert(
                "sdk.heartbeat_rtt_last_ms".to_string(),
                self.heartbeat_rtt_last_ms,
            );
            m.insert(
                "sdk.heartbeat_rtt_min_ms".to_string(),
                self.heartbeat_rtt_min_ms,
            );
            m.insert(
                "sdk.heartbeat_rtt_max_ms".to_string(),
                self.heartbeat_rtt_max_ms,
            );
            m.insert(
                "sdk.heartbeat_rtt_count".to_string(),
                self.heartbeat_rtt_count as f64,
            );
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_single_rtt() {
        let mut m = ConnectorMetrics::default();
        m.record_heartbeat_rtt(15.0);

        assert_eq!(m.heartbeat_rtt_count, 1);
        assert_eq!(m.heartbeat_rtt_last_ms, 15.0);
        assert_eq!(m.heartbeat_rtt_min_ms, 15.0);
        assert_eq!(m.heartbeat_rtt_max_ms, 15.0);
        assert_eq!(m.heartbeat_rtt_avg_ms(), 15.0);
    }

    #[test]
    fn test_record_multiple_rtts() {
        let mut m = ConnectorMetrics::default();
        m.record_heartbeat_rtt(10.0);
        m.record_heartbeat_rtt(20.0);
        m.record_heartbeat_rtt(30.0);

        assert_eq!(m.heartbeat_rtt_count, 3);
        assert_eq!(m.heartbeat_rtt_last_ms, 30.0);
        assert_eq!(m.heartbeat_rtt_min_ms, 10.0);
        assert_eq!(m.heartbeat_rtt_max_ms, 30.0);
        assert_eq!(m.heartbeat_rtt_avg_ms(), 20.0);
    }

    #[test]
    fn test_rtt_avg_zero_when_no_samples() {
        let m = ConnectorMetrics::default();
        assert_eq!(m.heartbeat_rtt_avg_ms(), 0.0);
        assert_eq!(m.heartbeat_rtt_count, 0);
    }

    #[test]
    fn test_rtt_min_max_with_decreasing_values() {
        let mut m = ConnectorMetrics::default();
        m.record_heartbeat_rtt(50.0);
        m.record_heartbeat_rtt(5.0);

        assert_eq!(m.heartbeat_rtt_min_ms, 5.0);
        assert_eq!(m.heartbeat_rtt_max_ms, 50.0);
    }

    #[test]
    fn test_sdk_custom_metrics_has_system_metrics_without_rtts() {
        let m = ConnectorMetrics::default();
        let custom = m.sdk_custom_metrics();
        assert!(
            custom.contains_key("sdk.system_total_memory_bytes"),
            "system metrics should always be present"
        );
        assert!(
            !custom.contains_key("sdk.heartbeat_rtt_avg_ms"),
            "RTT metrics should be absent when no samples"
        );
    }

    #[test]
    fn test_sdk_custom_metrics_includes_rtt_after_samples() {
        let mut m = ConnectorMetrics::default();
        m.record_heartbeat_rtt(10.0);
        m.record_heartbeat_rtt(20.0);

        let custom = m.sdk_custom_metrics();
        assert_eq!(custom["sdk.heartbeat_rtt_avg_ms"], 15.0);
        assert_eq!(custom["sdk.heartbeat_rtt_last_ms"], 20.0);
        assert_eq!(custom["sdk.heartbeat_rtt_min_ms"], 10.0);
        assert_eq!(custom["sdk.heartbeat_rtt_max_ms"], 20.0);
        assert_eq!(custom["sdk.heartbeat_rtt_count"], 2.0);
        assert!(
            custom.contains_key("sdk.system_total_memory_bytes"),
            "system metrics should also be present"
        );
    }

    #[test]
    fn test_sdk_custom_metrics_all_keys_prefixed() {
        let mut m = ConnectorMetrics::default();
        m.record_heartbeat_rtt(5.0);

        let custom = m.sdk_custom_metrics();
        for key in custom.keys() {
            assert!(key.starts_with("sdk."), "key {key} must have sdk. prefix");
        }
    }

    // =========================================================================
    // TaskTypeSchema builder tests
    // =========================================================================

    #[test]
    fn task_type_schema_default_is_empty_with_object_schemas() {
        let s = TaskTypeSchema::default();
        assert_eq!(s.task_type_id, "");
        assert_eq!(s.name, "");
        assert_eq!(s.description, "");
        assert_eq!(s.category, "");
        assert_eq!(s.icon, "");
        assert_eq!(s.input_schema_json, "{}");
        assert_eq!(s.output_schema_json, "{}");
    }

    #[test]
    fn task_type_schema_new_sets_identity_and_keeps_defaults() {
        let s = TaskTypeSchema::new("add", "Add", "Add two numbers");
        assert_eq!(s.task_type_id, "add");
        assert_eq!(s.name, "Add");
        assert_eq!(s.description, "Add two numbers");
        // Defaults preserved.
        assert_eq!(s.category, "");
        assert_eq!(s.icon, "");
        assert_eq!(s.input_schema_json, "{}");
        assert_eq!(s.output_schema_json, "{}");
    }

    #[test]
    fn task_type_schema_builder_chains() {
        let s = TaskTypeSchema::new("greet", "Greet", "Greet someone")
            .category("social")
            .icon("wave")
            .input_schema(serde_json::json!({
                "type": "object",
                "properties": {"name": {"type": "string"}},
                "required": ["name"]
            }))
            .output_schema(serde_json::json!({
                "type": "object",
                "properties": {"message": {"type": "string"}},
                "required": ["message"]
            }));

        assert_eq!(s.category, "social");
        assert_eq!(s.icon, "wave");

        // input_schema_json must be a parseable JSON object containing our shape.
        let parsed: serde_json::Value = serde_json::from_str(&s.input_schema_json).unwrap();
        assert_eq!(parsed["type"], "object");
        assert!(parsed["properties"]["name"].is_object());
        assert_eq!(parsed["required"][0], "name");

        let out: serde_json::Value = serde_json::from_str(&s.output_schema_json).unwrap();
        assert!(out["properties"]["message"].is_object());
    }

    #[test]
    fn task_type_schema_input_output_str_passthrough() {
        let raw_in = r#"{"type":"object","properties":{}}"#;
        let raw_out = r#"{"type":"object","required":["ok"]}"#;
        let s = TaskTypeSchema::new("noop", "noop", "no-op")
            .input_schema_str(raw_in)
            .output_schema_str(raw_out);
        assert_eq!(s.input_schema_json, raw_in);
        assert_eq!(s.output_schema_json, raw_out);
    }

    #[test]
    fn task_type_schema_struct_literal_still_works() {
        // Backward-compat smoke: existing call sites that build TaskTypeSchema
        // via struct literals must continue to compile and behave identically.
        let s = TaskTypeSchema {
            task_type_id: "legacy".to_string(),
            name: "Legacy".to_string(),
            description: "still ok".to_string(),
            category: "legacy".to_string(),
            icon: "scroll".to_string(),
            input_schema_json: "{}".to_string(),
            output_schema_json: "{}".to_string(),
        };
        assert_eq!(s.task_type_id, "legacy");
        assert_eq!(s.icon, "scroll");
    }

    #[test]
    fn task_type_schema_serde_round_trip() {
        let original = TaskTypeSchema::new("calc", "Calculator", "Math")
            .category("math")
            .input_schema(serde_json::json!({"type": "object"}))
            .output_schema(serde_json::json!({"type": "object"}));
        let json = serde_json::to_string(&original).unwrap();
        let back: TaskTypeSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(back.task_type_id, original.task_type_id);
        assert_eq!(back.category, original.category);
        assert_eq!(back.input_schema_json, original.input_schema_json);
    }
}
