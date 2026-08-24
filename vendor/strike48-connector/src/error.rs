use thiserror::Error;

/// Result type alias for connector operations
pub type Result<T> = std::result::Result<T, ConnectorError>;

/// Connector error types.
///
/// Marked `#[non_exhaustive]` so adding new variants in subsequent releases
/// does not break downstream `match` statements that handle the variants
/// they care about. Downstream code must include a wildcard arm.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum ConnectorError {
    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Not connected to Strike48 server")]
    NotConnected,

    #[error("Connector not registered")]
    NotRegistered,

    #[error("Stream error: {0}")]
    StreamError(String),

    #[error("Registration error: {0}")]
    RegistrationError(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Unsupported encoding: {0}")]
    UnsupportedEncoding(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Invoke failed: {0}")]
    InvokeFailed(String),

    #[error("Connector not running")]
    NotRunning,

    #[error("Already running")]
    AlreadyRunning,

    #[error("IO error: {0}")]
    Io(#[source] Box<std::io::Error>),

    #[error("gRPC error: {0}")]
    Grpc(#[source] Box<tonic::Status>),

    #[error("JSON error: {0}")]
    Json(#[source] Box<serde_json::Error>),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Proxy unreachable: {0}")]
    ProxyUnreachable(String),

    #[error("Proxy CONNECT failed: {0}")]
    ProxyConnectFailed(String),

    #[error("Proxy authentication failed: {0}")]
    ProxyAuthFailed(String),

    #[error("Other error: {0}")]
    Other(String),
}

impl From<std::io::Error> for ConnectorError {
    fn from(e: std::io::Error) -> Self {
        ConnectorError::Io(Box::new(e))
    }
}

impl From<tonic::Status> for ConnectorError {
    fn from(e: tonic::Status) -> Self {
        ConnectorError::Grpc(Box::new(e))
    }
}

impl From<serde_json::Error> for ConnectorError {
    fn from(e: serde_json::Error) -> Self {
        ConnectorError::Json(Box::new(e))
    }
}

impl ConnectorError {
    pub fn code(&self) -> &'static str {
        match self {
            ConnectorError::ConnectionError(_) => "CONNECTION_ERROR",
            ConnectorError::NotConnected => "NOT_CONNECTED",
            ConnectorError::NotRegistered => "NOT_REGISTERED",
            ConnectorError::StreamError(_) => "STREAM_ERROR",
            ConnectorError::RegistrationError(_) => "REGISTRATION_ERROR",
            ConnectorError::InvalidConfig(_) => "INVALID_CONFIG",
            ConnectorError::SerializationError(_) => "SERIALIZATION_ERROR",
            ConnectorError::DeserializationError(_) => "DESERIALIZATION_ERROR",
            ConnectorError::UnsupportedEncoding(_) => "UNSUPPORTED_ENCODING",
            ConnectorError::Timeout(_) => "TIMEOUT",
            ConnectorError::InvokeFailed(_) => "INVOKE_FAILED",
            ConnectorError::NotRunning => "NOT_RUNNING",
            ConnectorError::AlreadyRunning => "ALREADY_RUNNING",
            ConnectorError::Io(_) => "IO_ERROR",
            ConnectorError::Grpc(_) => "GRPC_ERROR",
            ConnectorError::Json(_) => "JSON_ERROR",
            ConnectorError::NotImplemented(_) => "NOT_IMPLEMENTED",
            ConnectorError::ProxyUnreachable(_) => "PROXY_UNREACHABLE",
            ConnectorError::ProxyConnectFailed(_) => "PROXY_CONNECT_FAILED",
            ConnectorError::ProxyAuthFailed(_) => "PROXY_AUTH_FAILED",
            ConnectorError::Other(_) => "OTHER",
        }
    }

    /// Whether this error is transient and reconnection may succeed.
    ///
    /// Non-recoverable errors (invalid config, permanent registration
    /// rejection, serialization bugs) should stop the reconnect loop
    /// to avoid wasting resources and hiding real problems.
    pub fn is_recoverable(&self) -> bool {
        match self {
            ConnectorError::ConnectionError(_)
            | ConnectorError::NotConnected
            | ConnectorError::StreamError(_)
            | ConnectorError::Timeout(_)
            | ConnectorError::Io(_)
            | ConnectorError::ProxyUnreachable(_)
            | ConnectorError::ProxyConnectFailed(_)
            | ConnectorError::ProxyAuthFailed(_)
            | ConnectorError::Grpc(_) => true,

            ConnectorError::RegistrationError(msg) => {
                let lower = msg.to_lowercase();
                // Permanent config/policy errors — no point retrying
                let permanent = lower.contains("not enabled")
                    || lower.contains("not supported")
                    || lower.contains("disabled")
                    || lower.contains("invalid connector")
                    || lower.contains("permission denied")
                    || lower.contains("not allowed");
                // Auth errors (jwt_invalid, auth_invalid, etc.) are handled
                // in-stream by the registration failure path which clears
                // credentials and retries. They should never be considered
                // permanent shutdowns if they do reach this branch.
                !permanent
            }

            ConnectorError::InvalidConfig(_)
            | ConnectorError::NotRegistered
            | ConnectorError::SerializationError(_)
            | ConnectorError::DeserializationError(_)
            | ConnectorError::UnsupportedEncoding(_)
            | ConnectorError::NotImplemented(_)
            | ConnectorError::NotRunning
            | ConnectorError::AlreadyRunning
            | ConnectorError::Json(_) => false,

            ConnectorError::InvokeFailed(_) | ConnectorError::Other(_) => true,
        }
    }
}

#[cfg(test)]
mod proxy_error_tests {
    use super::*;

    #[test]
    fn proxy_errors_are_recoverable() {
        assert!(ConnectorError::ProxyUnreachable("x".into()).is_recoverable());
        assert!(ConnectorError::ProxyConnectFailed("x".into()).is_recoverable());
        assert!(ConnectorError::ProxyAuthFailed("x".into()).is_recoverable());
    }

    #[test]
    fn proxy_error_codes() {
        assert_eq!(
            ConnectorError::ProxyAuthFailed("x".into()).code(),
            "PROXY_AUTH_FAILED"
        );
    }
}
