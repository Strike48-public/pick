//! Error types for the pentest connector

use thiserror::Error;

/// Main error type for the pentest connector
#[derive(Error, Debug)]
pub enum Error {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Tool execution error: {0}")]
    ToolExecution(String),

    #[error("Tool not found: {0}")]
    ToolNotFound(String),

    #[error("Invalid parameters: {0}")]
    InvalidParams(String),

    #[error("Platform not supported: {0}")]
    PlatformNotSupported(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Timeout: {0}")]
    Timeout(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Capture error: {0}")]
    Capture(String),

    #[error("SDK error: {0}")]
    Sdk(String),

    #[error("File browser error: {0}")]
    FileBrowser(String),

    #[error("matrix: {0}")]
    Matrix(String),

    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// Result type alias using our Error type
pub type Result<T> = std::result::Result<T, Error>;

impl From<anyhow::Error> for Error {
    fn from(err: anyhow::Error) -> Self {
        Error::Unknown(err.to_string())
    }
}

impl From<strike48_connector::ConnectorError> for Error {
    fn from(err: strike48_connector::ConnectorError) -> Self {
        Error::Sdk(err.to_string())
    }
}
