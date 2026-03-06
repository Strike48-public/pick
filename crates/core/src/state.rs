//! Application state management

use serde::{Deserialize, Serialize};

/// Connection status enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ConnectorStatus {
    #[default]
    Disconnected,
    Connecting,
    Registered,
    Reconnecting,
    Error(String),
}

impl ConnectorStatus {
    /// Get the status color (for UI)
    pub fn color(&self) -> &'static str {
        match self {
            ConnectorStatus::Disconnected => "#f44336", // red
            ConnectorStatus::Connecting => "#ff9800",   // yellow
            ConnectorStatus::Registered => "#4caf50",   // green
            ConnectorStatus::Reconnecting => "#ff9800", // yellow
            ConnectorStatus::Error(_) => "#f44336",     // red
        }
    }

    /// Get the status text
    pub fn text(&self) -> String {
        match self {
            ConnectorStatus::Disconnected => "Disconnected".to_string(),
            ConnectorStatus::Connecting => "Connecting...".to_string(),
            ConnectorStatus::Registered => "Connected".to_string(),
            ConnectorStatus::Reconnecting => "Reconnecting...".to_string(),
            ConnectorStatus::Error(msg) => msg.clone(),
        }
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        matches!(self, ConnectorStatus::Registered)
    }
}

/// Scan configuration for port scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub host: String,
    pub ports: Vec<u16>,
    pub timeout_ms: u64,
    pub concurrency: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            ports: vec![22, 80, 443, 8080],
            timeout_ms: 2000,
            concurrency: 50,
        }
    }
}

impl ScanConfig {
    /// Parse a port specification string (e.g., "22,80,443" or "1-1024")
    pub fn parse_ports(spec: &str) -> Vec<u16> {
        let mut ports = Vec::new();
        for part in spec.split(',') {
            let part = part.trim();
            if part.contains('-') {
                let parts: Vec<&str> = part.split('-').collect();
                if parts.len() == 2 {
                    if let (Ok(start), Ok(end)) = (parts[0].parse::<u16>(), parts[1].parse::<u16>())
                    {
                        ports.extend(start..=end);
                    }
                }
            } else if let Ok(port) = part.parse::<u16>() {
                ports.push(port);
            }
        }
        ports
    }
}

/// Scan progress tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub total: usize,
    pub completed: usize,
    pub open_ports: Vec<u16>,
}
