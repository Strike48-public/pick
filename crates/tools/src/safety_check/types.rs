//! Type definitions for safety check results.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Overall safety status of the network environment.
///
/// Four levels, each with a distinct meaning and intended color. Every verdict
/// is always accompanied by the per-check reasons that produced it - the status
/// is the headline, never the whole story.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyStatus {
    /// Everything checked out and was fully verified (green).
    Safe,
    /// Nothing bad found, but at least one thing could not be fully verified
    /// yet - e.g. gateway reputation enrichment is still pending (lime).
    MostlySafe,
    /// Normal public-network unknowns; take basic precautions like a VPN
    /// (amber). Triggered by warnings or checks that could not run.
    Caution,
    /// Active threat detected; do not do sensitive work and consider
    /// disconnecting (red).
    Unsafe,
}

/// Status of an individual security check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CheckStatus {
    /// Check passed successfully.
    Passed,
    /// Check ran cleanly locally, but a remote verification step is still
    /// pending (e.g. IP reputation lookup the agent must perform).
    NeedsEnrichment,
    /// Check detected potential issues.
    Warning,
    /// Check failed, critical issue detected.
    Failed,
    /// Check could not be completed.
    Unknown,
}

/// Severity level of a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    /// Critical security issue requiring immediate action.
    Critical,
    /// High severity issue, should be addressed.
    High,
    /// Medium severity issue, proceed with caution.
    Medium,
    /// Low severity or informational.
    Low,
    /// Informational only, no action needed.
    Info,
}

/// Threat level of a device on the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// Device appears safe.
    Safe,
    /// Device shows suspicious characteristics.
    Suspicious,
    /// Device identified as malicious.
    Malicious,
}

/// Priority level for recommendations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Priority {
    /// Critical action required immediately.
    Critical,
    /// High priority action.
    High,
    /// Medium priority suggestion.
    Medium,
    /// Low priority or informational.
    Low,
}

/// Result of a single security check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    /// Name of the check performed.
    pub name: String,
    /// Status of the check.
    pub status: CheckStatus,
    /// Detailed findings or explanation.
    pub details: String,
    /// Severity level of findings.
    pub severity: Severity,
}

/// A device discovered on the local network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// IP address of the device.
    pub ip: IpAddr,
    /// MAC address if available.
    pub mac: Option<String>,
    /// Hostname if resolved.
    pub hostname: Option<String>,
    /// Vendor name from MAC OUI lookup.
    pub vendor: Option<String>,
    /// Open ports detected on this device.
    pub open_ports: Vec<u16>,
    /// Assessed threat level.
    pub threat_level: ThreatLevel,
}

/// Map of the local network topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMap {
    /// The default gateway/router.
    pub gateway: Device,
    /// The operator's device running this check.
    pub your_device: Device,
    /// Other devices discovered on the network.
    pub other_devices: Vec<Device>,
}

/// An actionable recommendation based on findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recommendation {
    /// Priority level of this recommendation.
    pub priority: Priority,
    /// Short title of the recommendation.
    pub title: String,
    /// Detailed description and rationale.
    pub description: String,
    /// Specific action to take (command, setting change, etc).
    pub action: Option<String>,
}

/// Complete result of a safety check run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyCheckResult {
    /// Overall safety status.
    pub status: SafetyStatus,
    /// Individual check results.
    pub checks: Vec<CheckResult>,
    /// Network topology map if available.
    pub network_map: Option<NetworkMap>,
    /// Actionable recommendations.
    pub recommendations: Vec<Recommendation>,
    /// Timestamp when check was performed.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl std::fmt::Display for SafetyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SafetyStatus::Safe => write!(f, "SAFE"),
            SafetyStatus::MostlySafe => write!(f, "MOSTLY SAFE"),
            SafetyStatus::Caution => write!(f, "CAUTION"),
            SafetyStatus::Unsafe => write!(f, "UNSAFE"),
        }
    }
}

impl std::fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckStatus::Passed => write!(f, "PASS"),
            CheckStatus::NeedsEnrichment => write!(f, "PENDING"),
            CheckStatus::Warning => write!(f, "WARN"),
            CheckStatus::Failed => write!(f, "FAIL"),
            CheckStatus::Unknown => write!(f, "UNKNOWN"),
        }
    }
}
