//! Types for autopwn attack planning and execution

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Attack strategy recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AttackStrategy {
    /// WEP attack (capture IVs + crack)
    Wep {
        estimated_time_sec: u64,
        confidence: f32,
        target_ivs: u32,
    },
    /// WPA/WPA2 attack (capture handshake + crack)
    Wpa {
        capture_mode: CaptureMode,
        crack_method: CrackMethod,
        estimated_time_sec: u64,
        confidence: f32,
    },
    /// Attack not supported
    Unsupported { reason: String },
}

impl AttackStrategy {
    pub fn is_supported(&self) -> bool {
        !matches!(self, AttackStrategy::Unsupported { .. })
    }

    pub fn estimated_duration(&self) -> Duration {
        let secs = match self {
            AttackStrategy::Wep {
                estimated_time_sec, ..
            } => *estimated_time_sec,
            AttackStrategy::Wpa {
                estimated_time_sec, ..
            } => *estimated_time_sec,
            AttackStrategy::Unsupported { .. } => 0,
        };
        Duration::from_secs(secs)
    }
}

/// How to capture the handshake
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    /// Wait for natural reconnection (slow but stealthy)
    Passive,
    /// Deauth specific client to force reconnection
    ActiveDeauth { target_client: Option<String> },
    /// Broadcast deauth to all clients
    Broadcast,
}

/// How to crack the captured data
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrackMethod {
    /// Dictionary attack with wordlist
    Dictionary { wordlists: Vec<String> },
    /// Mask attack (brute force with pattern)
    MaskAttack { pattern: String },
    /// Hybrid (dictionary + mask)
    Hybrid { wordlist: String, mask: String },
    /// Send to remote cracking service
    Remote { endpoint: String },
}

/// Complete attack plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackPlan {
    pub target_ssid: String,
    pub target_bssid: String,
    pub channel: u8,
    pub security: String,
    pub strategy: AttackStrategy,
    pub requires_monitor_mode: bool,
    pub requires_mac_cloning: bool,
    pub estimated_duration_sec: u64,
    pub warnings: Vec<String>,
}

/// Capture result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureResult {
    pub success: bool,
    pub capture_file: String,
    pub capture_type: CaptureType,
    pub quality: CaptureQuality,
    pub duration_sec: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CaptureType {
    WepIvs { count: u32 },
    WpaHandshake { verified: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureQuality {
    Excellent, // Ready to crack
    Good,      // Should work
    Fair,      // Might work
    Poor,      // Unlikely to crack
}

/// Cracking result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackResult {
    pub success: bool,
    pub password: Option<String>,
    pub attempts: u64,
    pub duration_sec: u64,
    pub method: String,
}

/// Security type parsed from scan
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityType {
    Open,
    Wep,
    Wpa,
    Wpa2,
    Wpa3,
    WpaEnterprise,
    Unknown,
}

impl SecurityType {
    /// Parse security string from WiFi scan
    pub fn parse(security: &str) -> Self {
        let sec_lower = security.to_lowercase();

        if sec_lower.contains("wpa3") {
            SecurityType::Wpa3
        } else if sec_lower.contains("wpa2") {
            SecurityType::Wpa2
        } else if sec_lower.contains("wpa") {
            if sec_lower.contains("enterprise") || sec_lower.contains("eap") {
                SecurityType::WpaEnterprise
            } else {
                SecurityType::Wpa
            }
        } else if sec_lower.contains("wep") {
            SecurityType::Wep
        } else if sec_lower.is_empty() || sec_lower.contains("open") {
            SecurityType::Open
        } else {
            SecurityType::Unknown
        }
    }

    pub fn is_attackable(&self) -> bool {
        matches!(
            self,
            SecurityType::Wep | SecurityType::Wpa | SecurityType::Wpa2
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityType::Open => "Open",
            SecurityType::Wep => "WEP",
            SecurityType::Wpa => "WPA",
            SecurityType::Wpa2 => "WPA2",
            SecurityType::Wpa3 => "WPA3",
            SecurityType::WpaEnterprise => "WPA-Enterprise",
            SecurityType::Unknown => "Unknown",
        }
    }
}
