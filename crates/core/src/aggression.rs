//! Aggression level management for penetration testing scans.
//!
//! Defines aggression levels that control the intensity, cost, and invasiveness
//! of penetration testing operations. Used by REST API for dynamic adjustment.

use serde::{Deserialize, Serialize};

/// Aggression level for penetration testing operations.
///
/// Controls the intensity, cost multiplier, and invasiveness of scan activities.
/// Can be dynamically adjusted mid-scan via REST API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AggressionLevel {
    /// Conservative: Minimal intrusion, 0.5x cost, passive reconnaissance only
    Conservative,
    /// Balanced: Standard pentesting, 1.0x cost (default)
    #[default]
    Balanced,
    /// Aggressive: Active exploitation, 1.5x cost
    Aggressive,
    /// Maximum: Full-scale attack simulation, 2.0x cost
    Maximum,
}

impl AggressionLevel {
    /// Human-readable display name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Conservative => "Conservative",
            Self::Balanced => "Balanced",
            Self::Aggressive => "Aggressive",
            Self::Maximum => "Maximum",
        }
    }

    /// Cost multiplier for this aggression level
    pub fn cost_multiplier(&self) -> f64 {
        match self {
            Self::Conservative => 0.5,
            Self::Balanced => 1.0,
            Self::Aggressive => 1.5,
            Self::Maximum => 2.0,
        }
    }

    /// Spawn policy guidelines for agents (placeholder for full implementation)
    pub fn spawn_policy(&self) -> SpawnPolicy {
        SpawnPolicy {
            aggression_level: *self,
        }
    }
}

/// Spawn policy for specialist agents (minimal placeholder)
pub struct SpawnPolicy {
    #[allow(dead_code)]
    aggression_level: AggressionLevel,
}

impl SpawnPolicy {
    /// Generate policy guidelines text
    pub fn to_guidelines(&self, level: AggressionLevel) -> String {
        format!(
            "**{} Mode**\nCost Multiplier: {}x baseline\n\nSpawn policy: {}",
            level.display_name(),
            level.cost_multiplier(),
            match level {
                AggressionLevel::Conservative =>
                    "Passive reconnaissance only, minimal resource usage",
                AggressionLevel::Balanced => "Standard penetration testing approach",
                AggressionLevel::Aggressive =>
                    "Active exploitation enabled, increased resource allocation",
                AggressionLevel::Maximum => "Full-scale attack simulation, maximum resources",
            }
        )
    }
}
