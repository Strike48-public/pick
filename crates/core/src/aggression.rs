//! Aggression level system for controlling specialist agent spawning.
//!
//! The aggression level determines how aggressively the Red Team agent spawns
//! specialist sub-agents for deep-dive security testing. This provides users
//! with control over the thoroughness-vs-speed trade-off.
//!
//! ## Architecture
//!
//! ```text
//! User Sets Aggression
//!         ↓
//! Orchestrator translates to SpawnPolicy
//!         ↓
//! Policy injected into Red Team agent context
//!         ↓
//! Agent makes tactical spawn decisions
//!         ↓
//! Can override with justification (based on OverridePolicy)
//! ```

use serde::{Deserialize, Serialize};

/// User-controlled aggression level for penetration testing scans.
///
/// Controls how liberally the Red Team agent spawns specialist sub-agents
/// for deep security analysis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AggressionLevel {
    /// Minimize sub-agents, only spawn when necessary.
    ///
    /// **Use when:**
    /// - Time-constrained assessments
    /// - Cost optimization is priority
    /// - Quick vulnerability surface mapping
    ///
    /// **Behavior:**
    /// - Red Team handles most targets itself using comprehensive knowledge
    /// - Spawns specialists only on complex targets (50+ endpoints)
    /// - Spawns only on clear suspicious findings
    Conservative,

    /// Intelligent tiered spawning (DEFAULT).
    ///
    /// **Use when:**
    /// - Standard penetration testing engagements
    /// - Balancing thoroughness with efficiency
    /// - General-purpose security assessments
    ///
    /// **Behavior:**
    /// - Spawns based on attack surface size (20+ endpoints)
    /// - Spawns on suspicious findings during initial testing
    /// - Good thoroughness/efficiency trade-off
    Balanced,

    /// Spawn specialists liberally for all target types.
    ///
    /// **Use when:**
    /// - Comprehensive security audits
    /// - High-value targets requiring thorough coverage
    /// - Compliance-driven assessments
    ///
    /// **Behavior:**
    /// - Spawns specialists for targets with 5+ endpoints
    /// - Always spawns on suspicious findings
    /// - Prioritizes thoroughness over speed
    Aggressive,

    /// Maximum coverage - spawn specialists for every target.
    ///
    /// **Use when:**
    /// - Critical infrastructure assessments
    /// - Pre-production security validation
    /// - Maximum thoroughness required regardless of cost
    ///
    /// **Behavior:**
    /// - Spawns specialists for every target type discovered
    /// - Spawns multiple specialists per domain (parallel deep dives)
    /// - Maximum thoroughness, disregard cost/speed
    /// - No agent overrides allowed (strict policy enforcement)
    Maximum,
}

impl AggressionLevel {
    /// Translate aggression level into concrete spawn policy.
    pub fn spawn_policy(self) -> SpawnPolicy {
        match self {
            Self::Conservative => SpawnPolicy {
                web_app_threshold: 50,
                api_threshold: 30,
                spawn_on_hints: false,
                parallel_specialists: false,
                max_concurrent_specialists: 2,
            },
            Self::Balanced => SpawnPolicy {
                web_app_threshold: 20,
                api_threshold: 15,
                spawn_on_hints: true,
                parallel_specialists: false,
                max_concurrent_specialists: 4,
            },
            Self::Aggressive => SpawnPolicy {
                web_app_threshold: 5,
                api_threshold: 5,
                spawn_on_hints: true,
                parallel_specialists: false,
                max_concurrent_specialists: 8,
            },
            Self::Maximum => SpawnPolicy {
                web_app_threshold: 1,
                api_threshold: 1,
                spawn_on_hints: true,
                parallel_specialists: true,
                max_concurrent_specialists: 16,
            },
        }
    }

    /// Determine what overrides the agent is allowed to make.
    pub fn allows_overrides(self) -> OverridePolicy {
        match self {
            Self::Conservative => OverridePolicy::UpgradeOnly,
            Self::Balanced => OverridePolicy::Both,
            Self::Aggressive => OverridePolicy::DowngradeOnly,
            Self::Maximum => OverridePolicy::None,
        }
    }

    /// Get cost warning if this level may be expensive.
    pub fn cost_warning(self) -> Option<CostWarning> {
        match self {
            Self::Conservative | Self::Balanced => None,
            Self::Aggressive => Some(CostWarning {
                level: WarnLevel::Info,
                message: "Aggressive mode may spawn multiple specialists. \
                         Estimated cost: 2-4x Conservative mode."
                    .to_string(),
            }),
            Self::Maximum => Some(CostWarning {
                level: WarnLevel::Warning,
                message: "⚠️  MAXIMUM mode spawns specialists for every target. \
                         This can be expensive for large networks. \
                         Estimated cost: 5-10x Conservative mode. \
                         Recommend starting with Aggressive mode first."
                    .to_string(),
            }),
        }
    }

    /// Rough cost multiplier relative to Conservative mode.
    pub fn cost_multiplier(self) -> f32 {
        match self {
            Self::Conservative => 1.0,
            Self::Balanced => 1.5,
            Self::Aggressive => 3.0,
            Self::Maximum => 7.0,
        }
    }

    /// Convert to display string.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Conservative => "conservative",
            Self::Balanced => "balanced",
            Self::Aggressive => "aggressive",
            Self::Maximum => "maximum",
        }
    }

    /// Convert to human-readable display name.
    pub fn display_name(self) -> &'static str {
        match self {
            Self::Conservative => "Conservative",
            Self::Balanced => "Balanced",
            Self::Aggressive => "Aggressive",
            Self::Maximum => "Maximum",
        }
    }
}

#[allow(clippy::derivable_impls)]
impl Default for AggressionLevel {
    fn default() -> Self {
        Self::Balanced
    }
}

impl std::str::FromStr for AggressionLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "conservative" | "c" => Ok(Self::Conservative),
            "balanced" | "b" => Ok(Self::Balanced),
            "aggressive" | "a" => Ok(Self::Aggressive),
            "maximum" | "max" | "m" => Ok(Self::Maximum),
            _ => Err(format!(
                "Invalid aggression level: {s}. \
                 Valid options: conservative, balanced, aggressive, maximum"
            )),
        }
    }
}

impl std::fmt::Display for AggressionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Concrete policy thresholds derived from aggression level.
///
/// Consumed by the orchestrator to decide when to spawn specialists.
#[derive(Debug, Clone, PartialEq)]
pub struct SpawnPolicy {
    /// Minimum number of endpoints before spawning web-app-specialist.
    pub web_app_threshold: usize,

    /// Minimum number of endpoints before spawning api-specialist.
    pub api_threshold: usize,

    /// Whether to spawn specialists when detecting suspicious findings
    /// during initial reconnaissance.
    pub spawn_on_hints: bool,

    /// Whether to spawn multiple specialists per domain for parallel
    /// deep dives (e.g., web-app-specialist + exploit-dev-specialist).
    pub parallel_specialists: bool,

    /// Maximum number of specialists that can run concurrently.
    pub max_concurrent_specialists: usize,
}

impl SpawnPolicy {
    /// Format policy as guidelines text for injection into agent prompt.
    pub fn to_guidelines(self, aggression: AggressionLevel) -> String {
        match aggression {
            AggressionLevel::Conservative => format!(
                "**Conservative Mode** - Minimize sub-agents:\n\
                 - Spawn web-app-specialist only for {}+ endpoints\n\
                 - Spawn api-specialist only for {}+ endpoints\n\
                 - Handle most targets yourself using comprehensive knowledge\n\
                 - Spawn only if you find clear suspicious findings\n\
                 - Prioritize speed and efficiency",
                self.web_app_threshold, self.api_threshold
            ),
            AggressionLevel::Balanced => format!(
                "**Balanced Mode** - Intelligent tiered spawning:\n\
                 - Spawn web-app-specialist for {}+ endpoints or complex apps\n\
                 - Spawn api-specialist for {}+ endpoints or GraphQL/complex auth\n\
                 - Spawn on suspicious findings during initial testing\n\
                 - Balance thoroughness with efficiency",
                self.web_app_threshold, self.api_threshold
            ),
            AggressionLevel::Aggressive => format!(
                "**Aggressive Mode** - Spawn specialists liberally:\n\
                 - Spawn web-app-specialist for any web app with {}+ endpoints\n\
                 - Spawn api-specialist for any API with {}+ endpoints\n\
                 - Always spawn on suspicious findings\n\
                 - Prioritize thoroughness over speed",
                self.web_app_threshold, self.api_threshold
            ),
            AggressionLevel::Maximum => "**Maximum Mode** - Maximum coverage:\n\
                 - Spawn specialists for every target type discovered\n\
                 - Spawn multiple specialists per domain (parallel deep dives)\n\
                 - Spawn immediately on discovery, don't wait for hints\n\
                 - Maximum thoroughness, disregard cost/speed\n\
                 - No policy overrides allowed"
                .to_string(),
        }
    }
}

/// Controls what overrides the agent can make to spawn policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverridePolicy {
    /// Agent can spawn MORE specialists than policy suggests.
    ///
    /// Used in Conservative mode: agent can upgrade to spawn when finding
    /// critical issues even on small targets.
    UpgradeOnly,

    /// Agent can spawn MORE or FEWER specialists based on judgment.
    ///
    /// Used in Balanced mode: agent has full judgment authority.
    Both,

    /// Agent can spawn FEWER specialists than policy suggests.
    ///
    /// Used in Aggressive mode: agent can skip truly trivial targets.
    DowngradeOnly,

    /// No overrides allowed - strict policy enforcement.
    ///
    /// Used in Maximum mode: user wants maximum coverage, period.
    None,
}

impl OverridePolicy {
    /// Whether the agent can spawn when policy says not to.
    pub fn can_upgrade(self) -> bool {
        matches!(self, Self::UpgradeOnly | Self::Both)
    }

    /// Whether the agent can skip spawning when policy says to spawn.
    pub fn can_downgrade(self) -> bool {
        matches!(self, Self::DowngradeOnly | Self::Both)
    }
}

/// Warning severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarnLevel {
    /// Informational notice (blue).
    Info,
    /// Important warning (yellow).
    Warning,
}

/// Cost warning displayed before expensive operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostWarning {
    pub level: WarnLevel,
    pub message: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggression_level_from_str() {
        assert_eq!(
            "conservative".parse::<AggressionLevel>().unwrap(),
            AggressionLevel::Conservative
        );
        assert_eq!(
            "c".parse::<AggressionLevel>().unwrap(),
            AggressionLevel::Conservative
        );
        assert_eq!(
            "balanced".parse::<AggressionLevel>().unwrap(),
            AggressionLevel::Balanced
        );
        assert_eq!(
            "b".parse::<AggressionLevel>().unwrap(),
            AggressionLevel::Balanced
        );
        assert_eq!(
            "aggressive".parse::<AggressionLevel>().unwrap(),
            AggressionLevel::Aggressive
        );
        assert_eq!(
            "a".parse::<AggressionLevel>().unwrap(),
            AggressionLevel::Aggressive
        );
        assert_eq!(
            "maximum".parse::<AggressionLevel>().unwrap(),
            AggressionLevel::Maximum
        );
        assert_eq!(
            "max".parse::<AggressionLevel>().unwrap(),
            AggressionLevel::Maximum
        );
        assert_eq!(
            "m".parse::<AggressionLevel>().unwrap(),
            AggressionLevel::Maximum
        );

        assert!("invalid".parse::<AggressionLevel>().is_err());
    }

    #[test]
    fn aggression_level_default_is_balanced() {
        assert_eq!(AggressionLevel::default(), AggressionLevel::Balanced);
    }

    #[test]
    fn spawn_policy_thresholds_decrease_with_aggression() {
        let conservative = AggressionLevel::Conservative.spawn_policy();
        let balanced = AggressionLevel::Balanced.spawn_policy();
        let aggressive = AggressionLevel::Aggressive.spawn_policy();
        let maximum = AggressionLevel::Maximum.spawn_policy();

        assert!(conservative.web_app_threshold > balanced.web_app_threshold);
        assert!(balanced.web_app_threshold > aggressive.web_app_threshold);
        assert!(aggressive.web_app_threshold > maximum.web_app_threshold);

        assert!(conservative.api_threshold > balanced.api_threshold);
        assert!(balanced.api_threshold > aggressive.api_threshold);
        assert!(aggressive.api_threshold > maximum.api_threshold);
    }

    #[test]
    fn override_policy_permissions() {
        let conservative = AggressionLevel::Conservative.allows_overrides();
        assert!(conservative.can_upgrade());
        assert!(!conservative.can_downgrade());

        let balanced = AggressionLevel::Balanced.allows_overrides();
        assert!(balanced.can_upgrade());
        assert!(balanced.can_downgrade());

        let aggressive = AggressionLevel::Aggressive.allows_overrides();
        assert!(!aggressive.can_upgrade());
        assert!(aggressive.can_downgrade());

        let maximum = AggressionLevel::Maximum.allows_overrides();
        assert!(!maximum.can_upgrade());
        assert!(!maximum.can_downgrade());
    }

    #[test]
    fn cost_multipliers_increase_with_aggression() {
        assert_eq!(AggressionLevel::Conservative.cost_multiplier(), 1.0);
        assert!(AggressionLevel::Balanced.cost_multiplier() > 1.0);
        assert!(
            AggressionLevel::Aggressive.cost_multiplier()
                > AggressionLevel::Balanced.cost_multiplier()
        );
        assert!(
            AggressionLevel::Maximum.cost_multiplier()
                > AggressionLevel::Aggressive.cost_multiplier()
        );
    }

    #[test]
    fn expensive_modes_have_warnings() {
        assert!(AggressionLevel::Conservative.cost_warning().is_none());
        assert!(AggressionLevel::Balanced.cost_warning().is_none());
        assert!(AggressionLevel::Aggressive.cost_warning().is_some());
        assert!(AggressionLevel::Maximum.cost_warning().is_some());
    }
}
