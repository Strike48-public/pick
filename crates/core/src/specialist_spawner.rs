//! Specialist agent spawning orchestration.
//!
//! This module provides the infrastructure for spawning domain-specific
//! specialist agents from the Red Team orchestrator agent based on
//! aggression level and target characteristics.

use crate::aggression::{AggressionLevel, OverridePolicy, SpawnPolicy};
use crate::error::{Error, Result};
use crate::matrix::{AgentInfo, ChatClient, CreateAgentInput};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Domain-specific specialist types available for spawning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SpecialistType {
    /// Web application security specialist (SQLi, XSS, SSRF, SSTI, XXE, etc.)
    WebApp,
    /// API security specialist (GraphQL, JWT, OAuth, REST vulnerabilities)
    Api,
    /// Binary exploitation and reverse engineering specialist
    Binary,
    /// AI/LLM security specialist (prompt injection, RAG poisoning, etc.)
    AiSecurity,
}

impl SpecialistType {
    /// Get the system prompt file path for this specialist.
    pub fn prompt_file(&self) -> PathBuf {
        let filename = match self {
            Self::WebApp => "web-app-specialist.md",
            Self::Api => "api-specialist.md",
            Self::Binary => "binary-specialist.md",
            Self::AiSecurity => "ai-security-specialist.md",
        };
        PathBuf::from("skills/claude-red/specialists").join(filename)
    }

    /// Get the specialist agent name suffix.
    pub fn agent_suffix(&self) -> &'static str {
        match self {
            Self::WebApp => "web-app",
            Self::Api => "api",
            Self::Binary => "binary",
            Self::AiSecurity => "ai-security",
        }
    }

    /// Get human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::WebApp => "Web Application Security Specialist",
            Self::Api => "API Security Specialist",
            Self::Binary => "Binary Exploitation Specialist",
            Self::AiSecurity => "AI/LLM Security Specialist",
        }
    }
}

impl std::fmt::Display for SpecialistType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Context passed to specialist when spawning.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpecialistContext {
    /// Target URL(s), endpoints, or binaries being analyzed.
    pub targets: Vec<String>,

    /// Initial reconnaissance findings from Red Team agent.
    pub initial_findings: Vec<String>,

    /// Specific areas of concern or suspicious behavior.
    pub concerns: Vec<String>,

    /// Attack surface summary (endpoint count, technologies detected, etc.)
    pub attack_surface: AttackSurface,
}

/// Attack surface summary for target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackSurface {
    /// Number of endpoints discovered.
    pub endpoint_count: usize,

    /// Technologies detected (frameworks, languages, libraries).
    pub technologies: Vec<String>,

    /// Authentication mechanisms detected.
    pub auth_mechanisms: Vec<String>,

    /// Entry points identified.
    pub entry_points: Vec<String>,
}

/// Spawn decision returned by policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnDecision {
    /// Spawn the specialist.
    Spawn,
    /// Do not spawn the specialist.
    Skip,
    /// Ask user for confirmation before spawning.
    AskUser,
}

/// Specialist spawner orchestrates specialist agent creation.
pub struct SpecialistSpawner {
    aggression: AggressionLevel,
    policy: SpawnPolicy,
    override_policy: OverridePolicy,
}

impl SpecialistSpawner {
    /// Create a new specialist spawner with the given aggression level.
    pub fn new(aggression: AggressionLevel) -> Self {
        let policy = aggression.spawn_policy();
        let override_policy = aggression.allows_overrides();
        Self {
            aggression,
            policy,
            override_policy,
        }
    }

    /// Evaluate whether to spawn a specialist given target characteristics.
    pub fn should_spawn(
        &self,
        specialist: SpecialistType,
        context: &SpecialistContext,
    ) -> SpawnDecision {
        let threshold = match specialist {
            SpecialistType::WebApp => self.policy.web_app_threshold,
            SpecialistType::Api => self.policy.api_threshold,
            SpecialistType::Binary => 1, // Always spawn for binaries (rare targets)
            SpecialistType::AiSecurity => 1, // Always spawn for AI/LLM (rare targets)
        };

        let meets_threshold = context.attack_surface.endpoint_count >= threshold;
        let has_hints = !context.concerns.is_empty();
        let spawn_on_hints = self.policy.spawn_on_hints;

        if meets_threshold || (has_hints && spawn_on_hints) {
            SpawnDecision::Spawn
        } else {
            SpawnDecision::Skip
        }
    }

    /// Spawn a specialist agent via the Matrix client.
    ///
    /// # Arguments
    /// * `client` - Matrix client for agent creation
    /// * `specialist` - Type of specialist to spawn
    /// * `context` - Context to pass to specialist
    /// * `parent_agent_name` - Name of the Red Team agent spawning this specialist
    ///
    /// # Returns
    /// `AgentInfo` for the newly created specialist agent.
    pub async fn spawn<C: ChatClient>(
        &self,
        client: &C,
        specialist: SpecialistType,
        context: SpecialistContext,
        parent_agent_name: &str,
    ) -> Result<AgentInfo> {
        // Load specialist system prompt from file
        let prompt_path = specialist.prompt_file();
        let system_message = std::fs::read_to_string(&prompt_path).map_err(|e| {
            Error::Config(format!(
                "Failed to load specialist prompt from {}: {}",
                prompt_path.display(),
                e
            ))
        })?;

        // Build specialist agent name
        let agent_name = format!("{}-{}", parent_agent_name, specialist.agent_suffix());

        // Build agent input
        let input = CreateAgentInput {
            name: agent_name.clone(),
            description: Some(format!(
                "{} (spawned by {})",
                specialist.display_name(),
                parent_agent_name
            )),
            system_message: Some(system_message),
            agent_greeting: Some(format!(
                "{} ready. Analyzing targets...",
                specialist.display_name()
            )),
            context: Some(serde_json::to_value(context)?),
            tools: None, // Inherit tools from parent connector
        };

        // Spawn via Matrix API
        tracing::info!(
            specialist = ?specialist,
            agent_name = %agent_name,
            parent = %parent_agent_name,
            "Spawning specialist agent"
        );

        client.create_agent(input).await
    }

    /// Get the current aggression level.
    pub fn aggression(&self) -> AggressionLevel {
        self.aggression
    }

    /// Get the current spawn policy.
    pub fn policy(&self) -> &SpawnPolicy {
        &self.policy
    }

    /// Check if agent can override policy to spawn when policy says skip.
    pub fn can_override_to_spawn(&self) -> bool {
        self.override_policy.can_upgrade()
    }

    /// Check if agent can override policy to skip when policy says spawn.
    pub fn can_override_to_skip(&self) -> bool {
        self.override_policy.can_downgrade()
    }

    /// Format spawn policy as guidelines text for Red Team agent prompt.
    pub fn policy_guidelines(&self) -> String {
        self.policy.clone().to_guidelines(self.aggression)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context(endpoint_count: usize, concerns: Vec<&str>) -> SpecialistContext {
        SpecialistContext {
            targets: vec!["https://example.com".to_string()],
            initial_findings: vec![],
            concerns: concerns.into_iter().map(|s| s.to_string()).collect(),
            attack_surface: AttackSurface {
                endpoint_count,
                technologies: vec![],
                auth_mechanisms: vec![],
                entry_points: vec![],
            },
        }
    }

    #[test]
    fn conservative_requires_high_threshold() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Conservative);
        let context = make_context(30, vec![]);

        // Below threshold (50) - skip
        assert_eq!(
            spawner.should_spawn(SpecialistType::WebApp, &context),
            SpawnDecision::Skip
        );

        // At threshold - spawn
        let context = make_context(50, vec![]);
        assert_eq!(
            spawner.should_spawn(SpecialistType::WebApp, &context),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn balanced_spawns_on_hints() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Balanced);

        // Below threshold (20) but no hints - skip
        let context = make_context(10, vec![]);
        assert_eq!(
            spawner.should_spawn(SpecialistType::WebApp, &context),
            SpawnDecision::Skip
        );

        // Below threshold but has hints - spawn
        let context = make_context(10, vec!["SQLi suspected"]);
        assert_eq!(
            spawner.should_spawn(SpecialistType::WebApp, &context),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn aggressive_low_threshold() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Aggressive);
        let context = make_context(5, vec![]);

        // Threshold is 5 - spawn
        assert_eq!(
            spawner.should_spawn(SpecialistType::WebApp, &context),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn maximum_always_spawns() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Maximum);
        let context = make_context(1, vec![]);

        // Threshold is 1 - always spawn
        assert_eq!(
            spawner.should_spawn(SpecialistType::WebApp, &context),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn binary_and_ai_always_spawn() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Balanced);
        let context = make_context(1, vec![]);

        // Binary and AI specialists always spawn (rare targets)
        assert_eq!(
            spawner.should_spawn(SpecialistType::Binary, &context),
            SpawnDecision::Spawn
        );
        assert_eq!(
            spawner.should_spawn(SpecialistType::AiSecurity, &context),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn override_policy_permissions() {
        let conservative = SpecialistSpawner::new(AggressionLevel::Conservative);
        assert!(conservative.can_override_to_spawn());
        assert!(!conservative.can_override_to_skip());

        let balanced = SpecialistSpawner::new(AggressionLevel::Balanced);
        assert!(balanced.can_override_to_spawn());
        assert!(balanced.can_override_to_skip());

        let aggressive = SpecialistSpawner::new(AggressionLevel::Aggressive);
        assert!(!aggressive.can_override_to_spawn());
        assert!(aggressive.can_override_to_skip());

        let maximum = SpecialistSpawner::new(AggressionLevel::Maximum);
        assert!(!maximum.can_override_to_spawn());
        assert!(!maximum.can_override_to_skip());
    }

    #[test]
    fn specialist_prompt_paths() {
        assert_eq!(
            SpecialistType::WebApp.prompt_file(),
            PathBuf::from("skills/claude-red/specialists/web-app-specialist.md")
        );
        assert_eq!(
            SpecialistType::Api.prompt_file(),
            PathBuf::from("skills/claude-red/specialists/api-specialist.md")
        );
        assert_eq!(
            SpecialistType::Binary.prompt_file(),
            PathBuf::from("skills/claude-red/specialists/binary-specialist.md")
        );
        assert_eq!(
            SpecialistType::AiSecurity.prompt_file(),
            PathBuf::from("skills/claude-red/specialists/ai-security-specialist.md")
        );
    }
}
