//! System tool for spawning domain-specific specialist agents.
//!
//! This tool is available to the Red Team agent to delegate deep-dive
//! security testing to specialized sub-agents based on target characteristics
//! and aggression level configuration.
//!
//! NOTE: This tool is currently a placeholder. Full implementation requires:
//! 1. Matrix client injection into ToolContext
//! 2. Aggression level propagation through ToolContext
//! 3. Parent agent name tracking in ToolContext
//!
//! Once these are wired, the spawn_specialist_impl function can be used.

use async_trait::async_trait;
use pentest_core::aggression::AggressionLevel;
use pentest_core::error::{Error, Result};
use pentest_core::matrix::MatrixChatClient;
use pentest_core::specialist_spawner::{
    AttackSurface, SpawnDecision, SpecialistContext, SpecialistSpawner, SpecialistType,
};
use pentest_core::tools::{execute_timed, PentestTool, Platform, ToolContext, ToolResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Input for the spawn_specialist tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnSpecialistInput {
    /// Type of specialist to spawn.
    pub specialist_type: SpecialistType,

    /// Target URLs, endpoints, or binaries being analyzed.
    pub targets: Vec<String>,

    /// Initial reconnaissance findings from Red Team agent.
    #[serde(default)]
    pub initial_findings: Vec<String>,

    /// Specific areas of concern or suspicious behavior.
    #[serde(default)]
    pub concerns: Vec<String>,

    /// Number of endpoints discovered.
    pub endpoint_count: usize,

    /// Technologies detected (frameworks, languages, libraries).
    #[serde(default)]
    pub technologies: Vec<String>,

    /// Authentication mechanisms detected.
    #[serde(default)]
    pub auth_mechanisms: Vec<String>,

    /// Entry points identified.
    #[serde(default)]
    pub entry_points: Vec<String>,

    /// Justification for spawning (required when overriding policy).
    #[serde(default)]
    pub justification: Option<String>,
}

/// Result of spawning a specialist.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpawnSpecialistResult {
    /// Whether the specialist was spawned.
    pub spawned: bool,

    /// Agent ID of the spawned specialist (if spawned).
    pub agent_id: Option<String>,

    /// Agent name of the spawned specialist (if spawned).
    pub agent_name: Option<String>,

    /// Reason if not spawned.
    pub reason: Option<String>,

    /// Spawn decision made by policy.
    pub decision: String,

    /// Whether this was a policy override.
    pub override_used: bool,

    /// Current aggression level.
    pub aggression_level: String,

    /// Spawn policy guidelines.
    pub policy_guidelines: String,
}

/// Spawn specialist tool.
pub struct SpawnSpecialistTool;

#[async_trait]
impl PentestTool for SpawnSpecialistTool {
    fn name(&self) -> &str {
        "spawn_specialist"
    }

    fn description(&self) -> &str {
        "Spawn a domain-specific specialist agent for deep-dive security testing. \
         Evaluates spawn policy based on aggression level and target characteristics. \
         Specialists: web-app, api, binary, ai-security."
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        // System tool - works everywhere
        vec![
            Platform::Desktop,
            Platform::Android,
            Platform::Ios,
            Platform::Web,
            Platform::Tui,
        ]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            // Parse input
            let _input: SpawnSpecialistInput = serde_json::from_value(params).map_err(|e| {
                Error::InvalidParams(format!("Invalid spawn_specialist parameters: {}", e))
            })?;

            // TODO: Full implementation requires ToolContext enhancements:
            // 1. Matrix client injection: ctx.matrix_client()
            // 2. Aggression level: ctx.aggression_level()
            // 3. Parent agent name: ctx.agent_name()
            //
            // Once available, call spawn_specialist_impl()

            Err(Error::Config(
                "spawn_specialist tool requires ToolContext enhancements (Matrix client, \
                 aggression level, agent name) - implementation ready, wiring pending"
                    .to_string(),
            ))
        })
        .await
    }
}

/// Internal implementation of spawn_specialist logic.
///
/// This function contains the complete specialist spawning logic and will be
/// called once ToolContext has Matrix client, aggression level, and agent name.
#[allow(dead_code)]
async fn spawn_specialist_impl(
    input: SpawnSpecialistInput,
    aggression: AggressionLevel,
    parent_agent_name: &str,
    matrix_client: &MatrixChatClient,
) -> Result<SpawnSpecialistResult> {
    let spawner = SpecialistSpawner::new(aggression);

    // Build specialist context
    let context = SpecialistContext {
        targets: input.targets,
        initial_findings: input.initial_findings,
        concerns: input.concerns,
        attack_surface: AttackSurface {
            endpoint_count: input.endpoint_count,
            technologies: input.technologies,
            auth_mechanisms: input.auth_mechanisms,
            entry_points: input.entry_points,
        },
    };

    // Evaluate spawn policy
    let decision = spawner.should_spawn(input.specialist_type, &context);

    // Check for policy override
    let mut override_used = false;
    let should_spawn = match decision {
        SpawnDecision::Spawn => true,
        SpawnDecision::Skip => {
            // Check if agent can override to spawn
            if input.justification.is_some() && spawner.can_override_to_spawn() {
                tracing::info!(
                    specialist = ?input.specialist_type,
                    justification = ?input.justification,
                    "Agent overriding policy to spawn specialist"
                );
                override_used = true;
                true
            } else if input.justification.is_some() {
                return Ok(SpawnSpecialistResult {
                    spawned: false,
                    agent_id: None,
                    agent_name: None,
                    reason: Some(format!(
                        "Policy override not allowed in {} mode",
                        aggression.display_name()
                    )),
                    decision: "skip".to_string(),
                    override_used: false,
                    aggression_level: aggression.display_name().to_string(),
                    policy_guidelines: spawner.policy_guidelines(),
                });
            } else {
                false
            }
        }
        SpawnDecision::AskUser => {
            // For now, treat AskUser as Skip (UI can implement confirmation later)
            return Ok(SpawnSpecialistResult {
                spawned: false,
                agent_id: None,
                agent_name: None,
                reason: Some("User confirmation required".to_string()),
                decision: "ask_user".to_string(),
                override_used: false,
                aggression_level: aggression.display_name().to_string(),
                policy_guidelines: spawner.policy_guidelines(),
            });
        }
    };

    if !should_spawn {
        return Ok(SpawnSpecialistResult {
            spawned: false,
            agent_id: None,
            agent_name: None,
            reason: Some(format!(
                "Policy says skip: {} mode threshold not met",
                aggression.display_name()
            )),
            decision: "skip".to_string(),
            override_used: false,
            aggression_level: aggression.display_name().to_string(),
            policy_guidelines: spawner.policy_guidelines(),
        });
    }

    // Spawn the specialist
    tracing::info!(
        specialist = ?input.specialist_type,
        parent = %parent_agent_name,
        override_used = override_used,
        "Spawning specialist agent"
    );

    match spawner
        .spawn(
            matrix_client,
            input.specialist_type,
            context,
            parent_agent_name,
        )
        .await
    {
        Ok(agent_info) => Ok(SpawnSpecialistResult {
            spawned: true,
            agent_id: Some(agent_info.id),
            agent_name: Some(agent_info.name),
            reason: None,
            decision: if override_used {
                "override_to_spawn".to_string()
            } else {
                "spawn".to_string()
            },
            override_used,
            aggression_level: aggression.display_name().to_string(),
            policy_guidelines: spawner.policy_guidelines(),
        }),
        Err(e) => Err(Error::Matrix(format!("Failed to spawn specialist: {}", e))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input(specialist: SpecialistType, endpoint_count: usize) -> SpawnSpecialistInput {
        SpawnSpecialistInput {
            specialist_type: specialist,
            targets: vec!["https://example.com".to_string()],
            initial_findings: vec![],
            concerns: vec![],
            endpoint_count,
            technologies: vec![],
            auth_mechanisms: vec![],
            entry_points: vec![],
            justification: None,
        }
    }

    #[test]
    fn spawn_specialist_input_serialization() {
        let input = make_input(SpecialistType::WebApp, 20);
        let json = serde_json::to_string(&input).unwrap();
        let deserialized: SpawnSpecialistInput = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.specialist_type, SpecialistType::WebApp);
        assert_eq!(deserialized.endpoint_count, 20);
    }

    #[test]
    fn spawn_specialist_result_serialization() {
        let result = SpawnSpecialistResult {
            spawned: true,
            agent_id: Some("agent-123".to_string()),
            agent_name: Some("pentest-connector-web-app".to_string()),
            reason: None,
            decision: "spawn".to_string(),
            override_used: false,
            aggression_level: "Balanced".to_string(),
            policy_guidelines: "**Balanced Mode**".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: SpawnSpecialistResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.spawned);
        assert_eq!(deserialized.agent_id.unwrap(), "agent-123");
    }

    #[test]
    fn tool_basic_properties() {
        let tool = SpawnSpecialistTool;
        assert_eq!(tool.name(), "spawn_specialist");
        assert!(!tool.description().is_empty());
        assert!(!tool.supported_platforms().is_empty());
    }
}
