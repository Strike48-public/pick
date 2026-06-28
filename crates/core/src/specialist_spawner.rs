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
    /// Cloud security specialist (IAM, instance-metadata abuse, storage
    /// exposure, serverless, container/K8s escapes). See pick#151.
    Cloud,
}

impl SpecialistType {
    /// Get the system prompt file path for this specialist.
    pub fn prompt_file(&self) -> PathBuf {
        let filename = match self {
            Self::WebApp => "web-app-specialist.md",
            Self::Api => "api-specialist.md",
            Self::Binary => "binary-specialist.md",
            Self::AiSecurity => "ai-security-specialist.md",
            Self::Cloud => "cloud-specialist.md",
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
            Self::Cloud => "cloud",
        }
    }

    /// Get human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::WebApp => "Web Application Security Specialist",
            Self::Api => "API Security Specialist",
            Self::Binary => "Binary Exploitation Specialist",
            Self::AiSecurity => "AI/LLM Security Specialist",
            Self::Cloud => "Cloud Security Specialist",
        }
    }
}

/// Cloud provider detected during reconnaissance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CloudProvider {
    /// Amazon Web Services.
    Aws,
    /// Microsoft Azure.
    Azure,
    /// Google Cloud Platform.
    Gcp,
    /// A cloud provider was detected but could not be classified.
    Unknown,
}

impl CloudProvider {
    /// Whether this provider has a documented, attackable instance-metadata
    /// endpoint (AWS IMDSv2, Azure IMDS, GCP metadata). `Unknown` does not:
    /// the metadata-credential chain is provider-specific, so an SSRF against
    /// an unclassified provider has nothing actionable to target.
    pub fn is_classified(self) -> bool {
        matches!(self, Self::Aws | Self::Azure | Self::Gcp)
    }
}

/// Cloud-specific attack-surface signals used to decide whether to spawn the
/// Cloud specialist (pick#151).
///
/// Unlike the WebApp/API specialists, the Cloud specialist is not driven by raw
/// endpoint counts: a single exposed bucket or a stolen credential is a stronger
/// signal than dozens of ordinary HTTP endpoints. These indicators are populated
/// during recon and evaluated by [`SpecialistSpawner::should_spawn`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudIndicators {
    /// Cloud provider detected, if any.
    #[serde(default)]
    pub provider: Option<CloudProvider>,

    /// An SSRF finding is available, enabling the metadata-credential chain
    /// (SSRF -> 169.254.169.254 -> temporary IAM credentials).
    #[serde(default)]
    pub ssrf_available: bool,

    /// Number of cloud storage endpoints detected (S3 buckets, Azure blobs,
    /// GCS buckets).
    #[serde(default)]
    pub storage_endpoints: usize,

    /// Cloud credentials (access keys, tokens) were discovered.
    #[serde(default)]
    pub credentials_found: bool,
}

impl CloudIndicators {
    /// Whether any cloud signal at all is present.
    pub fn has_any(&self) -> bool {
        self.provider.is_some()
            || self.ssrf_available
            || self.storage_endpoints > 0
            || self.credentials_found
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

    /// Cloud-specific attack-surface signals (pick#151). Defaulted so contexts
    /// serialized before the Cloud specialist existed still deserialize.
    #[serde(default)]
    pub cloud_indicators: CloudIndicators,
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
        // The Cloud specialist is driven by cloud indicators rather than the
        // endpoint-count threshold used by the web-facing specialists.
        if specialist == SpecialistType::Cloud {
            return self.should_spawn_cloud(&context.attack_surface.cloud_indicators);
        }

        let threshold = match specialist {
            SpecialistType::WebApp => self.policy.web_app_threshold,
            SpecialistType::Api => self.policy.api_threshold,
            SpecialistType::Binary => 1, // Always spawn for binaries (rare targets)
            SpecialistType::AiSecurity => 1, // Always spawn for AI/LLM (rare targets)
            SpecialistType::Cloud => {
                unreachable!(
                    "Cloud uses cloud_indicators, not endpoint_count; early-returned above"
                )
            }
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

    /// Cloud specialist spawn decision, scaled by aggression level.
    ///
    /// The thresholds mirror the pick#151 spec:
    /// - Conservative: credentials found, OR SSRF + a *classified* provider
    ///   (Aws/Azure/Gcp). The conservative trigger is the metadata-credential
    ///   chain, which is provider-specific (AWS IMDSv2 vs Azure `Metadata: true`
    ///   vs GCP `Metadata-Flavor: Google`), so an SSRF against an unclassified
    ///   (`Unknown`) provider has no actionable metadata endpoint and must skip.
    /// - Balanced: a provider is detected (including `Unknown`) AND there is some
    ///   surface to act on (SSRF, storage, or credentials). `Unknown` is allowed
    ///   here because surface signals like an exposed bucket are actionable
    ///   without knowing the exact provider.
    /// - Aggressive: any single cloud indicator.
    /// - Maximum: always spawn (treat every target as potentially cloud-hosted).
    fn should_spawn_cloud(&self, ind: &CloudIndicators) -> SpawnDecision {
        let spawn = match self.aggression {
            AggressionLevel::Conservative => {
                ind.credentials_found
                    || (ind.ssrf_available && ind.provider.is_some_and(|p| p.is_classified()))
            }
            AggressionLevel::Balanced => {
                ind.provider.is_some()
                    && (ind.ssrf_available || ind.storage_endpoints > 0 || ind.credentials_found)
            }
            AggressionLevel::Aggressive => ind.has_any(),
            AggressionLevel::Maximum => true,
        };

        // Visibility for the operator: skipping with no cloud signal at all is
        // expected fail-safe behavior, but it is indistinguishable from a recon
        // step that failed to populate indicators. Surface it so a missing-cloud
        // skip can be told apart from a not-cloud skip.
        if !spawn && !ind.has_any() {
            tracing::debug!(
                aggression = ?self.aggression,
                "Cloud specialist skipped: no cloud indicators present. If the target \
                 is cloud-hosted, recon may not have populated indicators."
            );
        }

        if spawn {
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
                cloud_indicators: CloudIndicators::default(),
            },
        }
    }

    /// Build a context whose only meaningful signal is its cloud indicators.
    ///
    /// `endpoint_count` is deliberately 0 to prove the Cloud specialist spawns on
    /// cloud indicators rather than on the endpoint-count threshold used by the
    /// WebApp/API specialists.
    fn make_cloud_context(indicators: CloudIndicators) -> SpecialistContext {
        SpecialistContext {
            targets: vec!["https://victim.example.com".to_string()],
            initial_findings: vec![],
            concerns: vec![],
            attack_surface: AttackSurface {
                endpoint_count: 0,
                technologies: vec![],
                auth_mechanisms: vec![],
                entry_points: vec![],
                cloud_indicators: indicators,
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

    /// Each specialist must have a prompt file shipped with the repo. The runtime
    /// `SpecialistSpawner::spawn()` reads these files to populate the agent's
    /// `system_message`; if any file is missing or empty, every spawn attempt
    /// fails with `Error::Config`. Asserting both existence and a minimum size
    /// guards against silent regressions where the file was deleted, truncated,
    /// or renamed.
    #[test]
    fn specialist_prompt_files_exist_and_have_content() {
        // Tests run from each crate's directory; resolve from the workspace root.
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(|p| p.parent())
            .expect("crates/core/.. should resolve to repo root")
            .to_path_buf();

        const MIN_PROMPT_BYTES: u64 = 1024;

        for specialist in [
            SpecialistType::WebApp,
            SpecialistType::Api,
            SpecialistType::Binary,
            SpecialistType::AiSecurity,
            SpecialistType::Cloud,
        ] {
            let path = repo_root.join(specialist.prompt_file());
            let metadata = std::fs::metadata(&path).unwrap_or_else(|e| {
                panic!("specialist prompt missing for {specialist:?} at {path:?}: {e}")
            });
            assert!(
                metadata.len() >= MIN_PROMPT_BYTES,
                "specialist prompt for {specialist:?} at {path:?} is suspiciously small \
                 ({} bytes < {MIN_PROMPT_BYTES} byte minimum)",
                metadata.len()
            );
            let body = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("specialist prompt unreadable at {path:?}: {e}"));
            assert!(
                body.contains("# ") && body.contains("Authorization preflight"),
                "specialist prompt for {specialist:?} is missing the required structural \
                 sections (heading and Authorization preflight)"
            );
        }
    }

    // --- Cloud specialist (pick#151) ---------------------------------------

    #[test]
    fn cloud_specialist_metadata() {
        assert_eq!(
            SpecialistType::Cloud.prompt_file(),
            PathBuf::from("skills/claude-red/specialists/cloud-specialist.md")
        );
        assert_eq!(SpecialistType::Cloud.agent_suffix(), "cloud");
        assert_eq!(
            SpecialistType::Cloud.display_name(),
            "Cloud Security Specialist"
        );
    }

    #[test]
    fn cloud_indicators_default_is_empty() {
        let ind = CloudIndicators::default();
        assert!(ind.provider.is_none());
        assert!(!ind.ssrf_available);
        assert_eq!(ind.storage_endpoints, 0);
        assert!(!ind.credentials_found);
        assert!(!ind.has_any());
    }

    #[test]
    fn cloud_indicators_has_any_detects_signal() {
        let ind = CloudIndicators {
            provider: Some(CloudProvider::Aws),
            ..Default::default()
        };
        assert!(ind.has_any());

        let ind = CloudIndicators {
            storage_endpoints: 1,
            ..Default::default()
        };
        assert!(ind.has_any());
    }

    #[test]
    fn cloud_provider_is_classified() {
        // Classified providers have documented, attackable metadata endpoints;
        // Unknown does not. A direct test fails immediately on a `matches!`
        // typo, rather than only via a downstream spawn-decision assertion.
        assert!(CloudProvider::Aws.is_classified());
        assert!(CloudProvider::Azure.is_classified());
        assert!(CloudProvider::Gcp.is_classified());
        assert!(!CloudProvider::Unknown.is_classified());
    }

    #[test]
    fn conservative_cloud_spawns_on_credentials() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Conservative);

        // Credentials found -> spawn even at the most conservative level.
        let ctx = make_cloud_context(CloudIndicators {
            credentials_found: true,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Spawn
        );

        // SSRF + a known provider is the other conservative trigger (metadata chain).
        let ctx = make_cloud_context(CloudIndicators {
            provider: Some(CloudProvider::Aws),
            ssrf_available: true,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn conservative_cloud_skips_weak_signal() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Conservative);

        // A bare storage endpoint is not enough at the conservative level.
        let ctx = make_cloud_context(CloudIndicators {
            storage_endpoints: 1,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Skip
        );

        // No cloud indicators at all -> skip.
        let ctx = make_cloud_context(CloudIndicators::default());
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Skip
        );
    }

    #[test]
    fn conservative_cloud_skips_signal_without_provider() {
        // Conservative requires SSRF *and* a known provider for the metadata
        // chain. SSRF alone (provider unknown) must skip - this pins the AND so a
        // regression to `ssrf_available || provider.is_some()` would be caught.
        let spawner = SpecialistSpawner::new(AggressionLevel::Conservative);
        let ctx = make_cloud_context(CloudIndicators {
            ssrf_available: true,
            provider: None,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Skip
        );

        // Provider alone (no SSRF, no creds) is also not a conservative trigger.
        let ctx = make_cloud_context(CloudIndicators {
            provider: Some(CloudProvider::Aws),
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Skip
        );
    }

    #[test]
    fn conservative_cloud_skips_unknown_provider_ssrf() {
        // The conservative trigger is the metadata-credential chain, which is
        // provider-specific (AWS IMDSv2 vs Azure `Metadata: true` vs GCP
        // `Metadata-Flavor: Google`). An SSRF against an *unclassified* provider
        // has no actionable metadata endpoint to attack, so the most cautious
        // level must skip rather than pay for cloud enumeration that cannot fire.
        // This pins the predicate to known providers (Aws/Azure/Gcp), not the
        // looser `provider.is_some()` which is also true for Unknown.
        let spawner = SpecialistSpawner::new(AggressionLevel::Conservative);
        let ctx = make_cloud_context(CloudIndicators {
            provider: Some(CloudProvider::Unknown),
            ssrf_available: true,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Skip
        );

        // Credentials in hand remain a conservative trigger regardless of
        // provider classification - a stolen key is actionable on its own.
        let ctx = make_cloud_context(CloudIndicators {
            provider: Some(CloudProvider::Unknown),
            credentials_found: true,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn conservative_cloud_spawns_on_ssrf_with_each_classified_provider() {
        // The SSRF metadata-credential trigger fires for every *classified*
        // provider, not just AWS. Exercise Azure and Gcp explicitly so a typo
        // dropping a variant from `is_classified` (e.g. losing `| Azure`) is
        // caught at the most security-critical aggression level.
        let spawner = SpecialistSpawner::new(AggressionLevel::Conservative);

        for provider in [CloudProvider::Aws, CloudProvider::Azure, CloudProvider::Gcp] {
            let ctx = make_cloud_context(CloudIndicators {
                provider: Some(provider),
                ssrf_available: true,
                ..Default::default()
            });
            assert_eq!(
                spawner.should_spawn(SpecialistType::Cloud, &ctx),
                SpawnDecision::Spawn,
                "SSRF + {:?} should spawn at Conservative",
                provider
            );
        }
    }

    #[test]
    fn balanced_cloud_skips_surface_without_provider() {
        // Balanced requires a provider AND some surface signal. Surface signals
        // without a provider must skip - even all of them at once - pinning the
        // `provider.is_some() && (...)` precedence.
        let spawner = SpecialistSpawner::new(AggressionLevel::Balanced);
        let ctx = make_cloud_context(CloudIndicators {
            provider: None,
            ssrf_available: true,
            storage_endpoints: 3,
            credentials_found: true,
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Skip
        );
    }

    #[test]
    fn aggressive_cloud_spawns_on_each_indicator_in_isolation() {
        // Aggressive spawns on any single indicator. Exercise each field alone
        // (the existing test only covers storage) so `has_any()` is proven to
        // check every field, including the Gcp provider variant.
        let spawner = SpecialistSpawner::new(AggressionLevel::Aggressive);

        for ind in [
            CloudIndicators {
                provider: Some(CloudProvider::Gcp),
                ..Default::default()
            },
            CloudIndicators {
                ssrf_available: true,
                ..Default::default()
            },
            CloudIndicators {
                credentials_found: true,
                ..Default::default()
            },
        ] {
            let ctx = make_cloud_context(ind);
            assert_eq!(
                spawner.should_spawn(SpecialistType::Cloud, &ctx),
                SpawnDecision::Spawn
            );
        }
    }

    #[test]
    fn cloud_spawn_is_independent_of_endpoint_count() {
        // The Cloud path must ignore endpoint_count entirely. make_cloud_context
        // sets it to 0; assert a spawn still happens on a cloud signal, proving
        // Cloud does not fall through to the endpoint-threshold logic.
        let spawner = SpecialistSpawner::new(AggressionLevel::Aggressive);
        let ctx = make_cloud_context(CloudIndicators {
            provider: Some(CloudProvider::Aws),
            ..Default::default()
        });
        assert_eq!(ctx.attack_surface.endpoint_count, 0);
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn balanced_cloud_spawns_on_provider_plus_surface() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Balanced);

        // Provider + any surface (storage here) -> spawn.
        let ctx = make_cloud_context(CloudIndicators {
            provider: Some(CloudProvider::Azure),
            storage_endpoints: 2,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Spawn
        );

        // Provider alone, no surface signal -> skip at balanced.
        let ctx = make_cloud_context(CloudIndicators {
            provider: Some(CloudProvider::Azure),
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Skip
        );
    }

    #[test]
    fn balanced_cloud_allows_unknown_provider_with_surface() {
        // Unlike Conservative (which requires a classified provider for the
        // SSRF metadata chain), Balanced spawns on an *unclassified* provider
        // as long as there is actionable surface - an exposed bucket is worth
        // testing without knowing the exact cloud. This pins the Balanced
        // predicate to the loose `provider.is_some()` so a regression to the
        // stricter `is_classified()` check (copied from the Conservative arm)
        // would be caught.
        let spawner = SpecialistSpawner::new(AggressionLevel::Balanced);

        let ctx = make_cloud_context(CloudIndicators {
            provider: Some(CloudProvider::Unknown),
            storage_endpoints: 2,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Spawn
        );

        // SSRF is also actionable surface at Balanced: Unknown + SSRF spawns
        // here even though the same combination skips at Conservative (which
        // gates the metadata chain on a classified provider). This directly
        // pins the SSRF branch of the Balanced predicate, not just storage.
        let ctx = make_cloud_context(CloudIndicators {
            provider: Some(CloudProvider::Unknown),
            ssrf_available: true,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Spawn
        );

        // But an unclassified provider with no surface signal still skips.
        let ctx = make_cloud_context(CloudIndicators {
            provider: Some(CloudProvider::Unknown),
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Skip
        );
    }

    #[test]
    fn aggressive_cloud_spawns_on_any_indicator() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Aggressive);

        // Any single indicator (a lone storage endpoint) is enough.
        let ctx = make_cloud_context(CloudIndicators {
            storage_endpoints: 1,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Spawn
        );

        // But still skip when there is genuinely no cloud signal.
        let ctx = make_cloud_context(CloudIndicators::default());
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Skip
        );
    }

    #[test]
    fn maximum_cloud_always_spawns() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Maximum);

        // At maximum aggression the Cloud specialist spawns even with no signal.
        let ctx = make_cloud_context(CloudIndicators::default());
        assert_eq!(
            spawner.should_spawn(SpecialistType::Cloud, &ctx),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn attack_surface_deserializes_without_cloud_field() {
        // Backward compatibility: contexts serialized before pick#151 have no
        // `cloud_indicators` field and must still deserialize (serde default).
        let json = r#"{
            "endpoint_count": 5,
            "technologies": [],
            "auth_mechanisms": [],
            "entry_points": []
        }"#;
        let surface: AttackSurface =
            serde_json::from_str(json).expect("legacy AttackSurface must deserialize");
        assert_eq!(surface.endpoint_count, 5);
        assert!(!surface.cloud_indicators.has_any());
    }
}
