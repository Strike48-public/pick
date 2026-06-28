//! Specialist agent spawning orchestration.
//!
//! This module provides the infrastructure for spawning domain-specific
//! specialist agents from the Red Team orchestrator agent based on
//! aggression level and target characteristics.

use crate::aggression::{AggressionLevel, OverridePolicy, SpawnPolicy};
use crate::error::{Error, Result};
use crate::matrix::{AgentInfo, ChatClient, CreateAgentInput};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::path::PathBuf;

/// Domain-specific specialist types available for spawning.
///
/// Specialists fall into two spawn-decision families:
/// - [`ThresholdSpecialist`] are gated by the recon endpoint-count threshold.
/// - [`IndicatorSpecialist`] are gated by their own attack-surface indicators
///   (e.g. the Cloud specialist on [`CloudIndicators`]).
///
/// Modelling this split at the type level keeps [`SpecialistSpawner::should_spawn`]
/// dispatch exhaustive - there is no "threshold for an indicator-driven
/// specialist" case to handle with a panic.
///
/// The external serde representation is intentionally a *flat* kebab-case string
/// (`"web-app"`, `"cloud"`, ...). That string is the LLM's JSON contract for the
/// `spawn_specialist` tool, so [`Serialize`]/[`Deserialize`] are hand-written to
/// delegate to the private flat [`SpecialistTypeWire`] enum rather than exposing
/// the nested structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SpecialistType {
    /// Endpoint-count-driven specialist.
    ThresholdBased(ThresholdSpecialist),
    /// Indicator-driven specialist.
    IndicatorBased(IndicatorSpecialist),
}

/// Specialists whose spawn decision is driven by the recon endpoint-count
/// threshold (and concern hints).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ThresholdSpecialist {
    /// Web application security specialist (SQLi, XSS, SSRF, SSTI, XXE, etc.)
    WebApp,
    /// API security specialist (GraphQL, JWT, OAuth, REST vulnerabilities)
    Api,
    /// Binary exploitation and reverse engineering specialist
    Binary,
    /// AI/LLM security specialist (prompt injection, RAG poisoning, etc.)
    AiSecurity,
}

/// Specialists whose spawn decision is driven by their own attack-surface
/// indicators rather than the endpoint-count threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IndicatorSpecialist {
    /// Cloud security specialist (IAM, instance-metadata abuse, storage
    /// exposure, serverless, container/K8s escapes). See pick#151.
    Cloud,
    /// Database security specialist (DBMS config, authn/authz,
    /// injection-to-takeover, exposure, NoSQL, cloud-managed DBs). See pick#161.
    Database,
}

/// Flat wire representation of [`SpecialistType`] - the single source of truth
/// for the kebab-case strings exchanged with the LLM. Keeping this as a plain
/// derived enum preserves serde's actionable `unknown variant ... expected one
/// of ...` error on bad input (which the Red Team agent uses to self-correct).
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SpecialistTypeWire {
    WebApp,
    Api,
    Binary,
    AiSecurity,
    Cloud,
    Database,
}

impl From<SpecialistType> for SpecialistTypeWire {
    fn from(value: SpecialistType) -> Self {
        match value {
            SpecialistType::ThresholdBased(ThresholdSpecialist::WebApp) => Self::WebApp,
            SpecialistType::ThresholdBased(ThresholdSpecialist::Api) => Self::Api,
            SpecialistType::ThresholdBased(ThresholdSpecialist::Binary) => Self::Binary,
            SpecialistType::ThresholdBased(ThresholdSpecialist::AiSecurity) => Self::AiSecurity,
            SpecialistType::IndicatorBased(IndicatorSpecialist::Cloud) => Self::Cloud,
            SpecialistType::IndicatorBased(IndicatorSpecialist::Database) => Self::Database,
        }
    }
}

impl From<SpecialistTypeWire> for SpecialistType {
    fn from(value: SpecialistTypeWire) -> Self {
        match value {
            SpecialistTypeWire::WebApp => Self::WEB_APP,
            SpecialistTypeWire::Api => Self::API,
            SpecialistTypeWire::Binary => Self::BINARY,
            SpecialistTypeWire::AiSecurity => Self::AI_SECURITY,
            SpecialistTypeWire::Cloud => Self::CLOUD,
            SpecialistTypeWire::Database => Self::DATABASE,
        }
    }
}

impl Serialize for SpecialistType {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        SpecialistTypeWire::from(*self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SpecialistType {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        SpecialistTypeWire::deserialize(deserializer).map(SpecialistType::from)
    }
}

impl From<ThresholdSpecialist> for SpecialistType {
    fn from(value: ThresholdSpecialist) -> Self {
        Self::ThresholdBased(value)
    }
}

impl From<IndicatorSpecialist> for SpecialistType {
    fn from(value: IndicatorSpecialist) -> Self {
        Self::IndicatorBased(value)
    }
}

impl SpecialistType {
    /// Web application security specialist.
    pub const WEB_APP: Self = Self::ThresholdBased(ThresholdSpecialist::WebApp);
    /// API security specialist.
    pub const API: Self = Self::ThresholdBased(ThresholdSpecialist::Api);
    /// Binary exploitation specialist.
    pub const BINARY: Self = Self::ThresholdBased(ThresholdSpecialist::Binary);
    /// AI/LLM security specialist.
    pub const AI_SECURITY: Self = Self::ThresholdBased(ThresholdSpecialist::AiSecurity);
    /// Cloud security specialist.
    pub const CLOUD: Self = Self::IndicatorBased(IndicatorSpecialist::Cloud);
    /// Database security specialist.
    pub const DATABASE: Self = Self::IndicatorBased(IndicatorSpecialist::Database);

    /// Get the system prompt file path for this specialist.
    pub fn prompt_file(&self) -> PathBuf {
        let filename = match self {
            Self::ThresholdBased(ThresholdSpecialist::WebApp) => "web-app-specialist.md",
            Self::ThresholdBased(ThresholdSpecialist::Api) => "api-specialist.md",
            Self::ThresholdBased(ThresholdSpecialist::Binary) => "binary-specialist.md",
            Self::ThresholdBased(ThresholdSpecialist::AiSecurity) => "ai-security-specialist.md",
            Self::IndicatorBased(IndicatorSpecialist::Cloud) => "cloud-specialist.md",
            Self::IndicatorBased(IndicatorSpecialist::Database) => "database-specialist.md",
        };
        PathBuf::from("skills/claude-red/specialists").join(filename)
    }

    /// Get the specialist agent name suffix.
    pub fn agent_suffix(&self) -> &'static str {
        match self {
            Self::ThresholdBased(ThresholdSpecialist::WebApp) => "web-app",
            Self::ThresholdBased(ThresholdSpecialist::Api) => "api",
            Self::ThresholdBased(ThresholdSpecialist::Binary) => "binary",
            Self::ThresholdBased(ThresholdSpecialist::AiSecurity) => "ai-security",
            Self::IndicatorBased(IndicatorSpecialist::Cloud) => "cloud",
            Self::IndicatorBased(IndicatorSpecialist::Database) => "database",
        }
    }

    /// Get human-readable display name.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::ThresholdBased(ThresholdSpecialist::WebApp) => {
                "Web Application Security Specialist"
            }
            Self::ThresholdBased(ThresholdSpecialist::Api) => "API Security Specialist",
            Self::ThresholdBased(ThresholdSpecialist::Binary) => "Binary Exploitation Specialist",
            Self::ThresholdBased(ThresholdSpecialist::AiSecurity) => "AI/LLM Security Specialist",
            Self::IndicatorBased(IndicatorSpecialist::Cloud) => "Cloud Security Specialist",
            Self::IndicatorBased(IndicatorSpecialist::Database) => "Database Security Specialist",
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

/// Database engine fingerprinted during reconnaissance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DbEngine {
    /// PostgreSQL.
    Postgres,
    /// MySQL / MariaDB.
    #[serde(rename = "mysql")]
    MySql,
    /// Microsoft SQL Server.
    #[serde(rename = "mssql")]
    MsSql,
    /// Oracle Database.
    Oracle,
    /// MongoDB.
    #[serde(rename = "mongodb")]
    MongoDb,
    /// Redis.
    Redis,
    /// Elasticsearch.
    Elasticsearch,
    /// Memcached.
    Memcached,
    /// A database service was detected but the engine could not be classified.
    Unknown,
}

impl DbEngine {
    /// Whether the engine was classified to a specific product. `Unknown` is
    /// not: engine-specific techniques (default ports, auth model, privesc
    /// vectors) need a known engine to act on. Analogue of
    /// [`CloudProvider::is_classified`].
    pub fn is_identified(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// Database-specific attack-surface signals used to decide whether to spawn the
/// Database specialist (pick#161).
///
/// Like [`CloudIndicators`], the Database specialist is indicator-driven rather
/// than endpoint-count-driven: a single exposed Mongo/Redis instance or a
/// confirmed SQLi behind an identified engine is a stronger signal than dozens
/// of ordinary HTTP endpoints. These indicators are populated during recon and
/// evaluated by [`SpecialistSpawner::should_spawn`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseIndicators {
    /// DBMS engine(s) fingerprinted during recon.
    #[serde(default)]
    pub engines: Vec<DbEngine>,

    /// A database service is directly network-reachable (exposed port).
    #[serde(default)]
    pub direct_exposure: bool,

    /// SQLi confirmed at the app layer, enabling the SQLi -> DB takeover chain.
    #[serde(default)]
    pub sqli_available: bool,

    /// Credentials for a database account were discovered.
    #[serde(default)]
    pub credentials_found: bool,

    /// The database is a cloud-managed instance (RDS/Aurora/Azure SQL/Cloud
    /// SQL); coordinate with the Cloud specialist (pick#151) for account-level
    /// posture.
    #[serde(default)]
    pub cloud_managed: bool,
}

impl DatabaseIndicators {
    /// Whether any database signal at all is present.
    pub fn has_any(&self) -> bool {
        !self.engines.is_empty()
            || self.direct_exposure
            || self.sqli_available
            || self.credentials_found
            || self.cloud_managed
    }

    /// Whether at least one fingerprinted engine was classified to a specific
    /// product (i.e. not `Unknown`). The `Vec` analogue of
    /// `provider.is_some_and(|p| p.is_classified())` on the Cloud side.
    pub fn has_identified_engine(&self) -> bool {
        self.engines.iter().any(|e| e.is_identified())
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

    /// Database-specific attack-surface signals (pick#161). Defaulted so
    /// contexts serialized before the Database specialist existed still
    /// deserialize.
    #[serde(default)]
    pub database_indicators: DatabaseIndicators,
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
    ///
    /// Dispatch is exhaustive over the two spawn families: threshold-driven
    /// specialists go through [`Self::should_spawn_threshold`], indicator-driven
    /// ones through [`Self::should_spawn_indicator`]. Modelling the split in the
    /// type ([`SpecialistType`]) is what removes the old "threshold for an
    /// indicator-driven specialist" arm that previously needed `unreachable!`.
    pub fn should_spawn(
        &self,
        specialist: SpecialistType,
        context: &SpecialistContext,
    ) -> SpawnDecision {
        match specialist {
            SpecialistType::ThresholdBased(t) => self.should_spawn_threshold(t, context),
            SpecialistType::IndicatorBased(i) => self.should_spawn_indicator(i, context),
        }
    }

    /// Spawn decision for endpoint-count-driven specialists.
    fn should_spawn_threshold(
        &self,
        specialist: ThresholdSpecialist,
        context: &SpecialistContext,
    ) -> SpawnDecision {
        let threshold = match specialist {
            ThresholdSpecialist::WebApp => self.policy.web_app_threshold,
            ThresholdSpecialist::Api => self.policy.api_threshold,
            ThresholdSpecialist::Binary => 1, // Always spawn for binaries (rare targets)
            ThresholdSpecialist::AiSecurity => 1, // Always spawn for AI/LLM (rare targets)
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

    /// Spawn decision for indicator-driven specialists.
    fn should_spawn_indicator(
        &self,
        specialist: IndicatorSpecialist,
        context: &SpecialistContext,
    ) -> SpawnDecision {
        match specialist {
            IndicatorSpecialist::Cloud => {
                self.should_spawn_cloud(&context.attack_surface.cloud_indicators)
            }
            IndicatorSpecialist::Database => {
                self.should_spawn_database(&context.attack_surface.database_indicators)
            }
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

    /// Database specialist spawn decision, scaled by aggression level.
    ///
    /// Mirrors the pick#161 spec:
    /// - Conservative: credentials found, OR confirmed SQLi + an *identified*
    ///   engine (engine-specific takeover needs a known DBMS). Note this differs
    ///   from the Cloud specialist's Balanced rule: here an unidentified engine
    ///   never satisfies a conservative trigger.
    /// - Balanced: an identified engine AND some actionable surface (direct
    ///   exposure, SQLi, or credentials). Unlike Cloud's Balanced (which allows
    ///   an `Unknown` provider with surface), the Database specialist requires a
    ///   classified engine here - engine-native assessment is not actionable
    ///   without knowing the engine.
    /// - Aggressive: any single database indicator.
    /// - Maximum: always spawn.
    fn should_spawn_database(&self, ind: &DatabaseIndicators) -> SpawnDecision {
        let spawn = match self.aggression {
            AggressionLevel::Conservative => {
                ind.credentials_found || (ind.sqli_available && ind.has_identified_engine())
            }
            AggressionLevel::Balanced => {
                ind.has_identified_engine()
                    && (ind.direct_exposure || ind.sqli_available || ind.credentials_found)
            }
            AggressionLevel::Aggressive => ind.has_any(),
            AggressionLevel::Maximum => true,
        };

        // Operator visibility: distinguish a genuine "not a database target"
        // skip from a recon step that failed to populate indicators (mirrors the
        // Cloud specialist's skip-path logging).
        if !spawn && !ind.has_any() {
            tracing::debug!(
                aggression = ?self.aggression,
                "Database specialist skipped: no database indicators present. If the \
                 target exposes a database, recon may not have populated indicators."
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
                database_indicators: DatabaseIndicators::default(),
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
                database_indicators: DatabaseIndicators::default(),
            },
        }
    }

    /// Build a context whose only meaningful signal is its database indicators.
    ///
    /// `endpoint_count` is deliberately 0 to prove the Database specialist spawns
    /// on database indicators rather than on the endpoint-count threshold used by
    /// the WebApp/API specialists.
    fn make_database_context(indicators: DatabaseIndicators) -> SpecialistContext {
        SpecialistContext {
            targets: vec!["https://victim.example.com".to_string()],
            initial_findings: vec![],
            concerns: vec![],
            attack_surface: AttackSurface {
                endpoint_count: 0,
                technologies: vec![],
                auth_mechanisms: vec![],
                entry_points: vec![],
                cloud_indicators: CloudIndicators::default(),
                database_indicators: indicators,
            },
        }
    }

    #[test]
    fn conservative_requires_high_threshold() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Conservative);
        let context = make_context(30, vec![]);

        // Below threshold (50) - skip
        assert_eq!(
            spawner.should_spawn(SpecialistType::WEB_APP, &context),
            SpawnDecision::Skip
        );

        // At threshold - spawn
        let context = make_context(50, vec![]);
        assert_eq!(
            spawner.should_spawn(SpecialistType::WEB_APP, &context),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn balanced_spawns_on_hints() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Balanced);

        // Below threshold (20) but no hints - skip
        let context = make_context(10, vec![]);
        assert_eq!(
            spawner.should_spawn(SpecialistType::WEB_APP, &context),
            SpawnDecision::Skip
        );

        // Below threshold but has hints - spawn
        let context = make_context(10, vec!["SQLi suspected"]);
        assert_eq!(
            spawner.should_spawn(SpecialistType::WEB_APP, &context),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn aggressive_low_threshold() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Aggressive);
        let context = make_context(5, vec![]);

        // Threshold is 5 - spawn
        assert_eq!(
            spawner.should_spawn(SpecialistType::WEB_APP, &context),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn maximum_always_spawns() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Maximum);
        let context = make_context(1, vec![]);

        // Threshold is 1 - always spawn
        assert_eq!(
            spawner.should_spawn(SpecialistType::WEB_APP, &context),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn binary_and_ai_always_spawn() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Balanced);
        let context = make_context(1, vec![]);

        // Binary and AI specialists always spawn (rare targets)
        assert_eq!(
            spawner.should_spawn(SpecialistType::BINARY, &context),
            SpawnDecision::Spawn
        );
        assert_eq!(
            spawner.should_spawn(SpecialistType::AI_SECURITY, &context),
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
            SpecialistType::WEB_APP.prompt_file(),
            PathBuf::from("skills/claude-red/specialists/web-app-specialist.md")
        );
        assert_eq!(
            SpecialistType::API.prompt_file(),
            PathBuf::from("skills/claude-red/specialists/api-specialist.md")
        );
        assert_eq!(
            SpecialistType::BINARY.prompt_file(),
            PathBuf::from("skills/claude-red/specialists/binary-specialist.md")
        );
        assert_eq!(
            SpecialistType::AI_SECURITY.prompt_file(),
            PathBuf::from("skills/claude-red/specialists/ai-security-specialist.md")
        );
    }

    #[test]
    fn specialist_type_serializes_flat_kebab() {
        // The external serde form MUST stay flat kebab-case strings - this is the
        // LLM's JSON contract for the spawn_specialist tool. The refactor to
        // ThresholdBased | IndicatorBased must not change the wire shape.
        let cases = [
            (SpecialistType::WEB_APP, "\"web-app\""),
            (SpecialistType::API, "\"api\""),
            (SpecialistType::BINARY, "\"binary\""),
            (SpecialistType::AI_SECURITY, "\"ai-security\""),
            (SpecialistType::CLOUD, "\"cloud\""),
            (SpecialistType::DATABASE, "\"database\""),
        ];
        for (variant, expected) in cases {
            assert_eq!(serde_json::to_string(&variant).unwrap(), expected);
        }
    }

    #[test]
    fn specialist_type_deserializes_flat_kebab() {
        // Round-trips back from the flat strings.
        assert_eq!(
            serde_json::from_str::<SpecialistType>("\"web-app\"").unwrap(),
            SpecialistType::WEB_APP
        );
        assert_eq!(
            serde_json::from_str::<SpecialistType>("\"cloud\"").unwrap(),
            SpecialistType::CLOUD
        );

        // An unknown variant must produce serde's actionable "expected one of"
        // error (which the Red Team agent uses to self-correct). This guards
        // against an accidental regression to #[serde(untagged)], whose generic
        // "did not match any variant" message would lose that signal.
        let err = serde_json::from_str::<SpecialistType>("\"webapp\"").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("expected one of"),
            "expected an enumerated-variant error, got: {msg}"
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
            SpecialistType::WEB_APP,
            SpecialistType::API,
            SpecialistType::BINARY,
            SpecialistType::AI_SECURITY,
            SpecialistType::CLOUD,
            SpecialistType::DATABASE,
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
            SpecialistType::CLOUD.prompt_file(),
            PathBuf::from("skills/claude-red/specialists/cloud-specialist.md")
        );
        assert_eq!(SpecialistType::CLOUD.agent_suffix(), "cloud");
        assert_eq!(
            SpecialistType::CLOUD.display_name(),
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
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
            SpawnDecision::Spawn
        );

        // SSRF + a known provider is the other conservative trigger (metadata chain).
        let ctx = make_cloud_context(CloudIndicators {
            provider: Some(CloudProvider::Aws),
            ssrf_available: true,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
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
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
            SpawnDecision::Skip
        );

        // No cloud indicators at all -> skip.
        let ctx = make_cloud_context(CloudIndicators::default());
        assert_eq!(
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
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
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
            SpawnDecision::Skip
        );

        // Provider alone (no SSRF, no creds) is also not a conservative trigger.
        let ctx = make_cloud_context(CloudIndicators {
            provider: Some(CloudProvider::Aws),
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
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
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
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
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
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
                spawner.should_spawn(SpecialistType::CLOUD, &ctx),
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
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
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
                spawner.should_spawn(SpecialistType::CLOUD, &ctx),
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
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
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
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
            SpawnDecision::Spawn
        );

        // Provider alone, no surface signal -> skip at balanced.
        let ctx = make_cloud_context(CloudIndicators {
            provider: Some(CloudProvider::Azure),
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
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
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
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
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
            SpawnDecision::Spawn
        );

        // But an unclassified provider with no surface signal still skips.
        let ctx = make_cloud_context(CloudIndicators {
            provider: Some(CloudProvider::Unknown),
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
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
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
            SpawnDecision::Spawn
        );

        // But still skip when there is genuinely no cloud signal.
        let ctx = make_cloud_context(CloudIndicators::default());
        assert_eq!(
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
            SpawnDecision::Skip
        );
    }

    #[test]
    fn maximum_cloud_always_spawns() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Maximum);

        // At maximum aggression the Cloud specialist spawns even with no signal.
        let ctx = make_cloud_context(CloudIndicators::default());
        assert_eq!(
            spawner.should_spawn(SpecialistType::CLOUD, &ctx),
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

    // --- Database specialist (pick#161) ------------------------------------

    #[test]
    fn database_specialist_metadata() {
        assert_eq!(
            SpecialistType::DATABASE.prompt_file(),
            PathBuf::from("skills/claude-red/specialists/database-specialist.md")
        );
        assert_eq!(SpecialistType::DATABASE.agent_suffix(), "database");
        assert_eq!(
            SpecialistType::DATABASE.display_name(),
            "Database Security Specialist"
        );
    }

    #[test]
    fn db_engine_is_identified() {
        // Every classified engine is identified; only Unknown is not. A direct
        // test fails immediately on a `matches!` typo rather than only via a
        // downstream spawn-decision assertion (mirrors cloud_provider_is_classified).
        for engine in [
            DbEngine::Postgres,
            DbEngine::MySql,
            DbEngine::MsSql,
            DbEngine::Oracle,
            DbEngine::MongoDb,
            DbEngine::Redis,
            DbEngine::Elasticsearch,
            DbEngine::Memcached,
        ] {
            assert!(engine.is_identified(), "{engine:?} should be identified");
        }
        assert!(!DbEngine::Unknown.is_identified());
    }

    #[test]
    fn db_engine_serializes_to_operator_vocabulary() {
        // Pin the wire strings operators/the LLM use - in particular the
        // explicit renames that override the kebab default (my-sql/ms-sql/mongo-db).
        assert_eq!(
            serde_json::to_string(&DbEngine::Postgres).unwrap(),
            "\"postgres\""
        );
        assert_eq!(
            serde_json::to_string(&DbEngine::MySql).unwrap(),
            "\"mysql\""
        );
        assert_eq!(
            serde_json::to_string(&DbEngine::MsSql).unwrap(),
            "\"mssql\""
        );
        assert_eq!(
            serde_json::to_string(&DbEngine::MongoDb).unwrap(),
            "\"mongodb\""
        );
        assert_eq!(
            serde_json::from_str::<DbEngine>("\"mysql\"").unwrap(),
            DbEngine::MySql
        );
    }

    #[test]
    fn database_indicators_default_is_empty() {
        assert!(!DatabaseIndicators::default().has_any());
        assert!(!DatabaseIndicators::default().has_identified_engine());
    }

    #[test]
    fn database_indicators_has_any_detects_signal() {
        // Each field alone is a signal.
        assert!(DatabaseIndicators {
            engines: vec![DbEngine::Unknown],
            ..Default::default()
        }
        .has_any());
        assert!(DatabaseIndicators {
            direct_exposure: true,
            ..Default::default()
        }
        .has_any());
        assert!(DatabaseIndicators {
            cloud_managed: true,
            ..Default::default()
        }
        .has_any());
    }

    #[test]
    fn database_indicators_has_identified_engine() {
        // Empty and all-Unknown do NOT count as identified; any classified
        // engine in the list does. This is the Vec analogue of
        // provider.is_some_and(|p| p.is_classified()) on the Cloud side.
        assert!(!DatabaseIndicators::default().has_identified_engine());
        assert!(!DatabaseIndicators {
            engines: vec![DbEngine::Unknown],
            ..Default::default()
        }
        .has_identified_engine());
        assert!(DatabaseIndicators {
            engines: vec![DbEngine::Postgres],
            ..Default::default()
        }
        .has_identified_engine());
        assert!(DatabaseIndicators {
            engines: vec![DbEngine::Unknown, DbEngine::MySql],
            ..Default::default()
        }
        .has_identified_engine());
    }

    #[test]
    fn conservative_database_spawns_on_credentials() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Conservative);
        // Discovered DB credentials are actionable on their own, regardless of
        // engine classification.
        let ctx = make_database_context(DatabaseIndicators {
            credentials_found: true,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::DATABASE, &ctx),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn conservative_database_spawns_on_sqli_with_identified_engine() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Conservative);
        // Confirmed SQLi + an identified engine is the takeover-chain trigger.
        let ctx = make_database_context(DatabaseIndicators {
            engines: vec![DbEngine::Postgres],
            sqli_available: true,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::DATABASE, &ctx),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn conservative_database_skips_sqli_with_unknown_engine() {
        // The conservative takeover trigger needs an *identified* engine -
        // engine-specific privesc/file-read is not actionable against an
        // unclassified engine. SQLi + only Unknown must skip. This is the
        // Database analogue of conservative_cloud_skips_unknown_provider_ssrf
        // and pins the has_identified_engine() predicate.
        let spawner = SpecialistSpawner::new(AggressionLevel::Conservative);
        let ctx = make_database_context(DatabaseIndicators {
            engines: vec![DbEngine::Unknown],
            sqli_available: true,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::DATABASE, &ctx),
            SpawnDecision::Skip
        );
    }

    #[test]
    fn conservative_database_skips_weak_signal() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Conservative);
        // Bare direct exposure is not enough at the conservative level.
        let ctx = make_database_context(DatabaseIndicators {
            direct_exposure: true,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::DATABASE, &ctx),
            SpawnDecision::Skip
        );
        // No indicators at all -> skip.
        let ctx = make_database_context(DatabaseIndicators::default());
        assert_eq!(
            spawner.should_spawn(SpecialistType::DATABASE, &ctx),
            SpawnDecision::Skip
        );
    }

    #[test]
    fn balanced_database_spawns_on_identified_engine_plus_surface() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Balanced);
        // Identified engine + any one of the three actionable surface signals
        // (direct exposure, SQLi, or credentials) must spawn. Exercise each
        // branch of the OR so a regression dropping one is caught.
        let surfaces = [
            DatabaseIndicators {
                engines: vec![DbEngine::MySql],
                direct_exposure: true,
                ..Default::default()
            },
            DatabaseIndicators {
                engines: vec![DbEngine::MySql],
                sqli_available: true,
                ..Default::default()
            },
            DatabaseIndicators {
                engines: vec![DbEngine::MySql],
                credentials_found: true,
                ..Default::default()
            },
        ];
        for ind in surfaces {
            let ctx = make_database_context(ind);
            assert_eq!(
                spawner.should_spawn(SpecialistType::DATABASE, &ctx),
                SpawnDecision::Spawn
            );
        }
    }

    #[test]
    fn balanced_database_skips_unknown_engine_with_surface() {
        // Database DIFFERS from Cloud here: the Cloud specialist's Balanced rule
        // allows an `Unknown` provider with surface, but the Database
        // specialist's Balanced rule requires an *identified* engine - engine-
        // native assessment is not actionable without knowing the engine. An
        // unidentified engine + surface must skip. Pins that divergence so a
        // future copy-paste from the Cloud arm cannot loosen it.
        let spawner = SpecialistSpawner::new(AggressionLevel::Balanced);
        let ctx = make_database_context(DatabaseIndicators {
            engines: vec![DbEngine::Unknown],
            direct_exposure: true,
            sqli_available: true,
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::DATABASE, &ctx),
            SpawnDecision::Skip
        );
    }

    #[test]
    fn balanced_database_skips_engine_without_surface() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Balanced);
        // An identified engine with no actionable surface signal -> skip.
        let ctx = make_database_context(DatabaseIndicators {
            engines: vec![DbEngine::Postgres],
            ..Default::default()
        });
        assert_eq!(
            spawner.should_spawn(SpecialistType::DATABASE, &ctx),
            SpawnDecision::Skip
        );
    }

    #[test]
    fn aggressive_database_spawns_on_each_indicator_in_isolation() {
        // Aggressive spawns on any single indicator, including a lone Unknown
        // engine - has_any() must check every field.
        let spawner = SpecialistSpawner::new(AggressionLevel::Aggressive);
        for ind in [
            DatabaseIndicators {
                engines: vec![DbEngine::Unknown],
                ..Default::default()
            },
            DatabaseIndicators {
                direct_exposure: true,
                ..Default::default()
            },
            DatabaseIndicators {
                sqli_available: true,
                ..Default::default()
            },
            DatabaseIndicators {
                credentials_found: true,
                ..Default::default()
            },
            DatabaseIndicators {
                cloud_managed: true,
                ..Default::default()
            },
        ] {
            let ctx = make_database_context(ind);
            assert_eq!(
                spawner.should_spawn(SpecialistType::DATABASE, &ctx),
                SpawnDecision::Spawn
            );
        }
        // But still skip when there is genuinely no database signal.
        let ctx = make_database_context(DatabaseIndicators::default());
        assert_eq!(
            spawner.should_spawn(SpecialistType::DATABASE, &ctx),
            SpawnDecision::Skip
        );
    }

    #[test]
    fn maximum_database_always_spawns() {
        let spawner = SpecialistSpawner::new(AggressionLevel::Maximum);
        let ctx = make_database_context(DatabaseIndicators::default());
        assert_eq!(
            spawner.should_spawn(SpecialistType::DATABASE, &ctx),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn database_spawn_is_independent_of_endpoint_count() {
        // make_database_context sets endpoint_count = 0; a spawn on a database
        // signal proves Database does not fall through to endpoint-threshold logic.
        let spawner = SpecialistSpawner::new(AggressionLevel::Aggressive);
        let ctx = make_database_context(DatabaseIndicators {
            engines: vec![DbEngine::Redis],
            direct_exposure: true,
            ..Default::default()
        });
        assert_eq!(ctx.attack_surface.endpoint_count, 0);
        assert_eq!(
            spawner.should_spawn(SpecialistType::DATABASE, &ctx),
            SpawnDecision::Spawn
        );
    }

    #[test]
    fn attack_surface_deserializes_without_database_field() {
        // Backward compatibility: contexts serialized before pick#161 have no
        // `database_indicators` field and must still deserialize (serde default).
        let json = r#"{
            "endpoint_count": 5,
            "technologies": [],
            "auth_mechanisms": [],
            "entry_points": []
        }"#;
        let surface: AttackSurface =
            serde_json::from_str(json).expect("legacy AttackSurface must deserialize");
        assert!(!surface.database_indicators.has_any());
    }
}
