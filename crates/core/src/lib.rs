//! Pentest Connector Core Library
//!
//! This crate provides the core types and abstractions for the multiplatform
//! pentest connector application.

pub mod aggression;
pub mod clipboard;
pub mod config;
pub mod connector;
pub mod connector_registration;
pub mod error;
pub mod evidence;
pub mod export;
pub mod file_browser;
pub mod identity;
pub mod jwt_validator;
pub mod logging;
pub mod matrix;
pub mod onboarding;
pub mod orchestrator;
pub mod paths;
pub mod provenance;
pub mod rendering;
pub mod sanitize;
pub mod secure_store;
pub mod seed;
pub mod settings;
pub mod share;
pub mod social_share;
pub mod specialist_spawner;
pub mod state;
pub mod telemetry;
pub mod terminal;
pub mod theme_loader;
pub mod timeout;
pub mod tool_connector;
pub mod tools;
pub mod url_validation;
pub mod validation;
pub mod workspace;

/// Cross-target result of the guided WSL install, re-exported at the crate root
/// so UI code can name it as `pentest_core::WslInstallStatus`.
pub use config::WslInstallStatus;

/// The canned chat message the Easy Mode "Scan" button sends. Deliberately
/// short: it states the intent + the explicit `document_write` trigger the
/// shared agent persona keys on to enter self-serve report mode (see
/// `RED_TEAM_SYSTEM_PROMPT`, "Self-serve report format"). The scan strategy
/// (batching), the report title/Markdown format, and the frontmatter schema all
/// live in that system prompt — NOT here — so this reads like a real user ask
/// rather than a wall of operator instructions. The `document_write` mention is
/// the load-bearing part: the persona only saves an easy-mode report when the
/// message explicitly asks for it.
pub fn easy_mode_scan_prompt() -> String {
    "Scan my local network: find the devices, their open services, and any risks, \
     then save the results as a shareable report using `document_write`."
        .to_string()
}

pub mod prelude {
    pub use crate::aggression::{AggressionLevel, OverridePolicy, SpawnPolicy};
    pub use crate::config::{
        load_connector_config, AppSettings, ConfigLoadResult, ConnectorConfig, DownloadState,
        ShellMode,
    };
    pub use crate::connector::ToolEvent;
    pub use crate::error::{Error, Result};
    pub use crate::evidence::{EvidenceNode, SeverityHistoryEntry, ValidationStatus};
    pub use crate::export::{
        EvidenceFile, Finding, SessionExport, SessionMetadata, Severity, ToolExecution,
    };
    pub use crate::identity::{IdentityStore, SessionMaterial};
    pub use crate::orchestrator::{
        build_pending_evidence_manifest, build_report_agent_seed_message,
        build_validator_seed_message, gate_for_report, parse_validator_verdicts, EngagementInfo,
        GateError, ManifestCounts, ManifestFinding, PendingEvidenceManifest, SeverityCounts,
        ValidatedFindingsManifest, Verdict, VerdictDecision, VerdictParseError,
    };
    pub use crate::provenance::{redact, ProbeCommand, Provenance, RAW_RESPONSE_MAX_BYTES};
    pub use crate::seed::{
        ProgressCallback, ResourceType, SeedManager, SeedProgress, SeedResource, SeedStatus,
        SeedSummary, SeedTier, TierSummary,
    };
    pub use crate::settings::{load_settings, save_settings};
    pub use crate::specialist_spawner::{
        AttackSurface, IdentityRole, SpawnDecision, SpecialistContext, SpecialistSpawner,
        SpecialistType, TestIdentity,
    };
    pub use crate::state::ConnectorStatus;
    pub use crate::terminal::{LogLevel, TerminalLine};
    pub use crate::tools::{PentestTool, ToolContext, ToolResult, ToolSchema};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn easy_mode_scan_prompt_requires_document_write() {
        let p = easy_mode_scan_prompt();
        assert!(
            p.to_lowercase().contains("network"),
            "prompt should mention the network: {p}"
        );
        // Easy mode has no separate report step, so the scan prompt must
        // explicitly require the platform document_write tool (not write_file)
        // so a shareable Document is created for the docs strip / share flow.
        assert!(
            p.contains("document_write"),
            "prompt must direct the agent to use document_write: {p}"
        );
    }

    #[test]
    fn scan_prompt_stays_short() {
        // The scan strategy + report/frontmatter mechanics now live in the agent
        // system prompt (RED_TEAM_SYSTEM_PROMPT, "Self-serve report format"), not
        // in this user message. Guard against it re-bloating into operator
        // instructions: it should read like a short user ask.
        let p = easy_mode_scan_prompt();
        assert!(
            p.len() < 300,
            "scan prompt should be a short user ask, not operator instructions ({} chars): {p}",
            p.len()
        );
        // These details belong in the system prompt now, not the user message.
        assert!(
            !p.contains("frontmatter"),
            "frontmatter schema should live in the system prompt, not the user message: {p}"
        );
    }
}
