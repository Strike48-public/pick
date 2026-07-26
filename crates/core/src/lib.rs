//! Pentest Connector Core Library
//!
//! This crate provides the core types and abstractions for the multiplatform
//! pentest connector application.

pub mod aggression;
pub mod config;
pub mod connector;
pub mod connector_registration;
pub mod error;
pub mod evidence;
pub mod export;
pub mod file_browser;
pub mod jwt_validator;
pub mod logging;
pub mod matrix;
pub mod orchestrator;
pub mod paths;
pub mod provenance;
pub mod rendering;
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

/// The canned chat message the Easy Mode "Scan" button sends. It instructs the
/// server-side agent to enumerate local interfaces, scan the local subnet, and
/// write a report document of the findings. Kept as one place so the wording is
/// consistent and testable.
pub fn easy_mode_scan_prompt() -> String {
    "Discover the devices on my local network: enumerate my network interfaces, \
     scan the local subnet for reachable hosts and their open services, then \
     summarize what you found.\n\n\
     Work efficiently — batch your tool calls instead of looping one host at a \
     time. `port_scan` accepts a whole `subnet` (CIDR, e.g. \"10.10.0.0/24\") or \
     a `hosts` list in a single call, and `service_banner` accepts a `targets` \
     list of {host, port} objects in a single call. Use those batch forms so the \
     scan takes a few calls, not dozens.\n\n\
     When you have the results, you MUST save the summary as a shareable report \
     by calling the `document_write` tool (NOT `write_file`) — create a document \
     titled something like \"Network Discovery Report\" whose body is the \
     findings summary in Markdown. This easy-mode flow has no separate report \
     step, so creating that document is your responsibility and is required: the \
     app surfaces it to the user for viewing and sharing. After the \
     `document_write` call succeeds, tell the user their report is ready.\n\n\
     At the very top of the document content, before the markdown body, include a \
     YAML frontmatter block fenced with lines of three dashes (---). Put optional \
     metadata there so the app can render a richer report card: \
     scope (the subnet or target you scanned, e.g. \"10.10.0.0/24\"), \
     source (this device's hostname), hosts (integer count that responded), \
     services (integer count enumerated), severity (a map with integer counts for \
     any of critical/high/medium/low/info), and findings (a short list, ideally 8 \
     or fewer, of items each with severity, title, and a one-to-two sentence body). \
     Use those exact lowercase severity words. Every field is optional — include \
     what you know. After the closing --- line, write the normal Markdown summary \
     (GFM tables are great for host/service breakdowns)."
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
        AttackSurface, SpawnDecision, SpecialistContext, SpecialistSpawner, SpecialistType,
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
    fn scan_prompt_requests_frontmatter() {
        let p = easy_mode_scan_prompt();
        assert!(
            p.contains("frontmatter"),
            "prompt should instruct the agent to emit frontmatter: {p}"
        );
        assert!(
            p.contains("scope"),
            "prompt should mention the scope field: {p}"
        );
    }
}
