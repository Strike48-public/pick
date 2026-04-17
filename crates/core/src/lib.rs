//! Pentest Connector Core Library
//!
//! This crate provides the core types and abstractions for the multiplatform
//! pentest connector application.

pub mod config;
pub mod connector;
pub mod error;
pub mod evidence;
pub mod export;
pub mod file_browser;
pub mod jwt_validator;
pub mod logging;
pub mod matrix;
pub mod orchestrator;
pub mod provenance;
pub mod rendering;
pub mod seed;
pub mod settings;
pub mod state;
pub mod terminal;
pub mod theme_loader;
pub mod tools;
pub mod workspace;

pub mod prelude {
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
        build_report_agent_seed_message, gate_for_report, EngagementInfo, GateError,
        ManifestCounts, ManifestFinding, SeverityCounts, ValidatedFindingsManifest,
    };
    pub use crate::provenance::{redact, ProbeCommand, Provenance, RAW_RESPONSE_MAX_BYTES};
    pub use crate::seed::{
        ProgressCallback, ResourceType, SeedManager, SeedProgress, SeedResource, SeedStatus,
        SeedSummary, SeedTier, TierSummary,
    };
    pub use crate::settings::{load_settings, save_settings};
    pub use crate::state::ConnectorStatus;
    pub use crate::terminal::{LogLevel, TerminalLine};
    pub use crate::tools::{PentestTool, ToolContext, ToolResult, ToolSchema};
}
