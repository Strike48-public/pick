//! Pentest Connector Core Library
//!
//! This crate provides the core types and abstractions for the multiplatform
//! pentest connector application.

pub mod config;
pub mod connector;
pub mod error;
pub mod export;
pub mod file_browser;
pub mod jwt_validator;
pub mod logging;
pub mod matrix;
pub mod paths;
pub mod rendering;
pub mod seed;
pub mod settings;
pub mod state;
pub mod terminal;
pub mod theme_loader;
pub mod timeout;
pub mod tools;
pub mod validation;
pub mod workspace;

pub mod prelude {
    pub use crate::config::{
        load_connector_config, AppSettings, ConfigLoadResult, ConnectorConfig, DownloadState,
        ShellMode,
    };
    pub use crate::connector::ToolEvent;
    pub use crate::error::{Error, Result};
    pub use crate::export::{
        EvidenceFile, Finding, SessionExport, SessionMetadata, Severity, ToolExecution,
    };
    pub use crate::seed::{
        ProgressCallback, ResourceType, SeedManager, SeedProgress, SeedResource, SeedStatus,
        SeedSummary, SeedTier, TierSummary,
    };
    pub use crate::settings::{load_settings, save_settings};
    pub use crate::state::ConnectorStatus;
    pub use crate::terminal::{LogLevel, TerminalLine};
    pub use crate::tools::{PentestTool, ToolContext, ToolResult, ToolSchema};
}
