//! Pentest Connector Core Library
//!
//! This crate provides the core types and abstractions for the multiplatform
//! pentest connector application.

pub mod config;
pub mod connector;
pub mod error;
pub mod file_browser;
pub mod logging;
pub mod matrix;
pub mod output_parser;
pub mod rendering;
pub mod settings;
pub mod state;
pub mod terminal;
pub mod tools;
pub mod workspace;

pub mod prelude {
    pub use crate::config::{
        load_connector_config, AppSettings, ConfigLoadResult, ConnectorConfig, DownloadState,
        ShellMode,
    };
    pub use crate::connector::ToolEvent;
    pub use crate::error::{Error, Result};
    pub use crate::settings::{load_settings, save_settings};
    pub use crate::state::ConnectorStatus;
    pub use crate::terminal::{LogLevel, TerminalLine};
    pub use crate::tools::{PentestTool, ToolContext, ToolResult, ToolSchema};
}
