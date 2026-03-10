//! Terminal output types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Log level for terminal output
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LogLevel {
    Debug,
    Info,
    Success,
    Warning,
    Error,
}

impl LogLevel {
    /// Get the color for this log level
    pub fn color(&self) -> &'static str {
        match self {
            LogLevel::Debug => "#808080",   // gray
            LogLevel::Info => "#00bcd4",    // cyan
            LogLevel::Success => "#4caf50", // green
            LogLevel::Warning => "#ff9800", // yellow/orange
            LogLevel::Error => "#f44336",   // red
        }
    }

    /// Get the prefix for this log level
    pub fn prefix(&self) -> &'static str {
        match self {
            LogLevel::Debug => "[DEBUG]",
            LogLevel::Info => "[INFO]",
            LogLevel::Success => "[OK]",
            LogLevel::Warning => "[WARN]",
            LogLevel::Error => "[ERROR]",
        }
    }

    /// Get the human-readable label for filter buttons
    pub fn label(&self) -> &'static str {
        match self {
            LogLevel::Debug => "Debug",
            LogLevel::Info => "Info",
            LogLevel::Success => "Success",
            LogLevel::Warning => "Warning",
            LogLevel::Error => "Error",
        }
    }

    /// Get the CSS class name for styling
    pub fn css_class(&self) -> &'static str {
        match self {
            LogLevel::Debug => "debug",
            LogLevel::Info => "info",
            LogLevel::Success => "success",
            LogLevel::Warning => "warning",
            LogLevel::Error => "error",
        }
    }
}

/// A single line of terminal output
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TerminalLine {
    pub timestamp: DateTime<Utc>,
    pub level: LogLevel,
    pub message: String,
    pub source: Option<String>,
    /// Optional expandable detail content (e.g. tool args/results as pretty JSON)
    #[serde(default)]
    pub details: Option<String>,
}

impl TerminalLine {
    /// Create a new terminal line
    pub fn new(level: LogLevel, message: impl Into<String>) -> Self {
        Self {
            timestamp: Utc::now(),
            level,
            message: message.into(),
            source: None,
            details: None,
        }
    }

    /// Create a new terminal line with a source
    pub fn with_source(
        level: LogLevel,
        message: impl Into<String>,
        source: impl Into<String>,
    ) -> Self {
        Self {
            timestamp: Utc::now(),
            level,
            message: message.into(),
            source: Some(source.into()),
            details: None,
        }
    }

    /// Attach expandable details to this line
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(details.into());
        self
    }

    /// Create an info line
    pub fn info(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Info, message)
    }

    /// Create a success line
    pub fn success(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Success, message)
    }

    /// Create a warning line
    pub fn warning(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Warning, message)
    }

    /// Create an error line
    pub fn error(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Error, message)
    }

    /// Create a debug line
    pub fn debug(message: impl Into<String>) -> Self {
        Self::new(LogLevel::Debug, message)
    }

    /// Format the line for display
    pub fn format(&self) -> String {
        let time = self.timestamp.format("%H:%M:%S");
        match &self.source {
            Some(src) => format!(
                "{} {} [{}] {}",
                time,
                self.level.prefix(),
                src,
                self.message
            ),
            None => format!("{} {} {}", time, self.level.prefix(), self.message),
        }
    }

    /// Format the line with full timestamp for export
    pub fn format_full(&self) -> String {
        let time = self.timestamp.format("%Y-%m-%d %H:%M:%S%.3f");
        let base = match &self.source {
            Some(src) => format!(
                "{} {} [{}] {}",
                time,
                self.level.prefix(),
                src,
                self.message
            ),
            None => format!("{} {} {}", time, self.level.prefix(), self.message),
        };

        // Include details if present
        if let Some(details) = &self.details {
            format!("{}\n{}", base, details)
        } else {
            base
        }
    }
}
