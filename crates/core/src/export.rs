//! Session export functionality for generating reports
//!
//! Provides utilities to export session data (tool calls, results, findings)
//! to various formats (JSON, Markdown) for documentation and reporting.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// A session export containing all relevant pentest data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionExport {
    pub metadata: SessionMetadata,
    pub tool_executions: Vec<ToolExecution>,
    pub findings: Vec<Finding>,
    pub files: Vec<EvidenceFile>,
}

/// Metadata about the session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetadata {
    pub session_id: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub connector_version: String,
    pub platform: String,
    pub target: Option<String>,
}

/// Record of a tool execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecution {
    pub timestamp: DateTime<Utc>,
    pub tool_name: String,
    pub params: serde_json::Value,
    pub success: bool,
    pub duration_ms: u64,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

/// A security finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub timestamp: DateTime<Utc>,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub affected_target: String,
    pub evidence: Vec<String>,
    pub recommendation: Option<String>,
}

/// Severity level for findings
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Reference to an evidence file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceFile {
    pub path: PathBuf,
    pub file_type: String,
    pub size_bytes: u64,
    pub created_at: DateTime<Utc>,
    pub description: Option<String>,
}

impl SessionExport {
    /// Create a new session export
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            metadata: SessionMetadata {
                session_id: session_id.into(),
                start_time: Utc::now(),
                end_time: None,
                connector_version: env!("CARGO_PKG_VERSION").to_string(),
                platform: std::env::consts::OS.to_string(),
                target: None,
            },
            tool_executions: Vec::new(),
            findings: Vec::new(),
            files: Vec::new(),
        }
    }

    /// Add a tool execution record
    pub fn add_tool_execution(&mut self, execution: ToolExecution) {
        self.tool_executions.push(execution);
    }

    /// Add a finding
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Add an evidence file
    pub fn add_file(&mut self, file: EvidenceFile) {
        self.files.push(file);
    }

    /// Export to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Export to Markdown string
    pub fn to_markdown(&self) -> String {
        let mut md = String::new();

        // Header
        md.push_str("# Penetration Test Report\n\n");
        md.push_str(&format!("**Session ID:** {}\n\n", self.metadata.session_id));
        md.push_str(&format!(
            "**Start Time:** {}\n\n",
            self.metadata.start_time.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        if let Some(end_time) = self.metadata.end_time {
            md.push_str(&format!(
                "**End Time:** {}\n\n",
                end_time.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }

        md.push_str(&format!("**Platform:** {}\n\n", self.metadata.platform));
        md.push_str(&format!(
            "**Connector Version:** {}\n\n",
            self.metadata.connector_version
        ));

        if let Some(target) = &self.metadata.target {
            md.push_str(&format!("**Target:** {}\n\n", target));
        }

        md.push_str("---\n\n");

        // Executive Summary
        md.push_str("## Executive Summary\n\n");
        md.push_str(&format!(
            "- **Total Tool Executions:** {}\n",
            self.tool_executions.len()
        ));
        md.push_str(&format!("- **Findings:** {}\n", self.findings.len()));

        let critical = self
            .findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .count();
        let high = self
            .findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::High))
            .count();
        let medium = self
            .findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Medium))
            .count();
        let low = self
            .findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Low))
            .count();

        md.push_str(&format!("  - Critical: {}\n", critical));
        md.push_str(&format!("  - High: {}\n", high));
        md.push_str(&format!("  - Medium: {}\n", medium));
        md.push_str(&format!("  - Low: {}\n", low));
        md.push_str(&format!("- **Evidence Files:** {}\n\n", self.files.len()));

        md.push_str("---\n\n");

        // Findings
        if !self.findings.is_empty() {
            md.push_str("## Findings\n\n");

            for finding in &self.findings {
                let severity_icon = match finding.severity {
                    Severity::Critical => "🔴",
                    Severity::High => "🟠",
                    Severity::Medium => "🟡",
                    Severity::Low => "🟢",
                    Severity::Info => "ℹ️",
                };

                md.push_str(&format!(
                    "### {} {} - {}\n\n",
                    severity_icon,
                    severity_str(finding.severity),
                    finding.title
                ));
                md.push_str(&format!(
                    "**Affected Target:** {}\n\n",
                    finding.affected_target
                ));
                md.push_str(&format!("**Description:** {}\n\n", finding.description));

                if !finding.evidence.is_empty() {
                    md.push_str("**Evidence:**\n\n");
                    for evidence in &finding.evidence {
                        md.push_str(&format!("- {}\n", evidence));
                    }
                    md.push('\n');
                }

                if let Some(rec) = &finding.recommendation {
                    md.push_str(&format!("**Recommendation:** {}\n\n", rec));
                }
            }

            md.push_str("---\n\n");
        }

        // Tool Executions
        if !self.tool_executions.is_empty() {
            md.push_str("## Tool Execution Timeline\n\n");
            md.push_str("| Time | Tool | Duration | Status |\n");
            md.push_str("|------|------|----------|--------|\n");

            for exec in &self.tool_executions {
                let status = if exec.success {
                    "✓ Success"
                } else {
                    "✗ Failed"
                };
                md.push_str(&format!(
                    "| {} | {} | {}ms | {} |\n",
                    exec.timestamp.format("%H:%M:%S"),
                    exec.tool_name,
                    exec.duration_ms,
                    status
                ));
            }

            md.push_str("\n---\n\n");
        }

        // Evidence Files
        if !self.files.is_empty() {
            md.push_str("## Evidence Files\n\n");
            md.push_str("| File | Type | Size | Description |\n");
            md.push_str("|------|------|------|-------------|\n");

            for file in &self.files {
                let size = format_bytes(file.size_bytes);
                let desc = file.description.as_deref().unwrap_or("-");
                md.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    file.path.display(),
                    file.file_type,
                    size,
                    desc
                ));
            }

            md.push('\n');
        }

        md
    }

    /// Save to file
    pub fn save_json(&self, path: impl Into<PathBuf>) -> std::io::Result<()> {
        let json = self.to_json().map_err(std::io::Error::other)?;
        std::fs::write(path.into(), json)
    }

    /// Save to markdown file
    pub fn save_markdown(&self, path: impl Into<PathBuf>) -> std::io::Result<()> {
        let md = self.to_markdown();
        std::fs::write(path.into(), md)
    }
}

/// Convert severity to string
fn severity_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "CRITICAL",
        Severity::High => "HIGH",
        Severity::Medium => "MEDIUM",
        Severity::Low => "LOW",
        Severity::Info => "INFO",
    }
}

/// Format bytes as human-readable size
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", bytes, UNITS[0])
    } else {
        format!("{:.2} {}", size, UNITS[unit_idx])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_export_json() {
        let mut export = SessionExport::new("test-session");
        export.add_tool_execution(ToolExecution {
            timestamp: Utc::now(),
            tool_name: "network_scan".to_string(),
            params: serde_json::json!({"target": "192.168.1.0/24"}),
            success: true,
            duration_ms: 1500,
            result: Some(serde_json::json!({"hosts_found": 5})),
            error: None,
        });

        let json = export.to_json().unwrap();
        assert!(json.contains("test-session"));
        assert!(json.contains("network_scan"));
    }

    #[test]
    fn test_session_export_markdown() {
        let mut export = SessionExport::new("test-session");
        export.add_finding(Finding {
            timestamp: Utc::now(),
            severity: Severity::High,
            title: "Weak WiFi Encryption".to_string(),
            description: "WEP encryption detected".to_string(),
            affected_target: "AP-12:34:56:78:9A:BC".to_string(),
            evidence: vec!["capture-01.cap".to_string()],
            recommendation: Some("Upgrade to WPA2 or WPA3".to_string()),
        });

        let md = export.to_markdown();
        assert!(md.contains("# Penetration Test Report"));
        assert!(md.contains("Weak WiFi Encryption"));
        assert!(md.contains("HIGH"));
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
    }
}
