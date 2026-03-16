//! Feroxbuster - Fast content discovery tool
//!
//! A fast, simple, recursive content discovery tool written in Rust.

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ExternalDependency, ParamType, PentestTool, Platform, ToolContext, ToolParam,
    ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use crate::external::install::ensure_tool_installed;
use crate::external::runner::{param_str_opt, param_str_or, CommandBuilder};
use crate::util::param_bool;

/// Feroxbuster content discovery tool
pub struct FeroxbusterTool;

#[async_trait]
impl PentestTool for FeroxbusterTool {
    fn name(&self) -> &str {
        "feroxbuster"
    }

    fn description(&self) -> &str {
        "Fast, simple, recursive content discovery tool written in Rust"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "feroxbuster",
                "feroxbuster",
                "Fast content discovery tool (Rust-based)"
            ))
            .param(ToolParam::required(
                "url",
                ParamType::String,
                "Target URL (e.g., 'http://example.com')",
            ))
            .param(ToolParam::optional(
                "wordlist",
                ParamType::String,
                "Wordlist path (default: common.txt from SecLists if available)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "extensions",
                ParamType::String,
                "File extensions to search for (comma-separated, e.g., 'php,html,txt')",
                json!(""),
            ))
            .param(ToolParam::optional(
                "threads",
                ParamType::Integer,
                "Number of concurrent threads (default: 50)",
                json!(50),
            ))
            .param(ToolParam::optional(
                "depth",
                ParamType::Integer,
                "Maximum recursion depth (default: 4)",
                json!(4),
            ))
            .param(ToolParam::optional(
                "status_codes",
                ParamType::String,
                "Status codes to include (comma-separated, default: 200,204,301,302,307,308,401,403,405)",
                json!("200,204,301,302,307,308,401,403,405"),
            ))
            .param(ToolParam::optional(
                "filter_status",
                ParamType::String,
                "Status codes to filter out (comma-separated)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Request timeout in seconds (default: 7)",
                json!(7),
            ))
            .param(ToolParam::optional(
                "quiet",
                ParamType::Boolean,
                "Only display found URLs (default: true)",
                json!(true),
            ))
            .param(ToolParam::optional(
                "scan_limit",
                ParamType::Integer,
                "Maximum number of requests (default: 0 = unlimited)",
                json!(0),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();

            // Ensure feroxbuster is installed
            ensure_tool_installed(&platform, "feroxbuster", "feroxbuster").await?;

            // Extract parameters
            let url = param_str_or(&params, "url", "");
            if url.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "url parameter is required".into(),
                ));
            }

            let wordlist = param_str_or(&params, "wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt");
            let extensions = param_str_opt(&params, "extensions");
            let threads = crate::util::param_u64(&params, "threads", 50);
            let depth = crate::util::param_u64(&params, "depth", 4);
            let status_codes = param_str_or(&params, "status_codes", "200,204,301,302,307,308,401,403,405");
            let filter_status = param_str_opt(&params, "filter_status");
            let timeout = crate::util::param_u64(&params, "timeout", 7);
            let quiet = param_bool(&params, "quiet", true);
            let scan_limit = crate::util::param_u64(&params, "scan_limit", 0);

            // Build feroxbuster command
            let mut builder = CommandBuilder::new()
                .arg("--url", &url)
                .arg("--wordlist", &wordlist)
                .arg("--threads", &threads.to_string())
                .arg("--depth", &depth.to_string())
                .arg("--status-codes", &status_codes)
                .arg("--timeout", &timeout.to_string())
                .flag("--json") // JSON output
                .flag("--no-state"); // Don't save state

            if quiet {
                builder = builder.flag("--quiet");
            }

            if let Some(exts) = extensions {
                if !exts.is_empty() {
                    builder = builder.arg("--extensions", &exts);
                }
            }

            if let Some(filter) = filter_status {
                if !filter.is_empty() {
                    builder = builder.arg("--filter-status", &filter);
                }
            }

            if scan_limit > 0 {
                builder = builder.arg("--scan-limit", &scan_limit.to_string());
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute feroxbuster
            let result = platform
                .execute_command("feroxbuster", &args_refs, Duration::from_secs(600))
                .await?;

            // Parse JSON output
            parse_feroxbuster_output(&result.stdout, &url)
        })
        .await
    }
}

/// Parse feroxbuster JSON output (one JSON object per line)
fn parse_feroxbuster_output(stdout: &str, url: &str) -> Result<Value> {
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }

        // Parse each JSON line
        if let Ok(finding) = serde_json::from_str::<Value>(line) {
            if finding.get("type").and_then(|v| v.as_str()) == Some("response") {
                findings.push(json!({
                    "url": finding.get("url").and_then(|v| v.as_str()).unwrap_or(""),
                    "status": finding.get("status").and_then(|v| v.as_u64()).unwrap_or(0),
                    "method": finding.get("method").and_then(|v| v.as_str()).unwrap_or("GET"),
                    "content_length": finding.get("content_length").and_then(|v| v.as_u64()).unwrap_or(0),
                    "line_count": finding.get("line_count").and_then(|v| v.as_u64()).unwrap_or(0),
                    "word_count": finding.get("word_count").and_then(|v| v.as_u64()).unwrap_or(0),
                }));
            }
        }
    }

    let count = findings.len();
    let summary = format!("Found {} resources", count);

    Ok(json!({
        "url": url,
        "findings": findings,
        "count": count,
        "summary": summary,
    }))
}
