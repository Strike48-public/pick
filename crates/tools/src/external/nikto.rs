//! Nikto - Web server vulnerability scanner
//!
//! Nikto is a comprehensive web server scanner that tests for dangerous files,
//! outdated server software, and server configuration issues.

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult,
    ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use super::install::ensure_tool_installed;
use super::runner::{param_str_opt, param_str_or, CommandBuilder};
use crate::util::param_u64;

/// Nikto web server vulnerability scanner
pub struct NiktoTool;

#[async_trait]
impl PentestTool for NiktoTool {
    fn name(&self) -> &str {
        "nikto"
    }

    fn description(&self) -> &str {
        "Comprehensive web server vulnerability scanner that tests for 6700+ dangerous files and configurations"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target URL (e.g., 'http://example.com' or 'https://example.com:8443')",
            ))
            .param(ToolParam::optional(
                "port",
                ParamType::Integer,
                "Port to scan (default: 80 for http, 443 for https)",
                json!(0),
            ))
            .param(ToolParam::optional(
                "ssl",
                ParamType::Boolean,
                "Force SSL mode (default: auto-detect from URL)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "tuning",
                ParamType::String,
                "Scan tuning: '1' (interesting files), '2' (misconfig), '3' (info disclosure), etc.",
                json!(""),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds (default: 600)",
                json!(600),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();

            // Ensure nikto is installed
            ensure_tool_installed(&platform, "nikto", "nikto").await?;

            // Extract parameters
            let target = param_str_or(&params, "target", "");
            if target.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "target parameter is required".into(),
                ));
            }

            let port = param_u64(&params, "port", 0);
            let ssl = crate::util::param_bool(&params, "ssl", false);
            let timeout = param_u64(&params, "timeout", 600);

            // Parse URL to extract host
            let host = if let Some(stripped) = target.strip_prefix("http://") {
                stripped.split('/').next().unwrap_or(stripped)
            } else if let Some(stripped) = target.strip_prefix("https://") {
                stripped.split('/').next().unwrap_or(stripped)
            } else {
                target.as_str()
            };

            // Build nikto command
            let mut builder = CommandBuilder::new()
                .arg("-h", host)
                .arg("-Format", "json")
                .arg("-output", "/tmp/nikto-output.json");

            // Port specification
            if port > 0 {
                builder = builder.arg("-p", &port.to_string());
            }

            // SSL mode
            if ssl || target.starts_with("https://") {
                builder = builder.flag("-ssl");
            }

            // Tuning options
            if let Some(tuning) = param_str_opt(&params, "tuning") {
                if !tuning.is_empty() {
                    builder = builder.arg("-Tuning", &tuning);
                }
            }

            // Disable interactive prompts
            builder = builder.flag("-ask").positional("no");

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute nikto
            let result = platform
                .execute_command("nikto", &args_refs, Duration::from_secs(timeout))
                .await?;

            // Nikto may return non-zero even on success, check for output
            if result.stdout.is_empty() && !result.stderr.is_empty() {
                return Err(pentest_core::error::Error::ToolExecution(format!(
                    "nikto failed: {}",
                    result.stderr
                )));
            }

            // Parse Nikto output (JSON or plain text)
            parse_nikto_output(&result.stdout, &target)
        })
        .await
    }
}

/// Parse Nikto output
fn parse_nikto_output(stdout: &str, target: &str) -> Result<Value> {
    let mut vulnerabilities = Vec::new();
    let mut info_items = Vec::new();

    // Try JSON parsing first
    if let Ok(json_data) = serde_json::from_str::<Value>(stdout) {
        // Nikto JSON format parsing
        if let Some(vulns) = json_data.get("vulnerabilities").and_then(|v| v.as_array()) {
            for vuln in vulns {
                vulnerabilities.push(json!({
                    "id": vuln.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                    "description": vuln.get("msg").and_then(|v| v.as_str()).unwrap_or(""),
                    "uri": vuln.get("uri").and_then(|v| v.as_str()).unwrap_or(""),
                    "method": vuln.get("method").and_then(|v| v.as_str()).unwrap_or("GET"),
                }));
            }
        }
    } else {
        // Plain text parsing
        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with('+') && !line.starts_with("+ Target") {
                // Vulnerability or info line
                if line.contains("OSVDB") || line.contains("CVE") {
                    vulnerabilities.push(json!({
                        "description": line.trim_start_matches('+').trim(),
                    }));
                } else {
                    info_items.push(json!({
                        "description": line.trim_start_matches('+').trim(),
                    }));
                }
            }
        }
    }

    Ok(json!({
        "target": target,
        "vulnerabilities": vulnerabilities,
        "info": info_items,
        "vulnerability_count": vulnerabilities.len(),
        "info_count": info_items.len(),
        "summary": format!("Found {} vulnerabilities and {} info items", vulnerabilities.len(), info_items.len()),
    }))
}
