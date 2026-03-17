//! Nuclei - Fast and customizable vulnerability scanner
//!
//! Nuclei is used to send requests across targets based on a template, leading to
//! zero false positives and providing fast scanning on a large number of hosts.

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

/// Nuclei vulnerability scanner
pub struct NucleiTool;

#[async_trait]
impl PentestTool for NucleiTool {
    fn name(&self) -> &str {
        "nuclei"
    }

    fn description(&self) -> &str {
        "Fast template-based vulnerability scanner with 1000+ community templates"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "nuclei",
                "nuclei",
                "Template-based vulnerability scanner (Go binary + ~500MB templates on first run)",
            ))
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target URL or host (e.g., 'https://example.com' or '192.168.1.1')",
            ))
            .param(ToolParam::optional(
                "templates",
                ParamType::String,
                "Template or template directory path (default: all templates)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "severity",
                ParamType::String,
                "Filter by severity: info, low, medium, high, critical (comma-separated)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "tags",
                ParamType::String,
                "Filter by tags (e.g., 'cve,xss,sqli')",
                json!(""),
            ))
            .param(ToolParam::optional(
                "exclude_tags",
                ParamType::String,
                "Exclude templates with tags",
                json!(""),
            ))
            .param(ToolParam::optional(
                "rate_limit",
                ParamType::Integer,
                "Maximum requests per second (default: 150)",
                json!(150),
            ))
            .param(ToolParam::optional(
                "concurrency",
                ParamType::Integer,
                "Maximum parallel templates (default: 25)",
                json!(25),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds (default: 300)",
                json!(300),
            ))
            .param(ToolParam::optional(
                "silent",
                ParamType::Boolean,
                "Display only results (default: true)",
                json!(true),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();

            // Ensure nuclei is installed
            ensure_tool_installed(&platform, "nuclei", "nuclei").await?;

            // Extract parameters
            let target = param_str_or(&params, "target", "");
            if target.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "target parameter is required".into(),
                ));
            }

            let templates = param_str_opt(&params, "templates");
            let severity = param_str_opt(&params, "severity");
            let tags = param_str_opt(&params, "tags");
            let exclude_tags = param_str_opt(&params, "exclude_tags");
            let rate_limit = crate::util::param_u64(&params, "rate_limit", 150);
            let concurrency = crate::util::param_u64(&params, "concurrency", 25);
            let timeout_secs = crate::util::param_u64(&params, "timeout", 300);
            let silent = param_bool(&params, "silent", true);

            // Build nuclei command
            let mut builder = CommandBuilder::new()
                .arg("-u", &target)
                .arg("-rate-limit", &rate_limit.to_string())
                .arg("-c", &concurrency.to_string())
                .flag("-json"); // JSON output

            if silent {
                builder = builder.flag("-silent");
            }

            if let Some(templates_path) = templates {
                if !templates_path.is_empty() {
                    builder = builder.arg("-t", &templates_path);
                }
            }

            if let Some(severity_str) = severity {
                if !severity_str.is_empty() {
                    builder = builder.arg("-severity", &severity_str);
                }
            }

            if let Some(tags_str) = tags {
                if !tags_str.is_empty() {
                    builder = builder.arg("-tags", &tags_str);
                }
            }

            if let Some(exclude_str) = exclude_tags {
                if !exclude_str.is_empty() {
                    builder = builder.arg("-exclude-tags", &exclude_str);
                }
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute nuclei
            let result = platform
                .execute_command("nuclei", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            // Nuclei returns 0 even with findings, non-zero on errors
            if result.exit_code != 0 && !result.stderr.is_empty() {
                return Ok(json!({
                    "target": target,
                    "vulnerabilities": [],
                    "count": 0,
                    "error": result.stderr,
                }));
            }

            // Parse JSON output
            parse_nuclei_output(&result.stdout, &target)
        })
        .await
    }
}

/// Parse nuclei JSON output (one JSON object per line)
fn parse_nuclei_output(stdout: &str, target: &str) -> Result<Value> {
    let mut vulnerabilities = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }

        // Parse each JSON line
        if let Ok(finding) = serde_json::from_str::<Value>(line) {
            vulnerabilities.push(json!({
                "template_id": finding.get("template-id").and_then(|v| v.as_str()).unwrap_or(""),
                "name": finding.get("info").and_then(|i| i.get("name")).and_then(|v| v.as_str()).unwrap_or(""),
                "severity": finding.get("info").and_then(|i| i.get("severity")).and_then(|v| v.as_str()).unwrap_or(""),
                "type": finding.get("type").and_then(|v| v.as_str()).unwrap_or(""),
                "matched_at": finding.get("matched-at").and_then(|v| v.as_str()).unwrap_or(""),
                "extracted_results": finding.get("extracted-results"),
                "curl_command": finding.get("curl-command").and_then(|v| v.as_str()).unwrap_or(""),
            }));
        }
    }

    let count = vulnerabilities.len();
    let summary = if count > 0 {
        let critical = vulnerabilities
            .iter()
            .filter(|v| v["severity"] == "critical")
            .count();
        let high = vulnerabilities
            .iter()
            .filter(|v| v["severity"] == "high")
            .count();
        let medium = vulnerabilities
            .iter()
            .filter(|v| v["severity"] == "medium")
            .count();
        let low = vulnerabilities
            .iter()
            .filter(|v| v["severity"] == "low")
            .count();

        format!(
            "Found {} vulnerabilities: {} critical, {} high, {} medium, {} low",
            count, critical, high, medium, low
        )
    } else {
        "No vulnerabilities found".to_string()
    };

    Ok(json!({
        "target": target,
        "vulnerabilities": vulnerabilities,
        "count": count,
        "summary": summary,
    }))
}
