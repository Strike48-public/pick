//! Sublist3r - Subdomain enumeration tool

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
use crate::external::runner::{param_str_or, CommandBuilder};
use crate::util::param_bool;

pub struct Sublist3rTool;

#[async_trait]
impl PentestTool for Sublist3rTool {
    fn name(&self) -> &str {
        "sublist3r"
    }

    fn description(&self) -> &str {
        "Fast subdomain enumeration tool using multiple search engines"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "sublist3r",
                "sublist3r",
                "Subdomain enumeration tool (Python-based)",
            ))
            .param(ToolParam::required(
                "domain",
                ParamType::String,
                "Target domain (e.g., 'example.com')",
            ))
            .param(ToolParam::optional(
                "bruteforce",
                ParamType::Boolean,
                "Enable bruteforce module (default: false)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "threads",
                ParamType::Integer,
                "Number of threads (default: 10)",
                json!(10),
            ))
            .param(ToolParam::optional(
                "ports",
                ParamType::String,
                "Scan ports on discovered subdomains (comma-separated)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds (default: 300)",
                json!(300),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "sublist3r", "sublist3r").await?;

            let domain = param_str_or(&params, "domain", "");
            if domain.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "domain parameter is required".into(),
                ));
            }

            let bruteforce = param_bool(&params, "bruteforce", false);
            let threads = crate::util::param_u64(&params, "threads", 10);
            let ports = param_str_or(&params, "ports", "");
            let timeout_secs = crate::util::param_u64(&params, "timeout", 300);

            let mut builder = CommandBuilder::new()
                .arg("-d", &domain)
                .arg("-t", &threads.to_string());

            if bruteforce {
                builder = builder.flag("-b");
            }

            if !ports.is_empty() {
                builder = builder.arg("-p", &ports);
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command("sublist3r", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            // Parse subdomains from output
            let mut subdomains = Vec::new();
            for line in result.stdout.lines() {
                let line = line.trim();
                if line.contains(&domain) && !line.starts_with('[') {
                    subdomains.push(line.to_string());
                }
            }

            Ok(json!({
                "domain": domain,
                "subdomains": subdomains,
                "count": subdomains.len(),
                "summary": format!("Found {} subdomains", subdomains.len()),
            }))
        })
        .await
    }
}
