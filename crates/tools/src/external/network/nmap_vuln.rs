//! Nmap Vuln - Vulnerability scanning with NSE scripts

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ExternalDependency, ParamType, PentestTool, Platform, ToolCategory, ToolContext,
    ToolParam, ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use crate::external::install::ensure_tool_installed;
use crate::external::runner::{param_str_or, CommandBuilder};

pub struct NmapVulnTool;

#[async_trait]
impl PentestTool for NmapVulnTool {
    fn name(&self) -> &str {
        "nmap_vuln"
    }

    fn description(&self) -> &str {
        "Nmap vulnerability scan using vuln NSE script category"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(
                ExternalDependency::new("nmap", "nmap", "Network scanner")
                    .category(ToolCategory::Network),
            )
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target IP, CIDR, or hostname, or a sentinel: 'current' (this \
                 host's primary subnet), 'auto'/'all' (every active local \
                 subnet). Prefer a sentinel over guessing a range for local \
                 scans - it uses the host's real interface subnets.",
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout",
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
            ensure_tool_installed(&platform, "nmap", "nmap").await?;

            let target = param_str_or(&params, "target", "");
            if target.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "target required".into(),
                ));
            }

            let timeout_secs = crate::util::param_u64(&params, "timeout", 600);

            // Resolve auto/current/all -> real subnets, validate, warn if
            // out-of-subnet. nmap accepts multiple positional targets, so a
            // multi-subnet resolution fans out in one invocation.
            let prepared = crate::scan_target::prepare_scan_targets(&target).await?;

            let builder = CommandBuilder::new()
                .arg("-sV", "")
                .arg("--script", "vuln")
                .extend(&prepared.targets);

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command("nmap", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            let mut vulns = Vec::new();
            for line in result.stdout.lines() {
                if line.contains("VULNERABLE") || line.contains("CVE-") {
                    vulns.push(line.trim().to_string());
                }
            }

            Ok(json!({
                "target": target,
                "resolved_targets": prepared.targets,
                "out_of_subnet_warning": prepared.warning,
                "vulnerabilities": vulns,
                "count": vulns.len(),
                "output": result.stdout,
            }))
        })
        .await
    }
}
