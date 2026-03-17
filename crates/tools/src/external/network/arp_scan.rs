//! ARP-scan - Fast ARP scanning and fingerprinting tool

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

pub struct ArpScanTool;

#[async_trait]
impl PentestTool for ArpScanTool {
    fn name(&self) -> &str {
        "arp_scan"
    }

    fn description(&self) -> &str {
        "Fast ARP scanning and fingerprinting tool"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "arp-scan",
                "arp-scan",
                "ARP scanner",
            ))
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target network (CIDR)",
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout",
                json!(60),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "arp-scan", "arp-scan").await?;

            let target = param_str_or(&params, "target", "");
            if target.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "target required".into(),
                ));
            }

            let timeout_secs = crate::util::param_u64(&params, "timeout", 60);

            let builder = CommandBuilder::new().positional(&target);

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command("arp-scan", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            let mut hosts = Vec::new();
            for line in result.stdout.lines() {
                if line.contains(':') && !line.starts_with("Interface") {
                    hosts.push(line.trim().to_string());
                }
            }

            Ok(json!({
                "target": target,
                "hosts": hosts,
                "count": hosts.len(),
            }))
        })
        .await
    }
}
