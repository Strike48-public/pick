//! ARP-scan - Fast ARP scanning and fingerprinting tool

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
            .external_dependency(
                ExternalDependency::new("arp-scan", "arp-scan", "ARP scanner")
                    .category(ToolCategory::Network),
            )
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target network (CIDR), or a sentinel: 'current' (this host's \
                 primary subnet), 'auto'/'all' (every active local subnet). \
                 Prefer a sentinel over guessing a range - it uses the host's \
                 real interface subnets.",
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

            // Resolve auto/current/all -> real subnets, validate, and surface an
            // out-of-subnet advisory. arp-scan accepts multiple positional
            // targets ("arp-scan [options] [hosts...]"), so a multi-subnet
            // resolution fans out in one invocation.
            let prepared = crate::scan_target::prepare_scan_targets(&target).await?;

            let builder = CommandBuilder::new().extend(&prepared.targets);

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
                "resolved_targets": prepared.targets,
                "out_of_subnet_warning": prepared.warning,
                "hosts": hosts,
                "count": hosts.len(),
            }))
        })
        .await
    }
}
