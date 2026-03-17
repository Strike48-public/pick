//! Masscan Fast - Ultra-fast port scanner with preset configs

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

pub struct MasscanFastTool;

#[async_trait]
impl PentestTool for MasscanFastTool {
    fn name(&self) -> &str {
        "masscan_fast"
    }

    fn description(&self) -> &str {
        "Ultra-fast port scanner optimized for speed (top 100 ports)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "masscan",
                "masscan",
                "Fast port scanner",
            ))
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target IP or CIDR range",
            ))
            .param(ToolParam::optional(
                "rate",
                ParamType::Integer,
                "Packets per second",
                json!(10000),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout",
                json!(120),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "masscan", "masscan").await?;

            let target = param_str_or(&params, "target", "");
            if target.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "target required".into(),
                ));
            }

            let rate = params.get("rate").and_then(|v| v.as_u64()).unwrap_or(10000);
            let timeout_secs = crate::util::param_u64(&params, "timeout", 120);

            let builder = CommandBuilder::new()
                .positional(&target)
                .arg("-p", "21,22,23,25,80,443,445,3306,3389,8080")
                .arg("--rate", &rate.to_string());

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command("masscan", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            let mut open_ports = Vec::new();
            for line in result.stdout.lines() {
                if line.contains("open") {
                    open_ports.push(line.to_string());
                }
            }

            Ok(json!({
                "target": target,
                "open_ports": open_ports,
                "count": open_ports.len(),
            }))
        })
        .await
    }
}
