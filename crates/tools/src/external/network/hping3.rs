//! hping3 - TCP/IP packet assembler/analyzer

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

pub struct Hping3Tool;

#[async_trait]
impl PentestTool for Hping3Tool {
    fn name(&self) -> &str {
        "hping3"
    }

    fn description(&self) -> &str {
        "TCP/IP packet assembler/analyzer for network testing"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new("hping3", "hping", "Packet tool"))
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target host",
            ))
            .param(ToolParam::optional(
                "count",
                ParamType::Integer,
                "Number of packets",
                json!(3),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout",
                json!(30),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "hping3", "hping").await?;

            let target = param_str_or(&params, "target", "");
            if target.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "target required".into(),
                ));
            }

            let count = params.get("count").and_then(|v| v.as_u64()).unwrap_or(3);
            let timeout_secs = crate::util::param_u64(&params, "timeout", 30);

            let builder = CommandBuilder::new()
                .arg("-c", &count.to_string())
                .positional(&target);

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command("hping3", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            Ok(json!({
                "target": target,
                "count": count,
                "output": result.stdout,
            }))
        })
        .await
    }
}
