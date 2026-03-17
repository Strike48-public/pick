//! enum4linux-ng - Next generation enum4linux

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

pub struct Enum4linuxNgTool;

#[async_trait]
impl PentestTool for Enum4linuxNgTool {
    fn name(&self) -> &str {
        "enum4linux_ng"
    }

    fn description(&self) -> &str {
        "Next generation SMB/Windows enumeration tool"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "enum4linux-ng",
                "enum4linux-ng",
                "SMB enumerator",
            ))
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target IP or hostname",
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout",
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
            ensure_tool_installed(&platform, "enum4linux-ng", "enum4linux-ng").await?;

            let target = param_str_or(&params, "target", "");
            if target.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "target required".into(),
                ));
            }

            let timeout_secs = crate::util::param_u64(&params, "timeout", 300);

            let builder = CommandBuilder::new().positional(&target);

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command(
                    "enum4linux-ng",
                    &args_refs,
                    Duration::from_secs(timeout_secs),
                )
                .await?;

            Ok(json!({
                "target": target,
                "output": result.stdout,
            }))
        })
        .await
    }
}
