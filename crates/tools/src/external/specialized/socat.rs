//! Socat - Multipurpose relay tool

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

pub struct SocatTool;

#[async_trait]
impl PentestTool for SocatTool {
    fn name(&self) -> &str {
        "socat"
    }

    fn description(&self) -> &str {
        "Multipurpose relay tool for bidirectional data transfer"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "socat",
                "socat",
                "Multipurpose relay",
            ))
            .param(ToolParam::required(
                "source",
                ParamType::String,
                "Source address",
            ))
            .param(ToolParam::required(
                "destination",
                ParamType::String,
                "Destination address",
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
            ensure_tool_installed(&platform, "socat", "socat").await?;

            let source = param_str_or(&params, "source", "");
            let destination = param_str_or(&params, "destination", "");
            if source.is_empty() || destination.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "source and destination required".into(),
                ));
            }

            let timeout_secs = crate::util::param_u64(&params, "timeout", 30);

            let builder = CommandBuilder::new()
                .positional(&source)
                .positional(&destination);
            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command("socat", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            Ok(json!({"success": result.exit_code == 0, "output": result.stdout}))
        })
        .await
    }
}
