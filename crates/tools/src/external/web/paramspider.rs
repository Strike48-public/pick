//! ParamSpider - Mining parameters from dark corners of web archives

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

pub struct ParamspiderTool;

#[async_trait]
impl PentestTool for ParamspiderTool {
    fn name(&self) -> &str {
        "paramspider"
    }

    fn description(&self) -> &str {
        "Mining parameters from dark corners of web archives"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "paramspider",
                "paramspider",
                "Parameter discovery",
            ))
            .param(ToolParam::required(
                "domain",
                ParamType::String,
                "Target domain",
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
            ensure_tool_installed(&platform, "paramspider", "paramspider").await?;

            let domain = param_str_or(&params, "domain", "");
            if domain.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "domain required".into(),
                ));
            }

            let timeout_secs = crate::util::param_u64(&params, "timeout", 300);

            let builder = CommandBuilder::new().arg("-d", &domain);

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command(
                    "paramspider",
                    &args_refs,
                    Duration::from_secs(timeout_secs),
                )
                .await?;

            let params_found: Vec<String> =
                result.stdout.lines().map(|s| s.to_string()).collect();
            Ok(json!({
                "domain": domain,
                "parameters": params_found,
                "count": params_found.len(),
            }))
        })
        .await
    }
}
