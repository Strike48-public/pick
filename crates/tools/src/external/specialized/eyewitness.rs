//! EyeWitness - Web application screenshot tool

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

pub struct EyewitnessTool;

#[async_trait]
impl PentestTool for EyewitnessTool {
    fn name(&self) -> &str {
        "eyewitness"
    }

    fn description(&self) -> &str {
        "Take screenshots of websites and gather information"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "eyewitness",
                "eyewitness",
                "Screenshot tool",
            ))
            .param(ToolParam::required(
                "url",
                ParamType::String,
                "Target URL or file",
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
            ensure_tool_installed(&platform, "eyewitness", "eyewitness").await?;

            let url = param_str_or(&params, "url", "");
            if url.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "url required".into(),
                ));
            }

            let timeout_secs = crate::util::param_u64(&params, "timeout", 300);

            let builder = CommandBuilder::new()
                .arg("--single", &url)
                .arg("--no-prompt", "");

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command("eyewitness", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            Ok(json!({
                "url": url,
                "output": result.stdout,
            }))
        })
        .await
    }
}
