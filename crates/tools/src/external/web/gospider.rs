//! Gospider - Fast web spider written in Go

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

pub struct GospiderTool;

#[async_trait]
impl PentestTool for GospiderTool {
    fn name(&self) -> &str {
        "gospider"
    }

    fn description(&self) -> &str {
        "Fast web spider/crawler written in Go"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "gospider",
                "gospider",
                "Web crawler (Go)",
            ))
            .param(ToolParam::required("url", ParamType::String, "Target URL"))
            .param(ToolParam::optional(
                "depth",
                ParamType::Integer,
                "Crawl depth",
                json!(2),
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
            ensure_tool_installed(&platform, "gospider", "gospider").await?;

            let url = param_str_or(&params, "url", "");
            if url.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "url required".into(),
                ));
            }

            let depth = params.get("depth").and_then(|v| v.as_u64()).unwrap_or(2);
            let timeout_secs = crate::util::param_u64(&params, "timeout", 120);

            let builder = CommandBuilder::new()
                .arg("-s", &url)
                .arg("-d", &depth.to_string());

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command("gospider", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            let urls: Vec<String> = result.stdout.lines().map(|s| s.to_string()).collect();
            Ok(json!({
                "url": url,
                "urls": urls,
                "count": urls.len(),
            }))
        })
        .await
    }
}
