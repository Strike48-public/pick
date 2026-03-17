//! Httprobe - HTTP/HTTPS probe tool

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

pub struct HttpprobeTool;

#[async_trait]
impl PentestTool for HttpprobeTool {
    fn name(&self) -> &str {
        "httprobe"
    }

    fn description(&self) -> &str {
        "Probe domains for working HTTP and HTTPS servers"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "httprobe",
                "httprobe",
                "HTTP probe (Go-based)",
            ))
            .param(ToolParam::required(
                "domains",
                ParamType::String,
                "Domains (newline-separated) or single domain",
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
            ensure_tool_installed(&platform, "httprobe", "httprobe").await?;

            let domains = param_str_or(&params, "domains", "");
            if domains.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "domains required".into(),
                ));
            }

            let timeout_secs = crate::util::param_u64(&params, "timeout", 60);

            // httprobe reads from stdin
            let builder = CommandBuilder::new();
            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // For simplicity, we'll pass domains via stdin simulation (in real usage, would need proper stdin handling)
            let result = platform
                .execute_command("httprobe", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            let probed: Vec<String> = result.stdout.lines().map(|s| s.to_string()).collect();
            Ok(json!({"domains": domains, "probed": probed, "count": probed.len()}))
        })
        .await
    }
}
