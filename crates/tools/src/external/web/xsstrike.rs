//! XSStrike - Advanced XSS detection and exploitation

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
use crate::external::runner::{param_str_opt, param_str_or, CommandBuilder};

pub struct XsstrikeTool;

#[async_trait]
impl PentestTool for XsstrikeTool {
    fn name(&self) -> &str {
        "xsstrike"
    }

    fn description(&self) -> &str {
        "Advanced XSS detection and exploitation suite with fuzzing engine"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "xsstrike",
                "xsstrike",
                "XSS detection tool (Python-based)"
            ))
            .param(ToolParam::required("url", ParamType::String, "Target URL"))
            .param(ToolParam::optional("data", ParamType::String, "POST data", json!("")))
            .param(ToolParam::optional("timeout", ParamType::Integer, "Timeout in seconds", json!(300)))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "xsstrike", "xsstrike").await?;

            let url = param_str_or(&params, "url", "");
            if url.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams("url required".into()));
            }

            let data = param_str_opt(&params, "data");
            let timeout_secs = crate::util::param_u64(&params, "timeout", 300);

            let mut builder = CommandBuilder::new().arg("-u", &url);
            if let Some(d) = data {
                if !d.is_empty() {
                    builder = builder.arg("--data", &d);
                }
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform.execute_command("xsstrike", &args_refs, Duration::from_secs(timeout_secs)).await?;

            let vulnerable = result.stdout.contains("Vulnerable") || result.stdout.contains("XSS");
            Ok(json!({
                "url": url,
                "vulnerable": vulnerable,
                "output": result.stdout,
            }))
        })
        .await
    }
}
