//! Commix - Command injection exploitation tool

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
use crate::util::param_bool;

pub struct CommixTool;

#[async_trait]
impl PentestTool for CommixTool {
    fn name(&self) -> &str {
        "commix"
    }

    fn description(&self) -> &str {
        "Automated command injection and exploitation tool"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "commix",
                "commix",
                "Command injection exploitation tool (Python-based)"
            ))
            .param(ToolParam::required(
                "url",
                ParamType::String,
                "Target URL with injectable parameter",
            ))
            .param(ToolParam::optional(
                "data",
                ParamType::String,
                "POST data string",
                json!(""),
            ))
            .param(ToolParam::optional(
                "cookie",
                ParamType::String,
                "HTTP Cookie header value",
                json!(""),
            ))
            .param(ToolParam::optional(
                "batch",
                ParamType::Boolean,
                "Never ask for user input (default: true)",
                json!(true),
            ))
            .param(ToolParam::optional(
                "level",
                ParamType::Integer,
                "Level of tests (1-3, default: 1)",
                json!(1),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds (default: 600)",
                json!(600),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "commix", "commix").await?;

            let url = param_str_or(&params, "url", "");
            if url.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "url parameter is required".into(),
                ));
            }

            let data = param_str_opt(&params, "data");
            let cookie = param_str_opt(&params, "cookie");
            let batch = param_bool(&params, "batch", true);
            let level = crate::util::param_u64(&params, "level", 1);
            let timeout_secs = crate::util::param_u64(&params, "timeout", 600);

            let mut builder = CommandBuilder::new()
                .arg("--url", &url)
                .arg("--level", &level.to_string());

            if batch {
                builder = builder.flag("--batch");
            }

            if let Some(d) = data {
                if !d.is_empty() {
                    builder = builder.arg("--data", &d);
                }
            }

            if let Some(c) = cookie {
                if !c.is_empty() {
                    builder = builder.arg("--cookie", &c);
                }
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command("commix", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            let vulnerable = result.stdout.contains("is vulnerable") || result.stdout.contains("injectable");

            Ok(json!({
                "url": url,
                "vulnerable": vulnerable,
                "summary": if vulnerable {
                    "Target is vulnerable to command injection"
                } else {
                    "No command injection vulnerabilities found"
                },
                "raw_output": result.stdout,
            }))
        })
        .await
    }
}
