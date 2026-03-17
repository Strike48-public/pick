//! Nikto (extended) - Web server scanner with additional options

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

pub struct NiktoNgTool;

#[async_trait]
impl PentestTool for NiktoNgTool {
    fn name(&self) -> &str {
        "nikto_ng"
    }

    fn description(&self) -> &str {
        "Web server scanner with tuning and evasion options"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new("nikto", "nikto", "Web scanner"))
            .param(ToolParam::required(
                "host",
                ParamType::String,
                "Target host",
            ))
            .param(ToolParam::optional(
                "port",
                ParamType::Integer,
                "Target port",
                json!(80),
            ))
            .param(ToolParam::optional(
                "ssl",
                ParamType::Boolean,
                "Use SSL",
                json!(false),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout",
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
            ensure_tool_installed(&platform, "nikto", "nikto").await?;

            let host = param_str_or(&params, "host", "");
            if host.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "host required".into(),
                ));
            }

            let port = params.get("port").and_then(|v| v.as_u64()).unwrap_or(80);
            let ssl = params.get("ssl").and_then(|v| v.as_bool()).unwrap_or(false);
            let timeout_secs = crate::util::param_u64(&params, "timeout", 600);

            let mut builder = CommandBuilder::new()
                .arg("-h", &host)
                .arg("-p", &port.to_string());

            if ssl {
                builder = builder.flag("-ssl");
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command("nikto", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            Ok(json!({
                "host": host,
                "port": port,
                "ssl": ssl,
                "output": result.stdout,
            }))
        })
        .await
    }
}
