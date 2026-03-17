//! SMBMap - SMB enumeration tool

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

pub struct SmbmapTool;

#[async_trait]
impl PentestTool for SmbmapTool {
    fn name(&self) -> &str {
        "smbmap"
    }

    fn description(&self) -> &str {
        "SMB share enumeration and interaction tool"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "smbmap",
                "smbmap",
                "SMB enumeration",
            ))
            .param(ToolParam::required(
                "host",
                ParamType::String,
                "Target host",
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
            ensure_tool_installed(&platform, "smbmap", "smbmap").await?;

            let host = param_str_or(&params, "host", "");
            if host.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "host required".into(),
                ));
            }

            let timeout_secs = crate::util::param_u64(&params, "timeout", 120);

            let builder = CommandBuilder::new().arg("-H", &host);

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command("smbmap", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            let mut shares = Vec::new();
            for line in result.stdout.lines() {
                if line.contains("READ") || line.contains("WRITE") {
                    shares.push(line.trim().to_string());
                }
            }

            Ok(json!({
                "host": host,
                "shares": shares,
                "output": result.stdout,
            }))
        })
        .await
    }
}
