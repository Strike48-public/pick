//! testssl.sh - Testing TLS/SSL encryption

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

pub struct TestsslTool;

#[async_trait]
impl PentestTool for TestsslTool {
    fn name(&self) -> &str {
        "testssl"
    }

    fn description(&self) -> &str {
        "Testing TLS/SSL encryption anywhere on any port"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "testssl",
                "testssl.sh",
                "TLS/SSL tester",
            ))
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target URL or host:port",
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
            ensure_tool_installed(&platform, "testssl", "testssl.sh").await?;

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
                .execute_command("testssl", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            let mut findings = Vec::new();
            for line in result.stdout.lines() {
                if line.contains("CRITICAL") || line.contains("HIGH") || line.contains("MEDIUM") {
                    findings.push(line.trim().to_string());
                }
            }

            Ok(json!({
                "target": target,
                "findings": findings,
                "output": result.stdout,
            }))
        })
        .await
    }
}
