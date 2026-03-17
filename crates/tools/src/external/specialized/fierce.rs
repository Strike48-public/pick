//! Fierce - DNS reconnaissance and subdomain enumeration

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

pub struct FierceTool;

#[async_trait]
impl PentestTool for FierceTool {
    fn name(&self) -> &str {
        "fierce"
    }

    fn description(&self) -> &str {
        "DNS reconnaissance tool for locating non-contiguous IP space"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "fierce",
                "fierce",
                "DNS reconnaissance",
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
            ensure_tool_installed(&platform, "fierce", "fierce").await?;

            let domain = param_str_or(&params, "domain", "");
            if domain.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "domain required".into(),
                ));
            }

            let timeout_secs = crate::util::param_u64(&params, "timeout", 300);

            let builder = CommandBuilder::new().arg("--domain", &domain);

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command("fierce", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            let mut findings = Vec::new();
            for line in result.stdout.lines() {
                if line.contains("Found:") || line.contains(&domain) {
                    findings.push(line.trim().to_string());
                }
            }

            Ok(json!({
                "domain": domain,
                "findings": findings,
                "output": result.stdout,
            }))
        })
        .await
    }
}
