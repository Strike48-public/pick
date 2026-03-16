//! Amass - In-depth DNS enumeration and network mapping

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

pub struct AmassTool;

#[async_trait]
impl PentestTool for AmassTool {
    fn name(&self) -> &str {
        "amass"
    }

    fn description(&self) -> &str {
        "In-depth DNS enumeration and network mapping tool"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "amass",
                "amass",
                "DNS enumeration and network mapping tool (Go-based)"
            ))
            .param(ToolParam::required(
                "domain",
                ParamType::String,
                "Target domain (e.g., 'example.com')",
            ))
            .param(ToolParam::optional(
                "mode",
                ParamType::String,
                "Mode: 'enum' (enumeration) or 'intel' (intelligence gathering), default: enum",
                json!("enum"),
            ))
            .param(ToolParam::optional(
                "passive",
                ParamType::Boolean,
                "Passive enumeration only (no DNS resolution, default: false)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "brute",
                ParamType::Boolean,
                "Enable brute forcing (default: false)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "wordlist",
                ParamType::String,
                "Wordlist for brute forcing",
                json!(""),
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
            ensure_tool_installed(&platform, "amass", "amass").await?;

            let domain = param_str_or(&params, "domain", "");
            if domain.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "domain parameter is required".into(),
                ));
            }

            let mode = param_str_or(&params, "mode", "enum");
            let passive = param_bool(&params, "passive", false);
            let brute = param_bool(&params, "brute", false);
            let wordlist = param_str_opt(&params, "wordlist");
            let timeout_secs = crate::util::param_u64(&params, "timeout", 600);

            let mut builder = CommandBuilder::new()
                .positional(&mode)
                .arg("-d", &domain);

            if passive {
                builder = builder.flag("-passive");
            }

            if brute {
                builder = builder.flag("-brute");
                if let Some(wl) = wordlist {
                    if !wl.is_empty() {
                        builder = builder.arg("-w", &wl);
                    }
                }
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command("amass", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            // Parse output (one subdomain per line)
            let mut subdomains = Vec::new();
            for line in result.stdout.lines() {
                let line = line.trim();
                if !line.is_empty() && line.contains(&domain) {
                    subdomains.push(line.to_string());
                }
            }

            Ok(json!({
                "domain": domain,
                "mode": mode,
                "subdomains": subdomains,
                "count": subdomains.len(),
                "summary": format!("Found {} subdomains using {} mode", subdomains.len(), mode),
            }))
        })
        .await
    }
}
