//! FFUF DNS - DNS subdomain enumeration using ffuf

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

pub struct FfufDnsTool;

#[async_trait]
impl PentestTool for FfufDnsTool {
    fn name(&self) -> &str {
        "ffuf_dns"
    }

    fn description(&self) -> &str {
        "Fast DNS subdomain enumeration using ffuf in DNS mode"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new("ffuf", "ffuf", "Fast fuzzer"))
            .param(ToolParam::required(
                "domain",
                ParamType::String,
                "Target domain (e.g., example.com)",
            ))
            .param(ToolParam::required(
                "wordlist",
                ParamType::String,
                "Wordlist path for subdomain names",
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
            ensure_tool_installed(&platform, "ffuf", "ffuf").await?;

            let domain = param_str_or(&params, "domain", "");
            let wordlist = param_str_or(&params, "wordlist", "");
            if domain.is_empty() || wordlist.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "domain and wordlist required".into(),
                ));
            }

            let timeout_secs = crate::util::param_u64(&params, "timeout", 300);

            let builder = CommandBuilder::new()
                .arg("-w", &wordlist)
                .arg("-u", &format!("http://FUZZ.{}", domain))
                .arg("-mode", "dns");

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command("ffuf", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            let mut subdomains = Vec::new();
            for line in result.stdout.lines() {
                if line.contains("Status:") || line.contains("Size:") {
                    subdomains.push(line.to_string());
                }
            }

            Ok(json!({
                "domain": domain,
                "subdomains": subdomains,
                "count": subdomains.len(),
            }))
        })
        .await
    }
}
