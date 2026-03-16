//! Arjun - HTTP parameter discovery tool
//!
//! Arjun can find query parameters for URL endpoints.

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

/// Arjun HTTP parameter discovery tool
pub struct ArjunTool;

#[async_trait]
impl PentestTool for ArjunTool {
    fn name(&self) -> &str {
        "arjun"
    }

    fn description(&self) -> &str {
        "HTTP parameter discovery tool for finding hidden GET/POST parameters"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "arjun",
                "arjun",
                "HTTP parameter discovery tool (Python-based)"
            ))
            .param(ToolParam::required(
                "url",
                ParamType::String,
                "Target URL (e.g., 'http://example.com/page')",
            ))
            .param(ToolParam::optional(
                "method",
                ParamType::String,
                "HTTP method: GET, POST, JSON, XML (default: GET)",
                json!("GET"),
            ))
            .param(ToolParam::optional(
                "wordlist",
                ParamType::String,
                "Custom wordlist path (default: built-in)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "threads",
                ParamType::Integer,
                "Number of threads (default: 5)",
                json!(5),
            ))
            .param(ToolParam::optional(
                "delay",
                ParamType::Integer,
                "Delay between requests in seconds (default: 0)",
                json!(0),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds (default: 300)",
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

            ensure_tool_installed(&platform, "arjun", "arjun").await?;

            let url = param_str_or(&params, "url", "");
            if url.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "url parameter is required".into(),
                ));
            }

            let method = param_str_or(&params, "method", "GET");
            let wordlist = param_str_opt(&params, "wordlist");
            let threads = crate::util::param_u64(&params, "threads", 5);
            let delay = crate::util::param_u64(&params, "delay", 0);
            let timeout_secs = crate::util::param_u64(&params, "timeout", 300);

            let mut builder = CommandBuilder::new()
                .arg("-u", &url)
                .arg("-m", &method)
                .arg("-t", &threads.to_string())
                .arg("-d", &delay.to_string())
                .flag("--json");

            if let Some(wl) = wordlist {
                if !wl.is_empty() {
                    builder = builder.arg("-w", &wl);
                }
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command("arjun", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            parse_arjun_output(&result.stdout, &url)
        })
        .await
    }
}

fn parse_arjun_output(stdout: &str, url: &str) -> Result<Value> {
    let mut parameters = Vec::new();

    for line in stdout.lines() {
        if line.contains("Valid parameter") || line.contains("Parameter:") {
            if let Some(param) = line.split(':').nth(1) {
                parameters.push(param.trim().to_string());
            }
        }
    }

    Ok(json!({
        "url": url,
        "parameters": parameters,
        "count": parameters.len(),
        "summary": format!("Found {} parameters", parameters.len()),
    }))
}
