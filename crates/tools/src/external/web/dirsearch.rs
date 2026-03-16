//! Dirsearch - Web path scanner

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

pub struct DirsearchTool;

#[async_trait]
impl PentestTool for DirsearchTool {
    fn name(&self) -> &str {
        "dirsearch"
    }

    fn description(&self) -> &str {
        "Web path scanner for discovering directories and files"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "dirsearch",
                "dirsearch",
                "Web path scanner (Python-based)"
            ))
            .param(ToolParam::required(
                "url",
                ParamType::String,
                "Target URL",
            ))
            .param(ToolParam::optional(
                "extensions",
                ParamType::String,
                "File extensions (comma-separated, e.g., 'php,html')",
                json!(""),
            ))
            .param(ToolParam::optional(
                "threads",
                ParamType::Integer,
                "Number of threads (default: 30)",
                json!(30),
            ))
            .param(ToolParam::optional(
                "wordlist",
                ParamType::String,
                "Custom wordlist path",
                json!(""),
            ))
            .param(ToolParam::optional(
                "exclude_status",
                ParamType::String,
                "Exclude status codes (comma-separated)",
                json!("404,403"),
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
            ensure_tool_installed(&platform, "dirsearch", "dirsearch").await?;

            let url = param_str_or(&params, "url", "");
            if url.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "url parameter is required".into(),
                ));
            }

            let extensions = param_str_opt(&params, "extensions");
            let threads = crate::util::param_u64(&params, "threads", 30);
            let wordlist = param_str_opt(&params, "wordlist");
            let exclude = param_str_or(&params, "exclude_status", "404,403");
            let timeout_secs = crate::util::param_u64(&params, "timeout", 300);

            let mut builder = CommandBuilder::new()
                .arg("-u", &url)
                .arg("-t", &threads.to_string())
                .arg("--exclude-status", &exclude)
                .flag("--format")
                .positional("json");

            if let Some(ext) = extensions {
                if !ext.is_empty() {
                    builder = builder.arg("-e", &ext);
                }
            }

            if let Some(wl) = wordlist {
                if !wl.is_empty() {
                    builder = builder.arg("-w", &wl);
                }
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command("dirsearch", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            // Try to parse JSON output
            if let Ok(findings) = serde_json::from_str::<Value>(&result.stdout) {
                return Ok(findings);
            }

            Ok(json!({
                "url": url,
                "findings": [],
                "raw_output": result.stdout,
            }))
        })
        .await
    }
}
