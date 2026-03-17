//! Crunch - Wordlist generator

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
use crate::external::runner::{param_str_opt, CommandBuilder};

pub struct CrunchTool;

#[async_trait]
impl PentestTool for CrunchTool {
    fn name(&self) -> &str {
        "crunch"
    }

    fn description(&self) -> &str {
        "Wordlist generator based on character sets and patterns"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "crunch",
                "crunch",
                "Wordlist generator",
            ))
            .param(ToolParam::required(
                "min_length",
                ParamType::Integer,
                "Minimum length",
            ))
            .param(ToolParam::required(
                "max_length",
                ParamType::Integer,
                "Maximum length",
            ))
            .param(ToolParam::optional(
                "charset",
                ParamType::String,
                "Character set",
                json!("abcdefghijklmnopqrstuvwxyz0123456789"),
            ))
            .param(ToolParam::optional(
                "pattern",
                ParamType::String,
                "Pattern (@ = lower, , = upper, % = digit, ^ = symbol)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout",
                json!(60),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "crunch", "crunch").await?;

            let min_len = crate::util::param_u64(&params, "min_length", 0);
            let max_len = crate::util::param_u64(&params, "max_length", 0);
            if min_len == 0 || max_len == 0 {
                return Err(pentest_core::error::Error::InvalidParams("min_length and max_length required".into()));
            }

            let charset = param_str_opt(&params, "charset");
            let pattern = param_str_opt(&params, "pattern");
            let timeout_secs = crate::util::param_u64(&params, "timeout", 60);

            let mut builder = CommandBuilder::new()
                .positional(&min_len.to_string())
                .positional(&max_len.to_string());

            if let Some(cs) = charset {
                if !cs.is_empty() {
                    builder = builder.positional(&cs);
                }
            }

            if let Some(pat) = pattern {
                if !pat.is_empty() {
                    builder = builder.arg("-t", &pat);
                }
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform.execute_command("crunch", &args_refs, Duration::from_secs(timeout_secs)).await?;

            let words: Vec<String> = result.stdout.lines().take(100).map(|s| s.to_string()).collect();
            Ok(json!({"words": words, "preview_count": words.len(), "output": "truncated to 100 words"}))
        })
        .await
    }
}
