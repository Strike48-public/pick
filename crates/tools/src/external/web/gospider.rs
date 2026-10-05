//! Gospider - Fast web spider written in Go

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ExternalDependency, ParamType, PentestTool, Platform, ToolCategory, ToolContext,
    ToolParam, ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use crate::external::install::ensure_tool_installed;
use crate::external::runner::{param_str_or, CommandBuilder};

pub struct GospiderTool;

#[async_trait]
impl PentestTool for GospiderTool {
    fn name(&self) -> &str {
        "gospider"
    }

    fn description(&self) -> &str {
        "Fast web spider/crawler written in Go"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(
                ExternalDependency::new("gospider", "gospider", "Web crawler (Go)")
                    .category(ToolCategory::WebDiscovery),
            )
            .param(ToolParam::required("url", ParamType::String, "Target URL"))
            .param(ToolParam::optional(
                "depth",
                ParamType::Integer,
                "Crawl depth",
                json!(2),
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
            ensure_tool_installed(&platform, "gospider", "gospider").await?;

            let (url, args, timeout_secs) = plan_gospider_invocation(&params)?;
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command("gospider", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            let urls: Vec<String> = result.stdout.lines().map(|s| s.to_string()).collect();
            Ok(json!({
                "url": url,
                "urls": urls,
                "count": urls.len(),
            }))
        })
        .await
    }
}

/// The url, argv and timeout `execute` runs gospider with. Pure, so the tests
/// pin the argv a model-shaped call produces.
fn plan_gospider_invocation(params: &Value) -> Result<(String, Vec<String>, u64)> {
    let url = param_str_or(params, "url", "");
    if url.is_empty() {
        return Err(pentest_core::error::Error::InvalidParams(
            "url required".into(),
        ));
    }

    // Model callers emit numeric args as float-strings (matrix#4715);
    // param_u64 coerces them, and falls back to the default on garbage or
    // negative values.
    let depth = crate::util::param_u64(params, "depth", 2);
    let timeout_secs = crate::util::param_u64(params, "timeout", 120);

    let args = CommandBuilder::new()
        .arg("-s", &url)
        .arg("-d", &depth.to_string())
        .build();
    Ok((url, args, timeout_secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn depth_arg(params: Value) -> String {
        let (_, args, _) = plan_gospider_invocation(&params).expect("plan");
        let i = args.iter().position(|a| a == "-d").expect("-d present");
        args[i + 1].clone()
    }

    #[test]
    fn depth_accepts_every_model_shape() {
        // Float-string, string and float depths must reach the argv as the
        // integer the model asked for, not the default of 2.
        for depth in [json!("4.0"), json!("4"), json!(4.0), json!(4)] {
            assert_eq!(
                depth_arg(json!({"url": "https://example.com", "depth": depth})),
                "4",
                "depth shape {depth}"
            );
        }
    }

    #[test]
    fn depth_falls_back_to_default_on_garbage_or_negative() {
        for depth in [json!("deep"), json!(-3), json!(null)] {
            assert_eq!(
                depth_arg(json!({"url": "https://example.com", "depth": depth})),
                "2"
            );
        }
        assert_eq!(depth_arg(json!({"url": "https://example.com"})), "2");
    }

    #[test]
    fn plan_carries_url_and_float_string_timeout() {
        let (url, args, timeout) =
            plan_gospider_invocation(&json!({"url": "https://example.com", "timeout": "30.0"}))
                .expect("plan");
        assert_eq!(url, "https://example.com");
        assert_eq!(
            args[..2],
            ["-s".to_string(), "https://example.com".to_string()]
        );
        assert_eq!(timeout, 30);
        assert!(plan_gospider_invocation(&json!({})).is_err());
    }
}
