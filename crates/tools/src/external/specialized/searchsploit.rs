//! Searchsploit - Exploit database search tool

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
use crate::util::param_bool;

pub struct SearchsploitTool;

#[async_trait]
impl PentestTool for SearchsploitTool {
    fn name(&self) -> &str {
        "searchsploit"
    }

    fn description(&self) -> &str {
        "Search Exploit Database for exploits and vulnerabilities"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "searchsploit",
                "exploitdb",
                "Exploit database search tool (local exploit-db)",
            ))
            .param(ToolParam::required(
                "search_term",
                ParamType::String,
                "Search term (software name, CVE, etc.)",
            ))
            .param(ToolParam::optional(
                "json",
                ParamType::Boolean,
                "Output in JSON format (default: true)",
                json!(true),
            ))
            .param(ToolParam::optional(
                "exact",
                ParamType::Boolean,
                "Exact match only (default: false)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds (default: 30)",
                json!(30),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "searchsploit", "exploitdb").await?;

            let search_term = param_str_or(&params, "search_term", "");
            if search_term.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "search_term parameter is required".into(),
                ));
            }

            let json_output = param_bool(&params, "json", true);
            let exact = param_bool(&params, "exact", false);
            let timeout_secs = crate::util::param_u64(&params, "timeout", 30);

            let mut builder = CommandBuilder::new();

            if json_output {
                builder = builder.flag("--json");
            }

            if exact {
                builder = builder.flag("--exact");
            }

            builder = builder.positional(&search_term);

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            let result = platform
                .execute_command(
                    "searchsploit",
                    &args_refs,
                    Duration::from_secs(timeout_secs),
                )
                .await?;

            // Try to parse JSON output
            if json_output {
                if let Ok(results) = serde_json::from_str::<Value>(&result.stdout) {
                    return Ok(results);
                }
            }

            Ok(json!({
                "search_term": search_term,
                "results": [],
                "raw_output": result.stdout,
            }))
        })
        .await
    }
}
