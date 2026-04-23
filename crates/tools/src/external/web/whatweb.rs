//! WhatWeb - Web scanner for identifying technologies

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed_with_provenance, ExternalDependency, ParamType, PentestTool, Platform,
    ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use crate::external::install::ensure_tool_installed;
use crate::external::runner::{param_str_or, CommandBuilder};
use crate::provenance_support::single_step_provenance;

pub struct WhatwebTool;

#[async_trait]
impl PentestTool for WhatwebTool {
    fn name(&self) -> &str {
        "whatweb"
    }

    fn description(&self) -> &str {
        "Identify websites - CMS, frameworks, JavaScript libraries, web servers"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "whatweb",
                "whatweb",
                "Web tech identifier",
            ))
            .param(ToolParam::required("url", ParamType::String, "Target URL"))
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
        execute_timed_with_provenance(|| async move {
            let platform = get_platform();
            ensure_tool_installed(&platform, "whatweb", "whatweb").await?;

            let url = param_str_or(&params, "url", "");
            if url.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "url required".into(),
                ));
            }

            let timeout_secs = crate::util::param_u64(&params, "timeout", 60);

            let builder = CommandBuilder::new().positional(&url);

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let result = platform
                .execute_command("whatweb", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            let excerpt = if result.stdout.is_empty() {
                result.stderr.as_str()
            } else {
                result.stdout.as_str()
            };
            let provenance = single_step_provenance(
                "whatweb",
                "whatweb",
                &args,
                "web tech identification",
                excerpt,
            );

            let data = json!({
                "url": url,
                "output": result.stdout,
                "plugins": parse_whatweb_output(&result.stdout),
            });

            // Produce evidence nodes for the three-agent pipeline
            let evidence_nodes =
                crate::evidence_producer::evidence_from_whatweb(&data, &url, provenance.clone());

            for node in evidence_nodes {
                crate::evidence_producer::push_evidence(node);
            }

            Ok((data, provenance))
        })
        .await
    }
}

/// Parse whatweb output into structured plugin data.
fn parse_whatweb_output(output: &str) -> Vec<Value> {
    let mut plugins = Vec::new();

    // Simple parsing - whatweb output format: [name], [name: version], etc.
    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }

        // Extract plugins from brackets [...]
        let parts: Vec<&str> = line.split('[').skip(1).collect();
        for part in parts {
            if let Some(end) = part.find(']') {
                let plugin_str = &part[..end];

                if let Some(colon_pos) = plugin_str.find(':') {
                    let name = plugin_str[..colon_pos].trim();
                    let version = plugin_str[colon_pos + 1..].trim();
                    plugins.push(json!({
                        "name": name,
                        "version": version,
                    }));
                } else {
                    plugins.push(json!({
                        "name": plugin_str.trim(),
                    }));
                }
            }
        }
    }

    plugins
}
