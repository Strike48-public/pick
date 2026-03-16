//! Dirb - Web content scanner
//!
//! Dirb is a web content scanner that looks for existing (and/or hidden)
//! web objects by launching a dictionary-based attack.

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult,
    ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use super::install::ensure_tool_installed;
use super::runner::{param_str_opt, param_str_or, CommandBuilder};
use crate::util::param_u64;

/// Dirb web content scanner
pub struct DirbTool;

#[async_trait]
impl PentestTool for DirbTool {
    fn name(&self) -> &str {
        "dirb"
    }

    fn description(&self) -> &str {
        "Web content scanner for discovering hidden web objects via dictionary-based attack"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "url",
                ParamType::String,
                "Target URL (e.g., 'http://example.com/')",
            ))
            .param(ToolParam::optional(
                "wordlist",
                ParamType::String,
                "Wordlist path (default: dirb common.txt)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "extensions",
                ParamType::String,
                "File extensions list (e.g., '.php,.html,.txt')",
                json!(""),
            ))
            .param(ToolParam::optional(
                "recursive",
                ParamType::Boolean,
                "Recursive scan (follow directories, default: false)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "speed_delay",
                ParamType::Integer,
                "Delay between requests in milliseconds (default: 0)",
                json!(0),
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

            // Ensure dirb is installed
            ensure_tool_installed(&platform, "dirb", "dirb").await?;

            // Extract parameters
            let url = param_str_or(&params, "url", "");
            if url.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "url parameter is required".into(),
                ));
            }

            let recursive = crate::util::param_bool(&params, "recursive", false);
            let speed_delay = param_u64(&params, "speed_delay", 0);
            let timeout = param_u64(&params, "timeout", 600);

            // Determine wordlist
            let wordlist = if let Some(wl) = param_str_opt(&params, "wordlist") {
                if !wl.is_empty() {
                    wl
                } else {
                    get_dirb_wordlist(&platform).await?
                }
            } else {
                get_dirb_wordlist(&platform).await?
            };

            // Build dirb command
            let mut builder = CommandBuilder::new()
                .positional(&url)
                .positional(&wordlist)
                .flag("-S") // Silent mode (no header)
                .flag("-w"); // Don't show warnings

            // Recursive mode
            if recursive {
                builder = builder.flag("-r");
            }

            // Speed delay
            if speed_delay > 0 {
                builder = builder.arg("-z", &speed_delay.to_string());
            }

            // Extensions
            if let Some(ext) = param_str_opt(&params, "extensions") {
                if !ext.is_empty() {
                    builder = builder.arg("-X", &ext);
                }
            }

            // Output file
            builder = builder.arg("-o", "/tmp/dirb-output.txt");

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute dirb
            let result = platform
                .execute_command("dirb", &args_refs, Duration::from_secs(timeout))
                .await?;

            // Read output file
            let output = super::runner::read_sandbox_file(&platform, "/tmp/dirb-output.txt")
                .await
                .unwrap_or_else(|_| result.stdout.clone());

            // Parse dirb output
            parse_dirb_output(&output, &url)
        })
        .await
    }
}

/// Get default dirb wordlist
async fn get_dirb_wordlist(platform: &impl CommandExec) -> Result<String> {
    // Try common dirb wordlist locations
    let paths = vec![
        "/usr/share/dirb/wordlists/common.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ];

    for path in paths {
        let check = platform
            .execute_command("test", &["-f", path], Duration::from_secs(5))
            .await?;
        if check.exit_code == 0 {
            return Ok(path.to_string());
        }
    }

    Err(pentest_core::error::Error::ToolExecution(
        "No dirb wordlist found. Install dirb or seclists package.".into(),
    ))
}

/// Parse dirb output
fn parse_dirb_output(output: &str, url: &str) -> Result<Value> {
    let mut findings = Vec::new();

    for line in output.lines() {
        let line = line.trim();

        // Dirb format: "+ http://example.com/admin (CODE:200|SIZE:1234)"
        if line.starts_with('+') {
            if let Some(url_part) = line.strip_prefix('+').and_then(|s| s.trim().split_whitespace().next()) {
                // Extract status code and size
                let status_code = if let Some(code_str) = line.split("CODE:").nth(1) {
                    code_str.split('|').next()
                        .and_then(|s| s.trim_end_matches(')').parse::<u16>().ok())
                        .unwrap_or(0)
                } else {
                    0
                };

                let size = if let Some(size_str) = line.split("SIZE:").nth(1) {
                    size_str.trim_end_matches(')')
                        .parse::<u64>().ok()
                        .unwrap_or(0)
                } else {
                    0
                };

                findings.push(json!({
                    "url": url_part,
                    "status_code": status_code,
                    "size": size,
                }));
            }
        }
    }

    Ok(json!({
        "url": url,
        "findings": findings,
        "count": findings.len(),
        "summary": format!("Found {} web objects", findings.len()),
    }))
}
