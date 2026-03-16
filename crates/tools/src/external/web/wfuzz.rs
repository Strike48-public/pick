//! Wfuzz - Web application fuzzer
//!
//! Wfuzz is a web application brute forcer for finding resources not linked directories,
//! servlets, scripts, etc., fuzzing GET and POST parameters for checking different kind of
//! injections (SQL, XSS, LDAP, etc.), and bruteforce forms parameters.

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

/// Wfuzz web application fuzzer
pub struct WfuzzTool;

#[async_trait]
impl PentestTool for WfuzzTool {
    fn name(&self) -> &str {
        "wfuzz"
    }

    fn description(&self) -> &str {
        "Web application fuzzer for finding hidden resources, parameters, and testing injections"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "wfuzz",
                "wfuzz",
                "Web application fuzzer (Python-based)"
            ))
            .param(ToolParam::required(
                "url",
                ParamType::String,
                "Target URL with FUZZ keyword (e.g., 'http://example.com/FUZZ')",
            ))
            .param(ToolParam::optional(
                "wordlist",
                ParamType::String,
                "Wordlist path (default: common.txt from SecLists if available)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "hide_code",
                ParamType::String,
                "Hide responses with these status codes (comma-separated, e.g., '404,400')",
                json!("404"),
            ))
            .param(ToolParam::optional(
                "show_code",
                ParamType::String,
                "Show only responses with these status codes (comma-separated)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "hide_words",
                ParamType::String,
                "Hide responses with this number of words (e.g., '100' or '50-100')",
                json!(""),
            ))
            .param(ToolParam::optional(
                "hide_chars",
                ParamType::String,
                "Hide responses with this number of characters",
                json!(""),
            ))
            .param(ToolParam::optional(
                "threads",
                ParamType::Integer,
                "Number of concurrent connections (default: 10)",
                json!(10),
            ))
            .param(ToolParam::optional(
                "method",
                ParamType::String,
                "HTTP method: GET, POST, PUT, DELETE (default: GET)",
                json!("GET"),
            ))
            .param(ToolParam::optional(
                "data",
                ParamType::String,
                "POST data with FUZZ keyword",
                json!(""),
            ))
            .param(ToolParam::optional(
                "headers",
                ParamType::String,
                "Custom headers (format: 'Header1: Value1, Header2: Value2')",
                json!(""),
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

            // Ensure wfuzz is installed
            ensure_tool_installed(&platform, "wfuzz", "wfuzz").await?;

            // Extract parameters
            let url = param_str_or(&params, "url", "");
            if url.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "url parameter is required".into(),
                ));
            }

            let wordlist = param_str_or(&params, "wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt");
            let hide_code = param_str_opt(&params, "hide_code");
            let show_code = param_str_opt(&params, "show_code");
            let hide_words = param_str_opt(&params, "hide_words");
            let hide_chars = param_str_opt(&params, "hide_chars");
            let threads = crate::util::param_u64(&params, "threads", 10);
            let method = param_str_or(&params, "method", "GET");
            let data = param_str_opt(&params, "data");
            let headers = param_str_opt(&params, "headers");
            let timeout_secs = crate::util::param_u64(&params, "timeout", 300);

            // Build wfuzz command
            let mut builder = CommandBuilder::new()
                .arg("-w", &wordlist)
                .arg("-t", &threads.to_string())
                .arg("-X", &method)
                .flag("-f")
                .positional("-") // Output to stdout
                .flag("--no-cache");

            // Filtering options
            if let Some(codes) = hide_code {
                if !codes.is_empty() {
                    builder = builder.arg("--hc", &codes);
                }
            }

            if let Some(codes) = show_code {
                if !codes.is_empty() {
                    builder = builder.arg("--sc", &codes);
                }
            }

            if let Some(words) = hide_words {
                if !words.is_empty() {
                    builder = builder.arg("--hw", &words);
                }
            }

            if let Some(chars) = hide_chars {
                if !chars.is_empty() {
                    builder = builder.arg("--hh", &chars);
                }
            }

            // POST data
            if let Some(post_data) = data {
                if !post_data.is_empty() {
                    builder = builder.arg("-d", &post_data);
                }
            }

            // Custom headers
            if let Some(headers_str) = headers {
                if !headers_str.is_empty() {
                    for header in headers_str.split(',') {
                        let header = header.trim();
                        if !header.is_empty() {
                            builder = builder.arg("-H", header);
                        }
                    }
                }
            }

            // Target URL (must be last)
            builder = builder.positional(&url);

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute wfuzz
            let result = platform
                .execute_command("wfuzz", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            // Parse output
            parse_wfuzz_output(&result.stdout, &url)
        })
        .await
    }
}

/// Parse wfuzz output
fn parse_wfuzz_output(stdout: &str, url: &str) -> Result<Value> {
    let mut findings = Vec::new();
    let mut total_requests = 0;

    for line in stdout.lines() {
        let line = line.trim();

        // Skip header and separator lines
        if line.starts_with('=') || line.starts_with("ID") || line.is_empty() {
            continue;
        }

        // Parse result lines (format: ID | Response | Lines | Words | Chars | Payload)
        let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
        if parts.len() >= 6 {
            total_requests += 1;

            findings.push(json!({
                "id": parts[0],
                "code": parts[1],
                "lines": parts[2],
                "words": parts[3],
                "chars": parts[4],
                "payload": parts[5],
            }));
        }
    }

    let summary = format!(
        "Found {} results from {} total requests",
        findings.len(),
        total_requests
    );

    Ok(json!({
        "url": url,
        "findings": findings,
        "count": findings.len(),
        "total_requests": total_requests,
        "summary": summary,
    }))
}
