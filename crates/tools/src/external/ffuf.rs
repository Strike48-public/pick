//! FFUF - Fast web fuzzer
//!
//! FFUF (Fuzz Faster U Fool) is a fast web fuzzer written in Go.
//! Supports directory/file discovery, vhost discovery, and parameter fuzzing.

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::timeout::ToolTimeouts;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use super::install::ensure_tool_installed;
use super::parsers::parse_json_output;
use super::runner::{param_str_opt, param_str_or, read_sandbox_file, CommandBuilder};
use crate::util::param_u64;

/// FFUF web fuzzer tool
pub struct FfufTool;

#[async_trait]
impl PentestTool for FfufTool {
    fn name(&self) -> &str {
        "ffuf"
    }

    fn description(&self) -> &str {
        "Fast web fuzzer for directory/vhost/parameter discovery using wordlists"
    }

    fn schema(&self) -> ToolSchema {
        use pentest_core::tools::ExternalDependency;

        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "ffuf",
                "ffuf",
                "Fast web fuzzer written in Go",
            ))
            .param(ToolParam::required(
                "url",
                ParamType::String,
                "Target URL with FUZZ keyword (e.g., http://target.com/FUZZ)",
            ))
            .param(ToolParam::optional(
                "wordlist",
                ParamType::String,
                "Wordlist path (default: common.txt from SecLists if available)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "threads",
                ParamType::Integer,
                "Number of concurrent threads (default: 40)",
                json!(40),
            ))
            .param(ToolParam::optional(
                "match_codes",
                ParamType::String,
                "Match HTTP status codes (default: 200,204,301,302,307,401,403,405)",
                json!("200,204,301,302,307,401,403,405"),
            ))
            .param(ToolParam::optional(
                "filter_size",
                ParamType::String,
                "Filter response size (e.g., '1234' or '100-200')",
                json!(""),
            ))
            .param(ToolParam::optional(
                "extensions",
                ParamType::String,
                "File extensions to append (comma-separated, e.g., '.php,.html')",
                json!(""),
            ))
            .param(ToolParam::optional(
                "headers",
                ParamType::Object,
                "Custom HTTP headers as key-value pairs",
                json!({}),
            ))
            .param(ToolParam::optional(
                "method",
                ParamType::String,
                "HTTP method (default: GET)",
                json!("GET"),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds (default: 10)",
                json!(10),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();

            // Ensure ffuf is installed
            ensure_tool_installed(&platform, "ffuf", "ffuf").await?;

            // Extract parameters
            let url = param_str_or(&params, "url", "");
            if url.is_empty() || !url.contains("FUZZ") {
                return Err(pentest_core::error::Error::InvalidParams(
                    "url parameter is required and must contain FUZZ keyword".into(),
                ));
            }

            let threads = param_u64(&params, "threads", 40);
            let match_codes =
                param_str_or(&params, "match_codes", "200,204,301,302,307,401,403,405");
            let method = param_str_or(&params, "method", "GET");
            let timeout = param_u64(&params, "timeout", 10);

            // Determine wordlist path
            let wordlist = if let Some(wl) = param_str_opt(&params, "wordlist") {
                if !wl.is_empty() {
                    wl
                } else {
                    get_default_wordlist(&platform).await?
                }
            } else {
                get_default_wordlist(&platform).await?
            };

            // Build ffuf command
            let output_file = "/tmp/ffuf-output.json";
            let mut builder = CommandBuilder::new()
                .arg("-u", &url)
                .arg("-w", &wordlist)
                .arg("-t", &threads.to_string())
                .arg("-mc", &match_codes)
                .arg("-X", &method)
                .arg("-timeout", &timeout.to_string())
                .arg("-o", output_file)
                .arg("-of", "json") // Force JSON output
                .flag("-s"); // Silent mode (no progress bar)

            // Add optional extensions
            if let Some(ext) = param_str_opt(&params, "extensions") {
                if !ext.is_empty() {
                    builder = builder.arg("-e", &ext);
                }
            }

            // Add optional size filter
            if let Some(fs) = param_str_opt(&params, "filter_size") {
                if !fs.is_empty() {
                    builder = builder.arg("-fs", &fs);
                }
            }

            // Add custom headers
            if let Some(headers) = params.get("headers").and_then(|v| v.as_object()) {
                for (key, value) in headers {
                    if let Some(val_str) = value.as_str() {
                        builder = builder.arg("-H", &format!("{}: {}", key, val_str));
                    }
                }
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute ffuf with configured overall timeout
            let timeouts = ToolTimeouts::default();
            let overall_timeout = timeouts.get_by_tool_name("ffuf");
            let result = platform
                .execute_command("ffuf", &args_refs, overall_timeout)
                .await?;

            if result.exit_code != 0 && result.stdout.is_empty() {
                return Err(pentest_core::error::Error::ToolExecution(format!(
                    "ffuf failed: {}",
                    result.stderr
                )));
            }

            // Read JSON output file
            let json_output = read_sandbox_file(&platform, output_file).await?;

            // Parse FFUF JSON output
            parse_ffuf_json(&json_output, &result.stderr)
        })
        .await
    }
}

/// Get default wordlist path (check for SecLists or use fallback)
async fn get_default_wordlist(platform: &impl CommandExec) -> Result<String> {
    // Try SecLists common.txt first
    let seclists_path = "/usr/share/seclists/Discovery/Web-Content/common.txt";
    let check = platform
        .execute_command("test", &["-f", seclists_path], Duration::from_secs(5))
        .await?;

    if check.exit_code == 0 {
        return Ok(seclists_path.to_string());
    }

    // Fallback: try to find any wordlist
    let fallback_paths = vec![
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/dict/words",
    ];

    for path in fallback_paths {
        let check = platform
            .execute_command("test", &["-f", path], Duration::from_secs(5))
            .await?;
        if check.exit_code == 0 {
            return Ok(path.to_string());
        }
    }

    Err(pentest_core::error::Error::ToolExecution(
        "No wordlist found. Install SecLists: pacman -S seclists".into(),
    ))
}

/// Parse FFUF JSON output
fn parse_ffuf_json(json_str: &str, stderr: &str) -> Result<Value> {
    let ffuf_output = parse_json_output(json_str)?;

    // Extract results array
    let results = ffuf_output
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            pentest_core::error::Error::ToolExecution("FFUF output missing 'results' array".into())
        })?;

    // Transform to our format
    let findings: Vec<Value> = results
        .iter()
        .map(|r| {
            json!({
                "url": r.get("url").and_then(|v| v.as_str()).unwrap_or(""),
                "status_code": r.get("status").and_then(|v| v.as_u64()).unwrap_or(0),
                "content_length": r.get("length").and_then(|v| v.as_u64()).unwrap_or(0),
                "words": r.get("words").and_then(|v| v.as_u64()).unwrap_or(0),
                "lines": r.get("lines").and_then(|v| v.as_u64()).unwrap_or(0),
                "redirect_location": r.get("redirectlocation").and_then(|v| v.as_str()).unwrap_or(""),
                "duration_ms": r.get("duration").and_then(|v| v.as_u64()).unwrap_or(0) / 1_000_000, // Convert nanoseconds to ms
            })
        })
        .collect();

    Ok(json!({
        "findings": findings,
        "count": findings.len(),
        "summary": format!("Found {} results", findings.len()),
        "stderr": stderr,
    }))
}
