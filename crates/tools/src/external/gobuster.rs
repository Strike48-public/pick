//! Gobuster - Directory/DNS/Vhost bruteforce tool
//!
//! Gobuster is a fast directory/file, DNS, and vhost bruteforce tool written in Go.

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

/// Gobuster tool
pub struct GobusterTool;

#[async_trait]
impl PentestTool for GobusterTool {
    fn name(&self) -> &str {
        "gobuster"
    }

    fn description(&self) -> &str {
        "Fast directory/file, DNS subdomain, and vhost bruteforce tool"
    }

    fn schema(&self) -> ToolSchema {
        use pentest_core::tools::ExternalDependency;

        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "gobuster",
                "gobuster",
                "Directory/DNS/vhost bruteforce tool written in Go"
            ))
            .param(ToolParam::required(
                "mode",
                ParamType::String,
                "Scan mode: 'dir' (directory), 'dns' (subdomains), or 'vhost' (virtual hosts)",
            ))
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target URL (for dir/vhost) or domain (for dns)",
            ))
            .param(ToolParam::optional(
                "wordlist",
                ParamType::String,
                "Wordlist path (default: auto-detect)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "threads",
                ParamType::Integer,
                "Number of concurrent threads (default: 10)",
                json!(10),
            ))
            .param(ToolParam::optional(
                "extensions",
                ParamType::String,
                "File extensions for dir mode (comma-separated, e.g., 'php,html,txt')",
                json!(""),
            ))
            .param(ToolParam::optional(
                "status_codes",
                ParamType::String,
                "Positive status codes (default: 200,204,301,302,307,401,403)",
                json!("200,204,301,302,307,401,403"),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds (default: 10)",
                json!(10),
            ))
            .param(ToolParam::optional(
                "user_agent",
                ParamType::String,
                "Custom User-Agent string",
                json!(""),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();

            // Ensure gobuster is installed
            ensure_tool_installed(&platform, "gobuster", "gobuster").await?;

            // Extract parameters
            let mode = param_str_or(&params, "mode", "dir");
            let target = param_str_or(&params, "target", "");
            if target.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "target parameter is required".into(),
                ));
            }

            // Validate mode
            if !["dir", "dns", "vhost"].contains(&mode.as_str()) {
                return Err(pentest_core::error::Error::InvalidParams(
                    "mode must be 'dir', 'dns', or 'vhost'".into(),
                ));
            }

            let threads = param_u64(&params, "threads", 10);
            let timeout = param_u64(&params, "timeout", 10);
            let status_codes = param_str_or(&params, "status_codes", "200,204,301,302,307,401,403");

            // Determine wordlist
            let wordlist = if let Some(wl) = param_str_opt(&params, "wordlist") {
                if !wl.is_empty() {
                    wl
                } else {
                    get_wordlist_for_mode(&platform, &mode).await?
                }
            } else {
                get_wordlist_for_mode(&platform, &mode).await?
            };

            // Build gobuster command based on mode
            let mut builder = CommandBuilder::new()
                .positional(&mode)
                .arg("-t", &threads.to_string())
                .arg("--timeout", &format!("{}s", timeout))
                .arg("-w", &wordlist);

            // Mode-specific arguments
            match mode.as_str() {
                "dir" => {
                    builder = builder
                        .arg("-u", &target)
                        .arg("-s", &status_codes);

                    // Add extensions if provided
                    if let Some(ext) = param_str_opt(&params, "extensions") {
                        if !ext.is_empty() {
                            builder = builder.arg("-x", &ext);
                        }
                    }
                }
                "dns" => {
                    builder = builder.arg("-d", &target);
                }
                "vhost" => {
                    builder = builder
                        .arg("-u", &target)
                        .arg("-s", &status_codes);
                }
                _ => unreachable!(),
            }

            // Add optional user agent
            if let Some(ua) = param_str_opt(&params, "user_agent") {
                if !ua.is_empty() {
                    builder = builder.arg("-a", &ua);
                }
            }

            // Add quiet flag for cleaner output
            builder = builder.flag("-q");

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute gobuster
            let result = platform
                .execute_command("gobuster", &args_refs, Duration::from_secs(600))
                .await?;

            // Parse output (line-by-line)
            parse_gobuster_output(&result.stdout, &result.stderr, &mode)
        })
        .await
    }
}

/// Get appropriate wordlist based on scan mode
async fn get_wordlist_for_mode(platform: &impl CommandExec, mode: &str) -> Result<String> {
    let paths = match mode {
        "dir" => vec![
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
            "/usr/share/wordlists/dirb/common.txt",
        ],
        "dns" => vec![
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/wordlists/dnsmap.txt",
        ],
        "vhost" => vec![
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        ],
        _ => vec![],
    };

    for path in paths {
        let check = platform
            .execute_command("test", &["-f", path], Duration::from_secs(5))
            .await?;
        if check.exit_code == 0 {
            return Ok(path.to_string());
        }
    }

    Err(pentest_core::error::Error::ToolExecution(format!(
        "No wordlist found for mode '{}'. Install SecLists: pacman -S seclists",
        mode
    )))
}

/// Parse gobuster output
fn parse_gobuster_output(stdout: &str, stderr: &str, mode: &str) -> Result<Value> {
    let mut findings = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('[') {
            continue; // Skip empty lines and progress indicators
        }

        // Parse based on mode
        match mode {
            "dir" => {
                // Example: /admin (Status: 200) [Size: 1234]
                if let Some(finding) = parse_dir_line(line) {
                    findings.push(finding);
                }
            }
            "dns" => {
                // Example: Found: admin.example.com [1.2.3.4]
                if let Some(finding) = parse_dns_line(line) {
                    findings.push(finding);
                }
            }
            "vhost" => {
                // Example: Found: admin.example.com (Status: 200) [Size: 1234]
                if let Some(finding) = parse_vhost_line(line) {
                    findings.push(finding);
                }
            }
            _ => {}
        }
    }

    Ok(json!({
        "findings": findings,
        "count": findings.len(),
        "summary": format!("Found {} results", findings.len()),
        "stderr": stderr,
    }))
}

fn parse_dir_line(line: &str) -> Option<Value> {
    // Example: /admin (Status: 200) [Size: 1234]
    let re = regex::Regex::new(r"^(/\S+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]").ok()?;
    let caps = re.captures(line)?;

    Some(json!({
        "path": caps.get(1)?.as_str(),
        "status_code": caps.get(2)?.as_str().parse::<u16>().ok()?,
        "size": caps.get(3)?.as_str().parse::<u64>().ok()?,
    }))
}

fn parse_dns_line(line: &str) -> Option<Value> {
    // Example: Found: admin.example.com
    // or: Found: admin.example.com [1.2.3.4]
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 && parts[0] == "Found:" {
        let subdomain = parts[1].trim();
        let ip = if parts.len() >= 3 {
            parts[2].trim_matches(|c| c == '[' || c == ']')
        } else {
            ""
        };

        return Some(json!({
            "subdomain": subdomain,
            "ip": ip,
        }));
    }
    None
}

fn parse_vhost_line(line: &str) -> Option<Value> {
    // Example: Found: admin.example.com (Status: 200) [Size: 1234]
    let re = regex::Regex::new(r"^Found:\s+(\S+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]").ok()?;
    let caps = re.captures(line)?;

    Some(json!({
        "vhost": caps.get(1)?.as_str(),
        "status_code": caps.get(2)?.as_str().parse::<u16>().ok()?,
        "size": caps.get(3)?.as_str().parse::<u64>().ok()?,
    }))
}
