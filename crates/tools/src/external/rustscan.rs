//! RustScan - Ultra-fast port scanner
//!
//! RustScan is a modern port scanner written in Rust that can scan all 65k ports
//! in under 3 seconds. It then pipes results to nmap for service detection.

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_core::validation::validate_target;
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use super::install::ensure_tool_installed;
use super::runner::{param_str_or, CommandBuilder};
use crate::util::param_u64;

/// RustScan ultra-fast port scanner
pub struct RustScanTool;

#[async_trait]
impl PentestTool for RustScanTool {
    fn name(&self) -> &str {
        "rustscan"
    }

    fn description(&self) -> &str {
        "Ultra-fast port scanner that can scan all 65k ports in seconds, with nmap integration"
    }

    fn schema(&self) -> ToolSchema {
        use pentest_core::tools::ExternalDependency;

        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "rustscan",
                "rustscan",
                "Modern ultra-fast port scanner written in Rust",
            ))
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target IP address or hostname (CIDR ranges supported)",
            ))
            .param(ToolParam::optional(
                "ports",
                ParamType::String,
                "Port range: '1-65535', '22,80,443', or 'all' (default: top 1000)",
                json!("1-1000"),
            ))
            .param(ToolParam::optional(
                "batch_size",
                ParamType::Integer,
                "Batch size for port scanning (higher = faster but more aggressive, default: 4500)",
                json!(4500),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout per port in milliseconds (default: 1500)",
                json!(1500),
            ))
            .param(ToolParam::optional(
                "ulimit",
                ParamType::Integer,
                "File descriptor limit (default: 5000, max: 65535)",
                json!(5000),
            ))
            .param(ToolParam::optional(
                "accessible",
                ParamType::Boolean,
                "Accessible mode (no nmap follow-up, just list open ports)",
                json!(true),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();

            // Ensure rustscan is installed
            ensure_tool_installed(&platform, "rustscan", "rustscan").await?;

            // Extract parameters
            let target = param_str_or(&params, "target", "");

            // Validate target to prevent command injection
            let target = validate_target(&target)?;
            if target.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "target parameter is required".into(),
                ));
            }

            let ports = param_str_or(&params, "ports", "1-1000");
            let batch_size = param_u64(&params, "batch_size", 4500);
            let timeout = param_u64(&params, "timeout", 1500);
            let ulimit = param_u64(&params, "ulimit", 5000);
            let accessible = crate::util::param_bool(&params, "accessible", true);

            // Build rustscan command
            let mut builder = CommandBuilder::new()
                .arg("-a", &target)
                .arg("-b", &batch_size.to_string())
                .arg("-t", &timeout.to_string())
                .arg("-u", &ulimit.to_string());

            // Port specification
            if ports == "all" {
                builder = builder.arg("-r", "1-65535");
            } else {
                builder = builder.arg("-r", &ports);
            }

            // Accessible mode (no nmap follow-up)
            if accessible {
                builder = builder.flag("--accessible");
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute rustscan
            let result = platform
                .execute_command("rustscan", &args_refs, Duration::from_secs(300))
                .await?;

            if result.exit_code != 0 && result.stdout.is_empty() {
                return Err(pentest_core::error::Error::ToolExecution(format!(
                    "rustscan failed: {}",
                    result.stderr
                )));
            }

            // Parse RustScan output
            parse_rustscan_output(&result.stdout, &target)
        })
        .await
    }
}

/// Parse RustScan output
fn parse_rustscan_output(stdout: &str, target: &str) -> Result<Value> {
    let mut open_ports = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();

        // RustScan outputs: "Open 10.10.2.169:22"
        // or "-> 22" format
        if line.starts_with("Open") {
            if let Some(port_str) = line.split(':').next_back() {
                if let Ok(port) = port_str.trim().parse::<u16>() {
                    open_ports.push(json!({
                        "port": port,
                        "state": "open",
                        "protocol": "tcp"
                    }));
                }
            }
        } else if line.starts_with("->") {
            // Format: "-> 22"
            if let Some(port_str) = line.strip_prefix("->") {
                if let Ok(port) = port_str.trim().parse::<u16>() {
                    open_ports.push(json!({
                        "port": port,
                        "state": "open",
                        "protocol": "tcp"
                    }));
                }
            }
        }
    }

    // Remove duplicates
    open_ports.sort_by_key(|p| p["port"].as_u64().unwrap_or(0));
    open_ports.dedup_by_key(|p| p["port"].as_u64().unwrap_or(0));

    Ok(json!({
        "target": target,
        "open_ports": open_ports,
        "count": open_ports.len(),
        "summary": format!("Found {} open port(s) on {}", open_ports.len(), target),
        "raw_output": stdout,
    }))
}
