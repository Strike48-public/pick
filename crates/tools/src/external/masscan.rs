//! Masscan - Internet-scale port scanner
//!
//! Masscan is the fastest port scanner, capable of scanning the entire Internet
//! in under 6 minutes. It produces results similar to nmap but much faster.

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
use super::runner::{param_str_or, read_sandbox_file, CommandBuilder};
use crate::util::param_u64;

/// Masscan internet-scale port scanner
pub struct MasscanTool;

#[async_trait]
impl PentestTool for MasscanTool {
    fn name(&self) -> &str {
        "masscan"
    }

    fn description(&self) -> &str {
        "Internet-scale asynchronous port scanner capable of scanning millions of IPs per second"
    }

    fn schema(&self) -> ToolSchema {
        use pentest_core::tools::ExternalDependency;

        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "masscan",
                "masscan",
                "Internet-scale asynchronous TCP port scanner",
            ))
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target IP/CIDR (e.g., '10.0.0.0/8', '192.168.1.1')",
            ))
            .param(ToolParam::optional(
                "ports",
                ParamType::String,
                "Ports to scan: '80', '1-1000', '80,443,8080' (default: top 100)",
                json!("0-100"),
            ))
            .param(ToolParam::optional(
                "rate",
                ParamType::Integer,
                "Packet transmission rate (packets/sec, default: 1000)",
                json!(1000),
            ))
            .param(ToolParam::optional(
                "banner",
                ParamType::Boolean,
                "Grab banners from services (slower, default: false)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Overall timeout in seconds (default: 600, range: 30-3600)",
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

            // Ensure masscan is installed
            ensure_tool_installed(&platform, "masscan", "masscan").await?;

            // Extract parameters
            let target = param_str_or(&params, "target", "");
            if target.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "target parameter is required".into(),
                ));
            }

            let ports = param_str_or(&params, "ports", "0-100");
            let rate = param_u64(&params, "rate", 1000);
            let banner = crate::util::param_bool(&params, "banner", false);

            // Get timeout with intelligent defaults and bounds checking
            let timeouts = ToolTimeouts::default();
            let default_timeout = timeouts.get_by_tool_name("masscan");
            let user_timeout =
                Duration::from_secs(param_u64(&params, "timeout", default_timeout.as_secs()));
            let timeout = pentest_core::timeout::clamp_timeout(
                user_timeout,
                pentest_core::timeout::categorize_tool("masscan"),
            );

            // Build masscan command
            let output_file = "/tmp/masscan-output.json";
            let mut builder = CommandBuilder::new()
                .positional(&target)
                .arg("-p", &ports)
                .arg("--rate", &rate.to_string())
                .arg("-oJ", output_file); // JSON output

            if banner {
                builder = builder.flag("--banners");
            }

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute masscan with configured timeout
            let result = platform
                .execute_command("masscan", &args_refs, timeout)
                .await?;

            if result.exit_code != 0 && result.stdout.is_empty() {
                return Err(pentest_core::error::Error::ToolExecution(format!(
                    "masscan failed: {}",
                    result.stderr
                )));
            }

            // Read and parse JSON output
            let json_output = read_sandbox_file(&platform, output_file).await?;
            parse_masscan_json(&json_output, &target)
        })
        .await
    }
}

/// Parse Masscan JSON output
fn parse_masscan_json(json_str: &str, target: &str) -> Result<Value> {
    // Masscan outputs JSONL (one JSON object per line)
    let mut hosts = Vec::new();

    for line in json_str.lines() {
        let line = line.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }

        if let Ok(entry) = serde_json::from_str::<Value>(line) {
            // Masscan format: {"ip": "1.2.3.4", "timestamp": "...", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]}
            if let Some(ip) = entry.get("ip").and_then(|v| v.as_str()) {
                if let Some(ports) = entry.get("ports").and_then(|v| v.as_array()) {
                    let open_ports: Vec<Value> = ports
                        .iter()
                        .map(|p| {
                            json!({
                                "port": p.get("port").and_then(|v| v.as_u64()).unwrap_or(0),
                                "protocol": p.get("proto").and_then(|v| v.as_str()).unwrap_or("tcp"),
                                "state": p.get("status").and_then(|v| v.as_str()).unwrap_or("open"),
                                "service": p.get("service").and_then(|v| v.get("name")).and_then(|v| v.as_str()).unwrap_or(""),
                                "banner": p.get("service").and_then(|v| v.get("banner")).and_then(|v| v.as_str()).unwrap_or(""),
                            })
                        })
                        .collect();

                    hosts.push(json!({
                        "ip": ip,
                        "ports": open_ports,
                        "port_count": open_ports.len(),
                    }));
                }
            }
        }
    }

    Ok(json!({
        "target": target,
        "hosts": hosts,
        "count": hosts.len(),
        "summary": format!("Found {} host(s) with open ports", hosts.len()),
    }))
}
