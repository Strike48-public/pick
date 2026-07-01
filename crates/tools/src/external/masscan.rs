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
use pentest_core::validation::{validate_port_spec, validate_target};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use super::install::ensure_tool_installed;
use super::runner::{param_exclude_list, param_str_or, read_sandbox_file, CommandBuilder};
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
                "Target IP, CIDR, or IPv4 dash range. Prefer CIDR ('10.0.0.0/8') or a simple \
                 IP1-IP2 range ('10.0.0.1-10.0.5.20'); multi-octet ranges are not scope-checked \
                 and may be rejected.",
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
            .param(ToolParam::optional(
                "exclude",
                ParamType::Array,
                "Hosts/CIDRs to exclude from the scan (maps to masscan --exclude). Use this to scan a range while skipping specific hosts, e.g. target='10.0.0.0/8' exclude=['10.0.0.1']. Out-of-scope hosts are also injected here automatically by the platform.",
                json!([]),
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

            // Validate target to prevent command injection
            let target = validate_target(&target)?;

            let ports = param_str_or(&params, "ports", "0-100");
            // Validate port specification to prevent command injection
            let ports = validate_port_spec(&ports)?;
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

            // Exclude list (issue #2524): out-of-scope hosts the scan must skip.
            // Validated as IP/CIDR/hostname to prevent injection via this param.
            let exclude = param_exclude_list(&params, "exclude")?;

            // Build masscan command
            let output_file = "/tmp/masscan-output.json";
            let mut builder = CommandBuilder::new()
                .positional(&target)
                .arg("-p", &ports)
                .arg("--rate", &rate.to_string())
                .arg("-oJ", output_file); // JSON output

            if let Some(exclude) = exclude {
                builder = builder.arg("--exclude", &exclude);
            }

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

#[cfg(test)]
mod tests {
    use super::*;

    // Tests for the --exclude wiring (issue #2524). execute() builds the command
    // inline; these replicate the exact `param_exclude_list` +
    // `CommandBuilder.arg("--exclude", ...)` composition it uses, so a wiring
    // regression (dropped flag, wrong join, emitted when empty) is caught.

    fn build_exclude_args(params: &Value) -> Vec<String> {
        let exclude = param_exclude_list(params, "exclude").expect("valid exclude");
        let mut builder = CommandBuilder::new()
            .positional("10.0.0.0/8")
            .arg("-p", "80");
        if let Some(exclude) = exclude {
            builder = builder.arg("--exclude", &exclude);
        }
        builder.build()
    }

    #[test]
    fn exclude_array_produces_exclude_flag() {
        let params = json!({"exclude": ["10.0.0.1"]});
        let args = build_exclude_args(&params);
        assert!(args.windows(2).any(|w| w == ["--exclude", "10.0.0.1"]));
    }

    #[test]
    fn absent_exclude_produces_no_flag() {
        let params = json!({"target": "10.0.0.0/8"});
        let args = build_exclude_args(&params);
        assert!(!args.iter().any(|a| a == "--exclude"));
    }

    #[test]
    fn empty_exclude_array_produces_no_flag() {
        let params = json!({"exclude": []});
        let args = build_exclude_args(&params);
        assert!(!args.iter().any(|a| a == "--exclude"));
    }
}
