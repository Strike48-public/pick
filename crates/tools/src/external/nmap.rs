//! Nmap - Network exploration and security auditing tool
//!
//! Nmap is the industry-standard network scanning tool with comprehensive
//! features for host discovery, port scanning, version detection, and OS fingerprinting.

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use super::install::ensure_tool_installed;
use super::runner::{param_str_opt, param_str_or, CommandBuilder};
use crate::util::{param_bool, param_u64};

/// Nmap network scanner tool
pub struct NmapTool;

#[async_trait]
impl PentestTool for NmapTool {
    fn name(&self) -> &str {
        "nmap"
    }

    fn description(&self) -> &str {
        "Industry-standard network scanner for host discovery, port scanning, version detection, and OS fingerprinting. STRATEGY: Start with top1000 ports (fast), then target full scans on interesting hosts only. Full port scans (-p-) across many hosts are very slow (15-30+ minutes)."
    }

    fn schema(&self) -> ToolSchema {
        use pentest_core::tools::ExternalDependency;

        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "nmap",
                "nmap",
                "Network Mapper - Security scanner for network exploration"
            ))
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target IP, hostname, or CIDR range (e.g., '192.168.1.0/24', 'example.com')",
            ))
            .param(ToolParam::optional(
                "scan_type",
                ParamType::String,
                "Scan type: 'connect' (TCP), 'syn' (SYN stealth), 'udp', 'ping' (host discovery only)",
                json!("connect"),
            ))
            .param(ToolParam::optional(
                "ports",
                ParamType::String,
                "Port specification: '80', '1-1000', 'top100', or 'all' (default: top 1000)",
                json!("top1000"),
            ))
            .param(ToolParam::optional(
                "service_detection",
                ParamType::Boolean,
                "Enable service version detection (-sV)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "os_detection",
                ParamType::Boolean,
                "Enable OS detection (-O, requires root)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "aggressive",
                ParamType::Boolean,
                "Enable aggressive scan (-A: OS, version, script, traceroute)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "timing",
                ParamType::Integer,
                "Timing template: 0 (paranoid) to 5 (insane), default 3 (normal)",
                json!(3),
            ))
            .param(ToolParam::optional(
                "scripts",
                ParamType::String,
                "NSE scripts to run (comma-separated or 'default', 'vuln', etc.)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "no_ping",
                ParamType::Boolean,
                "Skip host discovery (-Pn, treat all hosts as online)",
                json!(false),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Overall timeout in seconds (default: 1800). Full port scans (-p-) across multiple hosts require 1800-3600s. Top1000 scans typically complete in 60-300s.",
                json!(1800),
            ))
            .platforms(vec![Platform::Desktop, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let platform = get_platform();

            // Ensure nmap is installed
            ensure_tool_installed(&platform, "nmap", "nmap").await?;

            // Extract parameters
            let target = param_str_or(&params, "target", "");
            if target.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "target parameter is required".into(),
                ));
            }

            let scan_type = param_str_or(&params, "scan_type", "connect");
            let ports = param_str_or(&params, "ports", "top1000");
            let service_detection = param_bool(&params, "service_detection", false);
            let os_detection = param_bool(&params, "os_detection", false);
            let aggressive = param_bool(&params, "aggressive", false);
            let timing = param_u64(&params, "timing", 3).clamp(0, 5);
            let no_ping = param_bool(&params, "no_ping", false);
            let timeout = param_u64(&params, "timeout", 1800);

            // Build nmap command
            let mut builder = CommandBuilder::new();

            // Scan type
            match scan_type.as_str() {
                "syn" => builder = builder.flag("-sS"), // SYN stealth scan (requires root)
                "connect" => builder = builder.flag("-sT"), // TCP connect scan
                "udp" => builder = builder.flag("-sU"), // UDP scan
                "ping" => builder = builder.flag("-sn"), // Ping scan only
                _ => {
                    return Err(pentest_core::error::Error::InvalidParams(format!(
                        "Invalid scan_type: {}",
                        scan_type
                    )))
                }
            }

            // Port specification (skip for ping scan)
            if scan_type != "ping" {
                match ports.as_str() {
                    "top100" => builder = builder.arg("--top-ports", "100"),
                    "top1000" => {} // Default, no flag needed
                    "all" => builder = builder.flag("-p-"),
                    _ => builder = builder.arg("-p", &ports),
                }
            }

            // Service/OS detection
            if aggressive {
                builder = builder.flag("-A"); // Enable everything
            } else {
                if service_detection {
                    builder = builder.flag("-sV");
                }
                if os_detection {
                    builder = builder.flag("-O");
                }
            }

            // Timing template
            builder = builder.arg("-T", &timing.to_string());

            // Host discovery
            if no_ping {
                builder = builder.flag("-Pn");
            }

            // NSE scripts
            if let Some(scripts) = param_str_opt(&params, "scripts") {
                if !scripts.is_empty() {
                    builder = builder.arg("--script", &scripts);
                }
            }

            // Output format: XML for parsing
            let output_file = "/tmp/nmap-output.xml";
            builder = builder.arg("-oX", output_file);

            // Add target
            builder = builder.positional(&target);

            let args = builder.build();
            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute nmap
            let result = platform
                .execute_command("nmap", &args_refs, Duration::from_secs(timeout))
                .await?;

            // Read XML output
            let xml_output = super::runner::read_sandbox_file(&platform, output_file).await?;

            // Parse nmap XML output
            parse_nmap_xml(&xml_output, &result.stderr)
        })
        .await
    }
}

/// Parse nmap XML output into structured JSON
fn parse_nmap_xml(xml: &str, stderr: &str) -> Result<Value> {
    // For Phase 1, we'll do simple regex-based parsing
    // TODO: Add proper XML parsing with quick-xml crate in Phase 2

    let mut hosts = Vec::new();

    // Extract host blocks with regex
    let host_re = regex::Regex::new(r#"<host\s+[^>]*>(.*?)</host>"#).unwrap();

    for host_match in host_re.captures_iter(xml) {
        if let Some(host_xml) = host_match.get(1) {
            let host_data = parse_host_xml(host_xml.as_str());
            hosts.push(host_data);
        }
    }

    Ok(json!({
        "hosts": hosts,
        "count": hosts.len(),
        "summary": format!("Scanned {} host(s)", hosts.len()),
        "stderr": stderr,
        "raw_xml": xml, // Include raw XML for advanced parsing
    }))
}

/// Parse a single host block from nmap XML
fn parse_host_xml(xml: &str) -> Value {
    // Extract IP address
    let ip = extract_xml_attribute(xml, r#"<address\s+addr="([^"]+)"\s+addrtype="ipv4""#)
        .unwrap_or_else(|| "unknown".to_string());

    // Extract hostname
    let hostname = extract_xml_attribute(xml, r#"<hostname\s+name="([^"]+)""#).unwrap_or_default();

    // Extract state (up/down)
    let state = extract_xml_attribute(xml, r#"<status\s+state="([^"]+)""#)
        .unwrap_or_else(|| "unknown".to_string());

    // Extract open ports
    let mut ports = Vec::new();
    let port_re =
        regex::Regex::new(r#"<port\s+protocol="([^"]+)"\s+portid="([^"]+)"[^>]*>(.*?)</port>"#)
            .unwrap();

    for port_match in port_re.captures_iter(xml) {
        let protocol = port_match.get(1).map(|m| m.as_str()).unwrap_or("");
        let portid = port_match.get(2).map(|m| m.as_str()).unwrap_or("");
        let port_xml = port_match.get(3).map(|m| m.as_str()).unwrap_or("");

        let port_state = extract_xml_attribute(port_xml, r#"<state\s+state="([^"]+)""#)
            .unwrap_or_else(|| "unknown".to_string());

        // Only include open ports
        if port_state == "open" {
            let service =
                extract_xml_attribute(port_xml, r#"<service\s+name="([^"]+)""#).unwrap_or_default();
            let version = extract_xml_attribute(port_xml, r#"<service\s+[^>]*product="([^"]+)""#)
                .unwrap_or_default();

            ports.push(json!({
                "protocol": protocol,
                "port": portid.parse::<u16>().unwrap_or(0),
                "state": port_state,
                "service": service,
                "version": version,
            }));
        }
    }

    json!({
        "ip": ip,
        "hostname": hostname,
        "state": state,
        "ports": ports,
        "port_count": ports.len(),
    })
}

/// Extract an attribute value from XML using regex
fn extract_xml_attribute(xml: &str, pattern: &str) -> Option<String> {
    regex::Regex::new(pattern)
        .ok()?
        .captures(xml)?
        .get(1)
        .map(|m| m.as_str().to_string())
}
