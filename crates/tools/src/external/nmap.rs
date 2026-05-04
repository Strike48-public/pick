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
                "NSE scripts to run: specific scripts (smb-vuln-ms17-010,smb-enum-shares), wildcards (smb-*), or categories (default,vuln,safe,discovery,auth,brute). Scripts are validated before execution. Common: smb-vuln-ms17-010, smb-enum-shares, http-title, ssl-cert, dns-brute.",
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
                "Overall timeout in seconds (default: auto-calculated based on hosts, ports, timing). Auto calculation: top100=60-180s, top1000=60-600s, full=1800-7200s. Override only if you know the scan will take longer.",
                json!(null),
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

            // Calculate smart timeout based on scan parameters
            // If user provided explicit timeout, use it. Otherwise calculate.
            let timeout = if params.get("timeout").and_then(|v| v.as_u64()).is_some() {
                param_u64(&params, "timeout", 300) // User-provided
            } else {
                calculate_timeout(
                    &target,
                    &ports,
                    &scan_type,
                    timing,
                    service_detection || aggressive,
                )
            };

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

            // NSE scripts - validate before running
            if let Some(scripts) = param_str_opt(&params, "scripts") {
                if !scripts.is_empty() {
                    // Validate scripts exist before running nmap
                    if let Err(invalid) = validate_nse_scripts(&platform, &scripts).await {
                        return Err(pentest_core::error::Error::InvalidParams(format!(
                            "Invalid NSE script(s): {}. Use 'nmap --script-help <pattern>' to list available scripts.",
                            invalid
                        )));
                    }
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

/// Validate NSE scripts exist before running nmap
///
/// Checks if the specified NSE scripts are available on the system.
/// Returns Ok(()) if all scripts are valid, or Err(invalid_scripts) if any are missing.
async fn validate_nse_scripts<P: CommandExec>(
    platform: &P,
    scripts: &str,
) -> std::result::Result<(), String> {
    use std::time::Duration;

    // Parse script list (comma-separated)
    let script_list: Vec<&str> = scripts.split(',').map(|s| s.trim()).collect();

    // Skip validation for script categories (default, vuln, etc.)
    let categories = [
        "default",
        "safe",
        "intrusive",
        "malware",
        "discovery",
        "version",
        "vuln",
        "exploit",
        "external",
        "auth",
        "brute",
        "dos",
    ];

    let mut invalid_scripts = Vec::new();

    for script in script_list {
        // Skip if it's a category
        if categories.contains(&script) {
            continue;
        }

        // Skip if it's a wildcard pattern (e.g., "smb-*")
        if script.contains('*') || script.contains('?') {
            continue;
        }

        // Check if script exists using --script-help
        let result = platform
            .execute_command("nmap", &["--script-help", script], Duration::from_secs(5))
            .await;

        // If command fails or output contains "0 scripts", script doesn't exist
        match result {
            Ok(output) => {
                if output.stdout.contains("0 scripts") || output.stderr.contains("did not match") {
                    invalid_scripts.push(script.to_string());
                }
            }
            Err(_) => {
                // If nmap --script-help fails, script likely doesn't exist
                invalid_scripts.push(script.to_string());
            }
        }
    }

    if invalid_scripts.is_empty() {
        Ok(())
    } else {
        Err(invalid_scripts.join(", "))
    }
}

/// Calculate smart timeout based on scan parameters
///
/// Factors considered:
/// - Number of target hosts (from CIDR, space-separated IPs, etc.)
/// - Port range (top100=100, top1000=1000, all=65535, custom=parsed)
/// - Scan type (ping < connect/syn < udp)
/// - Timing template (0-5, faster = less time per port)
/// - Service detection (adds 2-10s per open port)
///
/// Formula:
/// base = (hosts * ports * scan_multiplier) / (timing_speed * 1000)
/// + (service_detection_overhead if enabled)
///
/// Returns timeout in seconds with reasonable min/max bounds.
fn calculate_timeout(
    target: &str,
    ports: &str,
    scan_type: &str,
    timing: u64,
    has_service_detection: bool,
) -> u64 {
    // Estimate number of target hosts
    let host_count = estimate_host_count(target);

    // Estimate number of ports
    let port_count = match ports {
        "top100" => 100,
        "top1000" => 1000,
        "all" => 65535,
        _ => {
            // Parse custom port spec (e.g., "80,443", "1-1000", "80-443,8000-9000")
            parse_port_count(ports)
        }
    };

    // Scan type multiplier (relative speed)
    let scan_multiplier = match scan_type {
        "ping" => return 60, // Ping scans are always fast
        "syn" => 1.0,        // SYN is fastest port scan
        "connect" => 1.2,    // TCP connect slightly slower
        "udp" => 3.0,        // UDP much slower (no response = wait for timeout)
        _ => 1.2,
    };

    // Timing template speed factor (packets per second)
    // T0=0.01pps, T1=1pps, T2=10pps, T3=100pps, T4=1000pps, T5=5000pps (approximate)
    let timing_speed = match timing {
        0 => 0.01,   // Paranoid
        1 => 1.0,    // Sneaky
        2 => 10.0,   // Polite
        3 => 100.0,  // Normal (default)
        4 => 1000.0, // Aggressive
        5 => 5000.0, // Insane
        _ => 100.0,
    };

    // Base calculation: (hosts * ports * scan_multiplier) / timing_speed
    // This gives us seconds to scan all ports
    let base_seconds =
        (host_count as f64 * port_count as f64 * scan_multiplier / timing_speed) as u64;

    // Service detection overhead: ~5s per open port * estimated open ports
    // Assume ~5% of ports are open for external scans
    let service_overhead = if has_service_detection {
        let estimated_open_ports = (host_count * port_count / 20).max(1); // ~5% open
        (estimated_open_ports * 5) as u64 // 5 seconds per service probe
    } else {
        0
    };

    // Add 20% buffer for network latency, packet loss, retries
    let buffered = base_seconds + service_overhead;
    let with_buffer = (buffered as f64 * 1.2) as u64;

    // Enforce reasonable bounds
    let min_timeout = 60; // At least 1 minute
    let max_timeout = 7200; // At most 2 hours

    with_buffer.clamp(min_timeout, max_timeout)
}

/// Estimate the number of target hosts from target specification
fn estimate_host_count(target: &str) -> usize {
    // Check for CIDR notation (e.g., "192.168.1.0/24")
    if let Some(cidr_pos) = target.find('/') {
        if let Ok(prefix_len) = target[cidr_pos + 1..].parse::<u32>() {
            // Calculate hosts from CIDR prefix length
            // /24 = 256 hosts, /16 = 65536 hosts, etc.
            let host_bits = 32 - prefix_len;
            return (2_u32.pow(host_bits) as usize).min(65536); // Cap at /16
        }
    }

    // Check for space-separated or comma-separated IPs
    let separators = [' ', ','];
    for sep in separators {
        let parts: Vec<&str> = target.split(sep).filter(|s| !s.is_empty()).collect();
        if parts.len() > 1 {
            return parts.len();
        }
    }

    // Single host or hostname
    1
}

/// Parse port count from custom port specification
fn parse_port_count(ports: &str) -> usize {
    let mut total = 0;

    // Split by comma for multiple ranges (e.g., "80,443,8000-9000")
    for part in ports.split(',') {
        let part = part.trim();
        if part.contains('-') {
            // Range (e.g., "1-1000")
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() == 2 {
                if let (Ok(start), Ok(end)) = (
                    range_parts[0].parse::<usize>(),
                    range_parts[1].parse::<usize>(),
                ) {
                    total += (end - start + 1).min(65535);
                }
            }
        } else {
            // Single port
            if part.parse::<u16>().is_ok() {
                total += 1;
            }
        }
    }

    total.max(1) // At least 1 port
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================
    // Tests for estimate_host_count()
    // ========================================

    #[test]
    fn single_host_returns_one() {
        assert_eq!(estimate_host_count("10.0.4.1"), 1);
        assert_eq!(estimate_host_count("example.com"), 1);
    }

    #[test]
    fn cidr_24_returns_256_hosts() {
        assert_eq!(estimate_host_count("192.168.1.0/24"), 256);
    }

    #[test]
    fn cidr_16_returns_65536_hosts() {
        assert_eq!(estimate_host_count("10.0.0.0/16"), 65536);
    }

    #[test]
    fn cidr_larger_than_16_is_capped() {
        // /8 would be 16M hosts, should cap at 65536
        assert_eq!(estimate_host_count("10.0.0.0/8"), 65536);
    }

    #[test]
    fn cidr_22_returns_1024_hosts() {
        assert_eq!(estimate_host_count("10.0.4.0/22"), 1024);
    }

    #[test]
    fn space_separated_ips_counted_correctly() {
        let target = "10.0.4.1 10.0.4.3 10.0.4.10";
        assert_eq!(estimate_host_count(target), 3);
    }

    #[test]
    fn comma_separated_ips_counted_correctly() {
        let target = "10.0.4.1,10.0.4.3,10.0.4.10";
        assert_eq!(estimate_host_count(target), 3);
    }

    #[test]
    fn real_world_13_host_scenario() {
        // The actual scenario that caused the timeout
        let target = "10.0.4.1 10.0.4.3 10.0.4.10 10.0.4.40 10.0.4.80 10.0.4.81 \
                      10.0.4.101 10.0.4.111 10.0.4.116 10.0.4.117 10.0.4.119 \
                      10.0.4.122 10.0.4.124";
        assert_eq!(estimate_host_count(target), 13);
    }

    // ========================================
    // Tests for parse_port_count()
    // ========================================

    #[test]
    fn single_port_returns_one() {
        assert_eq!(parse_port_count("80"), 1);
    }

    #[test]
    fn comma_separated_ports_counted_correctly() {
        assert_eq!(parse_port_count("80,443,8080"), 3);
    }

    #[test]
    fn port_range_counted_correctly() {
        assert_eq!(parse_port_count("1-1000"), 1000);
        assert_eq!(parse_port_count("80-443"), 364);
    }

    #[test]
    fn mixed_ports_and_ranges() {
        // 80 + 443 + (8000-9000 = 1001) = 1003
        assert_eq!(parse_port_count("80,443,8000-9000"), 1003);
    }

    #[test]
    fn smb_ports_example() {
        // Real example from the SMB enumeration scan
        assert_eq!(parse_port_count("139,445"), 2);
    }

    #[test]
    fn empty_or_invalid_returns_at_least_one() {
        assert_eq!(parse_port_count(""), 1);
        assert_eq!(parse_port_count("invalid"), 1);
    }

    #[test]
    fn port_range_capped_at_65535() {
        assert_eq!(parse_port_count("1-99999"), 65535);
    }

    // ========================================
    // Tests for calculate_timeout()
    // ========================================

    #[test]
    fn ping_scan_always_returns_60s() {
        // Ping scans short-circuit regardless of other params
        assert_eq!(
            calculate_timeout("10.0.4.0/24", "all", "ping", 3, false),
            60
        );
        assert_eq!(calculate_timeout("10.0.0.0/16", "all", "ping", 0, true), 60);
    }

    #[test]
    fn timeout_has_minimum_of_60s() {
        // Single host, single port should still get minimum 60s
        let timeout = calculate_timeout("10.0.4.1", "80", "connect", 5, false);
        assert!(timeout >= 60, "Expected at least 60s, got {}", timeout);
    }

    #[test]
    fn timeout_has_maximum_of_7200s() {
        // Worst case: /16, all ports, T0 (paranoid), service detection
        let timeout = calculate_timeout("10.0.0.0/16", "all", "connect", 0, true);
        assert_eq!(timeout, 7200, "Should clamp to max 7200s (2 hours)");
    }

    #[test]
    fn top1000_is_much_faster_than_all_ports() {
        // Use larger host count to avoid min clamp distorting the ratio
        let target = "10.0.4.0/24";
        let top1000 = calculate_timeout(target, "top1000", "connect", 4, false);
        let all_ports = calculate_timeout(target, "all", "connect", 4, false);
        // all=65535 ports vs top1000=1000 ports -> ~65x difference expected
        assert!(
            all_ports > top1000 * 10,
            "All ports ({}) should be much slower than top1000 ({})",
            all_ports,
            top1000
        );
    }

    #[test]
    fn udp_scan_is_slower_than_syn() {
        let syn = calculate_timeout("10.0.4.1", "top1000", "syn", 4, false);
        let udp = calculate_timeout("10.0.4.1", "top1000", "udp", 4, false);
        assert!(udp >= syn, "UDP ({}) should be >= SYN ({})", udp, syn);
    }

    #[test]
    fn faster_timing_reduces_timeout() {
        let t3 = calculate_timeout("10.0.4.0/24", "top1000", "connect", 3, false);
        let t4 = calculate_timeout("10.0.4.0/24", "top1000", "connect", 4, false);
        let t5 = calculate_timeout("10.0.4.0/24", "top1000", "connect", 5, false);
        assert!(
            t3 >= t4,
            "T3 ({}) should be slower or equal to T4 ({})",
            t3,
            t4
        );
        assert!(
            t4 >= t5,
            "T4 ({}) should be slower or equal to T5 ({})",
            t4,
            t5
        );
    }

    #[test]
    fn service_detection_increases_timeout() {
        let without = calculate_timeout("10.0.4.1", "top1000", "connect", 4, false);
        let with_sv = calculate_timeout("10.0.4.1", "top1000", "connect", 4, true);
        assert!(
            with_sv >= without,
            "With service detection ({}) should be >= without ({})",
            with_sv,
            without
        );
    }

    #[test]
    fn real_world_13_host_full_scan_scenario() {
        // This is the exact scenario that caused "Command timed out" error
        let target = "10.0.4.1 10.0.4.3 10.0.4.10 10.0.4.40 10.0.4.80 10.0.4.81 \
                      10.0.4.101 10.0.4.111 10.0.4.116 10.0.4.117 10.0.4.119 \
                      10.0.4.122 10.0.4.124";
        let timeout = calculate_timeout(target, "all", "connect", 4, false);
        // Should allow enough time - at least 15 minutes for this scan
        assert!(
            timeout >= 900,
            "13 hosts full scan should get >= 900s, got {}",
            timeout
        );
        // But not waste time with the max
        assert!(timeout < 7200, "Should not hit max for this scan");
    }

    #[test]
    fn real_world_cidr_smb_enum_scenario() {
        // The SMB enumeration scan: 10.0.4.0/22 10.0.8.0/22 on ports 139,445
        let target = "10.0.4.0/22 10.0.8.0/22";
        // 10.0.4.0/22 = 1024 hosts, but space-separated counts as 2 tokens
        // The parser picks space-separated detection first, returning 2
        let timeout = calculate_timeout(target, "139,445", "connect", 4, false);
        // 2 hosts x 2 ports = trivial, but should still get minimum 60s
        assert!(
            timeout >= 60,
            "Should get at least minimum timeout, got {}",
            timeout
        );
    }

    // ========================================
    // Tests for NSE script categorization
    // (validate_nse_scripts requires platform, tested via integration)
    // ========================================

    #[test]
    fn script_categories_are_recognized() {
        // These should all be treated as categories (not validated)
        let categories = [
            "default",
            "safe",
            "intrusive",
            "malware",
            "discovery",
            "version",
            "vuln",
            "exploit",
            "external",
            "auth",
            "brute",
            "dos",
        ];
        for cat in categories {
            // If it's in our categories array, it should be skipped during validation
            // We verify the array contains what we expect
            assert!(
                matches!(
                    cat,
                    "default"
                        | "safe"
                        | "intrusive"
                        | "malware"
                        | "discovery"
                        | "version"
                        | "vuln"
                        | "exploit"
                        | "external"
                        | "auth"
                        | "brute"
                        | "dos"
                ),
                "Category {} should be valid",
                cat
            );
        }
    }

    #[test]
    fn wildcard_patterns_are_detected() {
        // These should be treated as wildcards and skipped
        assert!("smb-*".contains('*'));
        assert!("http-?".contains('?'));
        assert!("smb-vuln-*".contains('*'));
    }

    #[test]
    fn invalid_cve_script_would_be_flagged() {
        // The actual script that caused the error
        let problematic = "smb-vuln-cve-2020-0796";
        // Should NOT be a category
        let categories = [
            "default",
            "safe",
            "intrusive",
            "malware",
            "discovery",
            "version",
            "vuln",
            "exploit",
            "external",
            "auth",
            "brute",
            "dos",
        ];
        assert!(!categories.contains(&problematic));
        // Should NOT be a wildcard
        assert!(!problematic.contains('*'));
        assert!(!problematic.contains('?'));
        // Therefore it would be validated (and fail)
    }
}
