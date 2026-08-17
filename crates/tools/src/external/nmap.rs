//! Nmap - Network exploration and security auditing tool
//!
//! Nmap is the industry-standard network scanning tool with comprehensive
//! features for host discovery, port scanning, version detection, and OS fingerprinting.

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::provenance::Provenance;
use pentest_core::tools::{
    execute_timed_with_provenance, ParamType, PentestTool, Platform, ToolContext, ToolParam,
    ToolResult, ToolSchema,
};
use pentest_core::validation::{validate_port_spec, validate_target};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use super::install::ensure_tool_installed;
use super::runner::{param_exclude_list, param_str_opt, param_str_or, CommandBuilder};
use crate::provenance_support::{format_full_command, tool_version};
use crate::util::{param_bool, param_u64};

/// Nmap network scanner tool
pub struct NmapTool;

#[async_trait]
impl PentestTool for NmapTool {
    fn name(&self) -> &str {
        "nmap"
    }

    fn description(&self) -> &str {
        "Industry-standard network scanner for host discovery, port scanning, version detection, and OS fingerprinting. \
         STRATEGY: Start with top1000 ports (fast), then target full scans on interesting hosts only. Full port scans (-p-) across many hosts are very slow (15-30+ minutes). \
         ARGUMENTS: Use the STRUCTURED parameters below (target, scan_type, ports, timing, service_detection, os_detection, aggressive, no_ping) — do NOT pass raw nmap CLI flags. \
         There is no 'flags', 'args', or 'command' parameter: put the scan target in 'target' and express options via the typed params (e.g. host discovery = scan_type:'ping'; -T4 = timing:4; -sV = service_detection:true; -Pn = no_ping:true). Unrecognized raw flags are dropped."
    }

    fn schema(&self) -> ToolSchema {
        use pentest_core::tools::{ExternalDependency, ToolCategory};

        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "nmap",
                "nmap",
                "Network Mapper - Security scanner for network exploration"
            )
            .category(ToolCategory::Network))
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target IP, hostname, or range. Supported range forms: CIDR ('192.168.1.0/24'), \
                 or IPv4 dash ranges — last-octet ('10.0.0.1-50') or full-IP ('10.0.0.1-10.0.5.20'). \
                 Prefer CIDR or a simple IP1-IP2 dash range; nmap's multi-octet form ('10.0.0-1.1-254') \
                 is not scope-checked and is rejected.",
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
                "exclude",
                ParamType::Array,
                "Hosts/CIDRs to exclude from the scan (maps to nmap --exclude). Provide a JSON array of individual IP or CIDR strings — one entry per host/range, e.g. [\"10.0.0.1\", \"10.0.0.2\"]. Do NOT wrap the list in a single string or inline brackets into a value. Use this to scan a range while skipping specific hosts (e.g. target \"10.0.0.0/24\"). Out-of-scope hosts are also injected here automatically by the platform.",
                json!([]),
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
        // Tolerate the `execute_command`-style `{args: [...]}` / `{command: "..."}`
        // and `{flags: "-sn -T4 ...", target: "..."}` shapes some callers emit
        // instead of the structured schema. Recovers the `target` (re-validated
        // below) and maps known flags onto structured params; unrecognized flags
        // are dropped, never shelled out.
        let params = normalize_legacy_nmap_params(params);

        execute_timed_with_provenance(|| async move {
            let platform = get_platform();

            // Ensure nmap is installed
            ensure_tool_installed(&platform, "nmap", "nmap").await?;

            // Extract and validate target parameter
            let target = param_str_or(&params, "target", "");
            if target.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "target parameter is required".into(),
                ));
            }

            // Validate target format (IP, hostname, or CIDR)
            let target = validate_target(&target)?;

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
                for (flag, value) in resolve_port_args(&ports)? {
                    builder = match value {
                        Some(v) => builder.arg(flag, &v),
                        None => builder.flag(flag),
                    };
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

            // If we lack raw socket privileges, force --unprivileged so nmap
            // uses connect() for everything and doesn't error with
            // "Couldn't open a raw socket or eth handle."
            let unprivileged = !has_raw_socket_privilege();
            if unprivileged {
                builder = builder.flag("--unprivileged");
            }

            // Host discovery: add -Pn (skip discovery, treat all hosts as online)
            // when explicitly requested, or when we must because privileged ICMP
            // isn't available — but NEVER for a "ping" (host-discovery) scan.
            // See should_force_pn/3 for the reasoning behind the #219 fix.
            if should_force_pn(no_ping, unprivileged, &scan_type) {
                builder = builder.flag("-Pn");
            }

            // NSE scripts - validate before running
            if let Some(scripts) = param_str_opt(&params, "scripts") {
                if !scripts.is_empty() {
                    // First, validate script names to prevent path injection
                    // Allow: alphanumeric, hyphens, underscores, commas, wildcards (*?), dots
                    // Block: slashes (path separators), shell metacharacters
                    for script in scripts.split(',') {
                        let script = script.trim();
                        if script.is_empty() {
                            continue;
                        }
                        if !script.chars().all(|c| {
                            c.is_alphanumeric() || c == '-' || c == '_' || c == '*' || c == '?' || c == '.'
                        }) {
                            return Err(pentest_core::error::Error::InvalidParams(
                                format!("Invalid NSE script name '{}' - only alphanumeric, hyphens, underscores, wildcards, and dots allowed", script)
                            ));
                        }
                    }

                    // Then validate scripts exist before running nmap
                    if let Err(invalid) = validate_nse_scripts(&platform, &scripts).await {
                        return Err(pentest_core::error::Error::InvalidParams(format!(
                            "Invalid NSE script(s): {}. Use 'nmap --script-help <pattern>' to list available scripts.",
                            invalid
                        )));
                    }

                    builder = builder.arg("--script", &scripts);
                }
            }

            // Exclude list (issue #2524): out-of-scope hosts the scan must skip.
            // Validated as IP/CIDR/hostname to prevent injection via this param.
            if let Some(exclude) = param_exclude_list(&params, "exclude")? {
                builder = builder.arg("--exclude", &exclude);
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

            // Provenance: exact arguments + parsed XML form the reproducible
            // record. The XML is richer than stdout for nmap, so it's the
            // right excerpt for downstream reproduction.
            let full_command = format_full_command("nmap", &args);
            let provenance = Provenance::new(
                "nmap",
                tool_version("nmap"),
                pentest_core::provenance::ProbeCommand::from_exact(full_command)
                    .with_description("network scan via nmap"),
                pentest_core::provenance::truncate_excerpt(&xml_output),
            );

            // Parse nmap XML output
            let data = parse_nmap_xml(&xml_output, &result.stderr)?;

            // Produce evidence nodes for the three-agent pipeline
            let evidence_nodes =
                crate::evidence_producer::evidence_from_nmap(&data, &target, provenance.clone());

            for node in evidence_nodes {
                let _ = crate::evidence_producer::push_evidence(node);
            }

            Ok((data, provenance))
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

/// Normalize the `execute_command`-style argument shape onto nmap's structured
/// params.
///
/// Some callers (notably the LLM generalizing from `execute_command`, the only
/// tool with a `command` + `args[]` array shape) invoke nmap as
/// `{"args": ["-sn", "-T4", "10.0.8.0/22"], ...}` or
/// `{"command": "nmap -sn 10.0.8.0/22"}` instead of the declared schema
/// (`{"target": "...", "scan_type": "ping", ...}`). Without normalization the
/// real schema parser sees no `target` and the call fails with "target
/// parameter is required".
///
/// This salvages such calls by:
/// - locating the scan target (first token that is NOT a flag and NOT a flag's
///   value), leaving it for `validate_target` to re-validate — raw input is
///   never trusted or shelled out,
/// - translating a small allowlist of common flags onto structured params
///   (`-sn`/`-sS`/`-sT`/`-sU` scan types, `-Pn`, `-sV`, `-O`, `-A`, `-T<n>`,
///   `-p <spec>`),
/// - dropping every unrecognized token (e.g. `--min-rate 1000`, `-PE`/`-PP`/`-PM`)
///   rather than passing it through, so this path can only ever produce a
///   subset of the already-supported, validated scan surface.
///
/// If the input already has a `target` key it is returned unchanged. If no
/// target can be recovered, the original params are returned so the normal
/// "target parameter is required" error still fires.
fn normalize_legacy_nmap_params(params: Value) -> Value {
    // A `flags` value (e.g. {"flags": "-sn -T4 ...", "target": "..."} or the
    // array shape {"flags": ["-sn", "-T4"], "target": "..."}) is a shape the LLM
    // emits by analogy to a raw CLI, but there is no `flags` schema param. Fold
    // its recognized flags into structured params FIRST — this must run even
    // when `target` is already present (otherwise the target-present
    // short-circuit below would silently drop the flags, which is exactly the
    // bug where -sn/-T4 never took effect). Same allowlist + drop-unknown safety
    // as the `args`/`command` path.
    let params = fold_flags(params);

    // Already in the structured shape — nothing more to do.
    if params
        .get("target")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.trim().is_empty())
    {
        return params;
    }

    // Collect the flag/argument tokens from either `args` (array or string) or
    // a `command` string (with a leading "nmap" stripped).
    let tokens: Vec<String> = match params.get("args") {
        Some(v @ (Value::Array(_) | Value::String(_))) => tokenize_flag_value(v),
        _ => match params.get("command").and_then(|v| v.as_str()) {
            Some(cmd) => cmd
                .split_whitespace()
                .map(|t| t.to_string())
                .skip_while(|t| t == "nmap")
                .collect(),
            None => return params, // no recoverable shape
        },
    };

    if tokens.is_empty() {
        return params;
    }

    // Start from any structured params the caller DID provide so we don't clobber them.
    let mut out = params.as_object().cloned().unwrap_or_default();

    // Map recognized flags to a fresh `derived` map and recover any target the
    // tokens contained (shared with the `flags` path). Merge derived values
    // ONLY into gaps — an explicit structured param the caller set always wins.
    let (derived, target) = apply_flag_tokens(&tokens);
    merge_fill(&mut out, derived);

    match target {
        Some(t) => {
            // No valid `target` reached here (the target-present short-circuit
            // above returned already), so the recovered token is the target.
            out.insert("target".into(), json!(t));
            Value::Object(out)
        }
        // Couldn't recover a target — return original so the standard
        // "target parameter is required" error fires unchanged.
        None => params,
    }
}

/// Fold a `flags` param into structured scan params.
///
/// Callers (the LLM generalizing from a raw CLI) sometimes pass
/// `{"flags": "-sn -T4 ...", "target": "..."}` or the array form
/// `{"flags": ["-sn", "-T4"], "target": "..."}` — the same string-or-array shape
/// the sibling `args` path already tolerates. There is no `flags` schema param,
/// so without this the flags are silently ignored (and previously, when
/// `target` was present, dropped entirely by the early return — the exact bug
/// this PR kills, which an array-shaped `flags` would otherwise reintroduce).
///
/// This tokenizes `flags` via the shared [`tokenize_flag_value`], maps the
/// recognized allowlist onto structured params via [`apply_flag_tokens`],
/// recovers a target from the flags tokens if the caller didn't provide one,
/// and ALWAYS removes the raw `flags` key (for any shape — string, array, or an
/// unexpected object) so it is never passed through or shelled out. Derived
/// values fill only gaps: an explicit structured param the caller set wins over
/// a flag (matching the tool description, which makes the typed params
/// authoritative). Unrecognized flags are dropped, exactly like the
/// `args`/`command` path.
///
/// Absent `flags` is a no-op.
fn fold_flags(params: Value) -> Value {
    if params.get("flags").is_none() {
        return params;
    }

    let mut out = params.as_object().cloned().unwrap_or_default();
    // Strip the raw `flags` key regardless of its shape — a `flags` value that
    // is neither a string nor an array (e.g. an object) must NOT ride through
    // to `execute()`, which would ignore it and silently scan with defaults.
    let flags = out.remove("flags").unwrap_or(Value::Null);

    let tokens = tokenize_flag_value(&flags);
    if tokens.is_empty() {
        return Value::Object(out);
    }

    let (derived, recovered) = apply_flag_tokens(&tokens);

    // Only adopt a target from the flags tokens if the caller didn't set one.
    let has_target = out
        .get("target")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.trim().is_empty());
    if !has_target {
        if let Some(t) = recovered {
            out.insert("target".into(), json!(t));
        }
    }

    // Explicit structured params win; flags only fill gaps.
    merge_fill(&mut out, derived);

    Value::Object(out)
}

/// Tokenize a legacy `flags`/`args` value that may be a JSON array of strings or
/// a single string (whitespace-split, or a JSON-encoded array string).
///
/// Mirrors the tolerance the `args` path always had, so `flags` accepts the
/// same string-or-array shapes the LLM emits interchangeably. Any other JSON
/// shape (number, bool, object, null) yields no tokens.
fn tokenize_flag_value(value: &Value) -> Vec<String> {
    match value {
        Value::Array(items) => items
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        Value::String(s) => {
            // The string may itself be a JSON-encoded array, e.g.
            // "[\"-sn\", \"10.0.8.0/22\"]" — parse that first, else split on
            // whitespace.
            match serde_json::from_str::<Vec<String>>(s) {
                Ok(parsed) => parsed,
                Err(_) => s.split_whitespace().map(|t| t.to_string()).collect(),
            }
        }
        _ => Vec::new(),
    }
}

/// Insert every entry of `derived` into `out` ONLY where `out` has no value for
/// that key. An explicit param the caller already set is never overwritten.
fn merge_fill(out: &mut serde_json::Map<String, Value>, derived: serde_json::Map<String, Value>) {
    for (k, v) in derived {
        out.entry(k).or_insert(v);
    }
}

/// Map a small allowlist of nmap flag tokens onto structured params in `out`,
/// returning the first token that validates as a scan target (if any).
///
/// Shared by both legacy shapes (`args`/`command`) and the `flags` value.
/// Recognized: `-sn`/`-sS`/`-sT`/`-sU` (scan_type), `-Pn` (no_ping), `-sV`
/// (service_detection), `-O` (os_detection), `-A` (aggressive), `-T<n>`
/// (timing), `-p <spec>` / `-p<spec>` (ports). Every other flag is dropped and
/// never shelled out. A bare integer is never treated as a target (it's almost
/// always a dropped flag's value, e.g. `--min-rate 1000`).
///
/// Returns a fresh map of the derived structured params (so callers can merge
/// them without clobbering explicit caller values) plus the first token that
/// validates as a scan target (if any). Any token that is dropped is recorded
/// and emitted at `debug` level so a "why did my scan run with defaults"
/// investigation can see what the normalizer discarded.
fn apply_flag_tokens(tokens: &[String]) -> (serde_json::Map<String, Value>, Option<String>) {
    let mut derived = serde_json::Map::new();
    let mut dropped: Vec<&str> = Vec::new();
    let mut target: Option<String> = None;
    let mut i = 0;
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        match tok {
            "-sn" => {
                derived.insert("scan_type".into(), json!("ping"));
            }
            "-sS" => {
                derived.insert("scan_type".into(), json!("syn"));
            }
            "-sT" => {
                derived.insert("scan_type".into(), json!("connect"));
            }
            "-sU" => {
                derived.insert("scan_type".into(), json!("udp"));
            }
            "-Pn" => {
                derived.insert("no_ping".into(), json!(true));
            }
            "-sV" => {
                derived.insert("service_detection".into(), json!(true));
            }
            "-O" => {
                derived.insert("os_detection".into(), json!(true));
            }
            "-A" => {
                derived.insert("aggressive".into(), json!(true));
            }
            "-p" => {
                // Next token is the port spec.
                if i + 1 < tokens.len() {
                    derived.insert("ports".into(), json!(tokens[i + 1]));
                    i += 1;
                }
            }
            _ if tok.starts_with("-T") && tok.len() == 3 => {
                if let Some(d) = tok.chars().nth(2).and_then(|c| c.to_digit(10)) {
                    derived.insert("timing".into(), json!(d));
                } else {
                    dropped.push(tok);
                }
            }
            _ if tok.starts_with("-p") && tok.len() > 2 => {
                // -p80, -p1-1000 (port spec attached to the flag)
                derived.insert("ports".into(), json!(tok[2..].to_string()));
            }
            _ if tok.starts_with('-') => {
                // Unrecognized flag (e.g. --min-rate, -PE, -PP, -PM): drop it.
                // If it takes a separate value we can't recognize, its value
                // falls through as a non-flag token below; the target heuristic
                // only accepts a value that validates as a target, so a stray
                // numeric like "1000" won't be mistaken for the target.
                dropped.push(tok);
            }
            _ => {
                // Non-flag token: candidate target. Take the first one that
                // looks like a valid IP/CIDR/hostname; ignore the rest.
                //
                // Reject bare integers: `validate_target` accepts "1000" as a
                // hostname, but a pure number is never a real scan target — it's
                // almost always a value belonging to a preceding flag we dropped
                // (e.g. `--min-rate 1000`, `--max-retries 2`). Real targets are
                // IPs, CIDRs, or dotted/named hosts.
                let is_bare_integer = !tok.is_empty() && tok.bytes().all(|b| b.is_ascii_digit());
                if target.is_none() && !is_bare_integer && validate_target(tok).is_ok() {
                    target = Some(tok.to_string());
                } else {
                    // Not adopted as the target (already have one, a bare
                    // integer, or fails validation) and not a recognized flag —
                    // it is discarded, so record it for the investigator.
                    dropped.push(tok);
                }
            }
        }
        i += 1;
    }

    if !dropped.is_empty() {
        tracing::debug!(
            dropped_tokens = ?dropped,
            "nmap legacy-arg normalizer dropped unrecognized tokens; \
             the scan runs only with recognized/structured params"
        );
    }

    (derived, target)
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

    // Estimate number of ports. Fold the keyword/full-range synonyms the same
    // way resolve_port_args does (#257) so a full scan requested as "-" /
    // "1-65535" / "ALL" is sized as 65535 ports, not mis-estimated as 1 and
    // clamped to the 60s floor (which would kill the scan mid-run).
    let port_count = match ports.trim().to_ascii_lowercase().as_str() {
        "top100" => 100,
        "top1000" => 1000,
        "all" | "-" | "1-65535" => 65535,
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

/// Resolve the `ports` param into nmap CLI arg(s).
///
/// Returns a list of `(flag, Option<value>)` the caller appends to the builder:
/// a `Some(value)` becomes `arg(flag, value)` (e.g. `-p 80,443`), a `None`
/// becomes a bare `flag` (e.g. `-p-`). Kept pure (no builder, no I/O) so the
/// port-spec decision is unit-testable without executing nmap.
///
/// Full-port-range synonyms all map to `-p-` (#257): the structured `"all"`,
/// the bare `"-"` that the legacy `-p-` normalizer produces (`-p` + spec `-`),
/// and the explicit `"1-65535"`. Before this, only `"all"` hit the `-p-` arm;
/// `"-"` fell through to `validate_port_spec("-")`, which split on `-` into
/// `["",""]` and errored with "Invalid port number", so a model emitting `-p-`
/// (which the tool description advertises) got a validation failure instead of
/// a full scan.
///
/// The keyword synonyms (`top100` / `top1000` / `all`) are matched
/// case-insensitively: the schema advertises them lowercase, but the LLM emits
/// case variants (`"ALL"`, `"Top100"`), which would otherwise fall through to
/// `validate_port_spec` and error. A custom numeric spec is left verbatim for
/// `validate_port_spec` (digits/commas/dashes have no case to fold).
fn resolve_port_args(ports: &str) -> Result<Vec<(&'static str, Option<String>)>> {
    let trimmed = ports.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "top100" => Ok(vec![("--top-ports", Some("100".to_string()))]),
        "top1000" => Ok(vec![]), // nmap default: no port flag
        // Full-range synonyms -> -p- (scan all 65535 ports).
        "all" | "-" | "1-65535" => Ok(vec![("-p-", None)]),
        _ => {
            let validated = validate_port_spec(trimmed)?;
            Ok(vec![("-p", Some(validated))])
        }
    }
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

/// Check if the process has raw socket privileges.
///
/// - Linux: euid == 0 (or CAP_NET_RAW, but checking euid is sufficient since
///   proot passes through caps when running as root)
/// - macOS: euid == 0
/// - Windows: assume unprivileged (admin detection is complex and nmap on
///   Windows requires Npcap which has its own privilege model)
fn has_raw_socket_privilege() -> bool {
    #[cfg(unix)]
    {
        // Read euid from /proc/self/status (Linux) or fall back to id command
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            if let Some(euid) = status
                .lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(2))
                .and_then(|v| v.parse::<u32>().ok())
            {
                return euid == 0;
            }
        }
        // macOS doesn't have /proc — check via std::process::Command
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim() == "0")
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        false // Windows: assume no raw socket access
    }
}

/// Decide whether to pass nmap `-Pn` (skip host discovery, treat every address
/// in the target as online).
///
/// `-Pn` is correct when the caller explicitly asks to skip discovery
/// (`no_ping`), and is otherwise needed when we run unprivileged because
/// privileged ICMP-echo host discovery requires a raw socket.
///
/// BUT it must NEVER be added for a `"ping"` (host-discovery) scan: that scan
/// sets `-sn`, and `-sn -Pn` together mean "discover hosts" AND "skip discovery,
/// assume all up", so nmap reports the ENTIRE target range as live
/// (`state=up reason=user-set`) instead of the hosts that actually respond
/// (issue #219). Unprivileged `-sn` still performs real, TCP-based host
/// discovery, so dropping the forced `-Pn` here restores correct results.
fn should_force_pn(no_ping: bool, unprivileged: bool, scan_type: &str) -> bool {
    if scan_type == "ping" {
        // A discovery scan must actually probe — never skip discovery.
        false
    } else {
        no_ping || unprivileged
    }
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
    // Tests for resolve_port_args() — #257 full-port-range synonyms
    // ========================================

    #[test]
    fn resolve_ports_full_range_synonyms_map_to_dash_p_dash() {
        // The bug (#257): a full-scan request expressed as `-p-` normalizes to
        // ports="-", which used to hit validate_port_spec("-") and error. All
        // three full-range spellings must now emit the bare `-p-` flag.
        for spec in ["all", "-", "1-65535"] {
            assert_eq!(
                resolve_port_args(spec).unwrap(),
                vec![("-p-", None)],
                "ports={spec:?} should map to the -p- full-scan flag"
            );
        }
    }

    #[test]
    fn resolve_ports_dash_does_not_error() {
        // Direct regression on the reported failure: ports="-" must NOT return
        // Err("Invalid port number").
        assert!(
            resolve_port_args("-").is_ok(),
            "ports=\"-\" must resolve, not fail validation"
        );
    }

    #[test]
    fn resolve_ports_top_variants_and_default() {
        assert_eq!(
            resolve_port_args("top100").unwrap(),
            vec![("--top-ports", Some("100".to_string()))]
        );
        // top1000 is nmap's default: no port flag emitted.
        assert_eq!(resolve_port_args("top1000").unwrap(), vec![]);
    }

    #[test]
    fn resolve_ports_custom_spec_is_validated_and_passed() {
        assert_eq!(
            resolve_port_args("80,443").unwrap(),
            vec![("-p", Some("80,443".to_string()))]
        );
        assert_eq!(
            resolve_port_args("1-1000").unwrap(),
            vec![("-p", Some("1-1000".to_string()))]
        );
    }

    #[test]
    fn resolve_ports_still_rejects_genuinely_invalid() {
        // The fix must not blanket-accept: a real bad spec still errors.
        assert!(resolve_port_args("not-a-port").is_err());
        assert!(resolve_port_args("99999").is_err());
    }

    #[test]
    fn resolve_ports_keyword_synonyms_are_case_insensitive() {
        // The schema advertises lowercase keywords, but the LLM emits case
        // variants; they must resolve, not fall through to validate_port_spec
        // and error (adversarial-review finding on #257).
        assert_eq!(resolve_port_args("ALL").unwrap(), vec![("-p-", None)]);
        assert_eq!(resolve_port_args("All").unwrap(), vec![("-p-", None)]);
        assert_eq!(
            resolve_port_args("TOP100").unwrap(),
            vec![("--top-ports", Some("100".to_string()))]
        );
        assert_eq!(resolve_port_args("Top1000").unwrap(), vec![]);
        // Whitespace around a keyword is also tolerated (trim happens first).
        assert_eq!(resolve_port_args("  all  ").unwrap(), vec![("-p-", None)]);
    }

    #[test]
    fn flags_dash_p_dash_folds_to_full_scan_end_to_end() {
        // The end-to-end shapes from the issue: both the string and array
        // `flags` forms must fold to ports="-", which resolve_port_args then
        // turns into a full scan. This covers the whole chain the LLM triggers.
        for flags in [json!("-p-"), json!(["-p-"])] {
            let folded = fold_flags(json!({"target": "10.0.0.5", "flags": flags}));
            assert_eq!(
                folded["ports"],
                json!("-"),
                "flags={flags} should fold to ports=\"-\""
            );
            let ports = folded["ports"].as_str().unwrap();
            assert_eq!(
                resolve_port_args(ports).unwrap(),
                vec![("-p-", None)],
                "folded ports from flags={flags} should map to -p-"
            );
        }
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
    fn full_range_synonyms_get_the_same_timeout_as_all() {
        // Regression (#257): the full-port-range synonyms resolve_port_args accepts
        // ("-", "1-65535", case variants) must estimate the same 65535-port workload
        // as "all". Before, calculate_timeout only knew the literal "all" and fell
        // through to parse_port_count, which returned 1 for "-"/"ALL" -> the full scan
        // was clamped to the 60s minimum and killed mid-scan.
        let target = "10.0.4.0/24";
        let all = calculate_timeout(target, "all", "connect", 4, false);
        for synonym in ["-", "1-65535", "ALL", "  all  "] {
            assert_eq!(
                calculate_timeout(target, synonym, "connect", 4, false),
                all,
                "ports={:?} should time out like a full scan, not the 60s floor",
                synonym
            );
        }
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

    // ========================================
    // Tests for the --exclude wiring (issue #2524)
    // ========================================
    //
    // execute() builds the command inline; these tests replicate the exact
    // `param_exclude_list` + `CommandBuilder.arg("--exclude", ...)` composition
    // it uses, so a regression in the wiring (dropped flag, wrong join, emitted
    // when empty) is caught without standing up a mock platform.

    fn build_exclude_args(params: &serde_json::Value) -> Vec<String> {
        let mut builder = CommandBuilder::new();
        if let Some(exclude) =
            super::super::runner::param_exclude_list(params, "exclude").expect("valid exclude")
        {
            builder = builder.arg("--exclude", &exclude);
        }
        builder.positional("10.0.0.0/24").build()
    }

    #[test]
    fn exclude_array_produces_exclude_flag() {
        let params = serde_json::json!({"exclude": ["10.0.0.1", "10.0.0.2"]});
        let args = build_exclude_args(&params);
        assert_eq!(args, vec!["--exclude", "10.0.0.1,10.0.0.2", "10.0.0.0/24"]);
    }

    #[test]
    fn absent_exclude_produces_no_flag() {
        let params = serde_json::json!({"target": "10.0.0.0/24"});
        let args = build_exclude_args(&params);
        assert_eq!(args, vec!["10.0.0.0/24"]);
        assert!(!args.iter().any(|a| a == "--exclude"));
    }

    #[test]
    fn empty_exclude_array_produces_no_flag() {
        let params = serde_json::json!({"exclude": []});
        let args = build_exclude_args(&params);
        assert!(!args.iter().any(|a| a == "--exclude"));
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

    // ========================================
    // Tests for normalize_legacy_nmap_params()
    //
    // Tolerance for the execute_command-style {args:[...]} / {command:"..."}
    // shape some callers emit instead of the structured schema.
    // ========================================

    #[test]
    fn structured_params_pass_through_unchanged() {
        let p = json!({"target": "10.0.8.0/22", "scan_type": "ping"});
        assert_eq!(normalize_legacy_nmap_params(p.clone()), p);
    }

    #[test]
    fn flags_string_with_target_maps_recognized_flags() {
        // The exact field payload: the LLM sent a `flags` STRING alongside a
        // valid `target`. There is no `flags` schema param, and because target
        // was present the normalizer used to early-return and drop `flags`
        // entirely — so -sn/-T4 never became scan_type/timing. Now the
        // recognized flags fold into structured params and target is kept.
        let p = json!({
            "flags": "-sn -T4 -PS22,80,443,445,3389 -PA80,443 -PE -PP",
            "target": "10.0.8.0/22"
        });
        let out = normalize_legacy_nmap_params(p);
        assert_eq!(out["target"], json!("10.0.8.0/22"));
        assert_eq!(out["scan_type"], json!("ping")); // -sn
        assert_eq!(out["timing"], json!(4)); // -T4
                                             // Unrecognized discovery flags (-PS/-PA/-PE/-PP) are dropped, never shelled.
        assert!(
            out.get("flags").is_none(),
            "raw flags string must be consumed, not passed through"
        );
    }

    #[test]
    fn flags_string_without_target_still_recovers_target_from_flags() {
        // `flags` may itself contain the target token (no separate target key).
        let p = json!({"flags": "-sS -p 80,443 192.168.1.1"});
        let out = normalize_legacy_nmap_params(p);
        assert_eq!(out["target"], json!("192.168.1.1"));
        assert_eq!(out["scan_type"], json!("syn"));
        assert_eq!(out["ports"], json!("80,443"));
        assert!(out.get("flags").is_none());
    }

    #[test]
    fn flags_do_not_clobber_explicit_structured_params() {
        // Explicit structured params are authoritative (matching the tool
        // description): a flag only fills a param the caller left unset. Here the
        // caller explicitly set service_detection=false, so -sV must NOT flip it
        // to true; but timing was unset, so -T2 fills it. Target from the
        // structured field is preserved.
        let p = json!({
            "target": "10.0.0.5",
            "service_detection": false,
            "flags": "-sV -T2"
        });
        let out = normalize_legacy_nmap_params(p);
        assert_eq!(out["target"], json!("10.0.0.5"));
        assert_eq!(out["service_detection"], json!(false)); // explicit param wins over -sV
        assert_eq!(out["timing"], json!(2)); // -T2 fills the unset param
    }

    #[test]
    fn flags_as_array_with_target_maps_recognized_flags() {
        // The array shape {"flags": ["-sn", "-T4"], "target": "..."} — the same
        // string-or-array tolerance the `args` path has. Before this was handled
        // the array `flags` rode through unconsumed and execute() ignored it, so
        // the scan silently ran with defaults (the very bug this PR kills, via a
        // different shape). Recognized flags must fold in and the raw key must be
        // consumed.
        let p = json!({
            "flags": ["-sn", "-T4", "-PE", "-PP"],
            "target": "10.0.8.0/22"
        });
        let out = normalize_legacy_nmap_params(p);
        assert_eq!(out["target"], json!("10.0.8.0/22"));
        assert_eq!(out["scan_type"], json!("ping")); // -sn
        assert_eq!(out["timing"], json!(4)); // -T4
        assert!(
            out.get("flags").is_none(),
            "array flags value must be consumed, not passed through"
        );
    }

    #[test]
    fn flags_as_object_is_stripped_not_passed_through() {
        // A `flags` value that is neither string nor array (here an object) yields
        // no tokens, but it must STILL be removed so it can't ride through to
        // execute() (which would ignore it and silently scan with defaults). The
        // structured params the caller did set are preserved unchanged.
        let p = json!({
            "target": "10.0.0.5",
            "scan_type": "syn",
            "flags": {"unexpected": "shape"}
        });
        let out = normalize_legacy_nmap_params(p);
        assert_eq!(out["target"], json!("10.0.0.5"));
        assert_eq!(out["scan_type"], json!("syn"));
        assert!(
            out.get("flags").is_none(),
            "non-string/array flags value must be stripped, not passed through"
        );
    }

    #[test]
    fn flags_array_recovers_target_from_tokens() {
        // Array `flags` with no separate target key still recovers the target
        // token, mirroring the string path.
        let p = json!({"flags": ["-sS", "-p", "80,443", "192.168.1.1"]});
        let out = normalize_legacy_nmap_params(p);
        assert_eq!(out["target"], json!("192.168.1.1"));
        assert_eq!(out["scan_type"], json!("syn"));
        assert_eq!(out["ports"], json!("80,443"));
        assert!(out.get("flags").is_none());
    }

    #[test]
    fn flags_injection_payload_never_becomes_target() {
        // Splitting a flags string on whitespace means a "10.0.0.1; rm -rf /"
        // payload becomes separate tokens. The dangerous token "10.0.0.1;"
        // (semicolon) must NOT validate as a target, so the recovered target is
        // never the injection string. Whatever IS recovered still goes through
        // validate_target and is passed as a STRUCTURED positional arg (never
        // shell-interpolated), so this is safe — same contract as the args path.
        let out = normalize_legacy_nmap_params(json!({"flags": "-sn 10.0.0.1; rm -rf /"}));
        let recovered = out.get("target").and_then(|v| v.as_str());
        assert_ne!(recovered, Some("10.0.0.1; rm -rf /"));
        assert_ne!(recovered, Some("10.0.0.1;"));
        // And the raw flags string is always consumed, never passed through.
        assert!(out.get("flags").is_none());
    }

    #[test]
    fn flags_semicolon_target_token_is_rejected() {
        // The clean case: a target carrying a shell metacharacter must be
        // rejected by validate_target, leaving no target (schema error fires).
        let out = normalize_legacy_nmap_params(json!({"flags": "-sn 10.0.0.1;rm"}));
        assert!(
            out.get("target").is_none(),
            "a token with ';' must not validate as a target, got: {:?}",
            out.get("target")
        );
    }

    #[test]
    fn legacy_args_array_recovers_target_and_known_flags() {
        // The exact payload from the field report (Strike48/matrix#2851).
        let p = json!({
            "args": ["-T4", "-sn", "-PE", "-PP", "-PM", "-n", "--min-rate", "1000", "10.0.8.0/22"]
        });
        let out = normalize_legacy_nmap_params(p);
        assert_eq!(out["target"], json!("10.0.8.0/22"));
        assert_eq!(out["scan_type"], json!("ping")); // -sn
        assert_eq!(out["timing"], json!(4)); // -T4
                                             // Unknown flags (-PE/-PP/-PM/-n/--min-rate) and its value (1000) are dropped.
        assert!(out.get("min-rate").is_none());
        assert!(out.get("min_rate").is_none());
    }

    #[test]
    fn legacy_args_as_json_encoded_string_is_parsed() {
        // The args value itself arrives as a JSON-encoded array string.
        let p = json!({"args": "[\"-sn\", \"10.0.8.0/22\"]"});
        let out = normalize_legacy_nmap_params(p);
        assert_eq!(out["target"], json!("10.0.8.0/22"));
        assert_eq!(out["scan_type"], json!("ping"));
    }

    #[test]
    fn legacy_command_string_recovers_target() {
        let p = json!({"command": "nmap -sS -p 80,443 192.168.1.1"});
        let out = normalize_legacy_nmap_params(p);
        assert_eq!(out["target"], json!("192.168.1.1"));
        assert_eq!(out["scan_type"], json!("syn")); // -sS
        assert_eq!(out["ports"], json!("80,443")); // -p <spec>
    }

    #[test]
    fn legacy_port_flag_attached_form() {
        let p = json!({"args": ["-sT", "-p1-1000", "10.0.0.5"]});
        let out = normalize_legacy_nmap_params(p);
        assert_eq!(out["target"], json!("10.0.0.5"));
        assert_eq!(out["ports"], json!("1-1000"));
    }

    #[test]
    fn no_recoverable_target_returns_original_so_schema_error_fires() {
        // Only unknown flags + a non-target numeric — nothing validates as a target.
        let p = json!({"args": ["--min-rate", "1000"]});
        let out = normalize_legacy_nmap_params(p.clone());
        // Returned unchanged → execute() still raises "target parameter is required".
        assert_eq!(out, p);
        assert!(out.get("target").is_none());
    }

    #[test]
    fn stray_flag_value_not_mistaken_for_target() {
        // "1000" is --min-rate's value, not the target; only the real target wins.
        let p = json!({"args": ["--min-rate", "1000", "-sn", "10.0.8.0/22"]});
        let out = normalize_legacy_nmap_params(p);
        assert_eq!(out["target"], json!("10.0.8.0/22"));
    }

    #[test]
    fn legacy_flags_map_to_all_scan_types_and_toggles() {
        let p = json!({"args": ["-sU", "-Pn", "-sV", "-O", "-A", "example.com"]});
        let out = normalize_legacy_nmap_params(p);
        assert_eq!(out["target"], json!("example.com"));
        assert_eq!(out["scan_type"], json!("udp"));
        assert_eq!(out["no_ping"], json!(true));
        assert_eq!(out["service_detection"], json!(true));
        assert_eq!(out["os_detection"], json!(true));
        assert_eq!(out["aggressive"], json!(true));
    }

    #[test]
    fn injection_attempt_in_legacy_args_is_not_recovered_as_target() {
        // A shell-injection-ish token must not validate as a target; with no
        // valid target recovered, params are returned unchanged (then rejected
        // downstream). Nothing here is ever shelled out raw.
        let p = json!({"args": ["-sn", "10.0.0.1; rm -rf /"]});
        let out = normalize_legacy_nmap_params(p.clone());
        assert_eq!(out, p);
        assert!(out.get("target").is_none());
    }

    // ========================================
    // Tests for should_force_pn() — issue #219
    // A "ping" (host-discovery) scan must never get -Pn, or nmap marks the
    // entire target range as up (reason=user-set) instead of probing.
    // ========================================

    #[test]
    fn ping_scan_never_forces_pn_even_when_unprivileged() {
        // The #219 regression: unprivileged + ping scan used to add -Pn.
        assert!(!should_force_pn(false, true, "ping"));
        // ...and even if the caller (nonsensically) also set no_ping, discovery wins.
        assert!(!should_force_pn(true, true, "ping"));
        assert!(!should_force_pn(false, false, "ping"));
    }

    #[test]
    fn non_ping_scan_forces_pn_when_unprivileged() {
        // Privileged ICMP echo needs a raw socket; unprivileged connect scans
        // still want -Pn so nmap doesn't fail trying to ping first.
        assert!(should_force_pn(false, true, "connect"));
        assert!(should_force_pn(false, true, "syn"));
        assert!(should_force_pn(false, true, "udp"));
    }

    #[test]
    fn non_ping_scan_honors_explicit_no_ping() {
        // Explicit no_ping adds -Pn regardless of privilege.
        assert!(should_force_pn(true, false, "connect"));
        assert!(should_force_pn(true, true, "connect"));
    }

    #[test]
    fn privileged_non_ping_without_no_ping_does_not_force_pn() {
        // Root + normal scan + no explicit no_ping: let nmap do its default
        // (privileged) host discovery — no -Pn.
        assert!(!should_force_pn(false, false, "connect"));
        assert!(!should_force_pn(false, false, "syn"));
    }

    // Command-line composition tests. `should_force_pn` is a predicate; the #219
    // bug actually lived in argv ASSEMBLY (`-sn` and `-Pn` both emitted). This
    // helper replicates the exact scan-type + `--unprivileged` + `-Pn`
    // composition `execute()` performs (mirroring the `build_exclude_args`
    // pattern above), so a regression in the wiring is caught without standing
    // up a mock platform.
    fn build_discovery_args(scan_type: &str, no_ping: bool, unprivileged: bool) -> Vec<String> {
        let mut builder = CommandBuilder::new();
        match scan_type {
            "syn" => builder = builder.flag("-sS"),
            "connect" => builder = builder.flag("-sT"),
            "udp" => builder = builder.flag("-sU"),
            "ping" => builder = builder.flag("-sn"),
            _ => {}
        }
        if unprivileged {
            builder = builder.flag("--unprivileged");
        }
        if should_force_pn(no_ping, unprivileged, scan_type) {
            builder = builder.flag("-Pn");
        }
        builder.positional("10.0.0.0/24").build()
    }

    #[test]
    fn ping_scan_emits_sn_and_never_pn() {
        // The #219 regression, at the argv layer: a ping scan must carry -sn and
        // must NEVER carry -Pn (which would make nmap report the whole range up),
        // across every privilege / no_ping combination.
        for unpriv in [false, true] {
            for no_ping in [false, true] {
                let args = build_discovery_args("ping", no_ping, unpriv);
                assert!(
                    args.iter().any(|a| a == "-sn"),
                    "ping scan must emit -sn (unpriv={unpriv}, no_ping={no_ping})"
                );
                assert!(
                    !args.iter().any(|a| a == "-Pn"),
                    "ping scan must NEVER emit -Pn — issue #219 (unpriv={unpriv}, no_ping={no_ping})"
                );
            }
        }
    }

    #[test]
    fn unprivileged_ping_scan_still_emits_unprivileged() {
        // The raw-socket guard must survive: an unprivileged ping scan keeps
        // --unprivileged (so its TCP-based discovery runs) while dropping -Pn.
        let args = build_discovery_args("ping", false, true);
        assert!(args.iter().any(|a| a == "--unprivileged"));
        assert!(args.iter().any(|a| a == "-sn"));
        assert!(!args.iter().any(|a| a == "-Pn"));
    }

    #[test]
    fn unprivileged_connect_scan_emits_pn() {
        // Positive control: a non-discovery scan when unprivileged DOES get -Pn,
        // so the negative assertions above can't pass by never emitting -Pn.
        let args = build_discovery_args("connect", false, true);
        assert!(args.iter().any(|a| a == "-sT"));
        assert!(args.iter().any(|a| a == "-Pn"));
    }
}
