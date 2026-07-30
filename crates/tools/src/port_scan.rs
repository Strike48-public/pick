//! Port scanning tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_core::validation::{validate_port_spec, validate_target};
use pentest_platform::{get_platform, NetworkOps, ScanConfig};
use serde_json::{json, Value};
use std::net::Ipv4Addr;
use std::sync::Arc;

use crate::util::{param_str, param_u64};

/// Collect the target hosts from `host` (single), `hosts` (list), and/or
/// `subnet` (IPv4 CIDR), de-duplicated in first-seen order. Lets one call scan
/// a whole subnet instead of the agent fanning out one `port_scan` per host.
fn collect_hosts(params: &Value) -> std::result::Result<Vec<String>, pentest_core::error::Error> {
    use pentest_core::error::Error;
    let mut out: Vec<String> = Vec::new();
    let mut push = |h: String| {
        if !out.contains(&h) {
            out.push(h);
        }
    };

    if let Some(h) = params.get("host").and_then(|v| v.as_str()) {
        if !h.is_empty() {
            push(validate_target(h)?);
        }
    }

    if let Some(arr) = params.get("hosts").and_then(|v| v.as_array()) {
        for v in arr {
            if let Some(h) = v.as_str() {
                if !h.is_empty() {
                    push(validate_target(h)?);
                }
            }
        }
    }

    if let Some(cidr) = params.get("subnet").and_then(|v| v.as_str()) {
        if !cidr.is_empty() {
            for h in expand_ipv4_cidr(cidr)? {
                push(h);
            }
        }
    }

    if out.is_empty() {
        return Err(Error::InvalidParams(
            "provide at least one of: host, hosts[], or subnet".into(),
        ));
    }
    Ok(out)
}

/// Expand an IPv4 CIDR (e.g. "10.10.0.0/24") into its usable host addresses.
/// Network and broadcast addresses are dropped for prefixes < /31. Capped at
/// 1024 hosts so a wide prefix can't blow up the scan; prefixes narrower than
/// /22 are rejected for the same reason.
fn expand_ipv4_cidr(cidr: &str) -> std::result::Result<Vec<String>, pentest_core::error::Error> {
    use pentest_core::error::Error;
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| Error::InvalidParams(format!("invalid CIDR: {cidr}")))?;
    let base: Ipv4Addr = addr
        .parse()
        .map_err(|_| Error::InvalidParams(format!("subnet only supports IPv4 CIDR: {cidr}")))?;
    let prefix: u32 = prefix
        .parse()
        .map_err(|_| Error::InvalidParams(format!("invalid CIDR prefix: {cidr}")))?;
    if prefix > 32 {
        return Err(Error::InvalidParams(format!("invalid CIDR prefix: {cidr}")));
    }
    if prefix < 22 {
        return Err(Error::InvalidParams(format!(
            "subnet /{prefix} is too large (max 1024 hosts, use /22 or narrower)"
        )));
    }

    let base_u32 = u32::from(base);
    let host_bits = 32 - prefix;
    let count = 1u32 << host_bits; // total addresses in the block
    let mask = if host_bits == 0 { 0 } else { count - 1 };
    let network = base_u32 & !mask;

    let mut hosts = Vec::new();
    for i in 0..count {
        // Skip network + broadcast for blocks that have them (prefix <= /30).
        if host_bits >= 2 && (i == 0 || i == count - 1) {
            continue;
        }
        hosts.push(Ipv4Addr::from(network + i).to_string());
    }
    Ok(hosts)
}

/// Port scanning tool
pub struct PortScanTool;

#[async_trait]
impl PentestTool for PortScanTool {
    fn name(&self) -> &str {
        "port_scan"
    }

    fn description(&self) -> &str {
        "Scan TCP ports on one or more hosts to identify open services. Scan a \
         whole subnet in ONE call via `subnet` (CIDR) or `hosts` (list) instead \
         of calling this once per host."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::optional(
                "host",
                ParamType::String,
                "Single target host IP or hostname",
                json!(null),
            ))
            .param(ToolParam::optional(
                "hosts",
                ParamType::Array,
                "List of target hosts to scan in one call (e.g. [\"10.0.0.1\", \"10.0.0.2\"])",
                json!([]),
            ))
            .param(ToolParam::optional(
                "subnet",
                ParamType::String,
                "IPv4 CIDR to scan in one call (e.g. '10.10.0.0/24'); /22 or narrower",
                json!(null),
            ))
            .param(ToolParam::optional(
                "ports",
                ParamType::String,
                "Port specification (e.g., '22,80,443' or '1-1024')",
                json!("22,80,443,8080"),
            ))
            .param(ToolParam::optional(
                "timeout_ms",
                ParamType::Integer,
                "Connection timeout per port in milliseconds",
                json!(2000),
            ))
            .param(ToolParam::optional(
                "concurrency",
                ParamType::Integer,
                "Number of concurrent connections per host",
                json!(50),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![
            Platform::Desktop,
            Platform::Web,
            Platform::Android,
            Platform::Ios,
            Platform::Tui,
        ]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            // Gather targets from host / hosts[] / subnet (CIDR).
            let hosts = collect_hosts(&params)?;

            let ports_str = {
                let s = param_str(&params, "ports");
                if s.is_empty() {
                    "22,80,443,8080".to_string()
                } else {
                    s
                }
            };
            let ports_str = validate_port_spec(&ports_str)?;

            let timeout_ms = param_u64(&params, "timeout_ms", 2000);
            let concurrency = param_u64(&params, "concurrency", 50) as usize;

            let ports = pentest_core::state::ScanConfig::parse_ports(&ports_str);
            if ports.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "No valid ports specified".into(),
                ));
            }

            // Scan each host concurrently, but cap the number of hosts in flight
            // so a /22 subnet doesn't open thousands of sockets at once (each
            // host already scans its ports concurrently up to `concurrency`).
            const MAX_HOSTS_IN_FLIGHT: usize = 16;
            let sem = Arc::new(tokio::sync::Semaphore::new(MAX_HOSTS_IN_FLIGHT));
            let ports = Arc::new(ports);

            let single_host = hosts.len() == 1;
            let futures = hosts.into_iter().map(|host| {
                let sem = sem.clone();
                let ports = ports.clone();
                async move {
                    let _permit = sem.acquire().await.expect("semaphore not closed");
                    let config = ScanConfig {
                        host: host.clone(),
                        ports: (*ports).clone(),
                        timeout_ms,
                        concurrency,
                    };
                    match get_platform().port_scan(config).await {
                        Ok(result) => Ok(result),
                        Err(e) => Err((host, e)),
                    }
                }
            });
            let results = futures::future::join_all(futures).await;

            // Single-host callers get the flat legacy shape (full per-port list
            // under `ports`) for backward compatibility.
            if single_host {
                return match results.into_iter().next().unwrap() {
                    Ok(r) => Ok(json!({
                        "host": r.host,
                        "ports": r.ports,
                        "open_count": r.open_count,
                        // Surface reachability failures so the agent can tell "we
                        // checked and found nothing open" apart from "we could not
                        // reach the target" (#306). unreachable_count == total_scanned
                        // means no packet reached the host.
                        "unreachable_count": r.unreachable_count,
                        "errors": r.errors,
                        "total_scanned": r.ports.len(),
                        "duration_ms": r.duration_ms,
                    })),
                    Err((host, e)) => {
                        Err(pentest_core::error::Error::Network(format!("{host}: {e}")))
                    }
                };
            }

            // Multi-host: emit ONLY hosts that have open ports, and for those
            // only the open ports (as {port, service}). A full 254-host ×
            // all-ports dump is ~100k+ tokens and gets truncated by the platform
            // summarizer — useless to the agent. This keeps the payload tiny and
            // directly feeds the batched service_banner step.
            let mut host_entries: Vec<Value> = Vec::new();
            let mut hosts_scanned = 0usize;
            // Hosts that no probe ever reached (every port Unreachable, none open).
            // Aggregated as a COUNT, not a per-host list: on a 254-host subnet a
            // mesh/routing failure can make hundreds unreachable, and listing each
            // would blow the token budget the tiny-payload design exists to protect.
            // The count lets the agent distinguish "scanned the subnet, nothing was
            // open" from "couldn't reach most of the subnet" (#306).
            let mut hosts_unreachable = 0usize;
            let mut errors: Vec<Value> = Vec::new();
            for r in results {
                match r {
                    Ok(scan) => {
                        hosts_scanned += 1;
                        if scan.open_count == 0 {
                            // Distinguish "reachable, nothing open" from "never
                            // reached": a host is unreachable when every scanned
                            // port failed to reach it.
                            if scan.unreachable_count > 0
                                && scan.unreachable_count == scan.ports.len()
                            {
                                hosts_unreachable += 1;
                            }
                            continue;
                        }
                        let open: Vec<Value> = scan
                            .ports
                            .iter()
                            .filter(|p| p.open)
                            .map(|p| json!({ "port": p.port, "service": p.service }))
                            .collect();
                        host_entries.push(json!({
                            "host": scan.host,
                            "open_ports": open,
                            "open_count": scan.open_count,
                        }));
                    }
                    Err((host, e)) => errors.push(json!({ "host": host, "error": e.to_string() })),
                }
            }
            Ok(json!({
                "hosts": host_entries,
                "hosts_scanned": hosts_scanned,
                "hosts_with_open_ports": host_entries.len(),
                "hosts_unreachable": hosts_unreachable,
                "errors": errors,
            }))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_ipv4_cidr_24_drops_network_and_broadcast() {
        let hosts = expand_ipv4_cidr("10.10.0.0/24").unwrap();
        assert_eq!(hosts.len(), 254); // 256 - network - broadcast
        assert_eq!(hosts.first().unwrap(), "10.10.0.1");
        assert_eq!(hosts.last().unwrap(), "10.10.0.254");
        assert!(!hosts.contains(&"10.10.0.0".to_string()));
        assert!(!hosts.contains(&"10.10.0.255".to_string()));
    }

    #[test]
    fn expand_ipv4_cidr_rejects_too_large_and_ipv6() {
        assert!(expand_ipv4_cidr("10.0.0.0/8").is_err()); // > 1024 hosts
        assert!(expand_ipv4_cidr("2001:db8::/64").is_err()); // IPv6 unsupported
        assert!(expand_ipv4_cidr("nonsense").is_err());
    }

    #[test]
    fn expand_ipv4_cidr_32_is_single_host() {
        // /31 and /32 have no network/broadcast to drop.
        assert_eq!(expand_ipv4_cidr("10.10.0.5/32").unwrap(), vec!["10.10.0.5"]);
    }

    #[test]
    fn collect_hosts_merges_and_dedups() {
        let params = json!({
            "host": "10.10.0.1",
            "hosts": ["10.10.0.2", "10.10.0.1"], // 10.10.0.1 duplicate
        });
        let hosts = collect_hosts(&params).unwrap();
        assert_eq!(hosts, vec!["10.10.0.1", "10.10.0.2"]);
    }

    #[test]
    fn collect_hosts_requires_a_target() {
        assert!(collect_hosts(&json!({})).is_err());
        assert!(collect_hosts(&json!({ "hosts": [] })).is_err());
    }
}
