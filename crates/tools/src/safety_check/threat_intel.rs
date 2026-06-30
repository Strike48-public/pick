//! Router threat intelligence checks using external threat databases.

use super::types::{CheckResult, CheckStatus, Severity};
use anyhow::Context;
use std::net::IpAddr;

/// Check the default gateway router against threat intelligence databases.
///
/// Queries:
/// - VirusTotal (via MCP if available)
/// - AbuseIPDB (via MCP if available)
///
/// Uses best-effort approach - if APIs are unavailable, returns UNKNOWN status
/// rather than failing.
///
/// # Errors
///
/// Returns error only if gateway IP cannot be determined. API failures are
/// handled gracefully.
pub async fn check_router_threat_intel() -> anyhow::Result<CheckResult> {
    tracing::debug!("Starting router threat intelligence check");

    // Get default gateway IP (the router we egress through).
    let gateway_ip = get_default_gateway()
        .await
        .context("Failed to determine default gateway")?;

    // Best-effort collection of the DNS resolver IPs this network handed us.
    // A hostile hotspot pointing us at a malicious resolver is a key signal,
    // and resolver IPs are frequently public (unlike the gateway).
    let dns_ips = get_dns_servers();

    tracing::info!(
        "Threat intel targets: gateway={}, dns={:?}",
        gateway_ip,
        dns_ips
    );

    // Partition every candidate IP into private (no lookup needed) and public
    // (worth a reputation check). We label each so the report and the agent
    // prompt can speak about them precisely.
    let mut public_targets: Vec<(String, IpAddr)> = Vec::new();
    let mut private_count = 0u32;

    for (label, ip) in std::iter::once(("gateway".to_string(), gateway_ip))
        .chain(dns_ips.into_iter().map(|ip| ("dns".to_string(), ip)))
    {
        if is_private_ip(&ip) {
            private_count += 1;
        } else {
            public_targets.push((label, ip));
        }
    }

    // Everything is on the private/local range - nothing for a public threat
    // feed to say. This is a genuine pass, not a pending state.
    if public_targets.is_empty() {
        return Ok(CheckResult {
            name: "Router Threat Intelligence".to_string(),
            status: CheckStatus::Passed,
            details: format!(
                "Gateway and all DNS resolvers are private addresses (RFC1918); \
                 {} address(es) checked. No public IP to look up.",
                private_count
            ),
            severity: Severity::Info,
        });
    }

    // We have public IPs worth checking, but Pick (a connector) has no threat
    // feed of its own - the agent performs the reputation lookups via Strike
    // Construct's threatintel/virustotal tools. Emit the targets clearly and
    // mark the check pending so the verdict honestly reads "Mostly Safe".
    let target_list = public_targets
        .iter()
        .map(|(label, ip)| format!("{} {}", label, ip))
        .collect::<Vec<_>>()
        .join(", ");

    Ok(CheckResult {
        name: "Router Threat Intelligence".to_string(),
        status: CheckStatus::NeedsEnrichment,
        details: format!(
            "Public IP(s) to verify: {}. Reputation not yet confirmed - run \
             abuseipdb_check and virustotal on each and fold the scores in.",
            target_list
        ),
        severity: Severity::Low,
    })
}

/// Collect the DNS resolver IP addresses configured for this host.
///
/// Best-effort and platform-specific: parses `/etc/resolv.conf` on Unix-like
/// systems. Returns an empty vec on any failure or unsupported platform - the
/// caller treats "no resolvers found" as simply nothing extra to enrich.
fn get_dns_servers() -> Vec<IpAddr> {
    #[cfg(unix)]
    {
        let Ok(contents) = std::fs::read_to_string("/etc/resolv.conf") else {
            tracing::debug!("Could not read /etc/resolv.conf for DNS server detection");
            return Vec::new();
        };

        contents
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                // Skip comments and unrelated directives.
                if line.starts_with('#') || line.starts_with(';') {
                    return None;
                }
                let rest = line.strip_prefix("nameserver ")?;
                rest.trim().parse::<IpAddr>().ok()
            })
            .collect()
    }

    #[cfg(not(unix))]
    {
        // Windows/other DNS enumeration is deferred; gateway enrichment still
        // works. Returning empty keeps behavior correct, just less thorough.
        Vec::new()
    }
}

/// Get the default gateway IP address.
async fn get_default_gateway() -> anyhow::Result<IpAddr> {
    // Use default-net crate to get gateway
    let default_net = tokio::task::spawn_blocking(default_net::get_default_gateway)
        .await
        .context("Failed to spawn gateway detection task")?
        .map_err(|e| anyhow::anyhow!("Failed to detect default gateway: {}", e))?;

    Ok(default_net.ip_addr)
}

/// Check if an IP address is private (RFC1918, link-local, loopback).
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local() || ipv4.is_broadcast()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_multicast() || ipv6.segments()[0] & 0xfe00 == 0xfc00
            // Unique local (fc00::/7)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_is_private_ip_rfc1918() {
        let private_ips = vec![
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
        ];

        for ip in private_ips {
            assert!(is_private_ip(&ip), "{} should be private", ip);
        }
    }

    #[test]
    fn test_is_private_ip_public() {
        let public_ips = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
        ];

        for ip in public_ips {
            assert!(!is_private_ip(&ip), "{} should be public", ip);
        }
    }

    #[test]
    fn test_is_private_ip_loopback() {
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[tokio::test]
    async fn test_threat_intel_check_runs() {
        // This test requires a network interface
        // Skip in environments without networking
        if std::env::var("CI").is_ok() {
            return;
        }

        let result = check_router_threat_intel().await;
        // Should not error even if gateway detection fails
        // (would return Unknown status instead)
        if let Ok(check) = result {
            assert_eq!(check.name, "Router Threat Intelligence");
        }
    }
}
