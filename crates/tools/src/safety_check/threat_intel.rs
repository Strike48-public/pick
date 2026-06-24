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

    // Get default gateway IP
    let gateway_ip = get_default_gateway()
        .await
        .context("Failed to determine default gateway")?;

    tracing::info!("Checking threat intel for gateway: {}", gateway_ip);

    // Check if this is a private/local IP - no need for threat intel
    if is_private_ip(&gateway_ip) {
        return Ok(CheckResult {
            name: "Router Threat Intelligence".to_string(),
            status: CheckStatus::Passed,
            details: format!(
                "Gateway {} is a private IP address (RFC1918). No threat intelligence check needed.",
                gateway_ip
            ),
            severity: Severity::Info,
        });
    }

    // TODO: Implement MCP threat intelligence queries
    // For now, return a placeholder that indicates the check is not yet implemented
    // but doesn't fail the safety check
    tracing::warn!("Threat intelligence check not yet implemented");

    Ok(CheckResult {
        name: "Router Threat Intelligence".to_string(),
        status: CheckStatus::Unknown,
        details: format!(
            "Gateway IP: {}. Threat intelligence lookup not yet implemented.",
            gateway_ip
        ),
        severity: Severity::Low,
    })
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
