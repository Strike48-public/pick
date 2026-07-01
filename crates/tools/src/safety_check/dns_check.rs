//! DNS integrity validation to detect DNS hijacking and poisoning.

use super::types::{CheckResult, CheckStatus, Severity};
use anyhow::Context;
use std::collections::HashMap;
use std::net::{IpAddr, ToSocketAddrs};

/// Known-good domains with their expected IP addresses.
///
/// These are stable, well-known services that should resolve to
/// predictable IP ranges. We use multiple domains to reduce false positives.
const KNOWN_DOMAINS: &[(&str, &[&str])] = &[
    // Google DNS - extremely stable
    ("dns.google", &["8.8.8.8", "8.8.4.4"]),
    // Cloudflare DNS - stable
    ("one.one.one.one", &["1.1.1.1", "1.0.0.1"]),
    // Google.com - should resolve to Google IP ranges (multiple valid IPs)
    // We'll validate it resolves to something, not specific IPs
];

/// Domains to test for basic connectivity (we don't validate exact IPs).
const CONNECTIVITY_DOMAINS: &[&str] = &["google.com", "github.com", "cloudflare.com"];

/// Check DNS integrity by validating known-good domain resolutions.
///
/// This detects:
/// - DNS hijacking (resolving to unexpected IPs)
/// - DNS poisoning (incorrect DNS responses)
/// - Captive portals (all domains resolve to same IP)
///
/// # Errors
///
/// Returns error if DNS resolution completely fails (no network connectivity).
pub async fn check_dns_integrity() -> anyhow::Result<CheckResult> {
    tracing::debug!("Starting DNS integrity check");

    let mut issues = Vec::new();
    let mut validated_domains = 0;
    let mut connectivity_ok = false;

    // Check known-good domains with expected IPs
    for (domain, expected_ips) in KNOWN_DOMAINS {
        match resolve_domain(domain).await {
            Ok(resolved_ips) => {
                validated_domains += 1;
                if !any_ip_matches(&resolved_ips, expected_ips) {
                    let issue = format!(
                        "{} resolved to unexpected IPs: {:?} (expected one of: {:?})",
                        domain, resolved_ips, expected_ips
                    );
                    tracing::warn!("{}", issue);
                    issues.push(issue);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to resolve {}: {}", domain, e);
                issues.push(format!("Failed to resolve {}: {}", domain, e));
            }
        }
    }

    // Check connectivity domains (just verify they resolve)
    let mut connectivity_resolutions = HashMap::new();
    for domain in CONNECTIVITY_DOMAINS {
        match resolve_domain(domain).await {
            Ok(ips) => {
                validated_domains += 1;
                connectivity_ok = true;
                connectivity_resolutions.insert(*domain, ips);
            }
            Err(e) => {
                tracing::debug!("Failed to resolve {}: {}", domain, e);
            }
        }
    }

    // Detect captive portal: all domains resolve to same IP
    if connectivity_resolutions.len() >= 2 {
        let first_ip = connectivity_resolutions
            .values()
            .next()
            .and_then(|ips| ips.first())
            .copied();
        if let Some(first) = first_ip {
            let all_same = connectivity_resolutions
                .values()
                .all(|ips| ips.contains(&first));
            if all_same {
                issues.push(format!(
                    "Captive portal detected: all domains resolve to {}",
                    first
                ));
            }
        }
    }

    // Determine status
    let (status, severity) = if !connectivity_ok || !issues.is_empty() {
        (CheckStatus::Failed, Severity::Critical)
    } else if validated_domains < 3 {
        (CheckStatus::Warning, Severity::Medium)
    } else {
        (CheckStatus::Passed, Severity::Info)
    };

    let details = if issues.is_empty() {
        format!(
            "Validated {} domains, all returned expected IPs. No DNS hijacking detected.",
            validated_domains
        )
    } else if !connectivity_ok {
        "No DNS connectivity - unable to resolve any domains. Check network connection.".to_string()
    } else {
        format!("DNS integrity issues detected:\n{}", issues.join("\n"))
    };

    Ok(CheckResult {
        name: "DNS Integrity".to_string(),
        status,
        details,
        severity,
    })
}

/// Resolve a domain to its IP addresses.
async fn resolve_domain(domain: &str) -> anyhow::Result<Vec<IpAddr>> {
    let socket_addr = format!("{}:443", domain);
    let addrs: Vec<IpAddr> = tokio::task::spawn_blocking(move || {
        socket_addr
            .to_socket_addrs()
            .map(|iter| iter.map(|addr| addr.ip()).collect())
    })
    .await
    .context("Failed to spawn DNS resolution task")?
    .context("DNS resolution failed")?;

    if addrs.is_empty() {
        anyhow::bail!("No IP addresses resolved for {}", domain);
    }

    Ok(addrs)
}

/// Check if any resolved IP matches the expected IPs.
fn any_ip_matches(resolved: &[IpAddr], expected: &[&str]) -> bool {
    expected.iter().any(|expected_ip| {
        if let Ok(expected_addr) = expected_ip.parse::<IpAddr>() {
            resolved.contains(&expected_addr)
        } else {
            false
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_any_ip_matches_positive() {
        let resolved = vec![
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)),
        ];
        let expected = &["8.8.8.8", "1.1.1.1"];

        assert!(any_ip_matches(&resolved, expected));
    }

    #[test]
    fn test_any_ip_matches_negative() {
        let resolved = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        let expected = &["8.8.8.8", "1.1.1.1"];

        assert!(!any_ip_matches(&resolved, expected));
    }

    #[tokio::test]
    async fn test_dns_check_runs() {
        // This is an integration test - it requires network connectivity
        // Skip in CI environments or when offline
        if std::env::var("CI").is_ok() {
            return;
        }

        let result = check_dns_integrity().await;
        assert!(result.is_ok(), "DNS check should not error: {:?}", result);

        let check = result.unwrap();
        assert_eq!(check.name, "DNS Integrity");
        // Don't assert specific status since it depends on network environment
    }
}
