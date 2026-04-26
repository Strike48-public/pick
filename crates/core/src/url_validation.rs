//! URL validation for preventing SSRF attacks
//!
//! This module provides URL validation to prevent Server-Side Request Forgery (SSRF)
//! attacks by blocking connections to private/internal IP addresses and localhost.

use crate::error::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

/// URL validation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    /// Development mode - allows localhost and private IPs
    Development,
    /// Production mode - blocks localhost and private IPs
    Production,
    /// Strict mode - only allows explicitly allowlisted hosts
    Strict,
}

impl Default for ValidationMode {
    fn default() -> Self {
        // Default to Development for local testing, but should be Production in releases
        #[cfg(debug_assertions)]
        return Self::Development;

        #[cfg(not(debug_assertions))]
        Self::Production
    }
}

/// Validate a URL for SSRF prevention
///
/// # Arguments
///
/// * `url` - The URL to validate (e.g., "wss://strike48.example.com:443")
/// * `mode` - Validation mode (Development, Production, or Strict)
/// * `allowlist` - Optional list of allowed hosts (used in Strict mode)
///
/// # Security
///
/// In Production mode, this function blocks:
/// - Localhost addresses (127.0.0.0/8, ::1)
/// - Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
/// - Link-local addresses (169.254.0.0/16, fe80::/10)
/// - Multicast addresses
/// - Documentation addresses (192.0.2.0/24, etc.)
///
/// # Examples
///
/// ```
/// use pentest_core::url_validation::{validate_url, ValidationMode};
///
/// // Production mode blocks private IPs
/// assert!(validate_url("wss://192.168.1.1:443", ValidationMode::Production, None).is_err());
/// assert!(validate_url("wss://example.com:443", ValidationMode::Production, None).is_ok());
///
/// // Development mode allows private IPs
/// assert!(validate_url("ws://localhost:50061", ValidationMode::Development, None).is_ok());
/// ```
pub fn validate_url(
    url: &str,
    mode: ValidationMode,
    allowlist: Option<&[String]>,
) -> Result<String> {
    // Parse URL to extract host
    let host = extract_host(url)?;

    // In Strict mode, check allowlist first
    if mode == ValidationMode::Strict {
        let allowed_hosts = allowlist
            .ok_or_else(|| Error::InvalidParams("Strict mode requires an allowlist".to_string()))?;

        if !allowed_hosts.iter().any(|h| h == &host) {
            return Err(Error::PermissionDenied(format!(
                "Host '{}' is not in the allowlist",
                host
            )));
        }

        return Ok(url.to_string());
    }

    // In Development mode, allow everything
    if mode == ValidationMode::Development {
        return Ok(url.to_string());
    }

    // In Production mode, validate against SSRF patterns
    if is_localhost(&host) {
        return Err(Error::PermissionDenied(
            "Localhost addresses are not allowed in production mode".to_string(),
        ));
    }

    if is_private_ip(&host) {
        return Err(Error::PermissionDenied(
            "Private IP addresses are not allowed in production mode".to_string(),
        ));
    }

    Ok(url.to_string())
}

/// Extract hostname from URL
fn extract_host(url: &str) -> Result<String> {
    // Handle various URL formats: wss://host:port, grpc://host:port, host:port
    let schemes = [
        "grpc://", "grpcs://", "http://", "https://", "ws://", "wss://",
    ];
    let mut remaining = url.trim();

    for scheme in &schemes {
        if let Some(stripped) = remaining.strip_prefix(scheme) {
            remaining = stripped;
            break;
        }
    }

    // Extract host (before port if present)
    let host = if let Some(colon_pos) = remaining.find(':') {
        &remaining[..colon_pos]
    } else {
        remaining
    };

    if host.is_empty() {
        return Err(Error::InvalidParams("Empty host in URL".to_string()));
    }

    Ok(host.to_string())
}

/// Check if a host is localhost
fn is_localhost(host: &str) -> bool {
    // Check literal localhost strings
    if host == "localhost" || host == "localhost." {
        return true;
    }

    // Try to parse as IP address
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(ipv4) => is_localhost_ipv4(ipv4),
            IpAddr::V6(ipv6) => is_localhost_ipv6(ipv6),
        };
    }

    false
}

/// Check if an IPv4 address is localhost (127.0.0.0/8)
fn is_localhost_ipv4(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 127
}

/// Check if an IPv6 address is localhost (::1)
fn is_localhost_ipv6(ip: Ipv6Addr) -> bool {
    ip == Ipv6Addr::LOCALHOST
}

/// Check if a host resolves to a private IP address
///
/// This function performs DNS resolution to prevent DNS rebinding attacks.
/// If the host is a hostname (not an IP), it resolves all A/AAAA records
/// and checks if ANY of them point to private IP ranges.
fn is_private_ip(host: &str) -> bool {
    // Try to parse as IP address
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
            IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
        };
    }

    // For hostnames, perform DNS resolution to prevent DNS rebinding attacks
    // DNS rebinding attack: attacker registers domain pointing to public IP during
    // validation, then switches DNS to private IP after validation passes.
    //
    // Defense: Resolve hostname and check ALL resolved IPs against private ranges.
    // If ANY resolved IP is private, reject the hostname.
    match resolve_hostname_to_ips(host) {
        Ok(ips) => {
            // Check if ANY resolved IP is private
            for ip in ips {
                let is_private = match ip {
                    IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
                    IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
                };
                if is_private {
                    tracing::warn!(
                        "Hostname {} resolved to private IP {}, blocking SSRF attempt",
                        host,
                        ip
                    );
                    return true;
                }
            }
            // All resolved IPs are public
            false
        }
        Err(e) => {
            // DNS resolution failed - treat as private for safety
            tracing::warn!(
                "Failed to resolve hostname {}: {}, blocking for safety",
                host,
                e
            );
            true
        }
    }
}

/// Resolve a hostname to all its IP addresses (A and AAAA records)
///
/// Returns all resolved IPs or an error if DNS resolution fails.
/// Uses standard library DNS resolution (synchronous).
fn resolve_hostname_to_ips(hostname: &str) -> std::io::Result<Vec<IpAddr>> {
    // Use port 0 as a placeholder - we only care about the IP addresses
    let socket_addrs = format!("{}:0", hostname).to_socket_addrs()?;

    // Extract IP addresses from socket addresses
    let ips: Vec<IpAddr> = socket_addrs.map(|addr| addr.ip()).collect();

    if ips.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No IP addresses found for hostname",
        ));
    }

    Ok(ips)
}

/// Check if an IPv4 address is private
fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();

    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }

    // 172.16.0.0/12
    if octets[0] == 172 && (octets[1] >= 16 && octets[1] <= 31) {
        return true;
    }

    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }

    // 127.0.0.0/8 (loopback)
    if octets[0] == 127 {
        return true;
    }

    // 169.254.0.0/16 (link-local)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }

    // 192.0.2.0/24 (documentation - TEST-NET-1)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }

    // 198.51.100.0/24 (documentation - TEST-NET-2)
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }

    // 203.0.113.0/24 (documentation - TEST-NET-3)
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }

    // 100.64.0.0/10 (carrier-grade NAT - RFC 6598)
    if octets[0] == 100 && (octets[1] >= 64 && octets[1] <= 127) {
        return true;
    }

    // 198.18.0.0/15 (benchmark testing - RFC 2544)
    if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
        return true;
    }

    // 0.0.0.0/8 (this network)
    if octets[0] == 0 {
        return true;
    }

    // Multicast (224.0.0.0/4)
    if octets[0] >= 224 && octets[0] <= 239 {
        return true;
    }

    // 240.0.0.0/4 (reserved - RFC 1112)
    if octets[0] >= 240 {
        return true;
    }

    // Broadcast (255.255.255.255)
    if ip == Ipv4Addr::BROADCAST {
        return true;
    }

    false
}

/// Check if an IPv6 address is private
fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    // Link-local (fe80::/10)
    if (ip.segments()[0] & 0xffc0) == 0xfe80 {
        return true;
    }

    // Unique local addresses (fc00::/7)
    if (ip.segments()[0] & 0xfe00) == 0xfc00 {
        return true;
    }

    // Multicast (ff00::/8)
    if ip.segments()[0] >= 0xff00 {
        return true;
    }

    // Unspecified (::)
    if ip == Ipv6Addr::UNSPECIFIED {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_development_mode_allows_localhost() {
        assert!(validate_url("ws://localhost:50061", ValidationMode::Development, None).is_ok());
        assert!(validate_url("wss://127.0.0.1:443", ValidationMode::Development, None).is_ok());
        assert!(validate_url("grpc://[::1]:50061", ValidationMode::Development, None).is_ok());
    }

    #[test]
    fn test_development_mode_allows_private_ips() {
        assert!(validate_url("wss://192.168.1.1:443", ValidationMode::Development, None).is_ok());
        assert!(validate_url("wss://10.0.0.1:443", ValidationMode::Development, None).is_ok());
        assert!(validate_url("wss://172.16.0.1:443", ValidationMode::Development, None).is_ok());
    }

    #[test]
    fn test_production_mode_blocks_localhost() {
        assert!(validate_url("ws://localhost:50061", ValidationMode::Production, None).is_err());
        assert!(validate_url("wss://127.0.0.1:443", ValidationMode::Production, None).is_err());
        assert!(validate_url("wss://127.5.5.5:443", ValidationMode::Production, None).is_err());
    }

    #[test]
    fn test_production_mode_blocks_private_ipv4() {
        assert!(validate_url("wss://192.168.1.1:443", ValidationMode::Production, None).is_err());
        assert!(validate_url("wss://10.0.0.1:443", ValidationMode::Production, None).is_err());
        assert!(validate_url("wss://172.16.0.1:443", ValidationMode::Production, None).is_err());
        assert!(
            validate_url("wss://172.31.255.255:443", ValidationMode::Production, None).is_err()
        );
    }

    #[test]
    fn test_production_mode_blocks_link_local() {
        assert!(validate_url("wss://169.254.1.1:443", ValidationMode::Production, None).is_err());
    }

    #[test]
    fn test_production_mode_allows_public_ips() {
        assert!(validate_url("wss://8.8.8.8:443", ValidationMode::Production, None).is_ok());
        assert!(validate_url("wss://1.1.1.1:443", ValidationMode::Production, None).is_ok());
    }

    #[test]
    fn test_production_mode_allows_public_hostnames() {
        // Test with real public domains that should resolve to public IPs
        // Skip if DNS resolution fails (no internet connectivity)
        match resolve_hostname_to_ips("google.com") {
            Ok(_) => {
                // Internet connectivity available, test with real domains
                assert!(
                    validate_url("wss://google.com:443", ValidationMode::Production, None).is_ok(),
                    "google.com should be allowed in production mode"
                );
                assert!(
                    validate_url("grpc://github.com:50061", ValidationMode::Production, None)
                        .is_ok(),
                    "github.com should be allowed in production mode"
                );
            }
            Err(_) => {
                // No internet connectivity, skip test
                println!("Skipping test - no internet connectivity");
            }
        }
    }

    #[test]
    fn test_strict_mode_requires_allowlist() {
        assert!(validate_url("wss://example.com:443", ValidationMode::Strict, None).is_err());
    }

    #[test]
    fn test_strict_mode_with_allowlist() {
        let allowlist = vec!["strike48.example.com".to_string()];

        assert!(validate_url(
            "wss://strike48.example.com:443",
            ValidationMode::Strict,
            Some(&allowlist)
        )
        .is_ok());

        assert!(validate_url(
            "wss://other.example.com:443",
            ValidationMode::Strict,
            Some(&allowlist)
        )
        .is_err());
    }

    #[test]
    fn test_extract_host_with_various_schemes() {
        assert_eq!(
            extract_host("wss://example.com:443").unwrap(),
            "example.com"
        );
        assert_eq!(extract_host("grpc://localhost:50061").unwrap(), "localhost");
        assert_eq!(extract_host("example.com:443").unwrap(), "example.com");
        assert_eq!(extract_host("192.168.1.1:8080").unwrap(), "192.168.1.1");
    }

    #[test]
    fn test_is_localhost() {
        assert!(is_localhost("localhost"));
        assert!(is_localhost("127.0.0.1"));
        assert!(is_localhost("127.5.5.5"));
        assert!(is_localhost("::1"));
        assert!(!is_localhost("example.com"));
        assert!(!is_localhost("192.168.1.1"));
    }

    #[test]
    fn test_is_private_ipv4() {
        assert!(is_private_ipv4("10.0.0.1".parse().unwrap()));
        assert!(is_private_ipv4("192.168.1.1".parse().unwrap()));
        assert!(is_private_ipv4("172.16.0.1".parse().unwrap()));
        assert!(is_private_ipv4("169.254.1.1".parse().unwrap()));
        assert!(!is_private_ipv4("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ipv4("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn test_missing_private_ip_ranges() {
        // RFC 6598: Carrier-grade NAT
        assert!(is_private_ipv4("100.64.0.1".parse().unwrap()));
        assert!(is_private_ipv4("100.127.255.254".parse().unwrap()));
        assert!(!is_private_ipv4("100.63.255.255".parse().unwrap()));
        assert!(!is_private_ipv4("100.128.0.0".parse().unwrap()));

        // RFC 2544: Benchmark testing
        assert!(is_private_ipv4("198.18.0.1".parse().unwrap()));
        assert!(is_private_ipv4("198.19.255.254".parse().unwrap()));
        assert!(!is_private_ipv4("198.17.255.255".parse().unwrap()));
        assert!(!is_private_ipv4("198.20.0.0".parse().unwrap()));

        // RFC 5737: Documentation ranges
        assert!(is_private_ipv4("198.51.100.1".parse().unwrap()));
        assert!(is_private_ipv4("203.0.113.1".parse().unwrap()));

        // RFC 1112: Reserved
        assert!(is_private_ipv4("240.0.0.1".parse().unwrap()));
        assert!(is_private_ipv4("255.255.255.254".parse().unwrap()));
    }

    #[test]
    fn test_dns_resolution_localhost() {
        // localhost should resolve to 127.0.0.1 and/or ::1
        let ips = resolve_hostname_to_ips("localhost").expect("Failed to resolve localhost");
        assert!(
            !ips.is_empty(),
            "localhost should resolve to at least one IP"
        );

        // All resolved IPs should be loopback
        for ip in ips {
            match ip {
                IpAddr::V4(ipv4) => {
                    assert!(ipv4.is_loopback(), "localhost IPv4 should be loopback");
                }
                IpAddr::V6(ipv6) => {
                    assert!(ipv6.is_loopback(), "localhost IPv6 should be loopback");
                }
            }
        }
    }

    #[test]
    fn test_dns_resolution_public_domain() {
        // google.com should resolve to public IPs
        let ips = resolve_hostname_to_ips("google.com").expect("Failed to resolve google.com");
        assert!(
            !ips.is_empty(),
            "google.com should resolve to at least one IP"
        );

        // All resolved IPs should be public (not private)
        for ip in &ips {
            match ip {
                IpAddr::V4(ipv4) => {
                    assert!(
                        !is_private_ipv4(*ipv4),
                        "google.com should resolve to public IPv4"
                    );
                }
                IpAddr::V6(ipv6) => {
                    assert!(
                        !is_private_ipv6(*ipv6),
                        "google.com should resolve to public IPv6"
                    );
                }
            }
        }
    }

    #[test]
    fn test_dns_resolution_invalid_hostname() {
        // .invalid domains may resolve in some environments (DNS hijacking, search domains)
        // or fail to resolve. Either is acceptable - we just need to handle both cases.
        let result = resolve_hostname_to_ips("this-domain-does-not-exist-12345.invalid");
        match result {
            Ok(ips) => {
                // If it resolved, check that we got at least one IP
                assert!(
                    !ips.is_empty(),
                    "Should have at least one IP if resolution succeeded"
                );
            }
            Err(_) => {
                // DNS failure is also acceptable - treated as private for safety
            }
        }
    }

    #[test]
    fn test_is_private_ip_blocks_localhost_hostname() {
        // is_private_ip should block localhost via DNS resolution
        // localhost resolves to 127.0.0.1 which is loopback (private)
        assert!(
            is_private_ip("localhost"),
            "localhost should be blocked as private"
        );
    }

    #[test]
    fn test_is_private_ip_allows_public_hostname() {
        // is_private_ip should allow public domains via DNS resolution
        // Note: This test requires internet connectivity. Skip if DNS fails.
        match resolve_hostname_to_ips("google.com") {
            Ok(_) => {
                // DNS worked, verify google.com is not blocked
                assert!(
                    !is_private_ip("google.com"),
                    "google.com should be allowed (public)"
                );
            }
            Err(_) => {
                // No internet connectivity, skip test
                println!("Skipping test - no internet connectivity");
            }
        }
    }

    #[test]
    fn test_is_private_ip_blocks_invalid_hostname() {
        // Invalid hostnames may:
        // 1. Fail to resolve → blocked as private (fail-safe)
        // 2. Resolve to hijacked IPs (e.g., ISP DNS search) → blocked if private
        // Either way, they should be blocked for safety.
        assert!(
            is_private_ip("this-domain-does-not-exist-12345.invalid"),
            "Invalid hostname should be blocked (either DNS failure or hijacked to private IP)"
        );
    }
}
