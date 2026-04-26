//! URL validation for preventing SSRF attacks
//!
//! This module provides URL validation to prevent Server-Side Request Forgery (SSRF)
//! attacks by blocking connections to private/internal IP addresses and localhost.

use crate::error::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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
fn is_private_ip(host: &str) -> bool {
    // Try to parse as IP address
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
            IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
        };
    }

    // For hostnames, we cannot reliably check without DNS resolution
    // In a production system, you might want to resolve and check
    // For now, we assume hostnames are safe (they go through DNS)
    false
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
        assert!(validate_url(
            "wss://strike48.example.com:443",
            ValidationMode::Production,
            None
        )
        .is_ok());
        assert!(validate_url(
            "grpc://api.example.com:50061",
            ValidationMode::Production,
            None
        )
        .is_ok());
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
}
