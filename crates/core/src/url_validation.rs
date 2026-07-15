//! URL validation for preventing SSRF attacks
//!
//! This module provides URL validation to prevent Server-Side Request Forgery (SSRF)
//! attacks by blocking connections to private/internal IP addresses and localhost.

use crate::error::{Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

/// URL validation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationMode {
    /// Development mode - allows EVERYTHING (localhost, private IPs, link-local,
    /// cloud-metadata). No SSRF protection at all; only for local iteration.
    Development,
    /// Production mode - blocks localhost and all private/internal ranges.
    Production,
    /// PrivateNetwork mode - allows RFC-1918 private ranges (10/8, 172.16/12,
    /// 192.168/16), loopback, and IPv6 ULA/loopback so an in-cluster connector
    /// can reach the platform over a private ClusterIP — while STILL blocking
    /// the cloud-metadata / link-local range (169.254.0.0/16, fe80::/10) and
    /// other non-LAN reserved ranges (multicast, broadcast, docs, CGN, etc.).
    /// This is the narrow relaxation for in-cluster dev: it does not expose the
    /// prime SSRF credential-theft target (169.254.169.254) the way Development
    /// does.
    PrivateNetwork,
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

    // In PrivateNetwork mode, allow LAN-private ranges + loopback (the
    // in-cluster ClusterIP case) but still reject the dangerous non-LAN ranges
    // — chiefly link-local / cloud-metadata (169.254.0.0/16, fe80::/10). Only
    // hosts that are literal IPs or resolve to LAN-private IPs are accepted;
    // everything else falls through to the standard Production checks below.
    if mode == ValidationMode::PrivateNetwork {
        match classify_lan_private(&host) {
            LanClass::LanPrivate => return Ok(url.to_string()),
            LanClass::BlockedInternal(reason) => {
                return Err(Error::PermissionDenied(reason));
            }
            // Public (or a hostname resolving to public IPs): fall through to
            // the Production path so public targets are validated identically.
            LanClass::Public => {}
        }
    }

    // In Production mode, validate against SSRF patterns
    if is_localhost(&host) {
        return Err(Error::PermissionDenied(
            "Localhost addresses are not allowed in production mode".to_string(),
        ));
    }

    match classify_host(&host) {
        HostClass::Public => {}
        HostClass::Private => {
            return Err(Error::PermissionDenied(
                "Private IP addresses are not allowed in production mode".to_string(),
            ));
        }
        HostClass::Unresolvable(reason) => {
            // Fail closed, but say WHY: previously any DNS failure was reported
            // as "Private IP addresses are not allowed", which is misleading (a
            // resolver hiccup is not a private address). Distinguish the two.
            return Err(Error::PermissionDenied(format!(
                "Could not resolve hostname '{host}' ({reason}); blocked for safety in production mode"
            )));
        }
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

    // Strip everything from the first path / query / fragment delimiter onward,
    // leaving just the authority (host[:port] or [ipv6][:port]). Without this,
    // a URL with a path but no port (e.g. https://gitlab.com/a/b.csv) fed the
    // whole "gitlab.com/a/b.csv" to DNS resolution, which failed and was then
    // mislabelled as a private-IP block — breaking resource seeding.
    //
    // IPv6 bracket notation is handled first so the ':' inside "[2001:db8::1]"
    // is not mistaken for a port separator.
    let authority = if remaining.starts_with('[') {
        remaining
    } else {
        remaining
            .find(['/', '?', '#'])
            .map_or(remaining, |i| &remaining[..i])
    };

    // Extract host (handle IPv6 bracket notation: [::1]:443 or [2001:db8::1]/path)
    let host = if authority.starts_with('[') {
        // IPv6 bracket notation - find closing bracket (anything after it, such
        // as :port or /path, is discarded).
        if let Some(bracket_end) = authority.find(']') {
            // Return just the host inside brackets (without the brackets)
            &authority[1..bracket_end]
        } else {
            return Err(Error::InvalidParams(
                "IPv6 bracket notation incomplete - missing closing bracket".to_string(),
            ));
        }
    } else if let Some(colon_pos) = authority.find(':') {
        // IPv4 or hostname with port
        &authority[..colon_pos]
    } else {
        // No port specified
        authority
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

/// SSRF classification of a host: safe to reach, a private/internal target, or
/// unresolvable (which we still block, but for a distinct, honest reason).
#[derive(Debug)]
enum HostClass {
    Public,
    Private,
    Unresolvable(String),
}

/// Classify a host for SSRF purposes.
///
/// Performs DNS resolution to prevent DNS rebinding attacks. If the host is a
/// hostname (not an IP), it resolves all A/AAAA records and treats the host as
/// private if ANY resolved IP is in a private range. A resolution *failure* is
/// reported as [`HostClass::Unresolvable`] (still blocked upstream, fail-closed)
/// rather than being conflated with an actual private address.
fn classify_host(host: &str) -> HostClass {
    // Try to parse as IP address
    if let Ok(ip) = host.parse::<IpAddr>() {
        let private = match ip {
            IpAddr::V4(ipv4) => is_private_ipv4(ipv4),
            IpAddr::V6(ipv6) => is_private_ipv6(ipv6),
        };
        return if private {
            HostClass::Private
        } else {
            HostClass::Public
        };
    }

    // For hostnames, perform DNS resolution to prevent DNS rebinding attacks:
    // an attacker points a domain at a public IP during validation, then swaps
    // DNS to a private IP afterward. Defense: resolve now and reject if ANY
    // resolved IP is private.
    match resolve_hostname_to_ips(host) {
        Ok(ips) => {
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
                    return HostClass::Private;
                }
            }
            HostClass::Public
        }
        Err(e) => {
            tracing::warn!(
                "Failed to resolve hostname {}: {}, blocking for safety",
                host,
                e
            );
            HostClass::Unresolvable(e.to_string())
        }
    }
}

/// Check if a host resolves to a private IP address.
///
/// Thin wrapper over [`classify_host`] that preserves the original boolean
/// contract (unresolvable is treated as private, i.e. blocked). Retained for
/// the test suite; production code uses [`classify_host`] so a resolution
/// failure can be reported accurately rather than as "private IP".
#[cfg(test)]
fn is_private_ip(host: &str) -> bool {
    !matches!(classify_host(host), HostClass::Public)
}

/// Classification for [`ValidationMode::PrivateNetwork`].
///
/// * `LanPrivate` — a LAN-private target we permit (RFC-1918 / loopback /
///   IPv6 ULA / IPv6 loopback).
/// * `BlockedInternal` — an internal/reserved address we still refuse even in
///   PrivateNetwork mode (link-local / cloud-metadata, multicast, broadcast,
///   documentation, CGN, benchmark, etc.). Carries the operator-facing reason.
/// * `Public` — not a private/internal literal; caller should apply the normal
///   Production validation (handles public IPs and hostname DNS resolution).
#[derive(Debug)]
enum LanClass {
    LanPrivate,
    BlockedInternal(String),
    Public,
}

/// Classify a host for [`ValidationMode::PrivateNetwork`].
///
/// Only literal IPs are decided here; hostnames return [`LanClass::Public`] so
/// the caller runs them through the DNS-resolving Production path (which
/// rejects any hostname resolving to a private range — we intentionally do NOT
/// let a hostname resolve into the LAN-private allow-set, to avoid DNS-rebinding
/// into, say, the metadata service via a name).
fn classify_lan_private(host: &str) -> LanClass {
    // localhost literal (string form) is loopback → allowed.
    if is_localhost(host) {
        return LanClass::LanPrivate;
    }

    let Ok(ip) = host.parse::<IpAddr>() else {
        // Not a literal IP — defer to the Production/DNS path.
        return LanClass::Public;
    };

    match ip {
        IpAddr::V4(v4) => {
            if is_lan_private_ipv4(v4) {
                LanClass::LanPrivate
            } else if is_private_ipv4(v4) {
                // Private per the full guard but NOT in the LAN allow-set:
                // link-local/metadata, multicast, broadcast, docs, CGN, etc.
                LanClass::BlockedInternal(format!(
                    "Address {v4} is an internal/reserved range not permitted even in private-network mode (e.g. link-local/metadata 169.254.0.0/16)"
                ))
            } else {
                LanClass::Public
            }
        }
        IpAddr::V6(v6) => {
            if is_lan_private_ipv6(v6) {
                LanClass::LanPrivate
            } else if is_private_ipv6(v6) {
                LanClass::BlockedInternal(format!(
                    "Address {v6} is an internal/reserved range not permitted even in private-network mode (e.g. link-local fe80::/10)"
                ))
            } else {
                LanClass::Public
            }
        }
    }
}

/// LAN-private IPv4 allow-set for PrivateNetwork mode: the three RFC-1918
/// ranges plus loopback. Deliberately EXCLUDES link-local (169.254/16) and all
/// other reserved ranges that [`is_private_ipv4`] also treats as private.
fn is_lan_private_ipv4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    // 10.0.0.0/8
    if o[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if o[0] == 172 && (16..=31).contains(&o[1]) {
        return true;
    }
    // 192.168.0.0/16
    if o[0] == 192 && o[1] == 168 {
        return true;
    }
    // 127.0.0.0/8 (loopback)
    if o[0] == 127 {
        return true;
    }
    false
}

/// LAN-private IPv6 allow-set for PrivateNetwork mode: unique-local (fc00::/7)
/// and loopback (::1). Excludes link-local (fe80::/10) and multicast.
fn is_lan_private_ipv6(ip: Ipv6Addr) -> bool {
    // Loopback ::1
    if ip == Ipv6Addr::LOCALHOST {
        return true;
    }
    // Unique local addresses fc00::/7
    if (ip.segments()[0] & 0xfe00) == 0xfc00 {
        return true;
    }
    false
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
    fn test_private_network_mode_allows_rfc1918_and_loopback() {
        // The in-cluster ClusterIP case: RFC-1918 ranges + loopback are allowed.
        for host in [
            "grpc://10.109.18.109:50061", // k8s service range (10/8)
            "grpc://10.244.0.14:50061",   // k8s pod range
            "wss://192.168.1.1:443",
            "wss://172.16.0.1:443",
            "wss://172.31.255.255:443",
            "ws://127.0.0.1:50061",
            "ws://localhost:50061",
            "grpc://[::1]:50061",
            "grpc://[fd00::1]:50061", // IPv6 ULA
        ] {
            assert!(
                validate_url(host, ValidationMode::PrivateNetwork, None).is_ok(),
                "{host} should be allowed in PrivateNetwork mode"
            );
        }
    }

    #[test]
    fn test_private_network_mode_still_blocks_link_local_and_metadata() {
        // The whole point of the narrow mode: the cloud-metadata / link-local
        // range stays blocked even though other private ranges are allowed.
        for host in [
            "http://169.254.169.254:80", // AWS/GCP metadata service
            "http://169.254.170.2:80",   // ECS task metadata
            "wss://169.254.1.1:443",     // link-local generally
            "wss://[fe80::1]:443",       // IPv6 link-local
            "wss://224.0.0.1:443",       // multicast
            "wss://255.255.255.255:443", // broadcast
            "wss://0.0.0.0:443",         // this-network
        ] {
            assert!(
                validate_url(host, ValidationMode::PrivateNetwork, None).is_err(),
                "{host} must be BLOCKED in PrivateNetwork mode"
            );
        }
    }

    #[test]
    fn test_private_network_mode_allows_public_ips() {
        // Public literals still pass (they fall through to the Production path).
        assert!(validate_url("wss://8.8.8.8:443", ValidationMode::PrivateNetwork, None).is_ok());
        assert!(validate_url("wss://1.1.1.1:443", ValidationMode::PrivateNetwork, None).is_ok());
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
    fn test_extract_host_strips_path() {
        // Regression: a URL with a path but NO port must return only the host,
        // not "host/path/...". Previously the no-port branch returned the whole
        // remainder, so the SSRF validator tried to DNS-resolve
        // "gitlab.com/exploit-database/.../files.csv" as a hostname, failed, and
        // mislabelled it "Private IP addresses are not allowed" — breaking Seed.
        assert_eq!(
            extract_host(
                "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
            )
            .unwrap(),
            "gitlab.com"
        );
        assert_eq!(
            extract_host("https://raw.githubusercontent.com/danielmiessler/SecLists/master/x.txt")
                .unwrap(),
            "raw.githubusercontent.com"
        );
        // Host + port + path together.
        assert_eq!(
            extract_host("https://example.com:8443/some/path").unwrap(),
            "example.com"
        );
        // Trailing slash, no path segments.
        assert_eq!(extract_host("https://example.com/").unwrap(), "example.com");
        // Query string with no path.
        assert_eq!(
            extract_host("https://example.com?foo=bar").unwrap(),
            "example.com"
        );
        // IPv6 with path.
        assert_eq!(
            extract_host("https://[2001:db8::1]/path").unwrap(),
            "2001:db8::1"
        );
        assert_eq!(
            extract_host("https://[2001:db8::1]:8080/path").unwrap(),
            "2001:db8::1"
        );
    }

    #[test]
    fn test_pathful_public_url_not_blocked_as_private() {
        // The end-to-end symptom: a public HTTPS URL with a path should pass
        // Production validation (subject to DNS). Skip if offline.
        match resolve_hostname_to_ips("raw.githubusercontent.com") {
            Ok(_) => assert!(
                validate_url(
                    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/x.txt",
                    ValidationMode::Production,
                    None,
                )
                .is_ok(),
                "public pathful URL must not be blocked as private"
            ),
            Err(_) => println!("Skipping - no internet connectivity"),
        }
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

    #[test]
    fn test_ipv6_bracket_notation() {
        // IPv6 localhost with brackets
        assert!(validate_url("wss://[::1]:443", ValidationMode::Development, None).is_ok());
        assert!(validate_url("wss://[::1]:443", ValidationMode::Production, None).is_err());

        // IPv6 address with brackets (full form)
        assert!(validate_url(
            "https://[2001:db8::1]:8080",
            ValidationMode::Development,
            None
        )
        .is_ok());

        // IPv6 without port
        assert!(validate_url("https://[2001:db8::1]", ValidationMode::Development, None).is_ok());

        // IPv6 link-local should be blocked in Production
        assert!(validate_url("wss://[fe80::1]:443", ValidationMode::Production, None).is_err());
    }

    #[test]
    fn test_ipv6_bracket_notation_malformed() {
        // Missing closing bracket
        assert!(validate_url("wss://[::1:443", ValidationMode::Development, None).is_err());

        // Empty brackets
        assert!(validate_url("wss://[]:443", ValidationMode::Development, None).is_err());
    }
}
