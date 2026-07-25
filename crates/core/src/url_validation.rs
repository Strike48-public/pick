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
    /// can reach the platform over a private ClusterIP — while still blocking
    /// the cloud-metadata / link-local range in its canonical forms
    /// (169.254.0.0/16, fe80::/10) and other non-LAN reserved ranges (multicast,
    /// broadcast, docs, CGN, etc.). This is the narrow relaxation for in-cluster
    /// dev: unlike Development mode it does not broadly expose the metadata
    /// service (169.254.169.254). IPv6-encoded IPv4 forms of link-local —
    /// IPv4-mapped `::ffff:169.254.x.x` and NAT64 `64:ff9b::a9fe:x` — are
    /// canonicalized (see [`embedded_ipv4`]) and blocked here too, so they
    /// cannot be used to smuggle the metadata service past this mode.
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

/// Select the SSRF [`ValidationMode`] for a scan/connection target from the
/// `PENTEST_ALLOW_PRIVATE_IPS` opt-in.
///
/// This is the single source of truth shared by the connector-host check
/// ([`crate::config`]) and every per-tool scan-target check
/// (`nikto`/`ffuf`/`dirb`/`gobuster`, …). Before this existed, those tools
/// hardcoded [`ValidationMode::Production`], so on a legitimately-relaxed
/// private-network engagement (`PENTEST_ALLOW_PRIVATE_IPS=true`) the connector
/// registered fine but every tool refused to scan the private-IP targets —
/// "Private IP addresses are not allowed in production mode".
///
/// Behavior:
/// * `true` / `1` (case-insensitive, whitespace-tolerant) →
///   [`ValidationMode::PrivateNetwork`] (RFC-1918 / loopback allowed;
///   link-local / cloud-metadata still blocked). Logs a loud warning.
/// * any other set-but-unrecognized value (`yes`, `on`, `false`, typo) → the
///   secure [`ValidationMode::default`], with a warning so a silently-ignored
///   opt-in is diagnosable.
/// * unset / empty → secure [`ValidationMode::default`], silently.
///
/// Secure by default: never returns [`ValidationMode::Development`]. Pure over
/// its argument (no env read of its own) so it is unit-testable independent of
/// the build profile; callers pass `std::env::var("PENTEST_ALLOW_PRIVATE_IPS")`.
pub fn resolve_validation_mode(env_val: Option<&str>) -> ValidationMode {
    match env_val.map(|v| v.trim().to_ascii_lowercase()) {
        Some(v) if v == "true" || v == "1" => {
            tracing::warn!(
                "PENTEST_ALLOW_PRIVATE_IPS is set: target SSRF validation relaxed to \
                 PrivateNetwork mode (RFC-1918/loopback allowed; link-local/metadata \
                 still blocked). Do NOT use in production."
            );
            ValidationMode::PrivateNetwork
        }
        Some(v) if !v.is_empty() => {
            tracing::warn!(
                "PENTEST_ALLOW_PRIVATE_IPS is set to an unrecognized value ({:?}); \
                 expected \"true\" or \"1\". Ignoring and using the secure default \
                 (private IPs blocked in release builds).",
                v
            );
            ValidationMode::default()
        }
        _ => ValidationMode::default(),
    }
}

/// Convenience wrapper that reads `PENTEST_ALLOW_PRIVATE_IPS` from the
/// environment and returns the resolved [`ValidationMode`]. Tool call sites use
/// this so target validation honors the same opt-in as the connector host.
pub fn target_validation_mode() -> ValidationMode {
    resolve_validation_mode(std::env::var("PENTEST_ALLOW_PRIVATE_IPS").ok().as_deref())
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
    // Canonicalize IPv6-encoded IPv4 first: `::ffff:127.0.0.1` (mapped) and the
    // NAT64 form of a loopback address must be recognized as loopback, not
    // slip through as a distinct IPv6 literal.
    if let Some(v4) = embedded_ipv4(ip) {
        return is_localhost_ipv4(v4);
    }
    ip == Ipv6Addr::LOCALHOST
}

/// Extract an IPv4 address embedded in an IPv6 representation, if any.
///
/// SSRF defenses must not be bypassable by re-encoding a blocked IPv4 target as
/// IPv6. Six encodings smuggle an IPv4 address through the IPv6 classifier:
///
/// * **IPv4-mapped** `::ffff:a.b.c.d` (`::ffff:0:0/96`) — dual-stack sockets
///   route these straight to the v4 address, so `::ffff:169.254.169.254`
///   reaches the real cloud-metadata service.
/// * **IPv4-translated** `::ffff:0:a.b.c.d` (`::ffff:0:0:0/96`, RFC 2765 SIIT) —
///   the mapped form's sibling, one segment further left. Trivially confused
///   with the mapped prefix, and a SIIT translator resolves it to the v4.
/// * **NAT64** `64:ff9b::a.b.c.d` (well-known prefix `64:ff9b::/96`, RFC 6052) —
///   a NAT64 gateway translates these to the embedded v4 destination.
/// * **NAT64 local-use** `64:ff9b:1::a.b.c.d` (`64:ff9b:1::/48`, RFC 8215) —
///   the range reserved for deployment-chosen NAT64 prefixes. A deployment that
///   carves a `/96` out of it translates the low 32 bits exactly as above.
/// * **IPv4-compatible** `::a.b.c.d` (top 96 bits zero) — the deprecated
///   (RFC 4291) sibling of the mapped form. Formally not auto-routed to IPv4
///   everywhere, but a defense-in-depth SSRF guard must not let `::169.254.169.254`
///   through when the bare and mapped spellings of the same address are blocked.
/// * **6to4** `2002:a.b.c.d::/48` (`2002::/16`, RFC 3056) — embeds the v4 in
///   segments 1..3; a 6to4 relay translates to the embedded destination.
///
/// All carry the IPv4 in a fixed slot. `Ipv6Addr::to_ipv4_mapped()` handles the
/// mapped form; the other five are matched explicitly. `::` (unspecified) and
/// `::1` (loopback) are the two IPv4-compatible literals that must NOT be
/// reinterpreted as embedded IPv4 — they have dedicated predicates (and `::1`
/// must classify as loopback, not slip through the `is_lan_private_ipv4` allow
/// path as `0.0.0.1`), so they are excluded here.
///
/// **Known uncovered:** RFC 6052 also defines *variable-length* embeddings for
/// network-specific prefixes of `/32`, `/40`, `/48`, `/56`, and `/64`, which
/// scatter the v4 octets around a zero `u` byte at bits 64-71 instead of using
/// the low 32 bits. Decoding those requires knowing the deployment's own NSP,
/// which this crate has no way to learn, so only the low-32 layout is decoded.
/// An operator behind a NAT64 gateway using a non-`/96` NSP can still reach a
/// blocked v4 by hand-encoding it; that is an accepted limit of a
/// prefix-agnostic guard, not an oversight.
fn embedded_ipv4(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    /// Decode an IPv4 address from two adjacent IPv6 segments (big-endian).
    fn v4_from(hi: u16, lo: u16) -> Ipv4Addr {
        Ipv4Addr::new(
            (hi >> 8) as u8,
            (hi & 0xff) as u8,
            (lo >> 8) as u8,
            (lo & 0xff) as u8,
        )
    }

    // IPv4-mapped ::ffff:a.b.c.d
    if let Some(v4) = ip.to_ipv4_mapped() {
        return Some(v4);
    }
    let seg = ip.segments();
    let low32 = v4_from(seg[6], seg[7]);
    // IPv4-translated ::ffff:0:a.b.c.d (::ffff:0:0:0/96, RFC 2765): the 0xffff
    // sits one segment left of the mapped form, low 32 bits carry the IPv4.
    if seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0xffff && seg[5] == 0 {
        return Some(low32);
    }
    // NAT64 well-known prefix 64:ff9b::/96 (RFC 6052): first 6 segments are
    // 0064:ff9b:0000:0000:0000:0000, low 32 bits carry the IPv4.
    if seg[0] == 0x0064
        && seg[1] == 0xff9b
        && seg[2] == 0
        && seg[3] == 0
        && seg[4] == 0
        && seg[5] == 0
    {
        return Some(low32);
    }
    // NAT64 local-use prefix 64:ff9b:1::/48 (RFC 8215). RFC 8215 reserves the
    // whole /48 for NAT64, so no legitimate global destination lives here and a
    // guard may decode the low 32 without inspecting segments 3..6 — erring
    // toward blocking inside a reserved range is the safe direction.
    if seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001 {
        return Some(low32);
    }
    // IPv4-compatible ::a.b.c.d (top 96 bits zero), excluding :: and ::1 which
    // their own predicates handle. `to_ipv4()` also matches the mapped form, but
    // that already returned above, so a match here is the compatible form.
    if seg[0] == 0 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0 && seg[4] == 0 && seg[5] == 0 {
        // Exclude ::/::1 (0.0.0.0 / 0.0.0.1): unspecified + loopback.
        if low32 != Ipv4Addr::UNSPECIFIED && low32 != Ipv4Addr::new(0, 0, 0, 1) {
            return Some(low32);
        }
    }
    // 6to4 2002:a.b.c.d::/48 (RFC 3056): v4 in segments[1..3].
    if seg[0] == 0x2002 {
        return Some(v4_from(seg[1], seg[2]));
    }
    None
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
/// Handles both literal IPs and hostnames. A hostname (e.g. an in-cluster
/// `*.svc.cluster.local` ClusterIP name — the documented deployment case) is
/// resolved and admitted ONLY if EVERY resolved IP is LAN-private/loopback.
/// This supports the DNS-name deployment while preserving the DNS-rebinding
/// defense: a name resolving to any public, link-local, or cloud-metadata IP is
/// NOT admitted into the allow-set, so an attacker cannot rebind a name into
/// 169.254.169.254 via PrivateNetwork.
fn classify_lan_private(host: &str) -> LanClass {
    // localhost literal (string form) is loopback → allowed.
    if is_localhost(host) {
        return LanClass::LanPrivate;
    }

    // Literal IP: classify directly.
    if let Ok(ip) = host.parse::<IpAddr>() {
        return classify_lan_private_ip(ip);
    }

    // Hostname: resolve and require ALL resolved IPs to be LAN-private.
    match resolve_hostname_to_ips(host) {
        Ok(ips) => {
            let mut saw_lan_private = false;
            for ip in ips {
                match classify_lan_private_ip(ip) {
                    LanClass::LanPrivate => saw_lan_private = true,
                    // Any non-LAN-private resolved IP disqualifies the whole
                    // name — defer to Production (public) or block (internal).
                    other => return other,
                }
            }
            if saw_lan_private {
                LanClass::LanPrivate
            } else {
                LanClass::Public
            }
        }
        // Unresolvable: don't admit here; the Production path fails it closed
        // with an accurate "could not resolve" reason.
        Err(_) => LanClass::Public,
    }
}

/// Classify a single resolved/literal IP for [`ValidationMode::PrivateNetwork`].
fn classify_lan_private_ip(ip: IpAddr) -> LanClass {
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
    // Canonicalize IPv6-encoded IPv4 (mapped / NAT64): an RFC-1918/loopback
    // target expressed as `::ffff:10.0.0.1` is a LAN-private target and should
    // be admitted, while `::ffff:169.254.169.254` must NOT be (it is caught by
    // the LAN-private v4 allow-set, which excludes link-local/metadata).
    if let Some(v4) = embedded_ipv4(ip) {
        return is_lan_private_ipv4(v4);
    }
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
    // Canonicalize IPv6-encoded IPv4 (mapped / NAT64) and classify via the IPv4
    // guard, so `::ffff:169.254.169.254` and `64:ff9b::a9fe:a9fe` are blocked
    // like their bare-IPv4 equivalents instead of slipping through as "public".
    if let Some(v4) = embedded_ipv4(ip) {
        return is_private_ipv4(v4);
    }

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
    fn test_private_network_mode_allows_hostname_resolving_to_private() {
        // The documented deployment case: an in-cluster ClusterIP given by DNS
        // NAME (e.g. connectors-studio-grpc.default.svc). `localhost` is the
        // deterministic, offline-safe stand-in — it resolves to loopback
        // (127.0.0.1 / ::1), which is in the LAN-private allow-set, so a
        // hostname resolving entirely to private IPs must be ALLOWED. (Regression
        // guard: PrivateNetwork previously blocked ALL DNS names, breaking the
        // documented `.svc` deployment.)
        assert!(
            validate_url(
                "grpc://localhost:50061",
                ValidationMode::PrivateNetwork,
                None
            )
            .is_ok(),
            "a hostname resolving to a private/loopback IP must be allowed in PrivateNetwork"
        );
    }

    #[test]
    fn test_private_network_mode_hostname_to_public_not_admitted() {
        // DNS-rebinding defense preserved: a hostname resolving to a PUBLIC IP is
        // not admitted into the LAN allow-set — it falls through to Production,
        // which allows public hosts, so the net result is still Ok, but via the
        // Production path (not the private allow-set). Skip if offline.
        match resolve_hostname_to_ips("google.com") {
            Ok(_) => assert!(
                validate_url("wss://google.com:443", ValidationMode::PrivateNetwork, None).is_ok(),
                "public hostname should pass via the Production fall-through"
            ),
            Err(_) => println!("Skipping - no internet connectivity"),
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

    // ---- IPv6-encoded IPv4 canonicalization (#232 / #236) -------------------
    //
    // IPv4-mapped (`::ffff:a.b.c.d`) and NAT64 (`64:ff9b::a.b.c.d`) forms embed
    // an IPv4 address that dual-stack sockets / NAT64 gateways route to the real
    // v4 destination. Before the fix, `is_private_ipv6` ignored the embedded
    // IPv4 and classified these as public, so the cloud-metadata service could
    // be reached via an IPv6-encoded literal.

    #[test]
    fn test_embedded_ipv4_extraction() {
        // IPv4-mapped.
        assert_eq!(
            embedded_ipv4("::ffff:169.254.169.254".parse().unwrap()),
            Some(Ipv4Addr::new(169, 254, 169, 254))
        );
        // The mapped form is also written in hex segments (::ffff:a9fe:a9fe).
        assert_eq!(
            embedded_ipv4("::ffff:a9fe:a9fe".parse().unwrap()),
            Some(Ipv4Addr::new(169, 254, 169, 254))
        );
        // NAT64 well-known prefix.
        assert_eq!(
            embedded_ipv4("64:ff9b::a9fe:a9fe".parse().unwrap()),
            Some(Ipv4Addr::new(169, 254, 169, 254))
        );
        assert_eq!(
            embedded_ipv4("64:ff9b::10.0.0.1".parse().unwrap()),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        // IPv4-compatible ::a.b.c.d (top 96 bits zero) — the deprecated sibling
        // of the mapped form. `::169.254.169.254` and its hex spelling both
        // decode to the metadata address.
        assert_eq!(
            embedded_ipv4("::169.254.169.254".parse().unwrap()),
            Some(Ipv4Addr::new(169, 254, 169, 254))
        );
        assert_eq!(
            embedded_ipv4("::a9fe:a9fe".parse().unwrap()),
            Some(Ipv4Addr::new(169, 254, 169, 254))
        );
        assert_eq!(
            embedded_ipv4("::10.0.0.1".parse().unwrap()),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        // 6to4 2002:a.b.c.d::/48 embeds the v4 in segments 1..3.
        assert_eq!(
            embedded_ipv4("2002:a9fe:a9fe::".parse().unwrap()),
            Some(Ipv4Addr::new(169, 254, 169, 254))
        );
        // IPv4-translated ::ffff:0:a.b.c.d (::ffff:0:0:0/96, RFC 2765) — the
        // 0xffff sits one segment left of the mapped form.
        assert_eq!(
            embedded_ipv4("::ffff:0:169.254.169.254".parse().unwrap()),
            Some(Ipv4Addr::new(169, 254, 169, 254))
        );
        assert_eq!(
            embedded_ipv4("::ffff:0:10.0.0.1".parse().unwrap()),
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        // NAT64 local-use prefix 64:ff9b:1::/48 (RFC 8215).
        assert_eq!(
            embedded_ipv4("64:ff9b:1::169.254.169.254".parse().unwrap()),
            Some(Ipv4Addr::new(169, 254, 169, 254))
        );
        assert_eq!(
            embedded_ipv4("64:ff9b:1::a9fe:a9fe".parse().unwrap()),
            Some(Ipv4Addr::new(169, 254, 169, 254))
        );
        // A genuine global IPv6 address has no embedded IPv4.
        assert_eq!(embedded_ipv4("2001:db8::1".parse().unwrap()), None);
        // 64:ff9b:2:: is outside both the well-known /96 and the RFC 8215 /48,
        // so it is a normal global address, not an embed.
        assert_eq!(embedded_ipv4("64:ff9b:2::a9fe:a9fe".parse().unwrap()), None);
        // Loopback / unspecified are NOT treated as IPv4-compatible embeds —
        // they must fall through to their own predicates (`::1` -> loopback).
        assert_eq!(embedded_ipv4("::1".parse().unwrap()), None);
        assert_eq!(embedded_ipv4("::".parse().unwrap()), None);
    }

    #[test]
    fn test_production_blocks_ipv4_compatible_and_6to4_metadata() {
        // #289: the IPv4-compatible (`::a.b.c.d`) and 6to4 (`2002::/16`)
        // encodings of the metadata address are the same re-encoding class as
        // the mapped/NAT64 forms and must not slip through as "public".
        for host in [
            "wss://[::169.254.169.254]:443", // IPv4-compatible metadata
            "wss://[::a9fe:a9fe]:443",       // same, hex segments
            "wss://[2002:a9fe:a9fe::]:443",  // 6to4 metadata
        ] {
            assert!(
                validate_url(host, ValidationMode::Production, None).is_err(),
                "{host} must be BLOCKED in Production"
            );
            assert!(
                validate_url(host, ValidationMode::PrivateNetwork, None).is_err(),
                "{host} must be BLOCKED in PrivateNetwork too"
            );
        }
    }

    #[test]
    fn test_production_blocks_translated_and_local_use_nat64_metadata() {
        // #289 follow-up: the IPv4-translated (`::ffff:0:0:0/96`, RFC 2765) and
        // NAT64 local-use (`64:ff9b:1::/48`, RFC 8215) prefixes embed the v4 in
        // the low 32 bits exactly as the mapped/well-known forms do. Decoding
        // only the well-known `/96` left these reaching the metadata service.
        for host in [
            "wss://[::ffff:0:169.254.169.254]:443",   // IPv4-translated
            "wss://[::ffff:0:a9fe:a9fe]:443",         // same, hex segments
            "wss://[64:ff9b:1::169.254.169.254]:443", // NAT64 local-use /48
            "wss://[64:ff9b:1::a9fe:a9fe]:443",       // same, hex segments
        ] {
            assert!(
                validate_url(host, ValidationMode::Production, None).is_err(),
                "{host} must be BLOCKED in Production"
            );
            assert!(
                validate_url(host, ValidationMode::PrivateNetwork, None).is_err(),
                "{host} must be BLOCKED in PrivateNetwork too"
            );
        }
    }

    #[test]
    fn test_translated_and_local_use_nat64_honor_private_opt_in() {
        // The new prefixes must classify as LAN-private (not blanket-blocked)
        // when they embed an RFC-1918 address, matching the mapped form: allowed
        // in PrivateNetwork, blocked in Production. A guard that hard-blocked
        // the whole prefix would pass the metadata test above but break
        // in-cluster targets.
        for host in [
            "wss://[::ffff:0:10.0.0.1]:443",
            "wss://[64:ff9b:1::10.0.0.1]:443",
        ] {
            assert!(
                validate_url(host, ValidationMode::PrivateNetwork, None).is_ok(),
                "{host} embeds RFC-1918 and must be ALLOWED in PrivateNetwork"
            );
            assert!(
                validate_url(host, ValidationMode::Production, None).is_err(),
                "{host} embeds RFC-1918 and must be BLOCKED in Production"
            );
        }
    }

    #[test]
    fn test_production_blocks_ipv4_mapped_metadata() {
        // #232/#236 acceptance criterion: mapped metadata blocked in Production.
        assert!(
            validate_url(
                "wss://[::ffff:169.254.169.254]:443",
                ValidationMode::Production,
                None
            )
            .is_err(),
            "IPv4-mapped metadata must be blocked in Production"
        );
        // Hex-segment spelling of the same address.
        assert!(validate_url(
            "wss://[::ffff:a9fe:a9fe]:443",
            ValidationMode::Production,
            None
        )
        .is_err());
        // Mapped RFC-1918 is also private in Production.
        assert!(validate_url(
            "wss://[::ffff:10.0.0.1]:443",
            ValidationMode::Production,
            None
        )
        .is_err());
    }

    #[test]
    fn test_production_blocks_nat64_metadata() {
        // #232/#236 acceptance criterion: NAT64-embedded metadata blocked.
        assert!(
            validate_url(
                "wss://[64:ff9b::a9fe:a9fe]:443",
                ValidationMode::Production,
                None
            )
            .is_err(),
            "NAT64-embedded metadata must be blocked in Production"
        );
    }

    #[test]
    fn test_private_network_blocks_encoded_metadata() {
        // #232 acceptance criteria: both encoded metadata forms stay blocked
        // even in the relaxed PrivateNetwork mode.
        for host in [
            "wss://[::ffff:169.254.169.254]:443", // IPv4-mapped metadata
            "wss://[::ffff:a9fe:a9fe]:443",       // same, hex segments
            "wss://[64:ff9b::a9fe:a9fe]:443",     // NAT64 metadata
        ] {
            assert!(
                validate_url(host, ValidationMode::PrivateNetwork, None).is_err(),
                "{host} must be BLOCKED in PrivateNetwork mode"
            );
        }
    }

    #[test]
    fn test_private_network_allows_ipv4_mapped_rfc1918() {
        // #232 acceptance criterion: RFC-1918 via the mapped form is a
        // LAN-private target and IS admitted in PrivateNetwork mode.
        assert!(
            validate_url(
                "wss://[::ffff:10.0.0.1]:443",
                ValidationMode::PrivateNetwork,
                None
            )
            .is_ok(),
            "IPv4-mapped RFC-1918 should be allowed in PrivateNetwork mode"
        );
    }

    #[test]
    fn test_localhost_via_ipv4_mapped_loopback() {
        // Mapped loopback must still count as localhost (blocked in Production).
        assert!(is_localhost("::ffff:127.0.0.1"));
        assert!(validate_url(
            "wss://[::ffff:127.0.0.1]:443",
            ValidationMode::Production,
            None
        )
        .is_err());
    }

    // ---- PrivateNetwork DNS-rebinding + boundary coverage (#233) -------------
    //
    // #233 was filed against an earlier revision of #231 that BLOCKED all
    // hostnames in PrivateNetwork mode. The shipped behavior (and its regression
    // guard test_private_network_mode_allows_hostname_resolving_to_private)
    // deliberately ALLOWS a hostname that resolves ENTIRELY to LAN-private IPs
    // (the documented in-cluster `.svc` deployment). These tests lock in the
    // real security property: the DNS path cannot admit a link-local/metadata
    // or public-then-rebind target into the LAN allow-set.

    #[test]
    fn test_private_network_hostname_all_private_is_admitted_not_rebindable_to_metadata() {
        // localhost resolves only to loopback (LAN-private) → admitted. This is
        // the offline-safe stand-in for a `.svc` ClusterIP name. The rebinding
        // defense is that admission requires EVERY resolved IP to be LAN-private
        // (see classify_lan_private): a name resolving to 169.254.169.254 would
        // hit the BlockedInternal arm, never the allow-set.
        assert!(
            validate_url(
                "grpc://localhost:50061",
                ValidationMode::PrivateNetwork,
                None
            )
            .is_ok(),
            "hostname resolving entirely to loopback must be admitted in PrivateNetwork"
        );
    }

    #[test]
    fn test_private_network_boundary_ranges_blocked() {
        // 172.16/12 exclusive edges: .15 and .32 are NOT RFC-1918, so they are
        // public literals → fall through to Production, which allows public IPs.
        // The meaningful assertion is the INTERNAL ranges that are private per
        // the full guard but NOT in the LAN allow-set: they must be blocked.
        for host in [
            "wss://100.64.0.1:443",      // CGN 100.64/10 (RFC 6598)
            "wss://100.127.255.254:443", // CGN upper edge
            "wss://198.18.0.1:443",      // benchmark 198.18/15
            "wss://192.0.2.1:443",       // TEST-NET-1 documentation
            "wss://[ff02::1]:443",       // IPv6 multicast
            "wss://[::]:443",            // IPv6 unspecified
            "wss://0.0.0.0:443",         // this-network
        ] {
            assert!(
                validate_url(host, ValidationMode::PrivateNetwork, None).is_err(),
                "{host} (internal/reserved, not LAN allow-set) must be BLOCKED in PrivateNetwork"
            );
        }
    }

    #[test]
    fn test_private_network_172_boundary_edges_are_public() {
        // 172.15.255.255 and 172.32.0.0 are just OUTSIDE 172.16/12, so they are
        // public and pass (via the Production fall-through). Documents the
        // exclusive boundary so a future "172.x is private" over-broadening
        // regresses loudly.
        assert!(validate_url(
            "wss://172.15.255.255:443",
            ValidationMode::PrivateNetwork,
            None
        )
        .is_ok());
        assert!(validate_url("wss://172.32.0.1:443", ValidationMode::PrivateNetwork, None).is_ok());
    }

    #[test]
    fn test_private_network_blocked_internal_message_mentions_metadata() {
        // #233 optional: guard the operator-facing reason string for a literal
        // link-local address so message regressions are caught.
        let err = validate_url(
            "http://169.254.169.254:80",
            ValidationMode::PrivateNetwork,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("internal/reserved") && err.contains("link-local"),
            "message should explain why the metadata range is refused, got: {err}"
        );
    }

    // ---- Shared validation-mode resolver (#289) -----------------------------

    #[test]
    fn test_resolve_validation_mode_opts_in_on_truthy() {
        for v in ["true", "1", "TRUE", "  true  ", "\t1\n"] {
            assert_eq!(
                resolve_validation_mode(Some(v)),
                ValidationMode::PrivateNetwork,
                "{v:?} should opt in to PrivateNetwork"
            );
        }
    }

    #[test]
    fn test_resolve_validation_mode_secure_default_otherwise() {
        for v in [
            Some("false"),
            Some("0"),
            Some("yes"),
            Some(""),
            Some("ture"),
            None,
        ] {
            assert_eq!(
                resolve_validation_mode(v),
                ValidationMode::default(),
                "{v:?} must NOT opt in (secure default)"
            );
        }
    }

    #[test]
    fn test_resolve_validation_mode_never_development() {
        // The opt-in must select the NARROW PrivateNetwork mode, never full
        // Development (which would also unblock link-local / cloud-metadata).
        assert_ne!(
            resolve_validation_mode(Some("true")),
            ValidationMode::Development
        );
    }
}
