//! Scan-free host network context: what subnets is this host actually on?
//!
//! The recurring operational failure this module addresses: an agent falls back
//! to a hallucinated range (e.g. `192.168.1.0/24`) instead of gathering network
//! facts, then scans the wrong network. The correct subnet is derivable from the
//! interface netmask - this module exposes that derivation as a plain, cheap
//! accessor (no nmap sweep, no ARP), so scanners can resolve `auto`/`current`
//! targets and the agent can be seeded with real subnets up front.
//!
//! Pure subnet math lives here (unit-testable, no I/O); [`network_context`] wraps
//! it with a single interface-enumeration call.

use pentest_platform::{get_platform, NetworkInterface, SystemInfo};
use std::net::{IpAddr, Ipv4Addr};

/// Narrowest (largest) prefix a derived subnet is ever widened to.
///
/// An interface may report a very wide prefix (e.g. /8 on some VPN/container
/// setups). A derived sweep subnet must never silently become "scan the whole
/// /8" (16M addresses). When the real prefix is wider than this, the subnet is
/// clamped to `/16` (bounded, still large) and the narrowing is logged so it is
/// observable. Mirrors the cap enforced by the safety-check discovery sweep.
pub const MIN_SUBNET_PREFIX: u8 = 16;

/// An active IPv4 subnet this host is on, plus whether it is the primary
/// (default-route) interface's subnet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subnet {
    /// Network CIDR in canonical base form, e.g. `"10.0.8.0/22"`.
    pub cidr: String,
    /// Interface name this subnet was derived from (e.g. `"eth0"`).
    pub interface: String,
    /// True if this is the default-route interface's subnet (the `current`
    /// target); the rest are secondary segments included by `auto`/`all`.
    pub is_primary: bool,
}

/// Compute the network-base CIDR for an IPv4 host + prefix (pure).
///
/// * Computes the network base via the netmask (`addr & mask`), so a /22 host
///   `10.0.11.5` yields `10.0.8.0/22`, not `10.0.11.0/24`.
/// * Clamps a `0` prefix and anything wider than [`MIN_SUBNET_PREFIX`] to the
///   cap - logging the narrowing - so a wide interface prefix cannot become an
///   implicit huge scan. A nonsensical `>32` is defensively clamped to `32`
///   (unreachable from a real prefix, so not logged).
///
/// Free of any interface/I/O so the subnet math is unit-testable.
pub fn subnet_cidr_v4(addr: Ipv4Addr, prefix_len: u8) -> String {
    let effective = if prefix_len == 0 || prefix_len < MIN_SUBNET_PREFIX {
        tracing::info!(
            "Interface prefix /{} is wider than the /{} cap; clamping derived subnet \
             to /{} to avoid an oversized scan",
            prefix_len,
            MIN_SUBNET_PREFIX,
            MIN_SUBNET_PREFIX
        );
        MIN_SUBNET_PREFIX
    } else {
        prefix_len.min(32)
    };

    // `effective` is in 16..=32 here, so the shift is well-defined.
    let mask: u32 = u32::MAX << (32 - effective as u32);
    let network = u32::from(addr) & mask;
    format!("{}/{}", Ipv4Addr::from(network), effective)
}

/// Derive the CIDR base for a single interface address (pure).
///
/// Returns `None` for a non-IPv4 address, a missing prefix (unknown netmask), or
/// a malformed address - never a guessed default. A known prefix is required
/// because the whole point is to stop inventing subnet sizes.
fn subnet_for_ipv4(ip: &str, prefix_len: Option<u8>) -> Option<String> {
    let bare = ip.split('/').next().unwrap_or(ip);
    let prefix = prefix_len?;
    match bare.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) if !v4.is_loopback() && !v4.is_link_local() => {
            Some(subnet_cidr_v4(v4, prefix))
        }
        _ => None,
    }
}

/// Reduce enumerated interfaces to a deduplicated list of active IPv4 subnets
/// (pure).
///
/// * Skips loopback interfaces and down interfaces.
/// * Marks a subnet primary when its interface name matches `primary_iface`.
/// * Drops addresses with no known prefix (can't derive a subnet without
///   inventing one) and non-IPv4 addresses (IPv6 subnets not yet modeled).
/// * Deduplicates by CIDR, preferring the primary attribution if any interface
///   claiming that CIDR is the primary.
///
/// Extracted from [`network_context`] so the derivation rules are unit-testable
/// without live interface enumeration.
pub fn subnets_from_interfaces(
    interfaces: &[NetworkInterface],
    primary_iface: Option<&str>,
) -> Vec<Subnet> {
    let mut out: Vec<Subnet> = Vec::new();
    for iface in interfaces {
        if iface.is_loopback || !iface.is_up {
            continue;
        }
        let is_primary = primary_iface == Some(iface.name.as_str());
        for addr in &iface.addresses {
            let Some(cidr) = subnet_for_ipv4(&addr.ip, addr.prefix_len) else {
                continue;
            };
            match out.iter_mut().find(|s| s.cidr == cidr) {
                Some(existing) => {
                    // A CIDR already seen: keep primary attribution if either
                    // sighting is primary.
                    existing.is_primary = existing.is_primary || is_primary;
                }
                None => out.push(Subnet {
                    cidr,
                    interface: iface.name.clone(),
                    is_primary,
                }),
            }
        }
    }
    out
}

/// Enumerate this host's active IPv4 subnets, scan-free.
///
/// One interface-enumeration call plus pure derivation - no nmap, no ARP. The
/// primary (default-route) subnet is flagged via `default_net`. Best-effort on
/// the primary detection: if the default interface can't be determined, no
/// subnet is marked primary (callers treat `current` as "first available").
///
/// # Errors
///
/// Propagates a platform interface-enumeration failure - the caller decides
/// whether an empty/failed context is fatal (e.g. resolving `auto` with no
/// known subnets) or merely degraded.
pub async fn network_context() -> pentest_core::error::Result<Vec<Subnet>> {
    let platform = get_platform();
    let interfaces = platform.get_network_interfaces().await?;
    let primary = default_net::get_default_interface().ok().map(|i| i.name);
    Ok(subnets_from_interfaces(&interfaces, primary.as_deref()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_platform::InterfaceAddr;

    fn iface(
        name: &str,
        up: bool,
        loopback: bool,
        addrs: &[(&str, Option<u8>)],
    ) -> NetworkInterface {
        NetworkInterface {
            name: name.to_string(),
            addresses: addrs
                .iter()
                .map(|(ip, p)| InterfaceAddr::new(*ip, *p))
                .collect(),
            mac_address: None,
            is_up: up,
            is_loopback: loopback,
        }
    }

    #[test]
    fn subnet_cidr_computes_network_base_from_prefix() {
        // The core fix: a /22 host resolves to its real /22 base, not a /24.
        assert_eq!(
            subnet_cidr_v4("10.0.11.5".parse().unwrap(), 22),
            "10.0.8.0/22"
        );
        assert_eq!(
            subnet_cidr_v4("192.168.40.130".parse().unwrap(), 24),
            "192.168.40.0/24"
        );
        assert_eq!(
            subnet_cidr_v4("192.168.1.130".parse().unwrap(), 25),
            "192.168.1.128/25"
        );
    }

    #[test]
    fn subnet_cidr_computes_base_via_netmask_across_prefixes() {
        // Not "zero the last octet": /25 of .130 -> .128, /26 of .200 -> .192,
        // /30 of .6 -> .4, /23 spanning two octets.
        assert_eq!(
            subnet_cidr_v4("172.16.5.9".parse().unwrap(), 23),
            "172.16.4.0/23"
        );
        assert_eq!(
            subnet_cidr_v4("10.0.0.200".parse().unwrap(), 26),
            "10.0.0.192/26"
        );
        assert_eq!(
            subnet_cidr_v4("10.0.0.6".parse().unwrap(), 30),
            "10.0.0.4/30"
        );
    }

    #[test]
    fn subnet_cidr_prefix_32_is_single_address() {
        assert_eq!(
            subnet_cidr_v4("203.0.113.7".parse().unwrap(), 32),
            "203.0.113.7/32"
        );
    }

    #[test]
    fn subnet_cidr_clamps_overly_wide_prefix() {
        // #182 safety cap: a prefix wider than /16 must clamp to /16, never
        // expand to a /8-scale sweep. A degenerate /0 clamps too (guards the
        // shift). /16 itself (the cap) passes through unchanged.
        assert_eq!(
            subnet_cidr_v4("10.1.2.3".parse().unwrap(), 8),
            "10.1.0.0/16"
        );
        assert_eq!(
            subnet_cidr_v4("172.20.30.40".parse().unwrap(), 12),
            "172.20.0.0/16"
        );
        assert_eq!(
            subnet_cidr_v4("10.1.2.3".parse().unwrap(), 0),
            "10.1.0.0/16"
        );
        assert_eq!(
            subnet_cidr_v4("10.1.2.3".parse().unwrap(), 16),
            "10.1.0.0/16"
        );
    }

    #[test]
    fn subnet_cidr_absurd_prefix_clamps_to_32() {
        // Unreachable from a real prefix, but guard the defensive >32 clamp so
        // the left-shift can never panic.
        assert_eq!(
            subnet_cidr_v4("10.0.0.1".parse().unwrap(), 99),
            "10.0.0.1/32"
        );
    }

    #[test]
    fn subnet_for_ipv4_requires_known_prefix() {
        // No prefix -> None (we refuse to invent a subnet size).
        assert_eq!(subnet_for_ipv4("10.0.8.5", None), None);
        // Loopback / link-local excluded.
        assert_eq!(subnet_for_ipv4("127.0.0.1", Some(8)), None);
        assert_eq!(subnet_for_ipv4("169.254.1.1", Some(16)), None);
        // Valid -> derived base.
        assert_eq!(
            subnet_for_ipv4("10.0.11.5", Some(22)),
            Some("10.0.8.0/22".to_string())
        );
    }

    #[test]
    fn multi_homed_host_yields_all_subnets_with_primary_flagged() {
        // The motivating case: two active interfaces on different subnets.
        let ifaces = vec![
            iface("enx0024", true, false, &[("10.0.8.42", Some(22))]),
            iface("wlp0s20", true, false, &[("10.0.40.5", Some(24))]),
            iface("lo", true, true, &[("127.0.0.1", Some(8))]),
        ];
        let subnets = subnets_from_interfaces(&ifaces, Some("wlp0s20"));

        assert_eq!(subnets.len(), 2, "loopback excluded, both LAN subnets kept");
        let primary: Vec<_> = subnets.iter().filter(|s| s.is_primary).collect();
        assert_eq!(primary.len(), 1);
        assert_eq!(primary[0].cidr, "10.0.40.0/24");
        assert!(subnets
            .iter()
            .any(|s| s.cidr == "10.0.8.0/22" && !s.is_primary));
    }

    #[test]
    fn down_interface_and_unknown_prefix_are_skipped() {
        let ifaces = vec![
            iface("eth0", false, false, &[("10.0.8.42", Some(22))]), // down
            iface("eth1", true, false, &[("10.0.9.5", None)]),       // no prefix
        ];
        assert!(subnets_from_interfaces(&ifaces, None).is_empty());
    }

    #[test]
    fn duplicate_cidr_deduplicated_keeping_primary() {
        // Two interfaces on the same CIDR: one primary. Result carries it once,
        // marked primary.
        let ifaces = vec![
            iface("eth0", true, false, &[("10.0.8.42", Some(22))]),
            iface("eth1", true, false, &[("10.0.8.99", Some(22))]),
        ];
        let subnets = subnets_from_interfaces(&ifaces, Some("eth1"));
        assert_eq!(subnets.len(), 1);
        assert_eq!(subnets[0].cidr, "10.0.8.0/22");
        assert!(subnets[0].is_primary);
    }
}
