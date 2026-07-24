//! Network device discovery and mapping.

use super::oui;
use super::types::{Device, NetworkMap, ThreatLevel};
use anyhow::Context;
use pentest_platform::{NetworkOps, SystemInfo};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Stdio;
use tokio::process::Command;

/// Open-port count above which a host is considered unusually exposed.
///
/// A device advertising this many services on a public/shared network is
/// noteworthy (could be a server, a poorly-secured host, or an attacker's
/// box). Kept conservative to avoid alarming a non-technical user over a
/// normal NAS or printer.
const SUSPICIOUS_PORT_THRESHOLD: usize = 10;

/// Narrowest (largest) prefix we will ever widen a discovery sweep to.
///
/// The interface may legitimately report a very wide prefix (e.g. /8 on some
/// VPN or container setups). Sweeping a /8 is 16M addresses - a netmask fix
/// (#182) must never silently turn into "scan the whole /8". When the real
/// prefix is wider than this, we clamp the sweep subnet to `/16` (still large,
/// but bounded) and log the clamp so the narrowing is observable. The full
/// host-count bounding for sizing lives in `cap_for_network_size` (mod.rs).
const MIN_SUBNET_PREFIX: u8 = 16;

/// Enrichment data for a single host, keyed by IP, drawn from the ARP table.
struct ArpInfo {
    mac: Option<String>,
    hostname: Option<String>,
}

/// Discover devices on the local network and enrich them.
///
/// Merges two host sources: an nmap `-sn` ping sweep of the local subnet
/// (derived from the interface netmask, capped at /16 - fast, finds hosts not
/// yet contacted) and the system ARP/neighbor table (instant,
/// cross-subnet, carries MACs). Each host is then enriched with MAC address and
/// hostname from the ARP table and a vendor name via OUI lookup. nmap is
/// best-effort - if it is unavailable, the ARP table alone is used.
///
/// # Errors
///
/// Returns error only if the gateway/local interface cannot be determined.
pub async fn discover_network() -> anyhow::Result<NetworkMap> {
    tracing::debug!("Starting network device discovery");

    // Get gateway and local IP
    let gateway_info = get_gateway_and_local_ip().await?;
    let (gateway_ip, local_ip, local_prefix) = gateway_info;

    tracing::info!("Discovered: gateway={}, local={}", gateway_ip, local_ip);

    // Enrichment source: MAC + hostname per IP from the system ARP/neighbor
    // table. This doubles as a discovery source - the kernel already knows
    // every neighbor it has talked to, across subnets, instantly and with
    // MACs. A failure here just yields a less-detailed map, never a failure.
    let arp_info = collect_arp_info().await;

    // Discovery source 1: an nmap ping sweep of the local subnet, derived from
    // the interface netmask (capped at /16). Fast and finds hosts we have not
    // yet talked to. Best-effort - on a wider network the /16 cap means the
    // sweep may not cover the whole segment, which is why we also merge the
    // ARP table.
    let subnet = determine_subnet(&local_ip, local_prefix)?;
    let nmap_ips = match run_nmap_arp_scan(&subnet).await {
        Ok(ips) => {
            tracing::info!("nmap discovered {} hosts in {}", ips.len(), subnet);
            ips
        }
        Err(e) => {
            // Not fatal: the ARP neighbor table alone is a valid host source.
            tracing::warn!("nmap sweep unavailable ({}); relying on ARP table", e);
            Vec::new()
        }
    };

    // Merge both sources into a deduplicated host set. ARP contributes
    // cross-subnet neighbors (e.g. the gateway in a /16) that a /24 sweep
    // would miss.
    let mut host_ips: std::collections::BTreeSet<IpAddr> = nmap_ips.into_iter().collect();
    host_ips.extend(arp_info.keys().copied());

    tracing::info!(
        "Total unique hosts after ARP+nmap merge: {}",
        host_ips.len()
    );

    // Self-attribution: collect every IP that belongs to THIS host, across all
    // interfaces (VPN tun, docker0/virbr0, mesh like Tailscale, a second NIC),
    // so Pick never reports its own addresses back as foreign "devices" on the
    // network. `get_gateway_and_local_ip` only knows the default-route address;
    // a multi-interface operator box has many more. Best-effort - if interface
    // enumeration fails we fall back to excluding just the default local IP.
    let mut own_ips = collect_own_ips().await;
    own_ips.insert(local_ip);

    // Build device list, enriching gateway and local device too.
    let gateway = build_device(gateway_ip, &arp_info);
    let your_device = build_device(local_ip, &arp_info);

    let other_devices = filter_foreign_hosts(host_ips, gateway_ip, &own_ips)
        .into_iter()
        .map(|ip| build_device(ip, &arp_info))
        .collect();

    Ok(NetworkMap {
        gateway,
        your_device,
        other_devices,
    })
}

/// Pure helper: from a discovered host set, keep only genuinely foreign hosts.
///
/// Excludes the gateway (rendered separately) and every address that belongs to
/// this host (`own_ips` - all local interfaces, not just the default one). This
/// is the self-reflection fix: without excluding the full `own_ips` set, a
/// multi-interface box (VPN/container/mesh) surfaces its own other addresses as
/// foreign "devices". Kept free of I/O so the exclusion is unit-testable.
fn filter_foreign_hosts<I>(
    host_ips: I,
    gateway_ip: IpAddr,
    own_ips: &HashSet<IpAddr>,
) -> Vec<IpAddr>
where
    I: IntoIterator<Item = IpAddr>,
{
    host_ips
        .into_iter()
        .filter(|ip| *ip != gateway_ip && !own_ips.contains(ip))
        .collect()
}

/// Build an enriched [`Device`] for an IP using ARP data and OUI lookup.
fn build_device(ip: IpAddr, arp_info: &HashMap<IpAddr, ArpInfo>) -> Device {
    let (mac, hostname) = match arp_info.get(&ip) {
        Some(info) => (info.mac.clone(), info.hostname.clone()),
        None => (None, None),
    };

    let vendor = mac
        .as_deref()
        .and_then(oui::lookup_vendor)
        .map(str::to_string);

    let open_ports: Vec<u16> = Vec::new();
    let threat_level = classify_threat(&open_ports);

    Device {
        ip,
        mac,
        hostname,
        vendor,
        open_ports,
        threat_level,
    }
}

/// Classify a host's threat level from local signals.
///
/// Conservative by design: only an unusually large number of open ports
/// raises a host to Suspicious. Confirmed-malicious classification is driven
/// by threat-intelligence enrichment (handled in the threat-intel check), not
/// here. With no port data yet (Phase 1 does no per-host port scan) every host
/// is Safe; the threshold is wired in for when port enrichment lands.
///
// TODO(self-attribution): when per-host port scanning lands, this will scan
// THIS host too and flag the listeners Pick's own installed tools opened (msf
// handlers, BloodHound Neo4j 7474/7687, etc.) as Suspicious. Before enabling
// port enrichment, subtract Pick-owned listeners via the installer registry +
// provenance (crates/core/src/provenance.rs) - the same self-filter applied to
// local IPs in `collect_own_ips`. See memory note
// `project-safety-check-self-reflection` for the full rationale.
fn classify_threat(open_ports: &[u16]) -> ThreatLevel {
    if open_ports.len() >= SUSPICIOUS_PORT_THRESHOLD {
        ThreatLevel::Suspicious
    } else {
        ThreatLevel::Safe
    }
}

/// Collect MAC + hostname per IP from the system ARP table (best-effort).
///
/// Returns an empty map on any failure - the caller treats missing enrichment
/// as simply less detail, not an error.
async fn collect_arp_info() -> HashMap<IpAddr, ArpInfo> {
    let platform = pentest_platform::get_platform();
    let entries = match platform.get_arp_table().await {
        Ok(entries) => entries,
        Err(e) => {
            tracing::debug!("ARP table unavailable for enrichment: {}", e);
            return HashMap::new();
        }
    };

    let mut map = HashMap::new();
    for entry in entries {
        let Ok(ip) = entry.ip.parse::<IpAddr>() else {
            continue;
        };
        // Treat an all-zero or empty MAC as absent.
        let mac = if entry.mac.is_empty() || entry.mac == "00:00:00:00:00:00" {
            None
        } else {
            Some(entry.mac)
        };
        map.insert(
            ip,
            ArpInfo {
                mac,
                hostname: entry.hostname,
            },
        );
    }
    map
}

/// Collect every IP address that belongs to this host, across all interfaces.
///
/// Uses the platform's interface enumeration (already implemented per-OS) so
/// the safety check can subtract Pick's own footprint before rendering the
/// network map. Without this, a VPN/container/mesh interface makes the host
/// see its own other addresses as foreign devices (self-reflection).
///
/// Best-effort: returns an empty set on any failure - the caller still excludes
/// the default local IP, so a failure just means a less-complete self-filter,
/// never an error. On failure we log at `warn`, not `debug`: an incomplete
/// self-filter silently weakens the whole check (the host's other-interface IPs
/// can reappear as foreign "devices"), so the degradation must be observable.
async fn collect_own_ips() -> HashSet<IpAddr> {
    let platform = pentest_platform::get_platform();
    match platform.get_network_interfaces().await {
        Ok(interfaces) => {
            let own = own_ips_from_interfaces(interfaces);
            tracing::info!(
                "Self-filter: {} local address(es) will be excluded",
                own.len()
            );
            own
        }
        Err(e) => {
            tracing::warn!(
                "Interface enumeration failed ({}); self-filter is INCOMPLETE - only the \
                 default local IP will be excluded, so VPN/container/mesh addresses may \
                 appear as foreign devices",
                e
            );
            HashSet::new()
        }
    }
}

/// Pure helper: reduce a set of network interfaces to this host's own IPs.
///
/// Extracted from [`collect_own_ips`] so the parsing/filtering rules are
/// unit-testable without live interface enumeration. Rules:
/// - loopback interfaces are skipped (never part of a LAN map);
/// - a CIDR suffix on the address string (e.g. "192.168.1.42/24") is stripped;
/// - loopback and IPv6 link-local (`fe80::/10`) addresses are excluded even if
///   the interface's `is_loopback` flag is unset or the backend mislabels them
///   (defense-in-depth against a buggy per-platform backend);
/// - a malformed address is dropped with a `debug` breadcrumb rather than
///   silently vanishing.
fn own_ips_from_interfaces(interfaces: Vec<pentest_platform::NetworkInterface>) -> HashSet<IpAddr> {
    let mut own = HashSet::new();
    for iface in interfaces {
        if iface.is_loopback {
            continue;
        }
        for ip_str in iface.ip_addresses {
            // Interface addresses may carry a CIDR suffix (e.g. "192.168.1.42/24")
            // depending on the platform backend; strip it before parsing.
            let addr = ip_str.split('/').next().unwrap_or(ip_str.as_str());
            match addr.parse::<IpAddr>() {
                Ok(ip) if is_own_addressable(&ip) => {
                    own.insert(ip);
                }
                Ok(_) => {
                    // Loopback / link-local: real but never a foreign LAN host,
                    // so no need to carry it in the self-filter set.
                }
                Err(e) => {
                    tracing::debug!("Ignoring malformed interface address {:?}: {}", ip_str, e);
                }
            }
        }
    }
    own
}

/// True if an address is a routable/LAN address worth excluding as "ours".
///
/// Filters out loopback and IPv6 link-local (`fe80::/10`) - addresses that
/// cannot appear as a distinct foreign host on the LAN map, so they never need
/// to be in the self-filter set.
fn is_own_addressable(ip: &IpAddr) -> bool {
    if ip.is_loopback() {
        return false;
    }
    if let IpAddr::V6(v6) = ip {
        // IPv6 link-local fe80::/10.
        if (v6.segments()[0] & 0xffc0) == 0xfe80 {
            return false;
        }
    }
    true
}

/// Get gateway and local IP address, plus the local IPv4 prefix length.
///
/// The prefix comes from `default_net`'s `Ipv4Net` (which carries `prefix_len`
/// / `netmask` alongside the address); it is threaded out here so the sweep
/// subnet reflects the real netmask instead of an assumed /24 (#182). `None`
/// when there is no IPv4 (should not happen given the `.context` below, but the
/// type keeps the IPv6-only future honest).
async fn get_gateway_and_local_ip() -> anyhow::Result<(IpAddr, IpAddr, Option<u8>)> {
    let interface = tokio::task::spawn_blocking(default_net::get_default_interface)
        .await
        .context("Failed to spawn interface detection task")?
        .map_err(|e| anyhow::anyhow!("Failed to detect default network interface: {}", e))?;

    let gateway = interface
        .gateway
        .context("No gateway found on default interface")?;
    let gateway_ip = gateway.ip_addr;

    let local_net = interface
        .ipv4
        .first()
        .context("No IPv4 address on default interface")?;
    let local_ip = IpAddr::V4(local_net.addr);
    let prefix_len = Some(local_net.prefix_len);

    Ok((gateway_ip, local_ip, prefix_len))
}

/// Determine the subnet CIDR notation from a local IP and its prefix length.
///
/// Uses the interface's real prefix instead of assuming /24 (#182). The network
/// base address is computed by applying the netmask (`addr & mask`), so a /25
/// host `.130` yields `.128/25`, not `.0/24`. A missing prefix (e.g. a future
/// IPv6-only path) falls back to /24 for IPv4 to preserve prior behavior.
///
/// Safety cap: a prefix wider than [`MIN_SUBNET_PREFIX`] is clamped up to it, so
/// the discovery sweep is never silently widened to a /8-scale range.
fn determine_subnet(local_ip: &IpAddr, prefix_len: Option<u8>) -> anyhow::Result<String> {
    match local_ip {
        IpAddr::V4(ipv4) => Ok(subnet_cidr_v4(*ipv4, prefix_len.unwrap_or(24))),
        IpAddr::V6(_) => {
            anyhow::bail!("IPv6 subnets not yet supported");
        }
    }
}

/// Pure helper: compute the sweep-subnet CIDR for an IPv4 host + prefix.
///
/// * Clamps a `0` prefix and anything wider than [`MIN_SUBNET_PREFIX`] to the
///   cap - logging the narrowing - so a wide interface prefix can't become an
///   implicit huge scan. A nonsensical `>32` is defensively clamped to `32`
///   (unreachable from a real `Ipv4Net`, so it is not logged).
/// * Computes the network base via the netmask, not by zeroing octets.
///
/// Kept free of any interface/I/O so the subnet math is unit-testable.
fn subnet_cidr_v4(addr: Ipv4Addr, prefix_len: u8) -> String {
    let effective = if prefix_len == 0 || prefix_len < MIN_SUBNET_PREFIX {
        tracing::info!(
            "Interface prefix /{} is wider than the /{} sweep cap; clamping discovery \
             subnet to /{} to avoid an oversized scan",
            prefix_len,
            MIN_SUBNET_PREFIX,
            MIN_SUBNET_PREFIX
        );
        MIN_SUBNET_PREFIX
    } else {
        prefix_len.min(32)
    };

    // Netmask for the effective prefix. `effective` is in 16..=32 here, so the
    // shift is well-defined (a /0 would need the all-zero mask special-case,
    // but the clamp above guarantees effective >= 16).
    let mask: u32 = u32::MAX << (32 - effective as u32);
    let network = u32::from(addr) & mask;
    format!("{}/{}", Ipv4Addr::from(network), effective)
}

/// Run nmap ARP scan to discover hosts on the subnet.
async fn run_nmap_arp_scan(subnet: &str) -> anyhow::Result<Vec<IpAddr>> {
    // Check if nmap is available
    let nmap_check = Command::new("nmap")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await;

    if nmap_check.is_err() || !nmap_check.unwrap().success() {
        anyhow::bail!("nmap not found - install nmap to enable network discovery");
    }

    // Run nmap with -sn (ping scan, no port scan) for speed
    let output = Command::new("nmap")
        .arg("-sn") // Ping scan only
        .arg("-T4") // Aggressive timing (faster)
        .arg(subnet)
        .output()
        .await
        .context("Failed to run nmap")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("nmap failed: {}", stderr);
    }

    // Parse output for IP addresses
    let stdout = String::from_utf8_lossy(&output.stdout);
    let ips = parse_nmap_output(&stdout);

    if ips.is_empty() {
        tracing::warn!("No hosts discovered by nmap");
    }

    Ok(ips)
}

/// Parse nmap output to extract discovered IP addresses.
fn parse_nmap_output(output: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();

    for line in output.lines() {
        // Look for "Nmap scan report for <IP>"
        if line.starts_with("Nmap scan report for ") {
            if let Some(ip_str) = line.split_whitespace().last() {
                // Remove parentheses if present
                let ip_str = ip_str.trim_start_matches('(').trim_end_matches(')');
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    ips.push(ip);
                }
            }
        }
    }

    ips
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_determine_subnet() {
        // A /24 host still derives the /24 network (backward-compat).
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let subnet = determine_subnet(&ip, Some(24)).unwrap();
        assert_eq!(subnet, "192.168.1.0/24");
    }

    #[test]
    fn test_determine_subnet_no_prefix_defaults_to_24() {
        // A missing prefix falls back to /24, preserving the old behavior.
        let ip = IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40));
        assert_eq!(determine_subnet(&ip, None).unwrap(), "10.20.30.0/24");
    }

    #[test]
    fn test_determine_subnet_ipv6_is_explicitly_unsupported() {
        let ip: IpAddr = "fe80::1".parse().unwrap();
        assert!(determine_subnet(&ip, Some(64)).is_err());
    }

    #[test]
    fn derives_subnet_from_real_prefix_not_assumed_24() {
        // #182: the derived subnet must reflect the real prefix, not /24.
        assert_eq!(
            subnet_cidr_v4(Ipv4Addr::new(172, 16, 5, 9), 23),
            "172.16.4.0/23"
        );
        assert_eq!(
            subnet_cidr_v4(Ipv4Addr::new(192, 168, 1, 130), 25),
            "192.168.1.128/25"
        );
    }

    #[test]
    fn computes_network_address_via_netmask_not_by_zeroing_octet() {
        // /25 of .130 -> .128 (bit 7 of the last octet is part of the network),
        // NOT .0 as a "zero the last octet" shortcut would give.
        assert_eq!(
            subnet_cidr_v4(Ipv4Addr::new(192, 168, 1, 130), 25),
            "192.168.1.128/25"
        );
        // /26 of .200 -> .192.
        assert_eq!(
            subnet_cidr_v4(Ipv4Addr::new(10, 0, 0, 200), 26),
            "10.0.0.192/26"
        );
        // /30 of .6 -> .4.
        assert_eq!(
            subnet_cidr_v4(Ipv4Addr::new(10, 0, 0, 6), 30),
            "10.0.0.4/30"
        );
    }

    #[test]
    fn exact_host_prefix_32_is_single_address() {
        assert_eq!(
            subnet_cidr_v4(Ipv4Addr::new(203, 0, 113, 7), 32),
            "203.0.113.7/32"
        );
    }

    #[test]
    fn very_wide_prefix_is_capped_not_silently_swept() {
        // #182 safety cap: a prefix wider than /16 must clamp to /16, never
        // expand the sweep to a /8-scale range. The network base is recomputed
        // at the clamped prefix.
        assert_eq!(subnet_cidr_v4(Ipv4Addr::new(10, 1, 2, 3), 8), "10.1.0.0/16");
        assert_eq!(
            subnet_cidr_v4(Ipv4Addr::new(172, 20, 30, 40), 12),
            "172.20.0.0/16"
        );
        // A degenerate /0 also clamps to /16 (guards the shift, too).
        assert_eq!(subnet_cidr_v4(Ipv4Addr::new(10, 1, 2, 3), 0), "10.1.0.0/16");
    }

    #[test]
    fn absurd_prefix_clamps_to_32() {
        // Unreachable from a real Ipv4Net, but guard the defensive >32 clamp
        // so it can never panic on the left-shift.
        assert_eq!(
            subnet_cidr_v4(Ipv4Addr::new(10, 0, 0, 1), 99),
            "10.0.0.1/32"
        );
    }

    #[test]
    fn exactly_16_is_not_clamped() {
        // Boundary: /16 is the cap itself, so it passes through unchanged.
        assert_eq!(
            subnet_cidr_v4(Ipv4Addr::new(10, 1, 2, 3), 16),
            "10.1.0.0/16"
        );
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn foreign_filter_excludes_all_own_interface_ips_not_just_default() {
        // The self-reflection bug: a host's OTHER interface addresses (VPN,
        // docker, mesh) show up in the discovered host set. They must be
        // excluded as our own, not surfaced as foreign devices.
        let gateway = ip("192.168.50.1");
        let default_local = ip("192.168.50.100");
        let own: HashSet<IpAddr> = [
            default_local,
            ip("172.17.0.1"),    // docker0
            ip("192.168.122.1"), // virbr0
            ip("100.64.0.1"),    // mesh VPN e.g. tailscale (CGNAT range)
        ]
        .into_iter()
        .collect();

        let discovered = vec![
            gateway,
            default_local,
            ip("172.17.0.1"),    // our own - must be dropped
            ip("100.64.0.1"),    // our own - must be dropped
            ip("192.168.50.55"), // a genuine peer - must stay
            ip("192.168.50.56"), // a genuine peer - must stay
        ];

        let foreign = filter_foreign_hosts(discovered, gateway, &own);

        // Only the two genuine peers survive.
        assert_eq!(foreign.len(), 2, "own IPs and gateway must be excluded");
        assert!(foreign.contains(&ip("192.168.50.55")));
        assert!(foreign.contains(&ip("192.168.50.56")));
        // Guard: none of our own addresses leaked through as "devices".
        assert!(!foreign.contains(&ip("172.17.0.1")));
        assert!(!foreign.contains(&ip("100.64.0.1")));
        assert!(!foreign.contains(&gateway));
    }

    fn iface(name: &str, is_loopback: bool, ips: &[&str]) -> pentest_platform::NetworkInterface {
        pentest_platform::NetworkInterface {
            name: name.to_string(),
            ip_addresses: ips.iter().map(|s| s.to_string()).collect(),
            mac_address: None,
            is_up: true,
            is_loopback,
        }
    }

    #[test]
    fn own_ips_strips_cidr_suffix_ipv4_and_ipv6() {
        let ifaces = vec![
            iface("eth0", false, &["192.168.1.42/24"]),
            iface("eth1", false, &["10.0.0.5"]),  // no suffix
            iface("wg0", false, &["fd00::1/64"]), // ULA v6 with suffix
        ];
        let own = own_ips_from_interfaces(ifaces);
        assert!(own.contains(&ip("192.168.1.42")));
        assert!(own.contains(&ip("10.0.0.5")));
        assert!(own.contains(&ip("fd00::1")));
    }

    #[test]
    fn own_ips_skips_loopback_interface_and_loopback_addr() {
        // A loopback *interface* is skipped wholesale...
        let via_iface = own_ips_from_interfaces(vec![iface("lo", true, &["127.0.0.1", "::1"])]);
        assert!(via_iface.is_empty());
        // ...and a loopback *address* on a non-loopback iface is excluded too
        // (defense against a backend that mislabels is_loopback).
        let via_addr = own_ips_from_interfaces(vec![iface("eth0", false, &["127.0.0.1"])]);
        assert!(
            via_addr.is_empty(),
            "loopback addr must not enter self-filter"
        );
    }

    #[test]
    fn own_ips_excludes_ipv6_link_local() {
        // fe80::/10 is per-interface local, never a distinct foreign LAN host.
        let own = own_ips_from_interfaces(vec![iface(
            "eth0",
            false,
            &["fe80::1343:2e71:941d:6935", "192.168.1.10"],
        )]);
        assert!(!own.iter().any(|i| i.to_string().starts_with("fe80")));
        assert!(own.contains(&ip("192.168.1.10")));
    }

    #[test]
    fn own_ips_drops_malformed_without_panicking() {
        let own = own_ips_from_interfaces(vec![iface(
            "eth0",
            false,
            &["192.168.1.256", "not-an-ip", "10.0.0.9"],
        )]);
        // Only the one valid address survives; malformed entries are dropped.
        assert_eq!(own.len(), 1);
        assert!(own.contains(&ip("10.0.0.9")));
    }

    #[test]
    fn own_ips_empty_interface_list_is_empty_set() {
        assert!(own_ips_from_interfaces(vec![]).is_empty());
    }

    #[test]
    fn foreign_filter_keeps_peers_when_only_default_ip_is_known() {
        // Degraded path (interface enumeration failed): own_ips has just the
        // default local IP. Real peers must still be reported.
        let gateway = ip("192.168.1.1");
        let own: HashSet<IpAddr> = [ip("192.168.1.100")].into_iter().collect();
        let discovered = vec![gateway, ip("192.168.1.100"), ip("192.168.1.50")];

        let foreign = filter_foreign_hosts(discovered, gateway, &own);

        assert_eq!(foreign, vec![ip("192.168.1.50")]);
    }

    #[test]
    fn test_parse_nmap_output() {
        let output = r#"
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.1.1
Host is up (0.0010s latency).
Nmap scan report for 192.168.1.100
Host is up (0.00050s latency).
Nmap scan report for 192.168.1.50
Host is up (0.0020s latency).
Nmap done: 256 IP addresses (3 hosts up) scanned in 2.5 seconds
"#;

        let ips = parse_nmap_output(output);
        assert_eq!(ips.len(), 3);
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));
    }

    #[test]
    fn test_parse_nmap_output_with_hostnames() {
        let output = r#"
Nmap scan report for router.local (192.168.1.1)
Host is up.
Nmap scan report for desktop.local (192.168.1.100)
Host is up.
"#;

        let ips = parse_nmap_output(output);
        assert_eq!(ips.len(), 2);
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(ips.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
    }

    #[tokio::test]
    #[ignore] // Requires nmap installed and network access
    async fn test_discover_network_integration() {
        let result = discover_network().await;
        if let Ok(map) = result {
            // Gateway and local device must resolve to real (non-0.0.0.0) IPs.
            assert!(!map.gateway.ip.is_unspecified());
            assert!(!map.your_device.ip.is_unspecified());
        }
    }
}
