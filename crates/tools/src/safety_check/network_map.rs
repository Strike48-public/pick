//! Network device discovery and mapping.

use super::oui;
use super::types::{Device, NetworkMap, ThreatLevel};
use anyhow::Context;
use pentest_platform::NetworkOps;
use std::collections::HashMap;
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

    // Build device list, enriching gateway and local device too.
    let gateway = build_device(gateway_ip, &arp_info);
    let your_device = build_device(local_ip, &arp_info);

    let mut other_devices = Vec::new();
    for ip in host_ips {
        // Skip gateway and local IP (rendered separately).
        if ip == gateway_ip || ip == local_ip {
            continue;
        }
        other_devices.push(build_device(ip, &arp_info));
    }

    Ok(NetworkMap {
        gateway,
        your_device,
        other_devices,
    })
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
    fn exactly_16_is_not_clamped() {
        // Boundary: /16 is the cap itself, so it passes through unchanged.
        assert_eq!(
            subnet_cidr_v4(Ipv4Addr::new(10, 1, 2, 3), 16),
            "10.1.0.0/16"
        );
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
