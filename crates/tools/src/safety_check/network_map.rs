//! Network device discovery and mapping.

use super::oui;
use super::types::{Device, NetworkMap, ThreatLevel};
use anyhow::Context;
use pentest_platform::NetworkOps;
use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Stdio;
use tokio::process::Command;

/// Open-port count above which a host is considered unusually exposed.
///
/// A device advertising this many services on a public/shared network is
/// noteworthy (could be a server, a poorly-secured host, or an attacker's
/// box). Kept conservative to avoid alarming a non-technical user over a
/// normal NAS or printer.
const SUSPICIOUS_PORT_THRESHOLD: usize = 10;

/// Enrichment data for a single host, keyed by IP, drawn from the ARP table.
struct ArpInfo {
    mac: Option<String>,
    hostname: Option<String>,
}

/// Discover devices on the local network and enrich them.
///
/// Merges two host sources: an nmap `-sn` ping sweep of the local /24 (fast,
/// finds hosts not yet contacted) and the system ARP/neighbor table (instant,
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
    let (gateway_ip, local_ip) = gateway_info;

    tracing::info!("Discovered: gateway={}, local={}", gateway_ip, local_ip);

    // Enrichment source: MAC + hostname per IP from the system ARP/neighbor
    // table. This doubles as a discovery source - the kernel already knows
    // every neighbor it has talked to, across subnets, instantly and with
    // MACs. A failure here just yields a less-detailed map, never a failure.
    let arp_info = collect_arp_info().await;

    // Discovery source 1: an nmap ping sweep of the local /24. Fast and finds
    // hosts we have not yet talked to. Best-effort - on a larger network this
    // only covers our own /24, which is why we also merge the ARP table.
    let subnet = determine_subnet(&local_ip)?;
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

/// Get gateway and local IP address.
async fn get_gateway_and_local_ip() -> anyhow::Result<(IpAddr, IpAddr)> {
    let interface = tokio::task::spawn_blocking(default_net::get_default_interface)
        .await
        .context("Failed to spawn interface detection task")?
        .map_err(|e| anyhow::anyhow!("Failed to detect default network interface: {}", e))?;

    let gateway = interface
        .gateway
        .context("No gateway found on default interface")?;
    let gateway_ip = gateway.ip_addr;

    let local_ip = interface
        .ipv4
        .first()
        .map(|net| IpAddr::V4(net.addr))
        .context("No IPv4 address on default interface")?;

    Ok((gateway_ip, local_ip))
}

/// Determine the subnet CIDR notation from a local IP.
///
/// Assumes /24 subnet for simplicity. In production, we'd use the netmask
/// from the interface.
fn determine_subnet(local_ip: &IpAddr) -> anyhow::Result<String> {
    match local_ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            Ok(format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]))
        }
        IpAddr::V6(_) => {
            anyhow::bail!("IPv6 subnets not yet supported");
        }
    }
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
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let subnet = determine_subnet(&ip).unwrap();
        assert_eq!(subnet, "192.168.1.0/24");
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
