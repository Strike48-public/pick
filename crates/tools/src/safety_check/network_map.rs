//! Network device discovery and mapping.

use super::types::{Device, NetworkMap, ThreatLevel};
use anyhow::Context;
use std::net::IpAddr;
use std::process::Stdio;
use tokio::process::Command;

/// Discover devices on the local network using ARP scanning.
///
/// Uses nmap with `-sn` flag (ping scan, no port scan) to quickly discover
/// active hosts on the local subnet.
///
/// # Errors
///
/// Returns error if nmap is not available or if network discovery completely fails.
pub async fn discover_network() -> anyhow::Result<NetworkMap> {
    tracing::debug!("Starting network device discovery");

    // Get gateway and local IP
    let gateway_info = get_gateway_and_local_ip().await?;
    let (gateway_ip, local_ip) = gateway_info;

    tracing::info!("Discovered: gateway={}, local={}", gateway_ip, local_ip);

    // Determine subnet to scan
    let subnet = determine_subnet(&local_ip)?;

    tracing::info!("Scanning subnet: {}", subnet);

    // Run nmap ARP scan
    let discovered_ips = run_nmap_arp_scan(&subnet).await?;

    tracing::info!("Discovered {} hosts", discovered_ips.len());

    // Build device list
    let gateway = Device {
        ip: gateway_ip,
        mac: None, // TODO: Get from ARP table
        hostname: None,
        vendor: None,
        open_ports: Vec::new(),
        threat_level: ThreatLevel::Safe,
    };

    let your_device = Device {
        ip: local_ip,
        mac: None,
        hostname: None,
        vendor: None,
        open_ports: Vec::new(),
        threat_level: ThreatLevel::Safe,
    };

    let mut other_devices = Vec::new();
    for ip in discovered_ips {
        // Skip gateway and local IP
        if ip == gateway_ip || ip == local_ip {
            continue;
        }

        other_devices.push(Device {
            ip,
            mac: None,      // TODO: Get from ARP table
            hostname: None, // TODO: Reverse DNS lookup
            vendor: None,   // TODO: OUI lookup
            open_ports: Vec::new(),
            threat_level: ThreatLevel::Safe,
        });
    }

    Ok(NetworkMap {
        gateway,
        your_device,
        other_devices,
    })
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
