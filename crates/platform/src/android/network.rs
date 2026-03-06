//! Android network operations

use crate::traits::*;
use pentest_core::error::Result;
use std::time::{Duration, Instant};

/// Perform a port scan
pub async fn port_scan(config: ScanConfig) -> Result<ScanResult> {
    let start = Instant::now();
    let timeout = Duration::from_millis(config.timeout_ms);

    let ports = crate::common::tcp_port_scan(&config.host, &config.ports, timeout, 0).await;

    let open_count = ports.iter().filter(|p| p.open).count();
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(ScanResult {
        host: config.host,
        ports,
        duration_ms,
        open_count,
    })
}

/// Get the ARP table with layered fallback (bd-23):
/// 1. Try /proc/net/arp
/// 2. If empty, try `ip neigh show`
/// 3. If that fails, warn and return empty
pub async fn get_arp_table() -> Result<Vec<ArpEntry>> {
    // Layer 1: /proc/net/arp
    let entries = arp_from_proc().await;
    if !entries.is_empty() {
        return Ok(entries);
    }

    // Layer 2: `ip neigh show`
    let entries = arp_from_ip_neigh().await;
    if !entries.is_empty() {
        return Ok(entries);
    }

    tracing::warn!("ARP table: both /proc/net/arp and ip neigh returned empty");
    Ok(vec![])
}

async fn arp_from_proc() -> Vec<ArpEntry> {
    let content = match tokio::fs::read_to_string("/proc/net/arp").await {
        Ok(c) => c,
        Err(_) => return vec![],
    };

    crate::common::parse_proc_arp(&content)
}

/// Run `ip neigh show` and parse the output via [`crate::common::parse_ip_neigh`].
async fn arp_from_ip_neigh() -> Vec<ArpEntry> {
    let output = match tokio::process::Command::new("ip")
        .args(["neigh", "show"])
        .output()
        .await
    {
        Ok(o) => o,
        Err(_) => return vec![],
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    crate::common::parse_ip_neigh(&stdout)
}

/// Discover SSDP devices
pub async fn ssdp_discover(timeout_ms: u64) -> Result<Vec<SsdpDevice>> {
    use std::net::UdpSocket;

    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return Ok(vec![]),
    };

    let _ = socket.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    let _ = socket.set_broadcast(true);

    let search_request = "M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: 2\r\n\
        ST: ssdp:all\r\n\r\n";

    let multicast_addr = "239.255.255.250:1900";
    if socket
        .send_to(search_request.as_bytes(), multicast_addr)
        .is_err()
    {
        return Ok(vec![]);
    }

    let mut devices = Vec::new();
    let mut buf = [0u8; 2048];

    while let Ok((len, _)) = socket.recv_from(&mut buf) {
        let response = String::from_utf8_lossy(&buf[..len]);
        if let Some(device) = parse_ssdp_response(&response) {
            devices.push(device);
        }
    }

    Ok(devices)
}

fn parse_ssdp_response(response: &str) -> Option<SsdpDevice> {
    let mut location = None;
    let mut server = None;
    let mut usn = None;
    let mut st = None;

    for line in response.lines() {
        let line = line.trim();
        if let Some(value) = line
            .strip_prefix("LOCATION:")
            .or_else(|| line.strip_prefix("Location:"))
        {
            location = Some(value.trim().to_string());
        } else if let Some(value) = line
            .strip_prefix("SERVER:")
            .or_else(|| line.strip_prefix("Server:"))
        {
            server = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("USN:") {
            usn = Some(value.trim().to_string());
        } else if let Some(value) = line.strip_prefix("ST:") {
            st = Some(value.trim().to_string());
        }
    }

    location.map(|loc| SsdpDevice {
        location: loc,
        server,
        usn,
        st,
        friendly_name: None,
        manufacturer: None,
        model: None,
    })
}
