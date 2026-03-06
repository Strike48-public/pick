//! Desktop network operations implementation

use crate::traits::*;
use pentest_core::error::{Error, Result};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Perform a port scan on the target host.
///
/// Delegates to [`crate::common::tcp_port_scan`] which supports DNS resolution
/// (via [`std::net::ToSocketAddrs`]) and semaphore-based concurrency limiting
/// (driven by `ScanConfig::concurrency`).
pub async fn port_scan(config: ScanConfig) -> Result<ScanResult> {
    let start = Instant::now();
    let timeout = Duration::from_millis(config.timeout_ms);

    let ports =
        crate::common::tcp_port_scan(&config.host, &config.ports, timeout, config.concurrency)
            .await;

    let open_count = ports.iter().filter(|p| p.open).count();
    let duration_ms = start.elapsed().as_millis() as u64;

    Ok(ScanResult {
        host: config.host,
        ports,
        duration_ms,
        open_count,
    })
}

/// Get the system ARP table
pub async fn get_arp_table() -> Result<Vec<ArpEntry>> {
    #[cfg(target_os = "linux")]
    {
        get_arp_table_linux().await
    }

    #[cfg(target_os = "macos")]
    {
        get_arp_table_macos().await
    }

    #[cfg(target_os = "windows")]
    {
        get_arp_table_windows().await
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(Error::PlatformNotSupported(
            "ARP table not supported on this platform".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
async fn get_arp_table_linux() -> Result<Vec<ArpEntry>> {
    let content = tokio::fs::read_to_string("/proc/net/arp").await?;
    let mut entries = crate::common::parse_proc_arp(&content);

    // Desktop Linux: filter out incomplete entries (00:00:00:00:00:00)
    entries.retain(|e| e.mac != "00:00:00:00:00:00");

    Ok(entries)
}

#[cfg(target_os = "macos")]
async fn get_arp_table_macos() -> Result<Vec<ArpEntry>> {
    use std::process::Command;

    let output = tokio::task::spawn_blocking(|| Command::new("arp").arg("-a").output())
        .await
        .map_err(|e| Error::Unknown(e.to_string()))?
        .map_err(Error::Io)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut entries = Vec::new();

    for line in stdout.lines() {
        // Format: hostname (ip) at mac on interface
        if let Some(start) = line.find('(') {
            if let Some(end) = line.find(')') {
                let ip = line[start + 1..end].to_string();
                if let Some(at_pos) = line.find(" at ") {
                    let rest = &line[at_pos + 4..];
                    let parts: Vec<&str> = rest.split_whitespace().collect();
                    if !parts.is_empty() {
                        let mac = parts[0].to_string();
                        let interface = parts.get(2).map(|s| s.to_string());
                        if mac != "(incomplete)" {
                            entries.push(ArpEntry {
                                ip,
                                mac,
                                interface,
                                hostname: None,
                            });
                        }
                    }
                }
            }
        }
    }

    Ok(entries)
}

#[cfg(target_os = "windows")]
async fn get_arp_table_windows() -> Result<Vec<ArpEntry>> {
    use std::process::Command;

    let output = tokio::task::spawn_blocking(|| Command::new("arp").arg("-a").output())
        .await
        .map_err(|e| Error::Unknown(e.to_string()))?
        .map_err(Error::Io)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut entries = Vec::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
            // Validate that the first column is a real IPv4 address and
            // the second column looks like a Windows-style MAC (xx-xx-xx-xx-xx-xx).
            let is_valid_ip = parts[0].parse::<std::net::Ipv4Addr>().is_ok();
            let is_valid_mac = {
                let segs: Vec<&str> = parts[1].split('-').collect();
                segs.len() == 6
                    && segs
                        .iter()
                        .all(|s| s.len() == 2 && s.chars().all(|c| c.is_ascii_hexdigit()))
            };
            if is_valid_ip && is_valid_mac {
                entries.push(ArpEntry {
                    ip: parts[0].to_string(),
                    mac: parts[1].replace('-', ":"),
                    interface: None,
                    hostname: None,
                });
            }
        }
    }

    Ok(entries)
}

/// Discover SSDP/UPnP devices
pub async fn ssdp_discover(timeout_ms: u64) -> Result<Vec<SsdpDevice>> {
    #[cfg(feature = "ssdp-client")]
    {
        use futures::StreamExt;
        use ssdp_client::SearchTarget;
        use std::collections::HashSet;
        use std::time::Duration;

        let timeout = Duration::from_millis(timeout_ms);

        let mut responses = ssdp_client::search(
            &SearchTarget::All,
            timeout,
            2,    // send 2 search requests
            None, // bind to any interface
        )
        .await
        .map_err(|e| Error::Network(format!("SSDP search failed: {}", e)))?;

        let mut devices = Vec::new();
        let mut seen_locations = HashSet::new();

        while let Some(response) = responses.next().await {
            match response {
                Ok(resp) => {
                    let location = resp.location().to_string();
                    if seen_locations.insert(location.clone()) {
                        devices.push(SsdpDevice {
                            location,
                            server: Some(resp.server().to_string()).filter(|s| !s.is_empty()),
                            usn: Some(resp.usn().to_string()).filter(|s| !s.is_empty()),
                            st: Some(resp.search_target().to_string()),
                            friendly_name: None,
                            manufacturer: None,
                            model: None,
                        });
                    }
                }
                Err(e) => {
                    tracing::warn!("SSDP response error: {}", e);
                }
            }
        }

        Ok(devices)
    }

    #[cfg(not(feature = "ssdp-client"))]
    {
        Err(Error::PlatformNotSupported(
            "SSDP discovery requires the 'ssdp-client' feature".into(),
        ))
    }
}

/// Discover mDNS services
pub async fn mdns_discover(service_type: &str, timeout_ms: u64) -> Result<Vec<MdnsService>> {
    tracing::info!(
        "mDNS discovery for {} with {}ms timeout",
        service_type,
        timeout_ms
    );

    #[cfg(feature = "mdns-sd")]
    {
        mdns_discover_impl(service_type, timeout_ms).await
    }

    #[cfg(not(feature = "mdns-sd"))]
    {
        tracing::warn!("mDNS discovery requires the 'desktop-mdns' feature");
        Ok(Vec::new())
    }
}

#[cfg(feature = "mdns-sd")]
async fn mdns_discover_impl(service_type: &str, timeout_ms: u64) -> Result<Vec<MdnsService>> {
    use mdns_sd::{ServiceDaemon, ServiceEvent};

    let service_type = service_type.to_string();
    let timeout = Duration::from_millis(timeout_ms);

    tokio::task::spawn_blocking(move || {
        let mdns = ServiceDaemon::new()
            .map_err(|e| Error::Unknown(format!("Failed to create mDNS daemon: {}", e)))?;

        let receiver = mdns
            .browse(&service_type)
            .map_err(|e| Error::Unknown(format!("Failed to browse mDNS: {}", e)))?;

        let mut services = Vec::new();
        let start = Instant::now();

        while start.elapsed() < timeout {
            let remaining = timeout.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }

            match receiver.recv_timeout(remaining) {
                Ok(event) => match event {
                    ServiceEvent::ServiceResolved(info) => {
                        let txt_records: HashMap<String, String> = info
                            .get_properties()
                            .iter()
                            .map(|p| (p.key().to_string(), p.val_str().to_string()))
                            .collect();

                        let host = info
                            .get_addresses()
                            .iter()
                            .next()
                            .map(|a| a.to_string())
                            .unwrap_or_else(|| info.get_hostname().to_string());

                        services.push(MdnsService {
                            name: info.get_fullname().to_string(),
                            service_type: info.get_type().to_string(),
                            host,
                            port: info.get_port(),
                            txt_records,
                        });
                    }
                    ServiceEvent::SearchStarted(_) => {}
                    ServiceEvent::ServiceFound(_, _) => {}
                    ServiceEvent::ServiceRemoved(_, _) => {}
                    ServiceEvent::SearchStopped(_) => break,
                },
                Err(_) => break,
            }
        }

        let _ = mdns.stop_browse(&service_type);
        let _ = mdns.shutdown();

        tracing::info!("mDNS discovery found {} services", services.len());
        Ok(services)
    })
    .await
    .map_err(|e| Error::Unknown(format!("mDNS task failed: {}", e)))?
}
