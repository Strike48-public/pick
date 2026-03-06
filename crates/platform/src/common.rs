//! Shared scanning and parsing logic used by all platforms.
//!
//! This module extracts duplicated port-scanning and ARP-parsing code that was
//! previously copy-pasted across android, desktop, and iOS implementations.

use crate::traits::{port_to_service, ArpEntry, ScannedPort};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Resolve `host:port` to a [`SocketAddr`], trying a direct parse first and
/// falling back to DNS resolution via [`ToSocketAddrs`].
fn resolve_addr(addr: &str, port: u16) -> SocketAddr {
    addr.parse::<SocketAddr>().unwrap_or_else(|_| {
        addr.to_socket_addrs()
            .ok()
            .and_then(|mut addrs| addrs.next())
            .unwrap_or_else(|| ([127, 0, 0, 1], port).into())
    })
}

/// Probe a single port on the given host string (which may be `ip:port` or
/// `hostname:port`).  DNS resolution is attempted when the address does not
/// parse directly as a [`SocketAddr`].
fn probe_port(host: &str, port: u16, timeout: Duration) -> ScannedPort {
    let addr_str = format!("{}:{}", host, port);
    let socket_addr = resolve_addr(&addr_str, port);
    let open = TcpStream::connect_timeout(&socket_addr, timeout).is_ok();

    ScannedPort {
        port,
        open,
        service: if open {
            port_to_service(port).map(String::from)
        } else {
            None
        },
    }
}

/// Perform a TCP connect scan against `host` on every port in `ports`.
///
/// Each port is probed via [`std::net::TcpStream::connect_timeout`] inside a
/// [`tokio::task::spawn_blocking`] call so the async runtime is never blocked.
///
/// When `max_concurrent` is greater than zero a [`tokio::sync::Semaphore`] is
/// used to limit the number of in-flight probes.  Pass `0` to allow unlimited
/// concurrency (the original behaviour).
///
/// The implementation supports DNS resolution: if `host:port` does not parse
/// directly as a [`SocketAddr`], the address is resolved via [`ToSocketAddrs`].
///
/// Open ports are annotated with a service name via [`port_to_service`].
pub async fn tcp_port_scan(
    host: &str,
    ports: &[u16],
    timeout: Duration,
    max_concurrent: usize,
) -> Vec<ScannedPort> {
    let semaphore = if max_concurrent > 0 {
        Some(Arc::new(Semaphore::new(max_concurrent)))
    } else {
        None
    };

    let mut handles = Vec::with_capacity(ports.len());

    for &port in ports {
        let host = host.to_owned();
        let sem = semaphore.clone();

        let handle = tokio::spawn(async move {
            // Acquire a permit when concurrency is bounded.
            let _permit = match sem {
                Some(ref s) => Some(s.acquire().await.unwrap()),
                None => None,
            };

            tokio::task::spawn_blocking(move || probe_port(&host, port, timeout))
                .await
                .unwrap_or(ScannedPort {
                    port,
                    open: false,
                    service: None,
                })
        });

        handles.push(handle);
    }

    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        if let Ok(result) = handle.await {
            results.push(result);
        }
    }
    results
}

/// Parse the contents of `/proc/net/arp` into a list of [`ArpEntry`] values.
///
/// The expected format (Linux & Android) is:
///
/// ```text
/// IP address       HW type     Flags       HW address            Mask     Device
/// 192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
/// ```
///
/// The header line is skipped. Lines with fewer than 4 whitespace-separated
/// columns are silently ignored.
pub fn parse_proc_arp(content: &str) -> Vec<ArpEntry> {
    content
        .lines()
        .skip(1) // Skip header
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                Some(ArpEntry {
                    ip: parts[0].to_string(),
                    mac: parts[3].to_string(),
                    interface: parts.get(5).map(|s| s.to_string()),
                    hostname: None,
                })
            } else {
                None
            }
        })
        .collect()
}

/// Parse the output of `ip neigh show` into a list of [`ArpEntry`] values.
///
/// The expected format is:
///
/// ```text
/// 192.168.1.1 dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
/// ```
///
/// Lines without an `lladdr` field or with an all-zero MAC address are skipped.
pub fn parse_ip_neigh(output: &str) -> Vec<ArpEntry> {
    output
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // Minimum: IP dev IFACE lladdr MAC STATE
            if parts.len() < 5 {
                return None;
            }
            let ip = parts[0].to_string();
            let interface = if parts.get(1) == Some(&"dev") {
                parts.get(2).map(|s| s.to_string())
            } else {
                None
            };
            let mac = parts
                .iter()
                .position(|&p| p == "lladdr")
                .and_then(|i| parts.get(i + 1))
                .map(|s| s.to_string())
                .unwrap_or_default();

            if mac.is_empty() || mac == "00:00:00:00:00:00" {
                return None;
            }

            Some(ArpEntry {
                ip,
                mac,
                interface,
                hostname: None,
            })
        })
        .collect()
}
