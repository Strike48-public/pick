//! Shared scanning and parsing logic used by all platforms.
//!
//! This module extracts duplicated port-scanning and ARP-parsing code that was
//! previously copy-pasted across android, desktop, and iOS implementations.

/// Platform-agnostic SSDP/UPnP discovery (pure-std UDP M-SEARCH).
pub mod ssdp;

/// Platform-agnostic mDNS/DNS-SD discovery (pure-std UDP multicast).
pub mod mdns;

use crate::traits::{port_to_service, ArpEntry, PortState, ScanResult, ScannedPort};
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Semaphore;

/// The command that reports whether a binary is on the host's PATH.
///
/// Unix (Linux/macOS/BSD) uses `which`; Windows has no `which` but ships
/// `where.exe`, which is PATHEXT-aware and, like `which`, exits 0 when the
/// binary is found and non-zero otherwise. Using the wrong one makes every
/// external tool read as "Missing" on Windows. See GitHub issue #183.
///
/// This describes the command for the **host** only. Commands sent into the
/// sandbox (WSL2 on Windows, proot/bwrap on Linux) always run in a Linux
/// environment where `which` is correct, so the sandbox path must not use this.
#[must_use]
pub const fn host_which_command() -> &'static str {
    if cfg!(target_os = "windows") {
        "where"
    } else {
        "which"
    }
}

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

/// Classify the outcome of a `connect_timeout` into a [`PortState`].
///
/// `None` means the connect succeeded (`Open`). For a failure we inspect the
/// [`io::ErrorKind`] so a genuinely closed port, a firewalled/timed-out port,
/// and a host we never reached stay distinct facts (#306). Collapsing them all
/// to "closed" lets an unroutable scan read as "checked and clean".
fn classify_connect(err: Option<io::ErrorKind>) -> PortState {
    match err {
        None => PortState::Open,
        // A reachable host explicitly refused the connection: nothing listening.
        Some(io::ErrorKind::ConnectionRefused) => PortState::Closed,
        // We never reached the target. `PermissionDenied` covers a sandbox or a
        // missing capability blocking the socket, which is likewise not a fact
        // about the remote port.
        Some(io::ErrorKind::HostUnreachable)
        | Some(io::ErrorKind::NetworkUnreachable)
        | Some(io::ErrorKind::PermissionDenied) => PortState::Unreachable,
        // Timeouts and anything else are indeterminate: could be a drop-by-policy
        // firewall or a slow host. Report as filtered, never as closed.
        Some(_) => PortState::Filtered,
    }
}

/// Probe a single port on the given host string (which may be `ip:port` or
/// `hostname:port`).  DNS resolution is attempted when the address does not
/// parse directly as a [`SocketAddr`].
fn probe_port(host: &str, port: u16, timeout: Duration) -> ScannedPort {
    let addr_str = format!("{}:{}", host, port);
    let socket_addr = resolve_addr(&addr_str, port);
    let state = classify_connect(
        TcpStream::connect_timeout(&socket_addr, timeout)
            .err()
            .map(|e| e.kind()),
    );
    let open = state == PortState::Open;

    ScannedPort {
        port,
        open,
        state,
        service: if open {
            port_to_service(port).map(String::from)
        } else {
            None
        },
    }
}

/// Assemble a [`ScanResult`] from probed ports, tallying open and unreachable
/// counts and rendering reachability failures into `errors[]`.
///
/// Pure and deterministic so it is unit-testable without a network: given the
/// same ports it always produces the same counts and error strings. This is
/// where "we could not check" is made distinguishable from "we checked and
/// found nothing" (#306).
fn assemble_scan_result(host: String, ports: Vec<ScannedPort>, duration_ms: u64) -> ScanResult {
    let open_count = ports.iter().filter(|p| p.open).count();
    let unreachable_count = ports
        .iter()
        .filter(|p| p.state == PortState::Unreachable)
        .count();

    let errors: Vec<String> = ports
        .iter()
        .filter(|p| p.state == PortState::Unreachable)
        .map(|p| {
            // Deliberately does not assert a specific cause: Unreachable folds
            // host/network-unreachable AND local sandbox/capability blocks
            // (PermissionDenied), so claiming "host unreachable" would overstate
            // what we know. The fact worth reporting is only that no probe
            // reached the target (#306).
            format!(
                "{}:{} unreachable (probe never reached the target)",
                host, p.port
            )
        })
        .collect();

    ScanResult {
        host,
        ports,
        duration_ms,
        open_count,
        unreachable_count,
        errors,
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
///
/// Returns a full [`ScanResult`] with timing and open/unreachable tallies so
/// every platform wrapper shares one assembly path (and cannot drift on how a
/// failed probe is counted). A probe that never reached the target is recorded
/// as [`PortState::Unreachable`] and surfaced in [`ScanResult::errors`], never
/// silently folded into a closed port (#306).
pub async fn tcp_port_scan(
    host: &str,
    ports: &[u16],
    timeout: Duration,
    max_concurrent: usize,
) -> ScanResult {
    let start = Instant::now();
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
                // A join failure means the probe never completed, so we cannot
                // claim the port is closed. Record it as Unreachable, not a
                // silent open:false (#306).
                .unwrap_or(ScannedPort {
                    port,
                    open: false,
                    state: PortState::Unreachable,
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

    let duration_ms = start.elapsed().as_millis() as u64;
    assemble_scan_result(host.to_owned(), results, duration_ms)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_which_command_matches_target_os() {
        // The host binary-probe command must be `where` on Windows (no `which`
        // there) and `which` on every Unix-like target. See #183.
        let cmd = host_which_command();
        if cfg!(target_os = "windows") {
            assert_eq!(cmd, "where");
        } else {
            assert_eq!(cmd, "which");
        }
    }

    // ── #306: reachability is distinct from closed ──────────────────────
    //
    // These exercise the pure classification/assembly seam without a network,
    // so they run in the standard suite on every CI lane. The connect() path
    // itself is I/O and platform-dependent; the fact worth guarding is that a
    // failed probe never masquerades as a closed-and-clean port.

    fn port(port: u16, state: PortState) -> ScannedPort {
        ScannedPort {
            port,
            open: state == PortState::Open,
            state,
            service: None,
        }
    }

    #[test]
    fn classify_success_is_open() {
        assert_eq!(classify_connect(None), PortState::Open);
    }

    #[test]
    fn classify_refused_is_closed() {
        // A reachable host that refuses the connection is a genuine closed port.
        assert_eq!(
            classify_connect(Some(io::ErrorKind::ConnectionRefused)),
            PortState::Closed
        );
    }

    #[test]
    fn classify_unreachable_kinds_are_unreachable_not_closed() {
        // The core of #306: host/network unreachable and sandbox-blocked
        // (PermissionDenied) connects must NOT collapse into a closed port.
        for kind in [
            io::ErrorKind::HostUnreachable,
            io::ErrorKind::NetworkUnreachable,
            io::ErrorKind::PermissionDenied,
        ] {
            let state = classify_connect(Some(kind));
            assert_eq!(
                state,
                PortState::Unreachable,
                "{kind:?} must classify as Unreachable, got {state:?}"
            );
            assert_ne!(
                state,
                PortState::Closed,
                "{kind:?} must never read as closed"
            );
        }
    }

    #[test]
    fn classify_timeout_is_filtered_not_closed() {
        // A timeout is indeterminate (firewall drop or slow host), never a
        // proven-closed port.
        let state = classify_connect(Some(io::ErrorKind::TimedOut));
        assert_eq!(state, PortState::Filtered);
        assert_ne!(state, PortState::Closed);
    }

    #[test]
    fn unreachable_scan_is_not_reported_as_scanned_and_clean() {
        // Regression for #306: an unroutable host yields zero open ports, but
        // the result must record the unreachability rather than looking clean.
        let ports = vec![
            port(22, PortState::Unreachable),
            port(80, PortState::Unreachable),
            port(443, PortState::Unreachable),
        ];
        let result = assemble_scan_result("203.0.113.7".to_string(), ports, 5);

        assert_eq!(result.open_count, 0, "no ports should read as open");
        assert_eq!(
            result.unreachable_count, 3,
            "all three probes were unreachable"
        );
        assert_eq!(
            result.unreachable_count,
            result.ports.len(),
            "fully unreachable host: no packet reached the target"
        );
        assert_eq!(result.errors.len(), 3, "each failure must surface an error");
        assert!(
            result.errors.iter().all(|e| e.contains("203.0.113.7")),
            "errors name the host: {:?}",
            result.errors
        );
    }

    #[test]
    fn clean_scan_has_no_errors() {
        // A reachable host with everything closed is genuinely clean: zero open,
        // zero unreachable, empty errors — distinguishable from the case above.
        let ports = vec![
            port(80, PortState::Open),
            port(22, PortState::Closed),
            port(3306, PortState::Closed),
        ];
        let result = assemble_scan_result("192.0.2.10".to_string(), ports, 3);

        assert_eq!(result.open_count, 1);
        assert_eq!(result.unreachable_count, 0);
        assert!(
            result.errors.is_empty(),
            "a reachable scan reports no reachability errors: {:?}",
            result.errors
        );
    }

    #[test]
    fn mixed_scan_counts_only_unreachable_as_errors() {
        // Filtered ports are indeterminate but were reached, so they are not
        // scan failures — only Unreachable feeds unreachable_count/errors.
        let ports = vec![
            port(80, PortState::Open),
            port(81, PortState::Filtered),
            port(82, PortState::Unreachable),
        ];
        let result = assemble_scan_result("198.51.100.5".to_string(), ports, 7);

        assert_eq!(result.open_count, 1);
        assert_eq!(
            result.unreachable_count, 1,
            "only the Unreachable port counts"
        );
        assert_eq!(result.errors.len(), 1);
        assert!(result.errors[0].contains(":82"), "error names the port");
    }
}
