//! Shared, platform-agnostic SSDP/UPnP discovery.
//!
//! This is a pure-`std` UDP `M-SEARCH` multicast implementation that works on
//! any platform whose sandbox permits outbound UDP multicast to
//! `239.255.255.250:1900` (Android and iOS with the local-network entitlement,
//! plus desktop). Android and iOS both call [`discover`]; desktop uses the
//! richer `ssdp-client` crate instead.

use crate::common::probe::ProbeOutcome;
use crate::traits::SsdpDevice;
use pentest_core::error::Result;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

/// Multicast endpoint every SSDP responder listens on.
const SSDP_MULTICAST_ADDR: &str = "239.255.255.250:1900";

/// Per-`recv` read timeout. Short so the loop can re-check the overall deadline
/// frequently instead of blocking for the whole discovery window on one recv.
const RECV_TIMEOUT_MS: u64 = 250;

/// Like [`discover`] but also reports whether the probe actually ran. `discover`
/// delegates to this and discards the outcome for call sites that only want the
/// device list.
pub async fn discover_with_outcome(timeout_ms: u64) -> (Vec<SsdpDevice>, ProbeOutcome) {
    if timeout_ms == 0 {
        return (Vec::new(), ProbeOutcome::Skipped("zero timeout".into()));
    }
    tokio::task::spawn_blocking(move || {
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => {
                return (
                    Vec::new(),
                    ProbeOutcome::Skipped(format!("bind failed: {e}")),
                )
            }
        };
        if let Err(e) = socket.set_read_timeout(Some(Duration::from_millis(RECV_TIMEOUT_MS))) {
            // Without a read timeout the recv loop would block past the deadline.
            return (
                Vec::new(),
                ProbeOutcome::Skipped(format!("set_read_timeout failed: {e}")),
            );
        }
        let _ = socket.set_broadcast(true);
        let search_request = "M-SEARCH * HTTP/1.1\r\n\
            HOST: 239.255.255.250:1900\r\n\
            MAN: \"ssdp:discover\"\r\n\
            MX: 2\r\n\
            ST: ssdp:all\r\n\r\n";
        if let Err(e) = socket.send_to(search_request.as_bytes(), SSDP_MULTICAST_ADDR) {
            return (
                Vec::new(),
                ProbeOutcome::Skipped(format!("send failed: {e}")),
            );
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut devices = Vec::new();
        let mut buf = [0u8; 2048];
        while Instant::now() < deadline {
            match socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    let response = String::from_utf8_lossy(&buf[..len]);
                    if let Some(device) = parse_ssdp_response(&response) {
                        devices.push(device);
                    }
                }
                Err(_) => continue,
            }
        }
        (devices, ProbeOutcome::Ran)
    })
    .await
    .unwrap_or_else(|_| {
        (
            Vec::new(),
            ProbeOutcome::Skipped("probe task panicked".into()),
        )
    })
}

/// Discover SSDP/UPnP devices by sending an `M-SEARCH` and collecting the
/// unicast responses until `timeout_ms` elapses.
///
/// Socket-setup or send failures return `Ok(vec![])` rather than an error so a
/// blocked sandbox degrades gracefully instead of failing the whole scan.
///
/// The recv loop is bounded by an overall wall-clock deadline (not the per-recv
/// timeout) and runs on a blocking thread: a busy network with steady multicast
/// chatter would otherwise re-arm the read timeout on every datagram and block
/// far past `timeout_ms`, and a blocking UDP recv on the async executor would
/// pin a worker for the whole window. Mirrors `mdns::discover`.
pub async fn discover(timeout_ms: u64) -> Result<Vec<SsdpDevice>> {
    Ok(discover_with_outcome(timeout_ms).await.0)
}

/// Parse a single SSDP `HTTP/1.1 200 OK` response into an [`SsdpDevice`].
///
/// Header matching is case-insensitive on the two headers UPnP clients spell
/// inconsistently (`LOCATION`/`Location`, `SERVER`/`Server`). A response with
/// no `LOCATION` header is not a usable device and yields `None`.
pub fn parse_ssdp_response(response: &str) -> Option<SsdpDevice> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_location_and_headers_case_insensitively() {
        let resp = "HTTP/1.1 200 OK\r\n\
            LOCATION: http://192.168.1.1:80/desc.xml\r\n\
            Server: Linux/3.14 UPnP/1.0\r\n\
            USN: uuid:abc::urn:schemas-upnp-org:device:Basic:1\r\n\
            ST: urn:schemas-upnp-org:device:Basic:1\r\n\r\n";
        let dev = parse_ssdp_response(resp).expect("should parse");
        assert_eq!(dev.location, "http://192.168.1.1:80/desc.xml");
        assert_eq!(dev.server.as_deref(), Some("Linux/3.14 UPnP/1.0"));
        assert!(dev.usn.is_some());
        assert!(dev.st.is_some());
    }

    #[test]
    fn no_location_yields_none() {
        let resp = "HTTP/1.1 200 OK\r\nServer: foo\r\n\r\n";
        assert!(parse_ssdp_response(resp).is_none());
    }

    #[tokio::test]
    async fn zero_timeout_reports_skipped_not_empty_ran() {
        let (devices, outcome) = discover_with_outcome(0).await;
        assert!(devices.is_empty());
        assert!(
            matches!(outcome, crate::common::probe::ProbeOutcome::Skipped(_)),
            "a zero-timeout probe did not run; must be Skipped, not Ran"
        );
    }
}
