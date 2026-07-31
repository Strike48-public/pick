//! Shared, platform-agnostic mDNS/DNS-SD discovery.
//!
//! A pure-`std` UDP implementation: send a multicast PTR query for a service
//! type to `224.0.0.251:5353`, collect responses for `timeout_ms`, and parse
//! the PTR/SRV/A/AAAA/TXT records into [`MdnsService`] entries. This avoids any
//! platform framework (no Bonjour/NSD interop) and works wherever outbound UDP
//! multicast is permitted (iOS with the local-network entitlement, desktop).
//!
//! The DNS wire parser is deliberately minimal but real: it supports name
//! compression pointers, and the four record types DNS-SD needs (PTR, SRV, A,
//! TXT). It is defensive — every length and offset is bounds-checked, so a
//! malformed packet yields fewer records rather than a panic. Socket failures
//! return `Ok(vec![])` so a blocked sandbox degrades gracefully.

use crate::traits::MdnsService;
use pentest_core::error::Result;
use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::time::{Duration, Instant};

/// The mDNS multicast endpoint (RFC 6762).
const MDNS_MULTICAST_ADDR: &str = "224.0.0.251:5353";
const MDNS_MULTICAST_IP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

// DNS record type codes we care about.
const TYPE_A: u16 = 1;
const TYPE_PTR: u16 = 12;
const TYPE_TXT: u16 = 16;
const TYPE_SRV: u16 = 33;

/// Discover mDNS/DNS-SD services of `service_type` (e.g. `_http._tcp.local.`).
///
/// Sends a PTR query, then reads responses until `timeout_ms` elapses, joining
/// PTR -> SRV -> A -> TXT records by name into [`MdnsService`] entries.
pub async fn discover(service_type: &str, timeout_ms: u64) -> Result<Vec<MdnsService>> {
    // Nothing to wait for -> no recv loop, return immediately (also avoids a
    // zero deadline that would exit the loop before the first recv anyway).
    if timeout_ms == 0 {
        return Ok(vec![]);
    }

    // The recv loop is a blocking UDP read; run it on a blocking thread so it
    // doesn't pin an async worker for the whole discovery window.
    let service_type = service_type.to_string();
    let services = tokio::task::spawn_blocking(move || {
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        // Best-effort multicast setup; failures just mean we might miss replies.
        let _ = socket.join_multicast_v4(&MDNS_MULTICAST_IP, &Ipv4Addr::UNSPECIFIED);
        let _ = socket.set_multicast_loop_v4(true);
        // Short per-recv timeout so we can loop until the overall deadline.
        let _ = socket.set_read_timeout(Some(Duration::from_millis(250)));

        let query = build_ptr_query(&service_type);
        if socket.send_to(&query, MDNS_MULTICAST_ADDR).is_err() {
            return Vec::new();
        }

        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut records = RecordSet::default();
        let mut buf = [0u8; 4096];

        while Instant::now() < deadline {
            match socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    if let Some(msg) = parse_dns_message(&buf[..len]) {
                        records.absorb(msg);
                    }
                }
                // Timeout on this recv; keep looping until the overall deadline.
                Err(_) => continue,
            }
        }

        records.into_services(&service_type)
    })
    .await
    .unwrap_or_default();

    Ok(services)
}

/// Build a standard mDNS PTR query for `service_type`.
///
/// One question, QTYPE=PTR, QCLASS=IN (0x0001). Transaction ID 0 per mDNS
/// convention. Returns an empty query buffer with just a header if the name
/// can't be encoded (it will simply elicit no useful responses).
fn build_ptr_query(service_type: &str) -> Vec<u8> {
    let mut msg = Vec::with_capacity(64);
    // Header: ID=0, flags=0, QDCOUNT=1, others 0.
    msg.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    encode_name(&mut msg, service_type);
    msg.extend_from_slice(&TYPE_PTR.to_be_bytes());
    msg.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    msg
}

/// Encode a dotted DNS name into length-prefixed labels terminated by a zero
/// byte. A trailing dot (as in `_http._tcp.local.`) produces no empty label.
fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        // Labels are capped at 63 bytes; skip over-long labels defensively.
        let take = bytes.len().min(63);
        out.push(take as u8);
        out.extend_from_slice(&bytes[..take]);
    }
    out.push(0);
}

/// A parsed DNS resource record (only the fields DNS-SD needs).
#[derive(Debug)]
enum Record {
    /// PTR: service_type -> instance name. Only the target (instance name) is
    /// needed; the owning service_type name is implied by the query.
    Ptr { target: String },
    /// SRV: instance name -> (port, host target).
    Srv {
        name: String,
        port: u16,
        target: String,
    },
    /// A: host -> IPv4.
    A { name: String, addr: Ipv4Addr },
    /// TXT: name -> key/value records.
    Txt {
        name: String,
        entries: HashMap<String, String>,
    },
}

/// Accumulates records across multiple response packets and joins them.
#[derive(Default)]
struct RecordSet {
    /// PTR targets: instance names advertised for the queried service.
    instances: Vec<String>,
    /// instance name -> (port, host target)
    srv: HashMap<String, (u16, String)>,
    /// host name -> IPv4 address
    hosts: HashMap<String, Ipv4Addr>,
    /// name -> TXT key/values
    txt: HashMap<String, HashMap<String, String>>,
}

impl RecordSet {
    fn absorb(&mut self, records: Vec<Record>) {
        for rec in records {
            match rec {
                Record::Ptr { target, .. } => {
                    if !self.instances.contains(&target) {
                        self.instances.push(target);
                    }
                }
                Record::Srv { name, port, target } => {
                    self.srv.insert(name, (port, target));
                }
                Record::A { name, addr } => {
                    self.hosts.insert(name, addr);
                }
                Record::Txt { name, entries } => {
                    self.txt.entry(name).or_default().extend(entries);
                }
            }
        }
    }

    /// Join accumulated records into services.
    ///
    /// One entry per discovered SRV/instance; the host is resolved from the A
    /// record when the SRV target is known, otherwise the SRV target name is
    /// used verbatim. Instances seen only via PTR (no SRV yet) are still
    /// emitted with an empty host/port so the caller sees them.
    fn into_services(self, service_type: &str) -> Vec<MdnsService> {
        let mut out = Vec::new();
        let mut seen = Vec::new();

        // Prefer instances that have an SRV record (fully-resolved services).
        for (name, (port, target)) in &self.srv {
            let host = self
                .hosts
                .get(target)
                .map(|ip| ip.to_string())
                .unwrap_or_else(|| target.trim_end_matches('.').to_string());
            let txt_records = self.txt.get(name).cloned().unwrap_or_default();
            seen.push(name.clone());
            out.push(MdnsService {
                name: name.trim_end_matches('.').to_string(),
                service_type: service_type.to_string(),
                host,
                port: *port,
                txt_records,
            });
        }

        // Instances known only from PTR (no SRV yet) still get surfaced.
        for inst in &self.instances {
            if seen.contains(inst) {
                continue;
            }
            let txt_records = self.txt.get(inst).cloned().unwrap_or_default();
            out.push(MdnsService {
                name: inst.trim_end_matches('.').to_string(),
                service_type: service_type.to_string(),
                host: String::new(),
                port: 0,
                txt_records,
            });
        }

        out
    }
}

/// Parse a DNS message, returning the records from the answer + additional
/// sections. Returns `None` if the header can't be read; individual malformed
/// records are skipped.
fn parse_dns_message(buf: &[u8]) -> Option<Vec<Record>> {
    if buf.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let ancount = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let nscount = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let arcount = u16::from_be_bytes([buf[10], buf[11]]) as usize;

    let mut pos = 12usize;

    // Skip the question section.
    for _ in 0..qdcount {
        let (_, next) = read_name(buf, pos)?;
        pos = next;
        // QTYPE (2) + QCLASS (2)
        pos = pos.checked_add(4)?;
        if pos > buf.len() {
            return None;
        }
    }

    let total_rr = ancount.saturating_add(nscount).saturating_add(arcount);
    let mut records = Vec::new();

    for _ in 0..total_rr {
        match read_record(buf, pos) {
            Some((rec, next)) => {
                pos = next;
                if let Some(rec) = rec {
                    records.push(rec);
                }
            }
            None => break,
        }
    }

    Some(records)
}

/// Read one resource record starting at `pos`. Returns the parsed record (or
/// `None` for record types we ignore) and the offset just past it.
fn read_record(buf: &[u8], pos: usize) -> Option<(Option<Record>, usize)> {
    let (name, mut pos) = read_name(buf, pos)?;

    // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
    if pos.checked_add(10)? > buf.len() {
        return None;
    }
    let rtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let rdlength = u16::from_be_bytes([buf[pos + 8], buf[pos + 9]]) as usize;
    pos += 10;

    let rdata_start = pos;
    let rdata_end = pos.checked_add(rdlength)?;
    if rdata_end > buf.len() {
        return None;
    }

    let record = match rtype {
        // The PTR owner name (service_type) is implied by our query, so we
        // keep only the target instance name from the rdata.
        TYPE_PTR => read_name(buf, rdata_start).map(|(target, _)| Record::Ptr { target }),
        TYPE_SRV => {
            // priority(2) weight(2) port(2) target(name)
            if rdlength >= 6 {
                let port = u16::from_be_bytes([buf[rdata_start + 4], buf[rdata_start + 5]]);
                read_name(buf, rdata_start + 6).map(|(target, _)| Record::Srv {
                    name,
                    port,
                    target,
                })
            } else {
                None
            }
        }
        TYPE_A => {
            if rdlength == 4 {
                let addr = Ipv4Addr::new(
                    buf[rdata_start],
                    buf[rdata_start + 1],
                    buf[rdata_start + 2],
                    buf[rdata_start + 3],
                );
                Some(Record::A { name, addr })
            } else {
                None
            }
        }
        TYPE_TXT => Some(Record::Txt {
            name,
            entries: parse_txt(&buf[rdata_start..rdata_end]),
        }),
        _ => None,
    };

    Some((record, rdata_end))
}

/// Parse a TXT rdata blob (a sequence of length-prefixed `key=value` strings).
fn parse_txt(rdata: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut i = 0usize;
    while i < rdata.len() {
        let len = rdata[i] as usize;
        i += 1;
        if i + len > rdata.len() {
            break;
        }
        let entry = String::from_utf8_lossy(&rdata[i..i + len]);
        i += len;
        match entry.split_once('=') {
            Some((k, v)) => {
                map.insert(k.to_string(), v.to_string());
            }
            None if !entry.is_empty() => {
                map.insert(entry.to_string(), String::new());
            }
            None => {}
        }
    }
    map
}

/// Read a (possibly compressed) DNS name starting at `pos`.
///
/// Returns the dotted name (with a trailing dot) and the offset of the first
/// byte after the name *in the record stream* — i.e. past the pointer if a
/// compression pointer was used. Follows compression pointers with a bounded
/// jump count to prevent loops.
fn read_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumps = 0usize;
    // Offset to return to the caller: fixed at the byte after the first pointer.
    let mut end_pos: Option<usize> = None;

    loop {
        if pos >= buf.len() {
            return None;
        }
        let len = buf[pos] as usize;

        // Compression pointer: top two bits set.
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= buf.len() {
                return None;
            }
            let ptr = ((len & 0x3F) << 8) | buf[pos + 1] as usize;
            if end_pos.is_none() {
                end_pos = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 16 {
                return None; // guard against pointer loops
            }
            pos = ptr;
            continue;
        }

        if len == 0 {
            pos += 1;
            break;
        }

        pos += 1;
        let label_end = pos.checked_add(len)?;
        if label_end > buf.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&buf[pos..label_end]).into_owned());
        pos = label_end;
    }

    let mut name = labels.join(".");
    name.push('.');
    Some((name, end_pos.unwrap_or(pos)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_name_produces_labels() {
        let mut out = Vec::new();
        encode_name(&mut out, "_http._tcp.local.");
        // _http (5) + _tcp (4) + local (5) + terminator
        assert_eq!(out[0], 5);
        assert_eq!(&out[1..6], b"_http");
        assert_eq!(*out.last().unwrap(), 0);
    }

    #[test]
    fn parse_txt_splits_key_value() {
        // "path=/" then "flag"
        let rdata = [
            6u8, b'p', b'a', b't', b'h', b'=', b'/', 4, b'f', b'l', b'a', b'g',
        ];
        let map = parse_txt(&rdata);
        assert_eq!(map.get("path").map(String::as_str), Some("/"));
        assert_eq!(map.get("flag").map(String::as_str), Some(""));
    }

    #[test]
    fn read_name_handles_simple_name() {
        // 3www 7example 3com 0
        let buf = [
            3, b'w', b'w', b'w', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0,
        ];
        let (name, next) = read_name(&buf, 0).expect("parse");
        assert_eq!(name, "www.example.com.");
        assert_eq!(next, buf.len());
    }

    #[test]
    fn read_name_follows_compression_pointer() {
        // At 0: "com" then root. At 5: "www" then pointer to offset 0.
        let mut buf = vec![3, b'c', b'o', b'm', 0];
        let start = buf.len();
        buf.extend_from_slice(&[3, b'w', b'w', b'w', 0xC0, 0x00]);
        let (name, next) = read_name(&buf, start).expect("parse");
        assert_eq!(name, "www.com.");
        // end offset is right after the 2-byte pointer
        assert_eq!(next, start + 6);
    }

    #[test]
    fn malformed_message_is_safe() {
        assert!(parse_dns_message(&[0, 0, 0]).is_none());
    }
}
