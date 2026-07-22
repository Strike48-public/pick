//! Native iOS network operations (libc-based).
//!
//! iOS has no `/proc/net/arp` and forbids spawning `arp`/`ip`, but the BSD
//! route socket is readable inside the app sandbox. This module reads the
//! kernel ARP cache the same way `arp -a` does: a `sysctl` with the
//! `NET_RT_FLAGS`/`AF_INET` MIB returns a stream of routing messages
//! (`rt_msghdr`) whose sockaddrs carry the IPv4 address and link-layer MAC.
//!
//! SSDP and mDNS are handled by the shared, platform-agnostic pure-UDP
//! implementations in [`crate::common`]; iOS just delegates to them (outbound
//! multicast is permitted with the app's local-network entitlement).
//!
//! The same Darwin route-socket layout is used on macOS, so this compiles and
//! is exercisable on the macOS host too.

use crate::traits::{ArpEntry, MdnsService, SsdpDevice};
use pentest_core::error::Result;

/// Discover SSDP/UPnP devices (delegates to the shared implementation).
pub async fn ssdp_discover(timeout_ms: u64) -> Result<Vec<SsdpDevice>> {
    crate::common::ssdp::discover(timeout_ms).await
}

/// Discover mDNS/DNS-SD services (delegates to the shared implementation).
pub async fn mdns_discover(service_type: &str, timeout_ms: u64) -> Result<Vec<MdnsService>> {
    crate::common::mdns::discover(service_type, timeout_ms).await
}

/// Read the kernel ARP cache via the BSD route socket `sysctl`.
///
/// Returns `Ok(vec![])` (never `Err`) if the sysctl is unavailable or the
/// buffer can't be read, so a locked-down device degrades gracefully instead
/// of failing the whole scan.
pub async fn get_arp_table() -> Result<Vec<ArpEntry>> {
    // The sysctl walk is a synchronous syscall; keep it off the async worker.
    let entries = tokio::task::spawn_blocking(read_arp_cache)
        .await
        .unwrap_or_default();
    Ok(entries)
}

/// Perform the two-call `sysctl` and parse the returned routing messages.
fn read_arp_cache() -> Vec<ArpEntry> {
    // MIB: CTL_NET, PF_ROUTE, protocol 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO.
    let mut mib: [libc::c_int; 6] = [
        libc::CTL_NET,
        libc::PF_ROUTE,
        0,
        libc::AF_INET,
        libc::NET_RT_FLAGS,
        libc::RTF_LLINFO,
    ];

    // SAFETY: standard two-call sysctl pattern — query the needed length, then
    // fill a buffer of that size. All pointers are valid for the calls made.
    unsafe {
        let mut needed: libc::size_t = 0;
        if libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            std::ptr::null_mut(),
            &mut needed,
            std::ptr::null_mut(),
            0,
        ) != 0
            || needed == 0
        {
            return Vec::new();
        }

        let mut buf = vec![0u8; needed];
        if libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut needed,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return Vec::new();
        }
        // The kernel may report fewer bytes than the earlier size query.
        buf.truncate(needed);
        parse_rt_messages(&buf)
    }
}

/// Walk the buffer of `rt_msghdr`-prefixed routing messages, extracting an
/// [`ArpEntry`] per message that carries both an IPv4 dst and a link-layer MAC.
///
/// The buffer is a packed sequence of messages; each starts with an
/// `rt_msghdr` whose `rtm_msglen` gives the total length of that message. The
/// gateway (`sockaddr_dl`) directly follows the header and the destination
/// (`sockaddr_inarp`, layout-compatible with `sockaddr_in`) follows that.
fn parse_rt_messages(buf: &[u8]) -> Vec<ArpEntry> {
    let mut entries = Vec::new();
    let hdr_size = std::mem::size_of::<libc::rt_msghdr>();
    let mut offset = 0usize;

    while offset + hdr_size <= buf.len() {
        // SAFETY: bounds checked above; read the header by copy (unaligned-safe).
        let rtm: libc::rt_msghdr = unsafe {
            std::ptr::read_unaligned(buf[offset..].as_ptr() as *const libc::rt_msghdr)
        };

        let msglen = rtm.rtm_msglen as usize;
        // A zero/short msglen would loop forever or overrun; stop defensively.
        if msglen < hdr_size || offset + msglen > buf.len() {
            break;
        }

        if let Some(entry) = parse_one_message(&buf[offset..offset + msglen], &rtm) {
            entries.push(entry);
        }

        offset += msglen;
    }

    entries
}

/// Parse a single routing message (already length-validated). The dst
/// `sockaddr_in` sits right after the header; the gateway `sockaddr_dl`
/// (holding the MAC) follows the dst.
fn parse_one_message(msg: &[u8], _rtm: &libc::rt_msghdr) -> Option<ArpEntry> {
    let hdr_size = std::mem::size_of::<libc::rt_msghdr>();

    // Sockaddrs are laid out after the header, each self-describing via its
    // leading sa_len byte. The ARP MIB always returns RTA_DST then RTA_GATEWAY.
    let mut pos = hdr_size;

    // First sockaddr: destination (AF_INET).
    let (ip, dst_len) = read_sockaddr_inet(msg, pos)?;
    pos += sa_advance(msg, pos, dst_len);

    // Second sockaddr: gateway (AF_LINK / sockaddr_dl with the MAC).
    let (mac, if_index) = read_sockaddr_dl(msg, pos)?;

    if mac.is_empty() {
        return None;
    }

    let interface = if_index_to_name(if_index);

    Some(ArpEntry {
        ip,
        mac,
        interface,
        hostname: None,
    })
}

/// Round a sockaddr length up the way the BSD route code advances between
/// consecutive sockaddrs (align to `c_long`; a zero length still consumes one
/// alignment unit).
fn sa_advance(buf: &[u8], pos: usize, sa_len: usize) -> usize {
    let _ = (buf, pos);
    let align = std::mem::size_of::<libc::c_long>();
    if sa_len == 0 {
        align
    } else {
        sa_len.div_ceil(align) * align
    }
}

/// Read an `AF_INET` sockaddr at `pos`, returning the dotted IPv4 string and
/// the sockaddr's `sa_len`.
fn read_sockaddr_inet(buf: &[u8], pos: usize) -> Option<(String, usize)> {
    let sa_size = std::mem::size_of::<libc::sockaddr_in>();
    if pos + sa_size > buf.len() {
        return None;
    }
    // SAFETY: bounds checked; read unaligned into an owned sockaddr_in.
    let sin: libc::sockaddr_in =
        unsafe { std::ptr::read_unaligned(buf[pos..].as_ptr() as *const libc::sockaddr_in) };

    let sa_len = sin.sin_len as usize;
    // s_addr is in network byte order; to_ne_bytes gives those bytes in order.
    let ip = std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
    Some((ip.to_string(), sa_len.max(sa_size)))
}

/// Read an `AF_LINK` `sockaddr_dl` at `pos`, returning the formatted MAC (may
/// be empty when the entry has no link-layer address) and the interface index.
fn read_sockaddr_dl(buf: &[u8], pos: usize) -> Option<(String, u32)> {
    let dl_size = std::mem::size_of::<libc::sockaddr_dl>();
    if pos + dl_size > buf.len() {
        return None;
    }
    // SAFETY: bounds checked; read unaligned into an owned sockaddr_dl.
    let sdl: libc::sockaddr_dl =
        unsafe { std::ptr::read_unaligned(buf[pos..].as_ptr() as *const libc::sockaddr_dl) };

    let if_index = sdl.sdl_index as u32;
    let nlen = sdl.sdl_nlen as usize;
    let alen = sdl.sdl_alen as usize;

    // The MAC is the `alen` bytes after the `nlen`-byte interface name inside
    // sdl_data. Guard against the fixed-size sdl_data array bounds.
    let mac = if alen == 6 && nlen + alen <= sdl.sdl_data.len() {
        (0..alen)
            .map(|k| format!("{:02x}", sdl.sdl_data[nlen + k] as u8))
            .collect::<Vec<_>>()
            .join(":")
    } else {
        String::new()
    };

    Some((mac, if_index))
}

/// Resolve an interface index to its name via `if_indextoname`.
fn if_index_to_name(if_index: u32) -> Option<String> {
    if if_index == 0 {
        return None;
    }
    // if_indextoname needs a buffer of at least IF_NAMESIZE bytes.
    let mut buf = [0u8; libc::IF_NAMESIZE];
    // SAFETY: buf is large enough per the contract; the result is NUL-terminated.
    unsafe {
        let ret = libc::if_indextoname(if_index, buf.as_mut_ptr() as *mut libc::c_char);
        if ret.is_null() {
            return None;
        }
        std::ffi::CStr::from_ptr(buf.as_ptr() as *const libc::c_char)
            .to_str()
            .ok()
            .map(|s| s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_empty_buffer_yields_no_entries() {
        assert!(parse_rt_messages(&[]).is_empty());
    }

    #[test]
    fn parse_truncated_header_is_safe() {
        // Fewer bytes than a full rt_msghdr must not panic.
        let buf = vec![0u8; std::mem::size_of::<libc::rt_msghdr>() / 2];
        assert!(parse_rt_messages(&buf).is_empty());
    }

    #[test]
    fn parse_zero_msglen_does_not_loop() {
        // A header-sized buffer whose rtm_msglen is 0 must terminate the walk.
        let buf = vec![0u8; std::mem::size_of::<libc::rt_msghdr>()];
        assert!(parse_rt_messages(&buf).is_empty());
    }

    #[test]
    fn read_arp_cache_never_panics() {
        // On the macOS host this returns real entries; in Linux CI the sysctl
        // MIB simply isn't there and we get an empty vec. Either way: no panic.
        let _ = read_arp_cache();
    }
}
