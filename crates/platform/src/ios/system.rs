//! Native iOS system information (libc-based).
//!
//! iOS forbids most host introspection, but POSIX `getifaddrs(3)` and
//! `sysctl(3)` are permitted inside the app sandbox with no special
//! entitlement — so local interface enumeration and real device stats can be
//! read natively rather than stubbed. These use the same Apple APIs available
//! on macOS, so the logic is exercisable on the host in tests.

use crate::traits::*;
use pentest_core::error::{Error, Result};
use std::ffi::{CStr, CString};

/// Read device/system information via `sysctl`.
pub async fn get_device_info() -> Result<DeviceInfo> {
    let cpu_count = sysctl_int("hw.logicalcpu").filter(|&n| n > 0).unwrap_or(1) as usize;
    let total_memory_mb = sysctl_int("hw.memsize").unwrap_or(0).max(0) as u64 / 1024 / 1024;

    Ok(DeviceInfo {
        os_name: "iOS".to_string(),
        // Available on modern Darwin (iOS 14+/macOS); empty if the kernel
        // doesn't expose it rather than a misleading "Unknown".
        os_version: sysctl_string("kern.osproductversion").unwrap_or_default(),
        hostname: sysctl_string("kern.hostname").unwrap_or_else(|| "iphone".to_string()),
        architecture: std::env::consts::ARCH.to_string(),
        cpu_count,
        total_memory_mb,
        platform_specific: PlatformDetails::Ios,
    })
}

/// Enumerate local network interfaces via `getifaddrs`.
///
/// Aggregates every address family per interface: IPv4/IPv6 addresses plus the
/// link-layer MAC (from `AF_LINK`), preserving the order the OS reports them.
pub async fn get_network_interfaces() -> Result<Vec<NetworkInterface>> {
    // SAFETY: getifaddrs allocates a linked list we must free with freeifaddrs.
    // We walk it fully before freeing and copy everything out into owned data.
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return Err(Error::Network("getifaddrs() failed".into()));
        }
        let interfaces = walk_ifaddrs(ifap);
        libc::freeifaddrs(ifap);
        Ok(interfaces)
    }
}

/// Walk the `getifaddrs` linked list into owned `NetworkInterface`s.
unsafe fn walk_ifaddrs(ifap: *mut libc::ifaddrs) -> Vec<NetworkInterface> {
    let mut ifaces: Vec<NetworkInterface> = Vec::new();
    let mut cur = ifap;

    // `as_ref` null-checks each node before forming the reference, so the
    // walk never dereferences a null/invalid pointer (the list terminates
    // when `ifa_next` is null).
    while let Some(ifa) = cur.as_ref() {
        cur = ifa.ifa_next;

        if ifa.ifa_name.is_null() {
            continue;
        }
        let name = CStr::from_ptr(ifa.ifa_name).to_string_lossy().into_owned();

        // Find or create the entry for this interface name.
        let idx = match ifaces.iter().position(|i| i.name == name) {
            Some(i) => i,
            None => {
                let flags = ifa.ifa_flags as libc::c_int;
                ifaces.push(NetworkInterface {
                    name: name.clone(),
                    addresses: Vec::new(),
                    mac_address: None,
                    is_up: flags & libc::IFF_UP != 0,
                    is_loopback: flags & libc::IFF_LOOPBACK != 0,
                });
                ifaces.len() - 1
            }
        };

        if ifa.ifa_addr.is_null() {
            continue;
        }
        match (*ifa.ifa_addr).sa_family as libc::c_int {
            libc::AF_INET => {
                let sin = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                // s_addr is stored in network byte order; to_ne_bytes yields
                // those bytes back in order regardless of host endianness.
                let ip = std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                ifaces[idx]
                    .addresses
                    .push(InterfaceAddr::new(ip.to_string(), None));
            }
            libc::AF_INET6 => {
                let sin6 = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                ifaces[idx]
                    .addresses
                    .push(InterfaceAddr::new(ip.to_string(), None));
            }
            libc::AF_LINK => {
                let sdl = &*(ifa.ifa_addr as *const libc::sockaddr_dl);
                let nlen = sdl.sdl_nlen as usize;
                let alen = sdl.sdl_alen as usize;
                // MAC is the 6 bytes after the interface name in sdl_data.
                // Guard against the fixed-size sdl_data array bounds.
                if alen == 6 && nlen + alen <= sdl.sdl_data.len() {
                    let mac = (0..alen)
                        .map(|k| format!("{:02x}", sdl.sdl_data[nlen + k] as u8))
                        .collect::<Vec<_>>()
                        .join(":");
                    ifaces[idx].mac_address = Some(mac);
                }
            }
            _ => {}
        }
    }

    ifaces
}

/// Read a string-valued sysctl by name (e.g. `kern.osproductversion`).
fn sysctl_string(name: &str) -> Option<String> {
    let cname = CString::new(name).ok()?;
    // SAFETY: standard two-call sysctlbyname pattern (query length, then value).
    unsafe {
        let mut len: libc::size_t = 0;
        if libc::sysctlbyname(
            cname.as_ptr(),
            std::ptr::null_mut(),
            &mut len,
            std::ptr::null_mut(),
            0,
        ) != 0
            || len == 0
        {
            return None;
        }
        let mut buf = vec![0u8; len];
        if libc::sysctlbyname(
            cname.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return None;
        }
        let s = CStr::from_bytes_until_nul(&buf)
            .ok()?
            .to_string_lossy()
            .into_owned();
        (!s.is_empty()).then_some(s)
    }
}

/// Read an integer-valued sysctl by name (handles both 4- and 8-byte values).
fn sysctl_int(name: &str) -> Option<i64> {
    let cname = CString::new(name).ok()?;
    // SAFETY: sysctl writes at most 8 bytes into a zeroed i64; on little-endian
    // Apple silicon a 4-byte result lands in the low bytes and reads correctly.
    unsafe {
        let mut val: i64 = 0;
        let mut len: libc::size_t = std::mem::size_of::<i64>();
        if libc::sysctlbyname(
            cname.as_ptr(),
            &mut val as *mut i64 as *mut libc::c_void,
            &mut len,
            std::ptr::null_mut(),
            0,
        ) != 0
        {
            return None;
        }
        Some(val)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These exercise the same Apple getifaddrs/sysctl paths on the macOS host
    // that run on iOS. Run with: cargo test -p pentest-platform --no-default-features --features ios
    #[tokio::test]
    async fn device_info_reports_real_stats() {
        let info = get_device_info().await.unwrap();
        assert_eq!(info.os_name, "iOS");
        assert!(info.cpu_count >= 1, "cpu_count should be positive");
        assert!(info.total_memory_mb > 0, "memory should be non-zero");
        assert!(!info.architecture.is_empty());
    }

    #[tokio::test]
    async fn network_interfaces_include_loopback() {
        let ifaces = get_network_interfaces().await.unwrap();
        assert!(
            !ifaces.is_empty(),
            "should enumerate at least one interface"
        );
        // Loopback is always present and should carry 127.0.0.1.
        let lo = ifaces
            .iter()
            .find(|i| i.is_loopback)
            .expect("a loopback interface should exist");
        assert!(
            lo.ip_strings().iter().any(|ip| ip == "127.0.0.1"),
            "loopback should report 127.0.0.1, got {:?}",
            lo.ip_strings()
        );
    }
}
