//! Android network operations

use crate::traits::*;
use pentest_core::error::Result;
use std::time::Duration;

/// Perform a port scan
pub async fn port_scan(config: ScanConfig) -> Result<ScanResult> {
    let timeout = Duration::from_millis(config.timeout_ms);

    Ok(crate::common::tcp_port_scan(&config.host, &config.ports, timeout, 0).await)
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

/// Discover SSDP devices.
///
/// Delegates to the shared, platform-agnostic implementation in
/// [`crate::common::ssdp`] (behavior-identical to the previous inline copy).
pub async fn ssdp_discover(timeout_ms: u64) -> Result<Vec<SsdpDevice>> {
    crate::common::ssdp::discover(timeout_ms).await
}
