//! Android system information

use crate::traits::*;
use pentest_core::error::Result;
use std::collections::HashMap;

/// Read a single Android system property via `getprop`, returning an empty
/// string when the property is missing or the command fails.
async fn read_prop(prop: &str) -> String {
    if let Ok(output) = tokio::process::Command::new("getprop")
        .arg(prop)
        .output()
        .await
    {
        let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
        val
    } else {
        String::new()
    }
}

/// Get device information
pub async fn get_device_info() -> Result<DeviceInfo> {
    let android_version = read_prop("ro.build.version.release").await;
    let device_model = read_prop("ro.product.model").await;
    let manufacturer = read_prop("ro.product.manufacturer").await;

    // Get memory info from /proc/meminfo
    let total_memory_mb = if let Ok(content) = tokio::fs::read_to_string("/proc/meminfo").await {
        content
            .lines()
            .find(|line| line.starts_with("MemTotal:"))
            .and_then(|line| {
                line.split_whitespace()
                    .nth(1)
                    .and_then(|s| s.parse::<u64>().ok())
            })
            .map(|kb| kb / 1024)
            .unwrap_or(0)
    } else {
        0
    };

    // Get CPU count from /proc/cpuinfo
    let cpu_count = if let Ok(content) = tokio::fs::read_to_string("/proc/cpuinfo").await {
        content
            .lines()
            .filter(|line| line.starts_with("processor"))
            .count()
    } else {
        1
    };

    // Get hostname
    let hostname = {
        let h = read_prop("net.hostname").await;
        if h.is_empty() {
            "android".to_string()
        } else {
            h
        }
    };

    // Get architecture
    let architecture = std::env::consts::ARCH.to_string();

    let os_version = android_version.clone();

    let platform_specific = PlatformDetails::Android {
        android_version,
        device_model,
        manufacturer,
        extra: HashMap::new(),
    };

    Ok(DeviceInfo {
        os_name: "Android".to_string(),
        os_version,
        hostname,
        architecture,
        cpu_count,
        total_memory_mb,
        platform_specific,
    })
}

/// Get network interfaces
pub async fn get_network_interfaces() -> Result<Vec<NetworkInterface>> {
    let mut interfaces = Vec::new();

    // Read from /proc/net/dev for interface names
    if let Ok(content) = tokio::fs::read_to_string("/proc/net/dev").await {
        for line in content.lines().skip(2) {
            if let Some(name) = line.split(':').next() {
                let name = name.trim().to_string();
                if name.is_empty() {
                    continue;
                }

                let is_loopback = name == "lo";

                // Try to get IP address using ip command
                let ip_addresses = get_interface_ips(&name).await;

                interfaces.push(NetworkInterface {
                    name,
                    ip_addresses,
                    mac_address: None, // Would need to read from /sys/class/net/*/address
                    is_up: true,
                    is_loopback,
                });
            }
        }
    }

    Ok(interfaces)
}

async fn get_interface_ips(interface: &str) -> Vec<String> {
    let mut ips = Vec::new();

    if let Ok(output) = tokio::process::Command::new("ip")
        .args(["addr", "show", interface])
        .output()
        .await
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if line.starts_with("inet ") {
                if let Some(addr) = line.split_whitespace().nth(1) {
                    // Remove CIDR notation
                    let ip = addr.split('/').next().unwrap_or(addr);
                    ips.push(ip.to_string());
                }
            }
        }
    }

    ips
}
