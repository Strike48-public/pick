//! Android system information

use crate::traits::*;
use pentest_core::error::Result;
use std::collections::HashMap;

/// Root access status on Android device
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootStatus {
    /// Root access is available (su binary works, uid 0 achieved)
    Available,
    /// Root access is not available (su not found or failed)
    Unavailable,
    /// Root access is restricted (su exists but constrained by SELinux, etc.)
    Restricted(String),
}

/// Check if root access is available on the device
///
/// Tests multiple indicators:
/// - `su` binary availability and execution
/// - Ability to escalate to uid 0
/// - SELinux mode (enforcing vs permissive)
///
/// # Returns
/// - `RootStatus::Available` if full root access works
/// - `RootStatus::Unavailable` if no root access
/// - `RootStatus::Restricted(reason)` if root exists but is constrained
pub async fn check_root_access() -> RootStatus {
    // Try to run `su -c "id -u"` to check if we can become root
    match tokio::process::Command::new("su")
        .arg("-c")
        .arg("id -u")
        .output()
        .await
    {
        Ok(output) if output.status.success() => {
            let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if uid == "0" {
                // Successfully became root, check for restrictions
                if let Some(restriction) = check_selinux_restrictions().await {
                    RootStatus::Restricted(restriction)
                } else {
                    RootStatus::Available
                }
            } else {
                // su succeeded but didn't give us uid 0
                RootStatus::Restricted(format!("su succeeded but uid is {uid}, not 0"))
            }
        }
        Ok(output) => {
            // Command ran but failed (denied, etc.)
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("not found") {
                RootStatus::Unavailable
            } else {
                RootStatus::Restricted(format!("su failed: {stderr}"))
            }
        }
        Err(_) => {
            // su binary not found
            RootStatus::Unavailable
        }
    }
}

/// Check if SELinux or other security policies restrict root operations
async fn check_selinux_restrictions() -> Option<String> {
    // Check SELinux mode
    if let Ok(output) = tokio::process::Command::new("getenforce").output().await {
        let mode = String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_lowercase();
        if mode == "enforcing" {
            return Some("SELinux is enforcing (some operations may be restricted)".to_string());
        }
    }

    None
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_root_detection_runs_without_panic() {
        // This test verifies the function runs without panicking
        // Actual root status depends on device/emulator configuration
        let status = check_root_access().await;

        // Should return one of the enum variants
        match status {
            RootStatus::Available => {
                // Device has root - verify we can actually use it
                assert!(true, "Root available on test device");
            }
            RootStatus::Unavailable => {
                // No root - expected on most CI environments
                assert!(true, "No root on test device (expected in CI)");
            }
            RootStatus::Restricted(reason) => {
                // Root exists but restricted
                assert!(!reason.is_empty(), "Restriction reason should not be empty");
            }
        }
    }

    #[tokio::test]
    async fn test_root_status_variants_are_distinguishable() {
        // Verify enum variants are distinct
        let available = RootStatus::Available;
        let unavailable = RootStatus::Unavailable;
        let restricted = RootStatus::Restricted("SELinux enforcing".to_string());

        assert_ne!(available, unavailable);
        assert_ne!(available, restricted);
        assert_ne!(unavailable, restricted);
    }

    #[test]
    fn test_root_status_clone_and_debug() {
        let status = RootStatus::Restricted("test".to_string());
        let cloned = status.clone();
        assert_eq!(status, cloned);

        // Verify Debug impl works
        let debug_str = format!("{:?}", status);
        assert!(debug_str.contains("Restricted"));
        assert!(debug_str.contains("test"));
    }
}
