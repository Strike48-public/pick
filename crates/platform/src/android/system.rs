//! Android system information

use crate::traits::*;
use pentest_core::error::Result;
use std::collections::HashMap;
use std::time::Duration;

/// Maximum time to wait for the `su` command to respond.
///
/// On rooted devices, the first invocation may trigger a SuperUser confirmation
/// prompt. Without a timeout, the call would hang indefinitely waiting for the
/// user. 5 seconds is generous for a fast denial path while preventing UI hang.
const SU_TIMEOUT: Duration = Duration::from_secs(5);

/// Root access status on Android device.
///
/// **Important**: This is informational only and is NOT a security boundary.
/// The status reflects a point-in-time check; root access may be revoked, SELinux
/// policies may change, or the device state may shift between detection and use.
/// Operations that require root must still handle failures gracefully — never
/// rely on `RootStatus::Available` as a guarantee that a privileged operation
/// will succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootStatus {
    /// Root access is available (su binary works, uid 0 achieved).
    Available,
    /// Root access is not available (su not found or failed to spawn).
    Unavailable,
    /// Root access exists but is constrained.
    ///
    /// The string is a categorized reason code (e.g., `"su_denied"`,
    /// `"selinux_enforcing"`, `"unexpected_uid"`) safe to display in UI/logs.
    /// Raw stderr from `su` is intentionally not exposed to avoid leaking
    /// device-specific information.
    Restricted(String),
}

/// Check if root access is available on the device.
///
/// Tests multiple indicators:
/// - `su` binary availability and execution (with 5s timeout)
/// - Ability to escalate to uid 0
/// - SELinux mode (enforcing vs permissive)
///
/// # Returns
/// - `RootStatus::Available` if full root access works
/// - `RootStatus::Unavailable` if no root access (su missing, spawn failed, or timed out)
/// - `RootStatus::Restricted(reason)` if root exists but is constrained
///
/// # Security Note
/// This is **informational only** and NOT a security boundary. The result is a
/// point-in-time check — see [`RootStatus`] for details. Privileged operations
/// must independently handle the case where root is unexpectedly unavailable.
pub async fn check_root_access() -> RootStatus {
    // Run `su -c "id -u"` with a timeout to prevent hang on interactive
    // permission prompts (SuperUser confirmation dialogs).
    let su_call = tokio::process::Command::new("su")
        .arg("-c")
        .arg("id -u")
        .output();

    let output = match tokio::time::timeout(SU_TIMEOUT, su_call).await {
        Ok(Ok(output)) => output,
        // Spawn failed (e.g., su binary not found) — treat as Unavailable.
        Ok(Err(_)) => return RootStatus::Unavailable,
        // Timed out — su likely waiting for user interaction. Without a clear
        // grant, treat as Restricted with a categorized code.
        Err(_) => return RootStatus::Restricted("su_timeout".to_string()),
    };

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.trim() == "0" {
            // Successfully became root; check for SELinux restrictions.
            match check_selinux_restrictions().await {
                Some(reason) => RootStatus::Restricted(reason),
                None => RootStatus::Available,
            }
        } else {
            // su exited 0 but didn't give us uid 0 — unexpected.
            RootStatus::Restricted("unexpected_uid".to_string())
        }
    } else {
        // su exited non-zero (denied, error, etc.). We do not parse stderr —
        // text varies across Android versions and could leak device info.
        // The caller can re-check or surface a generic "denied" state.
        RootStatus::Restricted("su_denied".to_string())
    }
}

/// Check whether SELinux is in enforcing mode.
///
/// Returns a categorized reason code if SELinux restricts root operations,
/// or `None` if SELinux is permissive/disabled or the check fails.
async fn check_selinux_restrictions() -> Option<String> {
    let output = tokio::process::Command::new("getenforce")
        .output()
        .await
        .ok()?;

    let mode = String::from_utf8_lossy(&output.stdout);
    if mode.trim().eq_ignore_ascii_case("enforcing") {
        Some("selinux_enforcing".to_string())
    } else {
        None
    }
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
    async fn check_root_access_returns_valid_variant() {
        // The actual variant returned depends on the host OS where the test runs.
        // On non-Android hosts (CI, dev machines), `su` typically isn't installed
        // or behaves differently — we verify the function returns a well-formed
        // result without panicking, regardless of environment.
        let status = check_root_access().await;
        assert!(matches!(
            status,
            RootStatus::Available | RootStatus::Unavailable | RootStatus::Restricted(_)
        ));

        // If Restricted, the reason must be one of our categorized codes,
        // never raw stderr output.
        if let RootStatus::Restricted(reason) = &status {
            let known_codes = [
                "su_denied",
                "su_timeout",
                "selinux_enforcing",
                "unexpected_uid",
            ];
            assert!(
                known_codes.contains(&reason.as_str()),
                "Restricted reason `{reason}` is not a known categorized code"
            );
        }
    }

    #[test]
    fn root_status_variants_are_distinguishable() {
        let available = RootStatus::Available;
        let unavailable = RootStatus::Unavailable;
        let restricted = RootStatus::Restricted("selinux_enforcing".to_string());

        assert_ne!(available, unavailable);
        assert_ne!(available, restricted);
        assert_ne!(unavailable, restricted);
    }

    #[test]
    fn root_status_implements_clone_and_debug() {
        let status = RootStatus::Restricted("su_denied".to_string());
        let cloned = status.clone();
        assert_eq!(status, cloned);

        let debug_str = format!("{status:?}");
        assert!(debug_str.contains("Restricted"));
        assert!(debug_str.contains("su_denied"));
    }
}
