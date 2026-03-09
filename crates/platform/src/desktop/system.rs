//! Desktop system information implementation

use crate::traits::*;
use pentest_core::error::{Error, Result};
use sysinfo::System;

/// Get device/system information
pub async fn get_device_info() -> Result<DeviceInfo> {
    let mut sys = System::new_all();
    sys.refresh_all();

    let os_name = System::name().unwrap_or_else(|| "Unknown".to_string());
    let os_version = System::os_version().unwrap_or_else(|| "Unknown".to_string());
    let hostname = System::host_name().unwrap_or_else(|| "Unknown".to_string());
    let architecture = std::env::consts::ARCH.to_string();
    let cpu_count = sys.cpus().len();
    let total_memory_mb = sys.total_memory() / 1024 / 1024;

    let platform_specific = PlatformDetails::Desktop {
        kernel_version: System::kernel_version().unwrap_or_else(|| "Unknown".to_string()),
        cpu_brand: sys
            .cpus()
            .first()
            .map(|c| c.brand().to_string())
            .unwrap_or_else(|| "Unknown".to_string()),
        used_memory_mb: sys.used_memory() / 1024 / 1024,
        process_count: sys.processes().len(),
    };

    Ok(DeviceInfo {
        os_name,
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
    #[cfg(feature = "network-interface")]
    {
        use network_interface::{NetworkInterface as NI, NetworkInterfaceConfig};

        let interfaces = NI::show().map_err(|e| Error::Network(e.to_string()))?;

        Ok(interfaces
            .into_iter()
            .map(|iface| {
                let ip_addresses: Vec<String> = iface
                    .addr
                    .into_iter()
                    .map(|addr| addr.ip().to_string())
                    .collect();

                NetworkInterface {
                    name: iface.name,
                    ip_addresses,
                    mac_address: iface.mac_addr,
                    is_up: true,        // network-interface doesn't provide this
                    is_loopback: false, // would need to check IP
                }
            })
            .collect())
    }

    #[cfg(not(feature = "network-interface"))]
    {
        // Fallback implementation using system commands
        get_network_interfaces_fallback().await
    }
}

#[cfg(not(feature = "network-interface"))]
async fn get_network_interfaces_fallback() -> Result<Vec<NetworkInterface>> {
    #[cfg(target_os = "linux")]
    {
        use std::process::Command;

        let output =
            tokio::task::spawn_blocking(|| Command::new("ip").args(["addr", "show"]).output())
                .await
                .map_err(|e| Error::Unknown(e.to_string()))?
                .map_err(|e| Error::Io(e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut interfaces = Vec::new();
        let mut current_iface: Option<NetworkInterface> = None;

        for line in stdout.lines() {
            if line.starts_with(char::is_numeric) {
                // New interface line
                if let Some(iface) = current_iface.take() {
                    interfaces.push(iface);
                }

                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let name = parts[1].trim_end_matches(':').to_string();
                    let is_loopback = line.contains("LOOPBACK");
                    let is_up = line.contains("UP");

                    current_iface = Some(NetworkInterface {
                        name,
                        ip_addresses: Vec::new(),
                        mac_address: None,
                        is_up,
                        is_loopback,
                    });
                }
            } else if let Some(ref mut iface) = current_iface {
                let trimmed = line.trim();
                if trimmed.starts_with("inet ") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        // Extract IP without subnet mask
                        let ip = parts[1].split('/').next().unwrap_or(parts[1]);
                        iface.ip_addresses.push(ip.to_string());
                    }
                } else if trimmed.starts_with("inet6 ") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        let ip = parts[1].split('/').next().unwrap_or(parts[1]);
                        iface.ip_addresses.push(ip.to_string());
                    }
                } else if trimmed.starts_with("link/ether ") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        iface.mac_address = Some(parts[1].to_string());
                    }
                }
            }
        }

        if let Some(iface) = current_iface {
            interfaces.push(iface);
        }

        Ok(interfaces)
    }

    #[cfg(not(target_os = "linux"))]
    {
        Ok(Vec::new())
    }
}

/// Get WiFi networks
pub async fn get_wifi_networks() -> Result<Vec<WifiNetwork>> {
    #[cfg(feature = "wifi_scan")]
    {
        let networks = tokio::task::spawn_blocking(wifi_scan::scan)
            .await
            .map_err(|e| Error::Unknown(e.to_string()))?
            .map_err(|e| Error::Network(format!("WiFi scan failed: {}", e)))?;

        Ok(networks
            .into_iter()
            .filter(|n| !n.ssid.is_empty())
            .map(|n| WifiNetwork {
                ssid: n.ssid,
                bssid: n.mac,
                signal_strength: n.signal_level,
                frequency: 0, // not provided by wifi_scan
                channel: n.channel,
                security: n
                    .security
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(","),
            })
            .collect())
    }

    #[cfg(not(feature = "wifi_scan"))]
    {
        Err(Error::PlatformNotSupported(
            "WiFi scanning requires the 'wifi_scan' feature".into(),
        ))
    }
}

/// Check WiFi connection status for scan safety assessment
pub async fn check_wifi_connection_status() -> Result<WifiConnectionStatus> {
    let interfaces = get_network_interfaces().await?;

    // WiFi interface name patterns (Linux, macOS, Windows)
    let is_wifi_name = |name: &str| {
        name.starts_with("wlan")
            || name.starts_with("wlp")
            || name.starts_with("wl")
            || name.starts_with("en0") // macOS WiFi (usually)
            || name.contains("wi-fi")
            || name.contains("wireless")
            || name.to_lowercase().contains("wifi")
    };

    // Find active WiFi interfaces (up + has IP)
    let active_wifi: Vec<_> = interfaces
        .iter()
        .filter(|i| i.is_up && !i.ip_addresses.is_empty() && is_wifi_name(&i.name))
        .collect();

    // Find all WiFi interfaces (even if down)
    let all_wifi: Vec<String> = interfaces
        .iter()
        .filter(|i| is_wifi_name(&i.name))
        .map(|i| i.name.clone())
        .collect();

    let connected_via_wifi = !active_wifi.is_empty();
    let total_adapters = all_wifi.len();

    // Safe if: not on WiFi OR has multiple adapters (external available)
    let safe_to_scan = !connected_via_wifi || total_adapters > 1;

    Ok(WifiConnectionStatus {
        connected_via_wifi,
        active_interface: active_wifi.first().map(|i| i.name.clone()),
        total_adapters,
        safe_to_scan,
        all_wifi_interfaces: all_wifi,
    })
}
