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

/// Scan WiFi networks on a specific interface using `iw` command (Linux only)
#[cfg(target_os = "linux")]
async fn scan_specific_interface(interface: &str) -> Result<Vec<WifiNetwork>> {
    use tokio::process::Command;

    // First, verify the interface exists
    let check_output = Command::new("ip")
        .args(["link", "show", interface])
        .output()
        .await
        .map_err(|e| Error::Network(format!("Failed to check interface: {}", e)))?;

    if !check_output.status.success() {
        return Err(Error::Network(format!(
            "WiFi adapter '{}' not found. Please check Settings → WiFi Adapter.",
            interface
        )));
    }

    // Check if interface is in monitor mode
    let iw_info = Command::new("iw")
        .args(["dev", interface, "info"])
        .output()
        .await
        .map_err(|e| Error::Network(format!("Failed to check interface mode: {}", e)))?;

    let info_stdout = String::from_utf8_lossy(&iw_info.stdout);
    if info_stdout.contains("type monitor") {
        // Try to find the original managed-mode interface name.
        // Common patterns: wlan0mon → wlan0, wlp2s0mon → wlp2s0
        let base_iface = interface.strip_suffix("mon").unwrap_or(interface);
        let has_base = if base_iface != interface {
            // Check if the base interface still exists
            Command::new("iw")
                .args(["dev", base_iface, "info"])
                .output()
                .await
                .map(|o| o.status.success())
                .unwrap_or(false)
        } else {
            false
        };

        let hint = if has_base {
            format!(
                "Adapter '{}' is in monitor mode (used for packet capture/autopwn).\n\n\
                 Your base adapter '{}' is still available — try scanning with that instead.\n\
                 Or disable monitor mode first:\n  sudo airmon-ng stop {}",
                interface, base_iface, interface
            )
        } else {
            format!(
                "Adapter '{}' is in monitor mode. Regular WiFi scanning requires managed mode.\n\n\
                 To restore it:\n  sudo airmon-ng stop {}\n\n\
                 If that doesn't work:\n  sudo ip link set {} down\n  sudo iw dev {} set type managed\n  sudo ip link set {} up",
                interface, interface, interface, interface, interface
            )
        };

        return Err(Error::Network(hint));
    }

    // Temporarily unmanage the device from NetworkManager to release wpa_supplicant
    // This prevents "Device or resource busy" errors when scanning
    let _ = Command::new("nmcli")
        .args(["device", "set", interface, "managed", "no"])
        .output()
        .await;

    // Give it a moment for wpa_supplicant to release the device
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Ensure the interface is up — NetworkManager may leave it down after
    // unmanaging, causing "Network is down (-100)" from iw scan.
    let _ = Command::new("ip")
        .args(["link", "set", interface, "up"])
        .output()
        .await;
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    // Run iw scan
    let scan_result = Command::new("iw")
        .args(["dev", interface, "scan"])
        .output()
        .await
        .map_err(|e| Error::Network(format!("Failed to execute iw command: {}", e)));

    // Always re-manage the device (cleanup), even if scan failed
    let _ = Command::new("nmcli")
        .args(["device", "set", interface, "managed", "yes"])
        .output()
        .await;

    // Now check the scan result
    let output = scan_result?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Provide helpful error messages for common issues
        if stderr.contains("Device or resource busy") || stderr.contains("(-16)") {
            return Err(Error::Network(format!(
                "Adapter '{}' is still busy after releasing from NetworkManager.\n\n\
                 This can happen if:\n\
                 • The adapter driver is misbehaving\n\
                 • Another tool has locked the device\n\
                 • The adapter needs a reset\n\n\
                 Try unplugging and replugging the adapter, then:\n\
                 1. Wait 5-10 seconds after plugging it in\n\
                 2. Try the test again\n\
                 3. If still failing: sudo systemctl restart NetworkManager",
                interface
            )));
        }

        if stderr.contains("Network is down") || stderr.contains("(-100)") {
            return Err(Error::Network(format!(
                "WiFi adapter '{}' is down and could not be brought up.\n\n\
                 This can happen when NetworkManager has the interface suspended.\n\
                 Try: sudo ip link set {} up\n\
                 Or restart NetworkManager: sudo systemctl restart NetworkManager",
                interface, interface
            )));
        }

        return Err(Error::Network(format!(
            "WiFi scan failed on '{}': {}",
            interface, stderr
        )));
    }

    // Parse iw scan output
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut networks = Vec::new();
    let mut current_bssid = String::new();
    let mut current_ssid = String::new();
    let mut current_signal = 0;
    let mut current_channel = 0;
    let mut current_security = Vec::new();
    let mut current_has_privacy = false;
    let mut current_has_wpa = false;

    for line in stdout.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with("BSS ") {
            // Finalize previous network's security before saving
            if !current_bssid.is_empty() && !current_ssid.is_empty() {
                // If Privacy is set but no WPA/RSN found, it's WEP
                if current_has_privacy && !current_has_wpa && current_security.is_empty() {
                    current_security.push("WEP".to_string());
                }

                // If no security info found at all, mark as Open
                let security = if current_security.is_empty() {
                    "Open".to_string()
                } else {
                    current_security.join(",")
                };

                networks.push(WifiNetwork {
                    ssid: current_ssid.clone(),
                    bssid: current_bssid.clone(),
                    signal_strength: current_signal,
                    frequency: 0,
                    channel: current_channel,
                    security,
                    clients: None, // Not available without monitor mode
                });
            }

            // Start new network
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            current_bssid = parts
                .get(1)
                .unwrap_or(&"")
                .trim_end_matches('(')
                .to_string();
            current_ssid = String::new();
            current_signal = 0;
            current_channel = 0;
            current_security = Vec::new();
            current_has_privacy = false;
            current_has_wpa = false;
        } else if trimmed.starts_with("SSID: ") {
            current_ssid = trimmed.strip_prefix("SSID: ").unwrap_or("").to_string();
        } else if trimmed.starts_with("signal: ") {
            if let Some(signal_str) = trimmed.strip_prefix("signal: ") {
                if let Some(value) = signal_str.split_whitespace().next() {
                    current_signal = value.parse().unwrap_or(0);
                }
            }
        } else if trimmed.starts_with("DS Parameter set: channel ") {
            if let Some(channel_str) = trimmed.strip_prefix("DS Parameter set: channel ") {
                current_channel = channel_str.parse().unwrap_or(0);
            }
        } else if trimmed.starts_with("RSN:") || trimmed.starts_with("WPA:") {
            // Mark that we found WPA/WPA2/WPA3 (RSN = Robust Security Network = WPA2+)
            current_has_wpa = true;
            if trimmed.starts_with("RSN:") {
                current_security.push("WPA2".to_string());
            } else {
                current_security.push("WPA".to_string());
            }
        } else if trimmed.contains("Authentication suites:") && trimmed.contains("PSK") {
            current_security.push("PSK".to_string());
        } else if trimmed.contains("Capability:") && trimmed.contains("Privacy") {
            // Privacy bit just means encryption is enabled
            current_has_privacy = true;
        }
    }

    // Save last network with security finalization
    if !current_bssid.is_empty() && !current_ssid.is_empty() {
        // If Privacy is set but no WPA/RSN found, it's WEP
        if current_has_privacy && !current_has_wpa && current_security.is_empty() {
            current_security.push("WEP".to_string());
        }

        // If no security info found at all, mark as Open
        let security = if current_security.is_empty() {
            "Open".to_string()
        } else {
            current_security.join(",")
        };

        networks.push(WifiNetwork {
            ssid: current_ssid,
            bssid: current_bssid,
            signal_strength: current_signal,
            frequency: 0,
            channel: current_channel,
            security,
            clients: None, // Not available without monitor mode
        });
    }

    Ok(networks)
}

/// Get WiFi networks
///
/// # Arguments
/// * `interface` - Optional WiFi interface to scan (e.g., "wlan1"). If None, uses auto-detect.
pub async fn get_wifi_networks(interface: Option<String>) -> Result<Vec<WifiNetwork>> {
    // If interface specified, use iw command (Linux only)
    #[cfg(target_os = "linux")]
    if let Some(iface) = interface {
        return scan_specific_interface(&iface).await;
    }

    // Fallback to wifi_scan crate for auto-detect
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
                clients: None, // Not available without monitor mode
            })
            .collect())
    }

    #[cfg(not(feature = "wifi_scan"))]
    {
        let _ = interface; // Suppress unused warning
        Err(Error::PlatformNotSupported(
            "WiFi scanning requires the 'wifi_scan' feature".into(),
        ))
    }
}

/// Check WiFi connection status for scan safety assessment
///
/// # Arguments
/// * `selected_adapter` - User's chosen WiFi interface (e.g., "wlan1"). If provided,
///   safety is assessed based on whether this adapter differs from the active connection.
pub async fn check_wifi_connection_status(
    selected_adapter: Option<String>,
) -> Result<WifiConnectionStatus> {
    let interfaces = get_network_interfaces().await?;

    // WiFi interface name patterns (Linux, macOS, Windows)
    // Also recognises monitor-mode variants like wlan0mon, wlp2s0mon
    let is_wifi_name = |name: &str| {
        name.starts_with("wlan")
            || name.starts_with("wlp")
            || name.starts_with("wl")
            || name.starts_with("en0") // macOS WiFi (usually)
            || name.contains("wi-fi")
            || name.contains("wireless")
            || name.to_lowercase().contains("wifi")
            || name.ends_with("mon") // monitor-mode interfaces (e.g. wlan0mon)
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
    let active_interface = active_wifi.first().map(|i| i.name.clone());

    // Smart safety assessment based on selected adapter
    let safe_to_scan = if let Some(ref selected) = selected_adapter {
        // User explicitly chose an adapter
        if let Some(ref active) = active_interface {
            // Check if selected adapter differs from active connection
            selected != active // Safe if different, unsafe if same
        } else {
            // Not connected via WiFi, always safe
            true
        }
    } else {
        // Auto-detect mode: Safe if not on WiFi OR has multiple adapters
        !connected_via_wifi || total_adapters > 1
    };

    Ok(WifiConnectionStatus {
        connected_via_wifi,
        active_interface,
        total_adapters,
        safe_to_scan,
        all_wifi_interfaces: all_wifi,
    })
}
