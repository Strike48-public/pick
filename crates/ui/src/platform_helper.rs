//! Platform helper for conditional compilation

use pentest_platform::WifiConnectionStatus;

/// Check WiFi connection status (desktop/android/ios platforms)
///
/// # Arguments
/// * `selected_adapter` - User's chosen WiFi interface (e.g., "wlan1")
#[cfg(any(feature = "desktop", feature = "android", feature = "ios"))]
pub async fn check_wifi_status(
    selected_adapter: Option<String>,
) -> Result<WifiConnectionStatus, String> {
    use pentest_platform::{get_platform, SystemInfo as _};

    let platform = get_platform();
    platform
        .check_wifi_connection_status(selected_adapter)
        .await
        .map_err(|e| e.to_string())
}

/// Check WiFi connection status (fallback for other platforms)
#[cfg(not(any(feature = "desktop", feature = "android", feature = "ios")))]
pub async fn check_wifi_status(
    selected_adapter: Option<String>,
) -> Result<WifiConnectionStatus, String> {
    let _ = selected_adapter; // Suppress unused warning
    // Return safe by default for unsupported platforms
    Ok(WifiConnectionStatus {
        connected_via_wifi: false,
        active_interface: None,
        total_adapters: 0,
        safe_to_scan: true,
        all_wifi_interfaces: vec![],
    })
}

/// Test WiFi adapter functionality (desktop/android/ios platforms)
///
/// # Arguments
/// * `adapter` - WiFi interface to test (e.g., "wlan1")
#[cfg(any(feature = "desktop", feature = "android", feature = "ios"))]
pub async fn test_wifi_adapter(adapter: Option<String>) -> Result<String, String> {
    use pentest_platform::{get_platform, SystemInfo as _};

    let platform = get_platform();

    match adapter {
        Some(ref iface) => {
            // Test by attempting to scan with this specific adapter
            match platform.get_wifi_networks(Some(iface.clone())).await {
                Ok(networks) => {
                    Ok(format!(
                        "Adapter '{}' is working - found {} network(s)",
                        iface,
                        networks.len()
                    ))
                }
                Err(e) => Err(format!("Adapter '{}' test failed: {}", iface, e)),
            }
        }
        None => Err("Please select an adapter to test".to_string()),
    }
}

/// Test WiFi adapter functionality (fallback for other platforms)
#[cfg(not(any(feature = "desktop", feature = "android", feature = "ios")))]
pub async fn test_wifi_adapter(adapter: Option<String>) -> Result<String, String> {
    let _ = adapter;
    Err("WiFi adapter testing not supported on this platform".to_string())
}
