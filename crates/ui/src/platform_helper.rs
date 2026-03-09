//! Platform helper for conditional compilation

use pentest_platform::WifiConnectionStatus;

/// Check WiFi connection status (desktop/android/ios platforms)
#[cfg(any(feature = "desktop", feature = "android", feature = "ios"))]
pub async fn check_wifi_status() -> Result<WifiConnectionStatus, String> {
    use pentest_platform::{get_platform, SystemInfo as _};

    let platform = get_platform();
    platform
        .check_wifi_connection_status()
        .await
        .map_err(|e| e.to_string())
}

/// Check WiFi connection status (fallback for other platforms)
#[cfg(not(any(feature = "desktop", feature = "android", feature = "ios")))]
pub async fn check_wifi_status() -> Result<WifiConnectionStatus, String> {
    // Return safe by default for unsupported platforms
    Ok(WifiConnectionStatus {
        connected_via_wifi: false,
        active_interface: None,
        total_adapters: 0,
        safe_to_scan: true,
        all_wifi_interfaces: vec![],
    })
}
