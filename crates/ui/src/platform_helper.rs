//! Platform helper for conditional compilation

use pentest_platform::WifiConnectionStatus;

/// Check WiFi connection status
///
/// # Arguments
/// * `selected_adapter` - User's chosen WiFi interface (e.g., "wlan1")
#[cfg(any(
    feature = "desktop",
    feature = "android",
    feature = "ios",
    target_os = "android",
    target_os = "ios",
))]
pub async fn check_wifi_status(
    selected_adapter: Option<String>,
) -> Result<WifiConnectionStatus, String> {
    let platform = pentest_platform::get_platform();
    pentest_platform::SystemInfo::check_wifi_connection_status(&platform, selected_adapter)
        .await
        .map_err(|e| e.to_string())
}

/// Check WiFi connection status (fallback for other platforms)
#[cfg(not(any(
    feature = "desktop",
    feature = "android",
    feature = "ios",
    target_os = "android",
    target_os = "ios",
)))]
pub async fn check_wifi_status(
    _selected_adapter: Option<String>,
) -> Result<WifiConnectionStatus, String> {
    Ok(WifiConnectionStatus {
        connected_via_wifi: false,
        active_interface: None,
        total_adapters: 0,
        safe_to_scan: true,
        all_wifi_interfaces: vec![],
    })
}

/// Test WiFi adapter functionality
///
/// # Arguments
/// * `adapter` - WiFi interface to test (e.g., "wlan1")
#[cfg(any(
    feature = "desktop",
    feature = "android",
    feature = "ios",
    target_os = "android",
    target_os = "ios",
))]
pub async fn test_wifi_adapter(adapter: Option<String>) -> Result<String, String> {
    let platform = pentest_platform::get_platform();

    match adapter {
        Some(ref iface) => {
            match pentest_platform::SystemInfo::get_wifi_networks(&platform, Some(iface.clone()))
                .await
            {
                Ok(networks) => Ok(format!(
                    "Adapter '{}' is working - found {} network(s)",
                    iface,
                    networks.len()
                )),
                Err(e) => Err(format!("Adapter '{}' test failed: {}", iface, e)),
            }
        }
        None => Err("Please select an adapter to test".to_string()),
    }
}

/// Test WiFi adapter functionality (fallback for other platforms)
#[cfg(not(any(
    feature = "desktop",
    feature = "android",
    feature = "ios",
    target_os = "android",
    target_os = "ios",
)))]
pub async fn test_wifi_adapter(adapter: Option<String>) -> Result<String, String> {
    let _ = adapter;
    Err("WiFi adapter testing not supported on this platform".to_string())
}

/// Request screen capture permission (Android MediaProjection consent dialog).
#[cfg(target_os = "android")]
pub fn request_screen_capture() {
    pentest_platform::android::request_screen_capture();
}

/// Request screen capture permission (no-op on non-Android).
#[cfg(not(target_os = "android"))]
pub fn request_screen_capture() {}
