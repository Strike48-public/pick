//! Android platform implementation

mod device_enrichment;
mod jni_bridge;
mod mdns;
mod network;
pub mod proot;
pub mod pty_shell;
mod screenshot;
mod system;
mod traffic;
mod wifi;
mod wifi_attack;

use crate::traits::*;
use async_trait::async_trait;
use pentest_core::error::Result;
use std::time::Duration;

/// Android application home directory inside the app's private storage.
const APP_HOME: &str = "/data/data/com.strike48.pentest_connector/files";

/// One-time Android environment setup.
///
/// Sets `HOME` and `STRIKE48_KEYS_DIR` environment variables and creates the
/// keys directory on disk.  Safe to call multiple times — only the first
/// invocation performs any work.
pub fn init() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        if std::env::var("HOME").is_err() {
            std::env::set_var("HOME", APP_HOME);
        }

        let keys_dir = format!("{APP_HOME}/.strike48/keys");
        let _ = std::fs::create_dir_all(&keys_dir);
        std::env::set_var("STRIKE48_KEYS_DIR", &keys_dir);

        // Set TLS insecure mode from build-time defaults.
        // Dev builds accept self-signed certs; prod builds require valid certs.
        if std::env::var("MATRIX_TLS_INSECURE").is_err() {
            let insecure = if pentest_core::build_defaults::DEFAULT_TLS_INSECURE {
                "true"
            } else {
                "false"
            };
            std::env::set_var("MATRIX_TLS_INSECURE", insecure);
            std::env::set_var("MATRIX_INSECURE", insecure);
        }

        tracing::info!(
            "Android init: HOME={}, STRIKE48_KEYS_DIR={keys_dir}",
            std::env::var("HOME").unwrap_or_default()
        );
    });
}

/// Start the foreground service to prevent Android from killing the connector.
/// Call once after the app is fully initialized and the connector is about to run.
pub fn start_foreground_service() {
    jni_bridge::start_foreground_service();
}

/// Request all required Android runtime permissions.
/// Call once at app startup.
pub fn request_permissions() {
    jni_bridge::request_permissions();
}

/// Launch the MediaProjection screen capture consent dialog.
/// Must be called before screenshot capture will work.
pub fn request_screen_capture() {
    jni_bridge::request_screen_capture();
}

/// Open a URL in the system browser via Android Intent.
pub fn open_browser(url: &str) -> Result<()> {
    jni_bridge::open_browser(url)
}

/// Tell the Android OAuthCallbackActivity which port the local callback server is on.
pub fn set_oauth_callback_port(port: u16) -> Result<()> {
    jni_bridge::set_oauth_callback_port(port)
}

/// Android platform provider
pub struct AndroidPlatform;

impl AndroidPlatform {
    pub fn new() -> Self {
        Self
    }
}

impl Default for AndroidPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetworkOps for AndroidPlatform {
    async fn port_scan(&self, config: ScanConfig) -> Result<ScanResult> {
        network::port_scan(config).await
    }

    async fn get_arp_table(&self) -> Result<Vec<ArpEntry>> {
        network::get_arp_table().await
    }

    async fn ssdp_discover(&self, timeout_ms: u64) -> Result<Vec<SsdpDevice>> {
        network::ssdp_discover(timeout_ms).await
    }

    async fn mdns_discover(&self, service_type: &str, timeout_ms: u64) -> Result<Vec<MdnsService>> {
        mdns::mdns_discover(service_type, timeout_ms).await
    }
}

#[async_trait]
impl SystemInfo for AndroidPlatform {
    async fn get_device_info(&self) -> Result<DeviceInfo> {
        let mut info = system::get_device_info().await?;
        device_enrichment::enrich(&mut info);
        Ok(info)
    }

    async fn get_network_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        system::get_network_interfaces().await
    }

    async fn get_wifi_networks(&self, interface: Option<String>) -> Result<Vec<WifiNetwork>> {
        // TODO: Implement interface selection for Android (Task #5)
        let _ = interface; // Suppress unused warning
        wifi::get_wifi_networks().await
    }

    async fn check_wifi_connection_status(
        &self,
        selected_adapter: Option<String>,
    ) -> Result<WifiConnectionStatus> {
        let _ = selected_adapter;
        // Android has a built-in WiFi adapter (wlan0) and mobile data fallback,
        // so it's always safe to scan — disconnecting from WiFi won't lose
        // connectivity because the device will fall back to cellular.
        Ok(WifiConnectionStatus {
            connected_via_wifi: true,
            active_interface: Some("wlan0".to_string()),
            total_adapters: 1,
            safe_to_scan: true,
            all_wifi_interfaces: vec!["wlan0".to_string()],
        })
    }
}

#[async_trait]
impl CaptureOps for AndroidPlatform {
    async fn capture_screenshot(&self) -> Result<Vec<u8>> {
        screenshot::capture_screenshot().await
    }

    async fn start_traffic_capture(&self) -> Result<CaptureHandle> {
        traffic::start_traffic_capture().await
    }

    async fn get_captured_packets(
        &self,
        handle: &CaptureHandle,
        limit: usize,
    ) -> Result<Vec<PacketInfo>> {
        traffic::get_captured_packets(handle, limit).await
    }

    async fn stop_traffic_capture(&self, handle: CaptureHandle) -> Result<()> {
        traffic::stop_traffic_capture(handle).await
    }
}

#[async_trait]
impl CommandExec for AndroidPlatform {
    async fn execute_command(
        &self,
        cmd: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandResult> {
        proot::execute_command(cmd, args, timeout).await
    }

    fn is_command_exec_supported(&self) -> bool {
        true
    }
}

// WifiAttackOps is implemented in wifi_attack.rs using `su -c` for root access.

impl PlatformProvider for AndroidPlatform {}
