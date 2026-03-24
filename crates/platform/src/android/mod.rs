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

use crate::traits::*;
use async_trait::async_trait;
use pentest_core::error::{Error, Result};
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
        let _ = selected_adapter; // Suppress unused warning
                                  // Android doesn't have the same WiFi adapter issues as desktop
                                  // Return safe by default
        Ok(WifiConnectionStatus {
            connected_via_wifi: false,
            active_interface: None,
            total_adapters: 1,
            safe_to_scan: true,
            all_wifi_interfaces: vec![],
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

#[async_trait]
impl WifiAttackOps for AndroidPlatform {
    async fn enable_monitor_mode(
        &self,
        _interface: &str,
        _allow_kill_network_manager: bool,
    ) -> Result<(String, bool)> {
        Err(Error::PlatformNotSupported(
            "WiFi attacks not supported on Android without root".into(),
        ))
    }

    async fn disable_monitor_mode(
        &self,
        _interface: &str,
        _restart_network_manager: bool,
    ) -> Result<()> {
        Err(Error::PlatformNotSupported(
            "WiFi attacks not supported on Android".into(),
        ))
    }

    async fn clone_mac(&self, _interface: &str, _target_mac: &str) -> Result<()> {
        Err(Error::PlatformNotSupported(
            "WiFi attacks not supported on Android".into(),
        ))
    }

    async fn test_injection(&self, _interface: &str) -> Result<InjectionCapability> {
        Ok(InjectionCapability {
            supported: false,
            success_rate: 0.0,
        })
    }

    async fn start_capture(
        &self,
        _interface: &str,
        _bssid: &str,
        _channel: u8,
        _output_file: &str,
    ) -> Result<WifiCaptureHandle> {
        Err(Error::PlatformNotSupported(
            "WiFi attacks not supported on Android".into(),
        ))
    }

    async fn stop_capture(&self, _handle: WifiCaptureHandle) -> Result<()> {
        Ok(())
    }

    async fn get_capture_stats(&self, _handle: &WifiCaptureHandle) -> Result<WifiCaptureStats> {
        Ok(WifiCaptureStats {
            packets: 0,
            ivs: 0,
            has_handshake: false,
            data_packets: 0,
        })
    }

    async fn fake_auth(&self, _interface: &str, _bssid: &str) -> Result<()> {
        Err(Error::PlatformNotSupported(
            "WiFi attacks not supported on Android".into(),
        ))
    }

    async fn start_arp_replay(&self, _interface: &str, _bssid: &str) -> Result<ArpReplayHandle> {
        Err(Error::PlatformNotSupported(
            "WiFi attacks not supported on Android".into(),
        ))
    }

    async fn stop_arp_replay(&self, _handle: ArpReplayHandle) -> Result<()> {
        Ok(())
    }

    async fn deauth_attack(
        &self,
        _interface: &str,
        _bssid: &str,
        _client: Option<&str>,
        _count: u8,
    ) -> Result<()> {
        Err(Error::PlatformNotSupported(
            "WiFi attacks not supported on Android".into(),
        ))
    }

    async fn verify_handshake(&self, _capture_file: &str, _bssid: &str) -> Result<bool> {
        Ok(false)
    }

    async fn crack_wep(&self, _capture_file: &str, _bssid: &str) -> Result<Option<String>> {
        Ok(None)
    }
}

impl PlatformProvider for AndroidPlatform {}
