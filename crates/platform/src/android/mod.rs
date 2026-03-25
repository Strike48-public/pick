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

/// Root access status for the device.
#[derive(Debug, Clone)]
pub struct RootStatus {
    /// Whether `su` binary exists on the device.
    pub su_binary_found: bool,
    /// Whether `su -c id` succeeds (Magisk has granted access).
    pub su_access_granted: bool,
    /// Magisk version string, if detected.
    pub magisk_version: Option<String>,
    /// Output of `id` via su (e.g. "uid=0(root)").
    pub su_id_output: Option<String>,
    /// Human-readable summary.
    pub summary: String,
}

/// Check root/su availability on this Android device.
///
/// Tests whether `su` exists, whether Magisk grants access, and returns
/// a structured status the UI can display.
pub async fn check_root_status() -> RootStatus {
    use tokio::process::Command;

    // Check su binary
    let su_exists = Command::new("which")
        .arg("su")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    // Check Magisk version
    let magisk_ver = Command::new("magisk")
        .arg("-c")
        .output()
        .await
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        });

    // Try su -c id (this triggers the Magisk su grant dialog)
    let su_result = Command::new("su")
        .args(["-c", "id"])
        .output()
        .await;

    let (su_granted, su_id) = match su_result {
        Ok(output) if output.status.success() => {
            let id_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            (id_str.contains("uid=0"), Some(id_str))
        }
        _ => (false, None),
    };

    let summary = if su_granted {
        "Root access granted".to_string()
    } else if su_exists {
        if magisk_ver.is_some() {
            "Magisk installed but su access denied — open Magisk app and grant access to Strike48".to_string()
        } else {
            "su binary found but access denied — grant superuser access to Strike48".to_string()
        }
    } else {
        "No root detected — WiFi attacks require a rooted device".to_string()
    };

    RootStatus {
        su_binary_found: su_exists,
        su_access_granted: su_granted,
        magisk_version: magisk_ver,
        su_id_output: su_id,
        summary,
    }
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

/// Commands that require real hardware / kernel access and must run via `su -c`
/// on the host rather than inside the proot sandbox.
const ROOT_COMMANDS: &[&str] = &[
    "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng", "airbase-ng",
    "airdecap-ng", "airdecloak-ng", "airolib-ng", "airserv-ng", "airtun-ng",
    "besside-ng", "packetforge-ng", "tkiptun-ng", "wesside-ng",
    "iw", "iwconfig", "iwlist", "ifconfig",
    "wifite", "reaver", "bully", "pixiewps", "mdk4", "bettercap",
    "hcxdumptool", "hcxpcapngtool",
    "ip", "tc", "iptables", "nftables",
    "modprobe", "insmod", "rmmod", "lsmod",
    "rfkill", "iwpriv",
];

/// Check if a command needs root / host hardware access.
fn needs_root_execution(cmd: &str) -> bool {
    // Extract base command name from full path
    let base = cmd.rsplit('/').next().unwrap_or(cmd);
    ROOT_COMMANDS.contains(&base)
}

/// Execute a command via `su -c` for real root + hardware access.
async fn execute_via_su(
    cmd: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<CommandResult> {
    use std::time::Instant;
    use tokio::process::Command;

    let full_cmd = if args.is_empty() {
        cmd.to_string()
    } else {
        // Shell-escape args
        let escaped: Vec<String> = args.iter().map(|a| {
            if a.contains(' ') || a.contains('\'') || a.contains('"') {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.to_string()
            }
        }).collect();
        format!("{} {}", cmd, escaped.join(" "))
    };

    tracing::debug!("execute_via_su: su -c '{}'", full_cmd);
    let start = Instant::now();

    let result = tokio::time::timeout(
        timeout,
        Command::new("su")
            .args(["-c", &full_cmd])
            .output(),
    )
    .await;

    let duration_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(output)) => {
            let exit_code = output.status.code().unwrap_or(-1);
            tracing::debug!("execute_via_su: exit_code={} for '{}'", exit_code, cmd);
            Ok(CommandResult::success(
                String::from_utf8_lossy(&output.stdout).into_owned(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
                exit_code,
                duration_ms,
            ))
        }
        Ok(Err(e)) => {
            tracing::error!("execute_via_su: failed for '{}': {}", cmd, e);
            Err(Error::ToolExecution(format!(
                "su execution failed (is the device rooted?): {}", e
            )))
        }
        Err(_) => Ok(CommandResult::timeout(
            String::new(),
            "Command timed out".to_string(),
            duration_ms,
        )),
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
        if needs_root_execution(cmd) {
            tracing::debug!("execute_command: routing '{}' via su (needs hardware/root)", cmd);
            execute_via_su(cmd, args, timeout).await
        } else {
            proot::execute_command(cmd, args, timeout).await
        }
    }

    fn is_command_exec_supported(&self) -> bool {
        true
    }
}

// WifiAttackOps is implemented in wifi_attack.rs using `su -c` for root access.

impl PlatformProvider for AndroidPlatform {}
