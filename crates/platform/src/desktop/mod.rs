//! Desktop platform implementation

mod capture;
pub mod command;
mod network;
pub mod pty_shell;
pub mod sandbox;
mod system;

// Re-export sandbox control functions
pub use command::{is_sandbox_enabled, set_use_sandbox};

// Re-export capture session management (single source of truth)
pub use capture::{
    get_current_packets, is_capture_active, is_pcap_available, start_current_capture,
    stop_current_capture,
};

use crate::traits::*;
use async_trait::async_trait;
use pentest_core::error::Result;
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// Wait for a child process to finish and collect its output.
/// Shared by command.rs, bwrap.rs, and proot.rs.
pub(crate) async fn wait_for_child_output(
    mut child: tokio::process::Child,
) -> std::io::Result<(String, String, i32)> {
    const MAX_OUTPUT: usize = 256 * 1024; // 256 KB limit

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();

    if let Some(mut stdout) = child.stdout.take() {
        stdout.read_to_end(&mut stdout_buf).await?;
        stdout_buf.truncate(MAX_OUTPUT);
    }

    if let Some(mut stderr) = child.stderr.take() {
        stderr.read_to_end(&mut stderr_buf).await?;
        stderr_buf.truncate(MAX_OUTPUT);
    }

    let status = child.wait().await?;
    let exit_code = status.code().unwrap_or(-1);

    let stdout = String::from_utf8_lossy(&stdout_buf).to_string();
    let stderr = String::from_utf8_lossy(&stderr_buf).to_string();

    Ok((stdout, stderr, exit_code))
}

/// Desktop platform provider
pub struct DesktopPlatform;

impl DesktopPlatform {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DesktopPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetworkOps for DesktopPlatform {
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
        network::mdns_discover(service_type, timeout_ms).await
    }
}

#[async_trait]
impl SystemInfo for DesktopPlatform {
    async fn get_device_info(&self) -> Result<DeviceInfo> {
        system::get_device_info().await
    }

    async fn get_network_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        system::get_network_interfaces().await
    }

    async fn get_wifi_networks(&self, interface: Option<String>) -> Result<Vec<WifiNetwork>> {
        system::get_wifi_networks(interface).await
    }

    async fn check_wifi_connection_status(
        &self,
        selected_adapter: Option<String>,
    ) -> Result<WifiConnectionStatus> {
        system::check_wifi_connection_status(selected_adapter).await
    }
}

#[async_trait]
impl CaptureOps for DesktopPlatform {
    async fn capture_screenshot(&self) -> Result<Vec<u8>> {
        capture::capture_screenshot().await
    }

    async fn start_traffic_capture(&self) -> Result<CaptureHandle> {
        capture::start_traffic_capture().await
    }

    async fn get_captured_packets(
        &self,
        handle: &CaptureHandle,
        limit: usize,
    ) -> Result<Vec<PacketInfo>> {
        capture::get_captured_packets(handle, limit).await
    }

    async fn stop_traffic_capture(&self, handle: CaptureHandle) -> Result<()> {
        capture::stop_traffic_capture(handle).await
    }
}

#[async_trait]
impl CommandExec for DesktopPlatform {
    async fn execute_command(
        &self,
        cmd: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandResult> {
        command::execute_command(cmd, args, timeout).await
    }

    async fn execute_command_in_dir(
        &self,
        cmd: &str,
        args: &[&str],
        timeout: Duration,
        working_dir: Option<&std::path::Path>,
    ) -> Result<CommandResult> {
        command::execute_command_in_dir(cmd, args, timeout, working_dir).await
    }
}

impl PlatformProvider for DesktopPlatform {}
