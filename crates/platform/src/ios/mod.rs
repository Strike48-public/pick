//! iOS platform implementation (stub)

use crate::traits::*;
use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use std::time::Duration;

/// iOS platform provider
pub struct IosPlatform;

impl IosPlatform {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IosPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetworkOps for IosPlatform {
    async fn port_scan(&self, config: ScanConfig) -> Result<ScanResult> {
        use std::time::Instant;

        let start = Instant::now();
        let timeout = Duration::from_millis(config.timeout_ms);

        let ports = crate::common::tcp_port_scan(&config.host, &config.ports, timeout, 0).await;

        let open_count = ports.iter().filter(|p| p.open).count();
        let duration_ms = start.elapsed().as_millis() as u64;

        Ok(ScanResult {
            host: config.host,
            ports,
            duration_ms,
            open_count,
        })
    }

    async fn get_arp_table(&self) -> Result<Vec<ArpEntry>> {
        Err(Error::PlatformNotSupported(
            "get_arp_table not available on iOS".into(),
        ))
    }

    async fn ssdp_discover(&self, _timeout_ms: u64) -> Result<Vec<SsdpDevice>> {
        Err(Error::PlatformNotSupported(
            "ssdp_discover not available on iOS".into(),
        ))
    }

    async fn mdns_discover(
        &self,
        _service_type: &str,
        _timeout_ms: u64,
    ) -> Result<Vec<MdnsService>> {
        Err(Error::PlatformNotSupported(
            "mdns_discover not available on iOS (requires Bonjour framework)".into(),
        ))
    }
}

#[async_trait]
impl SystemInfo for IosPlatform {
    async fn get_device_info(&self) -> Result<DeviceInfo> {
        Ok(DeviceInfo {
            os_name: "iOS".to_string(),
            os_version: String::new(),
            hostname: "iphone".to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            cpu_count: 1,
            total_memory_mb: 0,
            platform_specific: PlatformDetails::Ios,
        })
    }

    async fn get_network_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        Err(Error::PlatformNotSupported(
            "get_network_interfaces not available on iOS".into(),
        ))
    }

    async fn get_wifi_networks(&self, interface: Option<String>) -> Result<Vec<WifiNetwork>> {
        let _ = interface; // Suppress unused warning
        Err(Error::PlatformNotSupported(
            "get_wifi_networks not available on iOS".into(),
        ))
    }

    async fn check_wifi_connection_status(
        &self,
        selected_adapter: Option<String>,
    ) -> Result<WifiConnectionStatus> {
        let _ = selected_adapter; // Suppress unused warning
        // iOS doesn't have the same WiFi adapter issues as desktop
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
impl CaptureOps for IosPlatform {
    async fn capture_screenshot(&self) -> Result<Vec<u8>> {
        Err(Error::PlatformNotSupported(
            "Screenshot capture not supported on iOS".into(),
        ))
    }

    async fn start_traffic_capture(&self) -> Result<CaptureHandle> {
        Err(Error::PlatformNotSupported(
            "Traffic capture not supported on iOS".into(),
        ))
    }

    async fn get_captured_packets(
        &self,
        _handle: &CaptureHandle,
        _limit: usize,
    ) -> Result<Vec<PacketInfo>> {
        Err(Error::PlatformNotSupported(
            "get_captured_packets not available on iOS".into(),
        ))
    }

    async fn stop_traffic_capture(&self, _handle: CaptureHandle) -> Result<()> {
        Err(Error::PlatformNotSupported(
            "stop_traffic_capture not available on iOS".into(),
        ))
    }
}

#[async_trait]
impl CommandExec for IosPlatform {
    async fn execute_command(
        &self,
        _cmd: &str,
        _args: &[&str],
        _timeout: Duration,
    ) -> Result<CommandResult> {
        Err(Error::PlatformNotSupported(
            "Command execution not supported on iOS without jailbreak".into(),
        ))
    }

    fn is_command_exec_supported(&self) -> bool {
        false
    }
}

impl PlatformProvider for IosPlatform {}
