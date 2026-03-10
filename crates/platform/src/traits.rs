//! Platform trait definitions

use async_trait::async_trait;
use pentest_core::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

/// Combined platform provider trait
#[async_trait]
pub trait PlatformProvider:
    NetworkOps + SystemInfo + CaptureOps + CommandExec + WifiAttackOps + Send + Sync
{
}

/// Network operations trait
#[async_trait]
pub trait NetworkOps: Send + Sync {
    /// Scan ports on a target host
    async fn port_scan(&self, config: ScanConfig) -> Result<ScanResult>;

    /// Get the ARP table
    async fn get_arp_table(&self) -> Result<Vec<ArpEntry>>;

    /// Discover SSDP/UPnP devices
    async fn ssdp_discover(&self, timeout_ms: u64) -> Result<Vec<SsdpDevice>>;

    /// Discover mDNS services
    async fn mdns_discover(&self, service_type: &str, timeout_ms: u64) -> Result<Vec<MdnsService>>;
}

/// System information trait
#[async_trait]
pub trait SystemInfo: Send + Sync {
    /// Get device/system information
    async fn get_device_info(&self) -> Result<DeviceInfo>;

    /// Get network interfaces
    async fn get_network_interfaces(&self) -> Result<Vec<NetworkInterface>>;

    /// Get WiFi networks (if available)
    ///
    /// # Arguments
    /// * `interface` - Optional WiFi interface to scan (e.g., "wlan1"). If None, uses auto-detect.
    async fn get_wifi_networks(&self, interface: Option<String>) -> Result<Vec<WifiNetwork>>;

    /// Check WiFi connection status for scan safety assessment
    ///
    /// # Arguments
    /// * `selected_adapter` - User's chosen WiFi interface (e.g., "wlan1")
    async fn check_wifi_connection_status(
        &self,
        selected_adapter: Option<String>,
    ) -> Result<WifiConnectionStatus>;
}

/// Capture operations trait
#[async_trait]
pub trait CaptureOps: Send + Sync {
    /// Capture a screenshot
    async fn capture_screenshot(&self) -> Result<Vec<u8>>;

    /// Start traffic capture
    async fn start_traffic_capture(&self) -> Result<CaptureHandle>;

    /// Get captured packets
    async fn get_captured_packets(
        &self,
        handle: &CaptureHandle,
        limit: usize,
    ) -> Result<Vec<PacketInfo>>;

    /// Stop traffic capture
    async fn stop_traffic_capture(&self, handle: CaptureHandle) -> Result<()>;
}

/// Command execution trait
#[async_trait]
pub trait CommandExec: Send + Sync {
    /// Execute a command
    async fn execute_command(
        &self,
        cmd: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandResult>;

    /// Execute a command with a specific working directory.
    ///
    /// Default implementation ignores the working directory and delegates to
    /// `execute_command` — suitable for platforms where cwd control is not
    /// available (Android/iOS).
    async fn execute_command_in_dir(
        &self,
        cmd: &str,
        args: &[&str],
        timeout: Duration,
        _working_dir: Option<&std::path::Path>,
    ) -> Result<CommandResult> {
        self.execute_command(cmd, args, timeout).await
    }

    /// Check if command execution is supported
    fn is_command_exec_supported(&self) -> bool {
        true
    }
}

/// WiFi attack operations trait
#[async_trait]
pub trait WifiAttackOps: Send + Sync {
    /// Enable monitor mode on a WiFi interface
    /// Returns the monitor interface name (e.g., "wlan0mon")
    ///
    /// # Arguments
    /// * `interface` - WiFi interface name (e.g., "wlan0")
    /// * `allow_kill_network_manager` - If true, allows killing NetworkManager to enable monitor mode.
    ///   If false and monitor mode fails, returns an error instead of killing NetworkManager.
    async fn enable_monitor_mode(&self, interface: &str, allow_kill_network_manager: bool) -> Result<String>;

    /// Disable monitor mode and restore managed mode
    async fn disable_monitor_mode(&self, interface: &str) -> Result<()>;

    /// Clone MAC address to appear as another device
    async fn clone_mac(&self, interface: &str, target_mac: &str) -> Result<()>;

    /// Test packet injection capability
    async fn test_injection(&self, interface: &str) -> Result<InjectionCapability>;

    /// Start capturing WiFi packets
    async fn start_capture(
        &self,
        interface: &str,
        bssid: &str,
        channel: u8,
        output_file: &str,
    ) -> Result<WifiCaptureHandle>;

    /// Stop WiFi packet capture
    async fn stop_capture(&self, handle: WifiCaptureHandle) -> Result<()>;

    /// Get capture statistics (IVs, packets, handshake status)
    async fn get_capture_stats(&self, handle: &WifiCaptureHandle) -> Result<WifiCaptureStats>;

    /// Perform fake authentication (WEP)
    async fn fake_auth(&self, interface: &str, bssid: &str) -> Result<()>;

    /// Start ARP replay attack (WEP - generate IVs)
    async fn start_arp_replay(&self, interface: &str, bssid: &str) -> Result<ArpReplayHandle>;

    /// Stop ARP replay attack
    async fn stop_arp_replay(&self, handle: ArpReplayHandle) -> Result<()>;

    /// Send deauth packets to force client reconnection (WPA)
    async fn deauth_attack(
        &self,
        interface: &str,
        bssid: &str,
        client: Option<&str>,
        count: u8,
    ) -> Result<()>;

    /// Verify WPA handshake in capture file
    async fn verify_handshake(&self, capture_file: &str, bssid: &str) -> Result<bool>;

    /// Crack WEP key from captured IVs (live cracking)
    async fn crack_wep(&self, capture_file: &str, bssid: &str) -> Result<Option<String>>;
}

// ============ Data Types ============

/// Port scan configuration (re-exported from pentest-core to avoid duplication)
pub use pentest_core::state::ScanConfig;

/// Scanned port result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedPort {
    pub port: u16,
    pub open: bool,
    pub service: Option<String>,
}

/// Port scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub host: String,
    pub ports: Vec<ScannedPort>,
    pub duration_ms: u64,
    pub open_count: usize,
}

/// ARP table entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpEntry {
    pub ip: String,
    pub mac: String,
    pub interface: Option<String>,
    pub hostname: Option<String>,
}

/// SSDP/UPnP device
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsdpDevice {
    pub location: String,
    pub server: Option<String>,
    pub usn: Option<String>,
    pub st: Option<String>,
    pub friendly_name: Option<String>,
    pub manufacturer: Option<String>,
    pub model: Option<String>,
}

/// mDNS service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MdnsService {
    pub name: String,
    pub service_type: String,
    pub host: String,
    pub port: u16,
    pub txt_records: HashMap<String, String>,
}

/// Platform-specific device details, tagged by platform.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "platform")]
pub enum PlatformDetails {
    Desktop {
        kernel_version: String,
        cpu_brand: String,
        used_memory_mb: u64,
        process_count: usize,
    },
    Android {
        android_version: String,
        device_model: String,
        manufacturer: String,
        /// Optional enrichment fields (sdk_version, brand, product, hardware,
        /// board, display, fingerprint, api_level, build_fingerprint,
        /// installed_package_count, timezone, etc.)
        #[serde(default)]
        extra: HashMap<String, String>,
    },
    Ios,
    Web,
    #[default]
    Unknown,
}

/// Device/system information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub os_name: String,
    pub os_version: String,
    pub hostname: String,
    pub architecture: String,
    pub cpu_count: usize,
    pub total_memory_mb: u64,
    pub platform_specific: PlatformDetails,
}

/// Network interface information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ip_addresses: Vec<String>,
    pub mac_address: Option<String>,
    pub is_up: bool,
    pub is_loopback: bool,
}

/// WiFi network information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiNetwork {
    pub ssid: String,
    pub bssid: String,
    pub signal_strength: i32,
    pub frequency: u32,
    pub channel: u32,
    pub security: String,
    /// Number of connected clients (if available). None if not scanned in monitor mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clients: Option<u32>,
}

/// WiFi connection risk assessment for scan safety
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WifiConnectionStatus {
    /// Whether the active internet connection is via WiFi
    pub connected_via_wifi: bool,
    /// Name of the active WiFi interface (e.g., "wlan0")
    pub active_interface: Option<String>,
    /// Total number of WiFi adapters detected
    pub total_adapters: usize,
    /// Whether it's safe to scan (has external adapter OR on ethernet)
    pub safe_to_scan: bool,
    /// List of all WiFi interfaces (for future adapter selector)
    pub all_wifi_interfaces: Vec<String>,
}

/// Screenshot result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Screenshot {
    pub width: u32,
    pub height: u32,
    pub format: String,
    pub data: Vec<u8>,
}

/// Capture handle for traffic capture
#[derive(Debug, Clone)]
pub struct CaptureHandle {
    pub id: String,
    pub started_at: std::time::Instant,
}

/// Packet information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    pub timestamp: u64,
    pub protocol: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub size: usize,
    pub tcp_flags: Option<String>,
}

/// Command execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub timed_out: bool,
    pub duration_ms: u64,
}

impl CommandResult {
    /// Create a successful result
    pub fn success(stdout: String, stderr: String, exit_code: i32, duration_ms: u64) -> Self {
        Self {
            stdout,
            stderr,
            exit_code,
            timed_out: false,
            duration_ms,
        }
    }

    /// Create a timeout result
    pub fn timeout(stdout: String, stderr: String, duration_ms: u64) -> Self {
        Self {
            stdout,
            stderr,
            exit_code: -1,
            timed_out: true,
            duration_ms,
        }
    }
}

/// Well-known port to service name mapping
pub fn port_to_service(port: u16) -> Option<&'static str> {
    match port {
        20 => Some("ftp-data"),
        21 => Some("ftp"),
        22 => Some("ssh"),
        23 => Some("telnet"),
        25 => Some("smtp"),
        53 => Some("dns"),
        67 => Some("dhcp"),
        68 => Some("dhcp"),
        69 => Some("tftp"),
        80 => Some("http"),
        110 => Some("pop3"),
        119 => Some("nntp"),
        123 => Some("ntp"),
        135 => Some("msrpc"),
        137 => Some("netbios-ns"),
        138 => Some("netbios-dgm"),
        139 => Some("netbios-ssn"),
        143 => Some("imap"),
        161 => Some("snmp"),
        162 => Some("snmptrap"),
        389 => Some("ldap"),
        443 => Some("https"),
        445 => Some("microsoft-ds"),
        465 => Some("smtps"),
        514 => Some("syslog"),
        515 => Some("printer"),
        587 => Some("submission"),
        631 => Some("ipp"),
        636 => Some("ldaps"),
        993 => Some("imaps"),
        995 => Some("pop3s"),
        1433 => Some("mssql"),
        1434 => Some("mssql-m"),
        1521 => Some("oracle"),
        1723 => Some("pptp"),
        2049 => Some("nfs"),
        3306 => Some("mysql"),
        3389 => Some("rdp"),
        5432 => Some("postgresql"),
        5900 => Some("vnc"),
        5901 => Some("vnc"),
        6379 => Some("redis"),
        6667 => Some("irc"),
        8080 => Some("http-proxy"),
        8443 => Some("https-alt"),
        9090 => Some("zeus-admin"),
        27017 => Some("mongodb"),
        _ => None,
    }
}

/// WiFi capture handle
#[derive(Debug, Clone)]
pub struct WifiCaptureHandle {
    pub pid: u32,
    pub output_file: String,
    pub interface: String,
}

/// ARP replay attack handle
#[derive(Debug, Clone)]
pub struct ArpReplayHandle {
    pub pid: u32,
}

/// Packet injection capability
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InjectionCapability {
    pub supported: bool,
    pub success_rate: f32,
}

/// WiFi capture statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiCaptureStats {
    pub packets: u64,
    pub ivs: u32,            // For WEP
    pub has_handshake: bool, // For WPA
    pub data_packets: u64,
}
