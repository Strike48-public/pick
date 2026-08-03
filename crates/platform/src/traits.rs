//! Platform trait definitions

use async_trait::async_trait;
use pentest_core::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
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
    /// Returns (monitor_interface_name, killed_network_manager)
    ///
    /// # Arguments
    /// * `interface` - WiFi interface name (e.g., "wlan0")
    /// * `allow_kill_network_manager` - If true, allows killing NetworkManager to enable monitor mode.
    ///   If false and monitor mode fails, returns an error instead of killing NetworkManager.
    ///
    /// # Returns
    /// * `monitor_interface` - Name of the monitor interface (e.g., "wlan0mon")
    /// * `killed_network_manager` - True if NetworkManager was killed to enable monitor mode
    async fn enable_monitor_mode(
        &self,
        interface: &str,
        allow_kill_network_manager: bool,
    ) -> Result<(String, bool)>;

    /// Disable monitor mode and restore managed mode
    ///
    /// # Arguments
    /// * `interface` - Monitor interface name (e.g., "wlan0mon")
    /// * `restart_network_manager` - If true, restarts NetworkManager (only needed if it was killed during enable)
    async fn disable_monitor_mode(
        &self,
        interface: &str,
        restart_network_manager: bool,
    ) -> Result<()>;

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

/// Outcome of probing a single TCP port.
///
/// Distinguishing these matters for a pentest report: a genuinely closed port
/// (`Closed`) and a host that was never reachable (`Unreachable`) must not read
/// the same way. Collapsing every non-open outcome into "closed" lets an
/// unroutable scan masquerade as "checked and clean" (#306).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    /// The connect succeeded — a service is listening.
    Open,
    /// The connect was actively refused (`ConnectionRefused`) — a reachable
    /// host with nothing listening on this port.
    Closed,
    /// The connect timed out or failed indeterminately — likely firewalled or
    /// silently dropped. Not proof of closed, not proof of unreachable.
    Filtered,
    /// The probe never reached the target: host/network unreachable, or blocked
    /// by the sandbox / a missing capability. This is a scan failure, not a
    /// finding about the port.
    Unreachable,
}

/// Scanned port result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedPort {
    pub port: u16,
    /// Retained for backward compatibility; equivalent to `state == Open`.
    pub open: bool,
    pub state: PortState,
    pub service: Option<String>,
}

/// Port scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub host: String,
    pub ports: Vec<ScannedPort>,
    pub duration_ms: u64,
    pub open_count: usize,
    /// Number of probes that never reached the target (see [`PortState::Unreachable`]).
    /// When this equals the number of ports scanned, the host was never
    /// reachable and the empty open-port list must not be read as "clean".
    pub unreachable_count: usize,
    /// Human-readable reachability failures encountered during the scan. Empty
    /// on a fully successful scan; populated so a caller can tell "we checked
    /// and found nothing" apart from "we could not check".
    pub errors: Vec<String>,
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

/// A single address bound to a network interface, with its prefix length.
///
/// Modeled per-address (not per-interface) because a single interface can carry
/// several addresses on different prefixes - a dual-stack NIC (IPv4 + IPv6) or a
/// host with a secondary v4 on another subnet. A per-interface scalar prefix
/// would be ambiguous for exactly the multi-homed case network discovery needs
/// to get right, so the prefix travels with the address it describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceAddr {
    /// The IP address, without any CIDR suffix (e.g. "10.0.8.42").
    pub ip: String,
    /// CIDR prefix length for this address (e.g. `Some(22)` for a /22), or
    /// `None` when the backend could not determine it.
    pub prefix_len: Option<u8>,
}

impl InterfaceAddr {
    /// Construct from an IP string and an optional prefix.
    pub fn new(ip: impl Into<String>, prefix_len: Option<u8>) -> Self {
        Self {
            ip: ip.into(),
            prefix_len,
        }
    }

    /// Parse the address into an [`IpAddr`], dropping any accidental CIDR
    /// suffix. Returns `None` for a malformed address.
    pub fn parse_ip(&self) -> Option<IpAddr> {
        let bare = self.ip.split('/').next().unwrap_or(&self.ip);
        bare.parse().ok()
    }
}

/// Network interface information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    /// Addresses bound to this interface, each carrying its own prefix length.
    pub addresses: Vec<InterfaceAddr>,
    pub mac_address: Option<String>,
    pub is_up: bool,
    pub is_loopback: bool,
}

impl NetworkInterface {
    /// The interface's IP addresses as bare strings (no prefix), preserving the
    /// pre-`InterfaceAddr` ergonomics for the many call sites that only need the
    /// address, not its prefix.
    pub fn ip_strings(&self) -> Vec<String> {
        self.addresses.iter().map(|a| a.ip.clone()).collect()
    }

    /// True if the interface has at least one bound address.
    pub fn has_addresses(&self) -> bool {
        !self.addresses.is_empty()
    }
}

/// Parse an `ip addr`-style address token (e.g. `"10.0.8.42/22"` or a bare
/// `"10.0.8.42"`) into an [`InterfaceAddr`].
///
/// The prefix is taken verbatim from the `/N` suffix when present and parseable;
/// a missing or malformed suffix yields `prefix_len == None` rather than a
/// guessed default. Shared by the Linux `ip addr` fallback parsers (desktop and
/// Android) so the token handling stays consistent and unit-testable.
pub fn interface_addr_from_token(token: &str) -> InterfaceAddr {
    let mut parts = token.splitn(2, '/');
    let ip = parts.next().unwrap_or(token).to_string();
    let prefix_len = parts.next().and_then(|p| p.parse::<u8>().ok());
    InterfaceAddr { ip, prefix_len }
}

/// Convert an IPv4 netmask (e.g. `255.255.252.0`) to a CIDR prefix length
/// (e.g. `22`).
///
/// Returns `None` for a non-contiguous mask (bits not left-packed, e.g.
/// `255.0.255.0`), which is not a valid CIDR netmask and must not be silently
/// coerced into a plausible-looking prefix. Kept free of I/O so the conversion
/// is unit-testable.
pub fn prefix_len_from_ipv4_netmask(mask: std::net::Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let ones = bits.count_ones();
    // A valid netmask is `ones` contiguous 1s followed by zeros. Reconstruct that
    // canonical mask and compare; a mismatch means the mask was non-contiguous.
    let canonical = if ones == 0 {
        0
    } else {
        u32::MAX << (32 - ones)
    };
    if bits == canonical {
        Some(ones as u8)
    } else {
        None
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn netmask_to_prefix_covers_common_prefixes() {
        // The exact conversion network discovery relies on: a /22 host (the
        // multi-homed case this work targets) must yield 22, not a guessed /24.
        assert_eq!(
            prefix_len_from_ipv4_netmask(Ipv4Addr::new(255, 255, 252, 0)),
            Some(22)
        );
        assert_eq!(
            prefix_len_from_ipv4_netmask(Ipv4Addr::new(255, 255, 255, 0)),
            Some(24)
        );
        assert_eq!(
            prefix_len_from_ipv4_netmask(Ipv4Addr::new(255, 255, 255, 128)),
            Some(25)
        );
        assert_eq!(
            prefix_len_from_ipv4_netmask(Ipv4Addr::new(255, 0, 0, 0)),
            Some(8)
        );
    }

    #[test]
    fn netmask_to_prefix_handles_boundaries() {
        assert_eq!(
            prefix_len_from_ipv4_netmask(Ipv4Addr::new(0, 0, 0, 0)),
            Some(0)
        );
        assert_eq!(
            prefix_len_from_ipv4_netmask(Ipv4Addr::new(255, 255, 255, 255)),
            Some(32)
        );
    }

    #[test]
    fn netmask_to_prefix_rejects_noncontiguous_mask() {
        // A non-contiguous mask is not a valid CIDR netmask. It has the same
        // popcount as /16 (16 one-bits), so a naive count_ones() would wrongly
        // report /16; we must reject it as None instead of inventing a prefix.
        assert_eq!(
            prefix_len_from_ipv4_netmask(Ipv4Addr::new(255, 0, 255, 0)),
            None
        );
    }

    #[test]
    fn interface_addr_from_token_keeps_prefix() {
        // The /22 that the old parser discarded (forcing a /24 assumption
        // downstream) must survive.
        let a = interface_addr_from_token("10.0.8.42/22");
        assert_eq!(a.ip, "10.0.8.42");
        assert_eq!(a.prefix_len, Some(22));

        // Bare address (no suffix): prefix unknown, not guessed.
        let b = interface_addr_from_token("10.0.0.5");
        assert_eq!(b.ip, "10.0.0.5");
        assert_eq!(b.prefix_len, None);

        // IPv6 with prefix parses the same way.
        let c = interface_addr_from_token("fe80::1/64");
        assert_eq!(c.ip, "fe80::1");
        assert_eq!(c.prefix_len, Some(64));

        // Malformed suffix -> None, no panic.
        let d = interface_addr_from_token("10.0.0.5/notaprefix");
        assert_eq!(d.ip, "10.0.0.5");
        assert_eq!(d.prefix_len, None);
    }

    #[test]
    fn interface_addr_parse_ip_strips_cidr_suffix() {
        assert_eq!(
            InterfaceAddr::new("10.0.8.42/22", Some(22)).parse_ip(),
            Some("10.0.8.42".parse().unwrap())
        );
        assert_eq!(
            InterfaceAddr::new("10.0.8.42", Some(22)).parse_ip(),
            Some("10.0.8.42".parse().unwrap())
        );
        assert_eq!(InterfaceAddr::new("not-an-ip", None).parse_ip(), None);
    }

    #[test]
    fn ip_strings_flattens_addresses() {
        let iface = NetworkInterface {
            name: "eth0".to_string(),
            addresses: vec![
                InterfaceAddr::new("10.0.8.42", Some(22)),
                InterfaceAddr::new("fe80::1", Some(64)),
            ],
            mac_address: None,
            is_up: true,
            is_loopback: false,
        };
        assert_eq!(iface.ip_strings(), vec!["10.0.8.42", "fe80::1"]);
        assert!(iface.has_addresses());
    }
}
