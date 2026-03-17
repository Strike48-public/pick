//! Pentest Tools Implementation
//!
//! This crate implements all pentest tools using the platform abstraction layer.

pub mod arp_table;
pub mod autopwn;
pub mod cve_lookup;
pub mod default_creds;
pub mod device_info;
pub mod execute_command;
pub mod external; // NEW: External tool integrations (BlackArch)
pub mod list_files;
pub mod network_discover;
pub mod port_scan;
pub mod read_file;
pub mod screenshot;
pub mod service_banner;
pub mod smb_enum;
pub mod ssdp_discover;
pub mod traffic_capture;
pub mod util;
pub mod web_vuln_scan;
pub mod wifi_scan;
pub mod wifi_scan_detailed;
pub mod write_file;

use pentest_core::tools::ToolRegistry;

pub use arp_table::ArpTableTool;
pub use autopwn::{AutoPwnCaptureTool, AutoPwnCrackTool, AutoPwnPlanTool};
pub use cve_lookup::CveLookupTool;
pub use default_creds::DefaultCredsTool;
pub use device_info::DeviceInfoTool;
pub use execute_command::ExecuteCommandTool;
pub use external::{
    AircrackngTool, AmassTool, ArjunTool, ArpScanTool, AssetfinderTool, BettercapTool, CewlTool,
    CommixTool, CrackmapexecTool, CrunchTool, DirbTool, DirsearchTool, DnsenumTool, DnsreconTool,
    Enum4linuxNgTool, Enum4linuxTool, EvilwinrmTool, ExiftoolTool, FeroxbusterTool, FfufDnsTool,
    FfufTool, FierceTool, GauTool, GobusterTool, GospiderTool, HakrawlerTool, HashcatTool,
    HttpprobeTool, HydraTool, ImpacketGetuserspnsTool, ImpacketPsexecTool,
    ImpacketSecretsdumpTool, ImpacketWmiexecTool, JohnTool, KatanaTool, LinpeasTool,
    MasscanFastTool, MasscanTool, NbtscanTool, NcatTool, NetdiscoverTool, NiktoTool, NmapTool,
    NmapVulnTool, NucleiTool, ParamspiderTool, ResponderTool, RustScanTool, SearchsploitTool,
    SmbmapTool, SocatTool, SqlmapTool, SslscanTool, SubfinderTool, Sublist3rTool, TestsslTool,
    TheHarvesterTool, TsharkTool, WaybackurlsTool, WfuzzTool, WhoisTool, WpscanTool, XsstrikeTool,
}; // External tools
pub use list_files::ListFilesTool;
pub use network_discover::NetworkDiscoverTool;
pub use port_scan::PortScanTool;
pub use read_file::ReadFileTool;
pub use screenshot::ScreenshotTool;
pub use service_banner::ServiceBannerTool;
pub use smb_enum::SmbEnumTool;
pub use ssdp_discover::SsdpDiscoverTool;
pub use traffic_capture::TrafficCaptureTool;
pub use web_vuln_scan::WebVulnScanTool;
pub use wifi_scan::WifiScanTool;
pub use wifi_scan_detailed::WifiScanDetailedTool;
pub use write_file::WriteFileTool;

/// Create a tool registry with all available tools
pub fn create_tool_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();

    // Network scanning and discovery
    registry.register(PortScanTool);
    registry.register(NmapTool); // External: comprehensive network scanner
    registry.register(RustScanTool); // External: ultra-fast port scanner
    registry.register(MasscanTool); // External: internet-scale scanner
    registry.register(ArpTableTool);
    registry.register(SsdpDiscoverTool);
    registry.register(NetworkDiscoverTool);

    // WiFi tools
    registry.register(WifiScanTool);
    registry.register(WifiScanDetailedTool);
    registry.register(AutoPwnPlanTool);
    registry.register(AutoPwnCaptureTool);
    registry.register(AutoPwnCrackTool);

    // Vulnerability assessment
    registry.register(ServiceBannerTool);
    registry.register(CveLookupTool);
    registry.register(DefaultCredsTool);
    registry.register(WebVulnScanTool);
    registry.register(SmbEnumTool);
    registry.register(Enum4linuxTool); // External: SMB/Windows enumeration

    // Web application testing (External tools)
    registry.register(FfufTool); // Fast web fuzzer
    registry.register(GobusterTool); // Directory/DNS/vhost bruteforce
    registry.register(NiktoTool); // Web server vulnerability scanner
    registry.register(DirbTool); // Web content scanner
    // Phase 3: Advanced web tools
    registry.register(SqlmapTool); // SQL injection automation
    registry.register(NucleiTool); // Template-based vuln scanner
    registry.register(WpscanTool); // WordPress security scanner
    registry.register(WfuzzTool); // Web application fuzzer
    registry.register(FeroxbusterTool); // Fast content discovery (Rust)
    registry.register(ArjunTool); // HTTP parameter discovery
    registry.register(CommixTool); // Command injection exploitation
    registry.register(DirsearchTool); // Web path scanner
    registry.register(Sublist3rTool); // Subdomain enumeration
    registry.register(AmassTool); // DNS enumeration and network mapping
    registry.register(XsstrikeTool); // XSS detection
    registry.register(HakrawlerTool); // Web crawler
    registry.register(HttpprobeTool); // HTTP/HTTPS probe
    registry.register(WaybackurlsTool); // Wayback Machine URLs
    registry.register(GauTool); // Get All URLs
    registry.register(FfufDnsTool); // DNS subdomain fuzzing
    registry.register(SubfinderTool); // Subdomain discovery
    registry.register(AssetfinderTool); // Asset discovery
    registry.register(GospiderTool); // Fast web spider
    registry.register(KatanaTool); // Next-gen crawler
    registry.register(ParamspiderTool); // Parameter discovery

    // Credential attacks (External tools)
    registry.register(HydraTool); // Login bruteforcer (50+ protocols)
    registry.register(JohnTool); // Password cracker

    // Phase 4: Post-Exploitation & Lateral Movement
    registry.register(ImpacketSecretsdumpTool); // Windows credential extraction
    registry.register(ImpacketPsexecTool); // Remote execution via SMB
    registry.register(ImpacketWmiexecTool); // WMI-based remote execution
    registry.register(ImpacketGetuserspnsTool); // Kerberoasting attack
    registry.register(LinpeasTool); // Linux privilege escalation enum
    registry.register(CrackmapexecTool); // Network pentesting Swiss army knife
    registry.register(EvilwinrmTool); // WinRM shell

    // Phase 5+: Network exploitation
    registry.register(BettercapTool); // Network attacks and monitoring
    registry.register(ResponderTool); // LLMNR/NBT-NS poisoning
    registry.register(TsharkTool); // Network protocol analyzer
    registry.register(NetdiscoverTool); // ARP reconnaissance
    registry.register(MasscanFastTool); // Ultra-fast port scanner
    registry.register(NmapVulnTool); // Nmap vulnerability scanning
    registry.register(ArpScanTool); // ARP scanner
    registry.register(NbtscanTool); // NetBIOS scanner

    // Forensics
    registry.register(ExiftoolTool); // Metadata extraction

    // Wireless security
    registry.register(AircrackngTool); // WiFi WEP/WPA cracking

    // Specialized tools
    registry.register(HashcatTool); // GPU password cracking
    registry.register(SearchsploitTool); // Exploit database search
    registry.register(CewlTool); // Custom wordlist generator
    registry.register(NcatTool); // Netcat reimplementation
    registry.register(SocatTool); // Multipurpose relay tool
    registry.register(CrunchTool); // Wordlist generator
    registry.register(TheHarvesterTool); // OSINT gathering
    registry.register(DnsreconTool); // DNS enumeration
    registry.register(DnsenumTool); // DNS information gathering
    registry.register(FierceTool); // DNS reconnaissance
    registry.register(WhoisTool); // WHOIS lookup
    registry.register(SslscanTool); // SSL/TLS scanner
    registry.register(TestsslTool); // TLS/SSL testing
    registry.register(Enum4linuxNgTool); // Next-gen SMB enum
    registry.register(SmbmapTool); // SMB share enumeration

    // Device and system info
    registry.register(DeviceInfoTool);
    registry.register(ScreenshotTool);

    // Traffic capture
    if pentest_platform::is_pcap_available() {
        registry.register(TrafficCaptureTool);
    } else {
        tracing::info!("Packet capture unavailable (install Npcap on Windows or libpcap on Linux)");
    }

    // File and command operations
    registry.register(ExecuteCommandTool);
    registry.register(ReadFileTool);
    registry.register(WriteFileTool);
    registry.register(ListFilesTool);

    registry
}

/// Get all tool names (derived from the registry, not hand-maintained)
pub fn tool_names() -> Vec<String> {
    create_tool_registry()
        .names()
        .into_iter()
        .map(String::from)
        .collect()
}
