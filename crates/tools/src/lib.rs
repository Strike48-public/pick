//! Pentest Tools Implementation
//!
//! This crate implements all pentest tools using the platform abstraction layer.

pub mod arp_table;
pub mod autopwn;
pub mod credential_harvest;
pub mod cve_lookup;
pub mod default_creds;
pub mod device_info;
pub mod execute_command;
pub mod lateral_movement;
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
pub use autopwn::{
    AutoPwnCaptureTool, AutoPwnCrackTool, AutoPwnNetworkPlanTool, AutoPwnOrchestratorTool,
    AutoPwnPlanTool,
};
pub use credential_harvest::CredentialHarvestTool;
pub use cve_lookup::CveLookupTool;
pub use default_creds::DefaultCredsTool;
pub use device_info::DeviceInfoTool;
pub use execute_command::ExecuteCommandTool;
pub use lateral_movement::LateralMovementTool;
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
    registry.register(ArpTableTool);
    registry.register(SsdpDiscoverTool);
    registry.register(NetworkDiscoverTool);

    // WiFi tools
    registry.register(WifiScanTool);
    registry.register(WifiScanDetailedTool);
    registry.register(AutoPwnPlanTool);
    registry.register(AutoPwnCaptureTool);
    registry.register(AutoPwnCrackTool);

    // Network autopwn (fallback when WiFi pentest unavailable)
    registry.register(AutoPwnNetworkPlanTool);

    // Intelligent autopwn orchestrator (detects hardware and chooses strategy)
    registry.register(AutoPwnOrchestratorTool);

    // Vulnerability assessment
    registry.register(ServiceBannerTool);
    registry.register(CveLookupTool);
    registry.register(DefaultCredsTool);
    registry.register(WebVulnScanTool);
    registry.register(SmbEnumTool);

    // Post-exploitation
    registry.register(CredentialHarvestTool);
    registry.register(LateralMovementTool);

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
