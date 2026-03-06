//! Pentest Tools Implementation
//!
//! This crate implements all pentest tools using the platform abstraction layer.

pub mod arp_table;
pub mod device_info;
pub mod execute_command;
pub mod list_files;
pub mod network_discover;
pub mod port_scan;
pub mod read_file;
pub mod screenshot;
pub mod ssdp_discover;
pub mod traffic_capture;
pub mod util;
pub mod wifi_scan;
pub mod write_file;

use pentest_core::tools::ToolRegistry;

pub use arp_table::ArpTableTool;
pub use device_info::DeviceInfoTool;
pub use execute_command::ExecuteCommandTool;
pub use list_files::ListFilesTool;
pub use network_discover::NetworkDiscoverTool;
pub use port_scan::PortScanTool;
pub use read_file::ReadFileTool;
pub use screenshot::ScreenshotTool;
pub use ssdp_discover::SsdpDiscoverTool;
pub use traffic_capture::TrafficCaptureTool;
pub use wifi_scan::WifiScanTool;
pub use write_file::WriteFileTool;

/// Create a tool registry with all available tools
pub fn create_tool_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();

    registry.register(PortScanTool);
    registry.register(DeviceInfoTool);
    registry.register(WifiScanTool);
    registry.register(ArpTableTool);
    registry.register(SsdpDiscoverTool);
    registry.register(NetworkDiscoverTool);
    registry.register(ScreenshotTool);
    if pentest_platform::is_pcap_available() {
        registry.register(TrafficCaptureTool);
    } else {
        tracing::info!("Packet capture unavailable (install Npcap on Windows or libpcap on Linux)");
    }
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
