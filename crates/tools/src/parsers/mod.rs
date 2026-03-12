//! Output parsers for converting tool results into structured messages

use pentest_core::output_parser::{OutputParser, ParserContext, StructuredMessage};
use pentest_core::tools::ToolResult;
use std::collections::HashMap;
use std::sync::Arc;

pub mod arp_table;
pub mod autopwn_capture;
pub mod autopwn_crack;
pub mod autopwn_plan;
pub mod cve_lookup;
pub mod default_creds;
pub mod device_info;
pub mod execute_command;
pub mod file_operations;
pub mod network_discover;
pub mod port_scan;
pub mod screenshot;
pub mod service_banner;
pub mod smb_enum;
pub mod ssdp_discover;
pub mod traffic_capture;
pub mod web_vuln_scan;
pub mod wifi_scan;
pub mod wifi_scan_detailed;

pub use arp_table::ArpTableParser;
pub use autopwn_capture::AutoPwnCaptureParser;
pub use autopwn_crack::AutoPwnCrackParser;
pub use autopwn_plan::AutoPwnPlanParser;
pub use cve_lookup::CveLookupParser;
pub use default_creds::DefaultCredsParser;
pub use device_info::DeviceInfoParser;
pub use execute_command::ExecuteCommandParser;
pub use file_operations::{ListFilesParser, ReadFileParser, WriteFileParser};
pub use network_discover::NetworkDiscoverParser;
pub use port_scan::PortScanParser;
pub use screenshot::ScreenshotParser;
pub use service_banner::ServiceBannerParser;
pub use smb_enum::SmbEnumParser;
pub use ssdp_discover::SsdpDiscoverParser;
pub use traffic_capture::TrafficCaptureParser;
pub use web_vuln_scan::WebVulnScanParser;
pub use wifi_scan::WifiScanParser;
pub use wifi_scan_detailed::WifiScanDetailedParser;

/// Registry of output parsers
pub struct OutputParserRegistry {
    parsers: HashMap<String, Arc<dyn OutputParser>>,
}

impl OutputParserRegistry {
    /// Create a new parser registry with all parsers registered
    pub fn new() -> Self {
        let mut registry = Self {
            parsers: HashMap::new(),
        };

        // Register parsers for each tool
        registry.register(Arc::new(ArpTableParser));
        registry.register(Arc::new(AutoPwnCaptureParser));
        registry.register(Arc::new(AutoPwnCrackParser));
        registry.register(Arc::new(AutoPwnPlanParser));
        registry.register(Arc::new(CveLookupParser));
        registry.register(Arc::new(DefaultCredsParser));
        registry.register(Arc::new(DeviceInfoParser));
        registry.register(Arc::new(ExecuteCommandParser));
        registry.register(Arc::new(ListFilesParser));
        registry.register(Arc::new(NetworkDiscoverParser));
        registry.register(Arc::new(PortScanParser));
        registry.register(Arc::new(ReadFileParser));
        registry.register(Arc::new(ScreenshotParser));
        registry.register(Arc::new(ServiceBannerParser));
        registry.register(Arc::new(SmbEnumParser));
        registry.register(Arc::new(SsdpDiscoverParser));
        registry.register(Arc::new(TrafficCaptureParser));
        registry.register(Arc::new(WebVulnScanParser));
        registry.register(Arc::new(WifiScanParser));
        registry.register(Arc::new(WifiScanDetailedParser));
        registry.register(Arc::new(WriteFileParser));

        registry
    }

    /// Register a parser
    pub fn register(&mut self, parser: Arc<dyn OutputParser>) {
        let name = parser.parser_name().to_string();
        self.parsers.insert(name, parser);
    }

    /// Parse tool output into structured messages
    pub fn parse(
        &self,
        tool_name: &str,
        result: &ToolResult,
        context: &ParserContext,
    ) -> Vec<StructuredMessage> {
        match self.parsers.get(tool_name) {
            Some(parser) => {
                tracing::debug!("Parsing output for tool: {}", tool_name);
                let messages = parser.parse(tool_name, result, context);
                tracing::debug!("Generated {} structured messages", messages.len());
                messages
            }
            None => {
                tracing::debug!("No parser found for tool: {}", tool_name);
                vec![]
            }
        }
    }

    /// Check if a parser exists for a tool
    pub fn has_parser(&self, tool_name: &str) -> bool {
        self.parsers.contains_key(tool_name)
    }

    /// Get all registered parser names
    pub fn parser_names(&self) -> Vec<&str> {
        self.parsers.keys().map(|s| s.as_str()).collect()
    }
}

impl Default for OutputParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = OutputParserRegistry::new();
        assert!(registry.has_parser("port_scan"));
    }

    #[test]
    fn test_parser_names() {
        let registry = OutputParserRegistry::new();
        let names = registry.parser_names();
        assert!(names.contains(&"port_scan"));
    }
}
