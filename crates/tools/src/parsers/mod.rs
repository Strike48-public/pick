//! Output parsers for converting tool results into structured messages

use pentest_core::output_parser::{OutputParser, ParserContext, StructuredMessage};
use pentest_core::tools::ToolResult;
use std::collections::HashMap;
use std::sync::Arc;

pub mod port_scan;
pub mod wifi_scan;

pub use port_scan::PortScanParser;
pub use wifi_scan::WifiScanParser;

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
        registry.register(Arc::new(PortScanParser));
        registry.register(Arc::new(WifiScanParser));

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
