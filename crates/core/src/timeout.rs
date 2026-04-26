//! Timeout configuration and enforcement for external tool execution
//!
//! This module provides consistent timeout handling across all penetration testing
//! tools to prevent resource exhaustion and DoS attacks via long-running processes.
//!
//! # Design
//!
//! - Categorize tools by expected execution time
//! - Provide sensible defaults per category
//! - Allow per-tool configuration overrides
//! - Handle timeout errors gracefully

use std::time::Duration;

/// Timeout configuration for different tool categories
#[derive(Debug, Clone)]
pub struct ToolTimeouts {
    /// Quick checks that should complete in seconds (ping, DNS lookup, etc.)
    pub quick_scan: Duration,

    /// Network scans that may take several minutes (nmap, masscan, etc.)
    pub network_scan: Duration,

    /// Brute force and password cracking operations (hydra, john, etc.)
    pub brute_force: Duration,

    /// Vulnerability scanning and exploitation attempts
    pub vuln_scan: Duration,

    /// Traffic capture and analysis operations
    pub traffic_capture: Duration,

    /// Default timeout for uncategorized tools
    pub default: Duration,
}

impl Default for ToolTimeouts {
    fn default() -> Self {
        Self {
            quick_scan: Duration::from_secs(60),       // 1 minute
            network_scan: Duration::from_secs(600),    // 10 minutes
            brute_force: Duration::from_secs(3600),    // 1 hour
            vuln_scan: Duration::from_secs(1800),      // 30 minutes
            traffic_capture: Duration::from_secs(300), // 5 minutes
            default: Duration::from_secs(300),         // 5 minutes
        }
    }
}

impl ToolTimeouts {
    /// Create a new timeout configuration with custom values
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a timeout configuration optimized for testing (shorter timeouts)
    pub fn test() -> Self {
        Self {
            quick_scan: Duration::from_secs(5),
            network_scan: Duration::from_secs(30),
            brute_force: Duration::from_secs(60),
            vuln_scan: Duration::from_secs(30),
            traffic_capture: Duration::from_secs(15),
            default: Duration::from_secs(10),
        }
    }

    /// Create a timeout configuration optimized for production (longer timeouts)
    pub fn production() -> Self {
        Self {
            quick_scan: Duration::from_secs(120),      // 2 minutes
            network_scan: Duration::from_secs(1800),   // 30 minutes
            brute_force: Duration::from_secs(7200),    // 2 hours
            vuln_scan: Duration::from_secs(3600),      // 1 hour
            traffic_capture: Duration::from_secs(600), // 10 minutes
            default: Duration::from_secs(600),         // 10 minutes
        }
    }

    /// Get timeout for a specific tool category
    pub fn get(&self, category: ToolCategory) -> Duration {
        match category {
            ToolCategory::QuickScan => self.quick_scan,
            ToolCategory::NetworkScan => self.network_scan,
            ToolCategory::BruteForce => self.brute_force,
            ToolCategory::VulnScan => self.vuln_scan,
            ToolCategory::TrafficCapture => self.traffic_capture,
            ToolCategory::Default => self.default,
        }
    }

    /// Get timeout for a tool by name, using configured defaults
    pub fn get_by_tool_name(&self, tool_name: &str) -> Duration {
        let category = categorize_tool(tool_name);
        self.get(category)
    }
}

/// Tool categories for timeout purposes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolCategory {
    /// Quick checks (ping, DNS, ARP, etc.)
    QuickScan,

    /// Network scanning (nmap, masscan, etc.)
    NetworkScan,

    /// Brute force operations (hydra, john, hashcat, etc.)
    BruteForce,

    /// Vulnerability scanning (nikto, sqlmap, etc.)
    VulnScan,

    /// Traffic capture (tcpdump, tshark, etc.)
    TrafficCapture,

    /// Default category for unknown tools
    Default,
}

/// Categorize a tool by name to determine appropriate timeout
pub fn categorize_tool(tool_name: &str) -> ToolCategory {
    match tool_name.to_lowercase().as_str() {
        // Quick scans
        "ping" | "arping" | "fping" | "dns_lookup" | "whois" | "host" | "dig" => {
            ToolCategory::QuickScan
        }

        // Network scans
        "nmap" | "masscan" | "zmap" | "arp_scan" | "arp-scan" | "nbtscan" | "unicornscan" => {
            ToolCategory::NetworkScan
        }

        // Brute force
        "hydra" | "medusa" | "john" | "hashcat" | "patator" | "thc-hydra" => {
            ToolCategory::BruteForce
        }

        // Vulnerability scanning
        "nikto" | "sqlmap" | "wpscan" | "dirb" | "dirbuster" | "gobuster" | "wfuzz" | "ffuf" => {
            ToolCategory::VulnScan
        }

        // Traffic capture
        "tcpdump" | "tshark" | "wireshark" | "tcpflow" | "ngrep" => ToolCategory::TrafficCapture,

        // Port scanning (could be quick or slow depending on target)
        "port_scan" => ToolCategory::NetworkScan,

        // Default for unknown tools
        _ => ToolCategory::Default,
    }
}

/// Clamp a user-provided timeout to reasonable bounds
///
/// Prevents users from setting extremely short timeouts (DoS themselves)
/// or extremely long timeouts (resource exhaustion).
pub fn clamp_timeout(timeout: Duration, category: ToolCategory) -> Duration {
    let (min, max) = match category {
        ToolCategory::QuickScan => (Duration::from_secs(5), Duration::from_secs(300)),
        ToolCategory::NetworkScan => (Duration::from_secs(30), Duration::from_secs(3600)),
        ToolCategory::BruteForce => (Duration::from_secs(60), Duration::from_secs(14400)),
        ToolCategory::VulnScan => (Duration::from_secs(30), Duration::from_secs(7200)),
        ToolCategory::TrafficCapture => (Duration::from_secs(10), Duration::from_secs(1800)),
        ToolCategory::Default => (Duration::from_secs(10), Duration::from_secs(3600)),
    };

    if timeout < min {
        min
    } else if timeout > max {
        max
    } else {
        timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_timeouts() {
        let timeouts = ToolTimeouts::default();
        assert_eq!(timeouts.quick_scan, Duration::from_secs(60));
        assert_eq!(timeouts.network_scan, Duration::from_secs(600));
        assert_eq!(timeouts.brute_force, Duration::from_secs(3600));
        assert_eq!(timeouts.default, Duration::from_secs(300));
    }

    #[test]
    fn test_test_timeouts() {
        let timeouts = ToolTimeouts::test();
        assert_eq!(timeouts.quick_scan, Duration::from_secs(5));
        assert_eq!(timeouts.network_scan, Duration::from_secs(30));
    }

    #[test]
    fn test_production_timeouts() {
        let timeouts = ToolTimeouts::production();
        assert_eq!(timeouts.quick_scan, Duration::from_secs(120));
        assert_eq!(timeouts.network_scan, Duration::from_secs(1800));
    }

    #[test]
    fn test_get_by_category() {
        let timeouts = ToolTimeouts::default();
        assert_eq!(
            timeouts.get(ToolCategory::QuickScan),
            Duration::from_secs(60)
        );
        assert_eq!(
            timeouts.get(ToolCategory::NetworkScan),
            Duration::from_secs(600)
        );
    }

    #[test]
    fn test_categorize_tool() {
        assert_eq!(categorize_tool("nmap"), ToolCategory::NetworkScan);
        assert_eq!(categorize_tool("NMAP"), ToolCategory::NetworkScan);
        assert_eq!(categorize_tool("ping"), ToolCategory::QuickScan);
        assert_eq!(categorize_tool("hydra"), ToolCategory::BruteForce);
        assert_eq!(categorize_tool("nikto"), ToolCategory::VulnScan);
        assert_eq!(categorize_tool("tcpdump"), ToolCategory::TrafficCapture);
        assert_eq!(categorize_tool("unknown_tool"), ToolCategory::Default);
    }

    #[test]
    fn test_get_by_tool_name() {
        let timeouts = ToolTimeouts::default();
        assert_eq!(timeouts.get_by_tool_name("nmap"), Duration::from_secs(600));
        assert_eq!(timeouts.get_by_tool_name("ping"), Duration::from_secs(60));
        assert_eq!(
            timeouts.get_by_tool_name("hydra"),
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn test_clamp_timeout_within_bounds() {
        let timeout = Duration::from_secs(100);
        let clamped = clamp_timeout(timeout, ToolCategory::NetworkScan);
        assert_eq!(clamped, timeout); // Should not change
    }

    #[test]
    fn test_clamp_timeout_too_short() {
        let timeout = Duration::from_secs(1);
        let clamped = clamp_timeout(timeout, ToolCategory::NetworkScan);
        assert_eq!(clamped, Duration::from_secs(30)); // Clamped to minimum
    }

    #[test]
    fn test_clamp_timeout_too_long() {
        let timeout = Duration::from_secs(10000);
        let clamped = clamp_timeout(timeout, ToolCategory::NetworkScan);
        assert_eq!(clamped, Duration::from_secs(3600)); // Clamped to maximum
    }

    #[test]
    fn test_clamp_timeout_brute_force() {
        // Brute force should allow longer timeouts
        let timeout = Duration::from_secs(7200); // 2 hours
        let clamped = clamp_timeout(timeout, ToolCategory::BruteForce);
        assert_eq!(clamped, timeout); // Within bounds

        let too_long = Duration::from_secs(20000); // > 4 hours
        let clamped = clamp_timeout(too_long, ToolCategory::BruteForce);
        assert_eq!(clamped, Duration::from_secs(14400)); // Clamped to 4 hours
    }
}
