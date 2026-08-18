//! Safety Check tool for validating network security before pentesting operations.

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{PentestTool, ToolContext, ToolResult};
use serde_json::{json, Value};

/// Tool for performing comprehensive network safety checks.
///
/// Validates whether the local network environment is safe for penetration
/// testing by checking DNS integrity, router threat intelligence, and
/// network device discovery.
///
/// Particularly useful when working from public WiFi (airports, coffee shops)
/// where the network may be compromised.
pub struct SafetyCheckTool;

#[async_trait]
impl PentestTool for SafetyCheckTool {
    fn supported_platforms(&self) -> Vec<pentest_core::tools::Platform> {
        use pentest_core::tools::Platform;
        // Native network-safety checks (DNS/gateway heuristics) — runs on iOS.
        vec![
            Platform::Desktop,
            Platform::Android,
            Platform::Ios,
            Platform::Tui,
        ]
    }

    fn name(&self) -> &str {
        "safety_check"
    }

    fn description(&self) -> &str {
        "Perform a comprehensive network safety check to validate if the current network environment is safe for penetration testing operations. Checks DNS integrity (detects hijacking/captive portals), router threat intelligence (checks gateway reputation), and discovers network devices. Returns overall status (Safe/Caution/Unsafe) with detailed findings and actionable recommendations. Ideal for verifying public WiFi security before starting work."
    }

    async fn execute(&self, _params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        tracing::info!("Running safety check");

        // Run the safety check
        let result = crate::safety_check::run_safety_check().await?;

        // Format the report
        let report = crate::safety_check::format_report(&result);

        // Create structured output for AI consumption
        let structured_data = json!({
            "status": format!("{}", result.status),
            "timestamp": result.timestamp.to_rfc3339(),
            "checks": result.checks.iter().map(|c| json!({
                "name": c.name,
                "status": format!("{}", c.status),
                "details": c.details,
                "severity": format!("{:?}", c.severity),
            })).collect::<Vec<_>>(),
            "network_map": result.network_map.as_ref().map(|map| json!({
                "gateway_ip": map.gateway.ip.to_string(),
                "your_ip": map.your_device.ip.to_string(),
                "device_count": map.other_devices.len(),
                "devices": map.other_devices.iter().map(|d| json!({
                    "ip": d.ip.to_string(),
                    "hostname": d.hostname,
                    "vendor": d.vendor,
                    "threat_level": format!("{:?}", d.threat_level),
                })).collect::<Vec<_>>(),
            })),
            "recommendations": result.recommendations.iter().map(|r| json!({
                "priority": format!("{:?}", r.priority),
                "title": r.title,
                "description": r.description,
                "action": r.action,
            })).collect::<Vec<_>>(),
        });

        Ok(ToolResult::success(json!({
            "report": report,
            "structured": structured_data,
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_info() {
        let tool = SafetyCheckTool;
        assert_eq!(tool.name(), "safety_check");
        assert!(tool.description().contains("network safety"));
        assert!(tool.description().contains("DNS integrity"));
    }
}
