//! Begin Scan Tool
//!
//! Initiates a penetration testing scan, creating the scan state tracking.
//! This tool should be called by the Red Team agent when the user explicitly
//! requests to start a scan.

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::tools::{execute_timed, PentestTool, Platform, ToolContext, ToolResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Input for the begin_scan tool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeginScanInput {
    /// Conversation ID where the scan is happening
    pub conversation_id: String,

    /// Agent ID of the Red Team agent
    pub agent_id: String,
}

/// Result of beginning a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeginScanResult {
    /// Whether the scan was started successfully
    pub success: bool,

    /// Scan ID (same as conversation_id)
    pub scan_id: String,

    /// Agent ID that will perform the scan
    pub agent_id: String,

    /// Current aggression level
    pub aggression_level: String,

    /// Message to display
    pub message: String,
}

/// Begin scan tool
pub struct BeginScanTool;

#[async_trait]
impl PentestTool for BeginScanTool {
    fn name(&self) -> &str {
        "begin_scan"
    }

    fn description(&self) -> &str {
        "Begin a penetration testing scan. Call this when the user explicitly requests to start a scan. \
         This initializes scan state tracking and enables mid-scan adjustments."
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        // System tool - works everywhere
        vec![
            Platform::Desktop,
            Platform::Android,
            Platform::Ios,
            Platform::Web,
            Platform::Tui,
        ]
    }

    async fn execute(&self, params: Value, ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            // Parse input
            let input: BeginScanInput = serde_json::from_value(params).map_err(|e| {
                Error::InvalidParams(format!("Invalid begin_scan parameters: {}", e))
            })?;

            let aggression = ctx.aggression_level();

            // The actual scan state creation happens via ConnectorEvent::ScanStarted
            // which is emitted by the LiveViewConnector when it sees this tool succeed.
            // We just return the scan info here.

            let result = BeginScanResult {
                success: true,
                scan_id: input.conversation_id.clone(),
                agent_id: input.agent_id.clone(),
                aggression_level: aggression.display_name().to_string(),
                message: format!(
                    "Scan started in {} mode ({}x cost multiplier). Use spawn_specialist to \
                     delegate deep-dive testing to domain experts.",
                    aggression.display_name(),
                    aggression.cost_multiplier()
                ),
            };

            Ok(serde_json::to_value(&result)?)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_basic_properties() {
        let tool = BeginScanTool;
        assert_eq!(tool.name(), "begin_scan");
        assert!(!tool.description().is_empty());
        assert!(!tool.supported_platforms().is_empty());
    }

    #[test]
    fn begin_scan_input_serialization() {
        let input = BeginScanInput {
            conversation_id: "conv-123".to_string(),
            agent_id: "agent-456".to_string(),
        };
        let json = serde_json::to_string(&input).unwrap();
        let deserialized: BeginScanInput = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.conversation_id, "conv-123");
        assert_eq!(deserialized.agent_id, "agent-456");
    }

    #[test]
    fn begin_scan_result_serialization() {
        let result = BeginScanResult {
            success: true,
            scan_id: "scan-123".to_string(),
            agent_id: "agent-789".to_string(),
            aggression_level: "Balanced".to_string(),
            message: "Scan started".to_string(),
        };
        let json = serde_json::to_string(&result).unwrap();
        let deserialized: BeginScanResult = serde_json::from_str(&json).unwrap();
        assert!(deserialized.success);
        assert_eq!(deserialized.scan_id, "scan-123");
        assert_eq!(deserialized.agent_id, "agent-789");
    }
}
