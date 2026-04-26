//! Port scanning tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_core::validation::{validate_port_spec, validate_target};
use pentest_platform::{get_platform, NetworkOps, ScanConfig};
use serde_json::{json, Value};

use crate::util::{param_str, param_u64};

/// Port scanning tool
pub struct PortScanTool;

#[async_trait]
impl PentestTool for PortScanTool {
    fn name(&self) -> &str {
        "port_scan"
    }

    fn description(&self) -> &str {
        "Scan TCP ports on a target host to identify open services"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "host",
                ParamType::String,
                "Target host IP or hostname",
            ))
            .param(ToolParam::optional(
                "ports",
                ParamType::String,
                "Port specification (e.g., '22,80,443' or '1-1024')",
                json!("22,80,443,8080"),
            ))
            .param(ToolParam::optional(
                "timeout_ms",
                ParamType::Integer,
                "Connection timeout per port in milliseconds",
                json!(2000),
            ))
            .param(ToolParam::optional(
                "concurrency",
                ParamType::Integer,
                "Number of concurrent connections",
                json!(50),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![
            Platform::Desktop,
            Platform::Web,
            Platform::Android,
            Platform::Ios,
            Platform::Tui,
        ]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            // Parse and validate parameters
            let host = params.get("host").and_then(|v| v.as_str()).ok_or_else(|| {
                pentest_core::error::Error::InvalidParams("host parameter is required".into())
            })?;

            // Validate host (IP or hostname)
            let host = validate_target(host)?;

            let ports_str = {
                let s = param_str(&params, "ports");
                if s.is_empty() {
                    "22,80,443,8080".to_string()
                } else {
                    s
                }
            };

            // Validate port specification
            let ports_str = validate_port_spec(&ports_str)?;

            let timeout_ms = param_u64(&params, "timeout_ms", 2000);

            let concurrency = param_u64(&params, "concurrency", 50) as usize;

            // Parse port specification
            let ports = pentest_core::state::ScanConfig::parse_ports(&ports_str);
            if ports.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "No valid ports specified".into(),
                ));
            }

            let config = ScanConfig {
                host: host.clone(),
                ports,
                timeout_ms,
                concurrency,
            };

            // Execute scan
            let platform = get_platform();
            let result = platform.port_scan(config).await?;
            Ok(json!({
                "host": result.host,
                "ports": result.ports,
                "open_count": result.open_count,
                "total_scanned": result.ports.len(),
                "duration_ms": result.duration_ms,
            }))
        })
        .await
    }
}
