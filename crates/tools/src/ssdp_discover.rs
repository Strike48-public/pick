//! SSDP/UPnP discovery tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, NetworkOps};
use serde_json::{json, Value};

use crate::util::param_u64;

/// SSDP discovery tool
pub struct SsdpDiscoverTool;

#[async_trait]
impl PentestTool for SsdpDiscoverTool {
    fn name(&self) -> &str {
        "ssdp_discover"
    }

    fn description(&self) -> &str {
        "Discover UPnP/SSDP devices on the local network (routers, smart TVs, IoT devices)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description()).param(ToolParam::optional(
            "timeout_ms",
            ParamType::Integer,
            "Discovery timeout in milliseconds",
            json!(5000),
        ))
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        let timeout_ms = param_u64(&params, "timeout_ms", 5000);

        execute_timed(|| async move {
            let platform = get_platform();
            let devices = platform.ssdp_discover(timeout_ms).await?;
            Ok(json!({
                "devices": devices.iter().map(|d| json!({
                    "location": d.location,
                    "server": d.server,
                    "usn": d.usn,
                    "st": d.st,
                    "friendly_name": d.friendly_name,
                    "manufacturer": d.manufacturer,
                    "model": d.model,
                })).collect::<Vec<_>>(),
                "count": devices.len(),
            }))
        })
        .await
    }
}
