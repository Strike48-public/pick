//! mDNS/DNS-SD network discovery tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, NetworkOps};
use serde_json::{json, Value};

use crate::util::{param_str, param_u64};

/// mDNS network discovery tool
pub struct NetworkDiscoverTool;

#[async_trait]
impl PentestTool for NetworkDiscoverTool {
    fn name(&self) -> &str {
        "network_discover"
    }

    fn description(&self) -> &str {
        "Discover services on the local network using mDNS/DNS-SD (Chromecast, printers, etc.)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::optional(
                "service_type",
                ParamType::String,
                "Service type to discover (e.g., '_http._tcp.local.', '_googlecast._tcp.local.')",
                json!("_services._dns-sd._udp.local."),
            ))
            .param(ToolParam::optional(
                "timeout_ms",
                ParamType::Integer,
                "Discovery timeout in milliseconds",
                json!(10000),
            ))
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let raw = param_str(&params, "service_type");
            let service_type = if raw.is_empty() {
                "_services._dns-sd._udp.local."
            } else {
                &raw
            };

            let timeout_ms = param_u64(&params, "timeout_ms", 10000);

            let platform = get_platform();
            let services = platform.mdns_discover(service_type, timeout_ms).await?;

            Ok(json!({
                "services": services.iter().map(|s| json!({
                    "name": s.name,
                    "service_type": s.service_type,
                    "host": s.host,
                    "port": s.port,
                    "txt_records": s.txt_records,
                })).collect::<Vec<_>>(),
                "count": services.len(),
            }))
        })
        .await
    }
}
