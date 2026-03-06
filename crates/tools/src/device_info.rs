//! Device information tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{execute_timed, PentestTool, Platform, ToolContext, ToolResult};
use pentest_platform::{get_platform, SystemInfo as _};
use serde_json::{json, Value};

/// Device information tool
pub struct DeviceInfoTool;

#[async_trait]
impl PentestTool for DeviceInfoTool {
    fn name(&self) -> &str {
        "device_info"
    }

    fn description(&self) -> &str {
        "Get system and device information including OS, hardware, and network details"
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![
            Platform::Desktop,
            Platform::Android,
            Platform::Ios,
            Platform::Web,
            Platform::Tui,
        ]
    }

    async fn execute(&self, _params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let platform = get_platform();
            let info = platform.get_device_info().await?;
            Ok(json!({
                "os_name": info.os_name,
                "os_version": info.os_version,
                "hostname": info.hostname,
                "architecture": info.architecture,
                "cpu_count": info.cpu_count,
                "total_memory_mb": info.total_memory_mb,
                "platform_specific": info.platform_specific,
            }))
        })
        .await
    }
}
