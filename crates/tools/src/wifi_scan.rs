//! WiFi network scanning tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{execute_timed, PentestTool, Platform, ToolContext, ToolResult};
use pentest_platform::{get_platform, SystemInfo as _};
use serde_json::{json, Value};

/// WiFi scanning tool
pub struct WifiScanTool;

#[async_trait]
impl PentestTool for WifiScanTool {
    fn name(&self) -> &str {
        "wifi_scan"
    }

    fn description(&self) -> &str {
        "Scan for nearby WiFi networks and get their details (SSID, signal strength, security)"
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

    async fn execute(&self, _params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let platform = get_platform();
            let networks = platform.get_wifi_networks().await?;
            Ok(json!({
                "networks": networks.iter().map(|n| json!({
                    "ssid": n.ssid,
                    "bssid": n.bssid,
                    "signal_strength": n.signal_strength,
                    "frequency": n.frequency,
                    "channel": n.channel,
                    "security": n.security,
                })).collect::<Vec<_>>(),
                "count": networks.len(),
            }))
        })
        .await
    }
}
