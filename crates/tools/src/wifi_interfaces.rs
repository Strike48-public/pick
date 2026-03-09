//! WiFi interface enumeration tool

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{execute_timed, PentestTool, Platform, ToolContext, ToolResult};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

/// WiFi interface listing tool
pub struct WifiInterfacesTool;

#[async_trait]
impl PentestTool for WifiInterfacesTool {
    fn name(&self) -> &str {
        "list_wifi_interfaces"
    }

    fn description(&self) -> &str {
        "List available wireless network interfaces on the system (for use with autopwn and other WiFi tools)"
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui] // Linux-focused
    }

    async fn execute(&self, _params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let platform = get_platform();

            // Use iw to list wireless interfaces
            let output = platform
                .execute_command(
                    "sh",
                    &["-c", "iw dev 2>/dev/null | grep -E 'Interface|wiphy|addr' | head -20"],
                    Duration::from_secs(10),
                )
                .await?;

            if output.exit_code != 0 {
                // Fallback: try listing network interfaces
                let fallback = platform
                    .execute_command(
                        "sh",
                        &["-c", "ip link show | grep -E 'wl|wlan' || echo 'No wireless interfaces found'"],
                        Duration::from_secs(5),
                    )
                    .await?;

                return Ok(json!({
                    "interfaces": [],
                    "raw_output": fallback.stdout.trim(),
                    "note": "Install 'iw' package for detailed wireless interface information"
                }));
            }

            // Parse iw output
            let mut interfaces = Vec::new();
            let mut current_interface = None;
            let mut current_phy = None;
            #[allow(unused_assignments)]
            let mut current_addr = None;

            for line in output.stdout.lines() {
                let line = line.trim();

                if line.starts_with("phy#") {
                    current_phy = Some(line.to_string());
                } else if line.starts_with("Interface") {
                    current_interface = line.split_whitespace().nth(1).map(String::from);
                } else if line.contains("addr") {
                    current_addr = line.split_whitespace().last().map(String::from);

                    // If we have all three pieces, create an interface entry
                    if let (Some(iface), Some(phy), Some(addr)) =
                        (current_interface.take(), current_phy.take(), current_addr.take())
                    {
                        interfaces.push(json!({
                            "interface": iface,
                            "phy": phy,
                            "mac_address": addr,
                        }));
                    }
                }
            }

            if interfaces.is_empty() {
                // Try to extract just interface names
                let simple_output = platform
                    .execute_command(
                        "sh",
                        &["-c", "iw dev | grep Interface | awk '{print $2}'"],
                        Duration::from_secs(5),
                    )
                    .await?;

                for line in simple_output.stdout.lines() {
                    let iface = line.trim();
                    if !iface.is_empty() {
                        interfaces.push(json!({
                            "interface": iface,
                            "phy": "unknown",
                            "mac_address": "unknown",
                        }));
                    }
                }
            }

            Ok(json!({
                "interfaces": interfaces,
                "count": interfaces.len(),
                "raw_output": output.stdout.trim(),
            }))
        })
        .await
    }
}
