//! Intelligent autopwn orchestrator that chooses WiFi or network attacks based on hardware

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::*;
use pentest_platform::{get_platform, SystemInfo};
use serde_json::{json, Value};

/// Intelligent autopwn orchestrator
///
/// Detects available hardware and automatically chooses the best attack path:
/// - WiFi pentest adapter available → WiFi attacks (WEP/WPA cracking)
/// - No WiFi adapter → Network-based attacks (discovery, scanning, exploitation)
pub struct AutoPwnOrchestratorTool;

#[async_trait]
impl PentestTool for AutoPwnOrchestratorTool {
    fn name(&self) -> &str {
        "autopwn_detect"
    }

    fn description(&self) -> &str {
        "Detect available hardware and recommend the best autopwn strategy (WiFi vs Network)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![
            Platform::Desktop,
            Platform::Android,
            Platform::Ios,
            Platform::Tui,
        ]
    }

    async fn execute(&self, _params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("🤖 AutoPwn Hardware Detection");
            tracing::info!("═══════════════════════════════════════════════════");

            let platform = get_platform();

            // Check WiFi adapter status
            let wifi_status = platform.check_wifi_connection_status(None).await?;

            tracing::info!(
                "WiFi Adapters Found: {}",
                wifi_status.all_wifi_interfaces.len()
            );
            for iface in &wifi_status.all_wifi_interfaces {
                tracing::info!("  - {}", iface);
            }

            // Determine attack strategy
            let has_pentest_adapter = wifi_status.all_wifi_interfaces.len() > 1
                || wifi_status.all_wifi_interfaces.iter().any(|iface| {
                    // Common pentest adapter patterns
                    iface.contains("wlan") && !iface.ends_with("0")
                        || iface.contains("mon")
                        || iface.contains("ath")
                        || iface.contains("wlx")
                });

            let strategy = if has_pentest_adapter {
                tracing::info!("");
                tracing::info!("✅ WiFi Pentest Hardware Detected");
                tracing::info!("   Recommendation: WiFi-based attacks");
                tracing::info!("   Strategy: Scan → Target Selection → Capture → Crack");
                tracing::info!("");
                tracing::info!("Attack Sequence:");
                tracing::info!("  1. WiFi scan (find targets)");
                tracing::info!("  2. Detailed scan (detect clients)");
                tracing::info!("  3. Select best target (signal + clients + security)");
                tracing::info!("  4. Plan attack (autopwn_plan)");
                tracing::info!("  5. Capture handshake/IVs (autopwn_capture)");
                tracing::info!("  6. Crack password (autopwn_crack)");

                json!({
                    "strategy": "wifi",
                    "has_pentest_adapter": true,
                    "adapters": wifi_status.all_wifi_interfaces,
                    "recommended_tools": [
                        "wifi_scan",
                        "wifi_scan_detailed",
                        "autopwn_plan",
                        "autopwn_capture",
                        "autopwn_crack"
                    ],
                    "next_step": "Run wifi_scan to discover nearby networks"
                })
            } else {
                tracing::info!("");
                tracing::info!("ℹ️  No WiFi Pentest Adapter Detected");
                tracing::info!("   Recommendation: Network-based attacks");
                tracing::info!("   Strategy: Discovery → Scanning → Enumeration → Exploitation");
                tracing::info!("");
                tracing::info!("Attack Sequence:");
                tracing::info!("  1. Network discovery (ARP, mDNS, SSDP)");
                tracing::info!("  2. Port scanning (identify services)");
                tracing::info!("  3. Service enumeration (banner grabbing)");
                tracing::info!("  4. Vulnerability assessment (CVEs, default creds)");
                tracing::info!("  5. Exploitation planning (manual analysis)");

                json!({
                    "strategy": "network",
                    "has_pentest_adapter": false,
                    "adapters": wifi_status.all_wifi_interfaces,
                    "recommended_tools": [
                        "autopwn_network_plan",
                        "arp_table",
                        "port_scan",
                        "service_banner",
                        "smb_enum",
                        "web_vuln_scan",
                        "cve_lookup",
                        "default_creds"
                    ],
                    "next_step": "Run autopwn_network_plan to create attack sequence"
                })
            };

            tracing::info!("═══════════════════════════════════════════════════");

            Ok(strategy)
        })
        .await
    }
}
