//! Automated penetration testing tools
//!
//! This module provides tools for automated penetration testing:
//! - WiFi attacks: `autopwn_plan`, `autopwn_capture`, `autopwn_crack`
//! - Toolchain execution: `autopwn_webapp` for automated web app assessments

mod capture;
mod crack;
mod strategy;
mod types;
mod vendor_intel;
mod wordlist;

pub mod toolchain;

pub use capture::AutoPwnCaptureTool;
pub use crack::AutoPwnCrackTool;
pub use toolchain::WebAppToolchain;
pub use types::*;

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::*;
use serde_json::{json, Value};

use strategy::{calculate_feasibility, select_strategy};
use vendor_intel::is_default_ssid;

/// Analyze a WiFi target and recommend the best attack strategy
pub struct AutoPwnPlanTool;

#[async_trait]
impl PentestTool for AutoPwnPlanTool {
    fn name(&self) -> &str {
        "autopwn_plan"
    }

    fn description(&self) -> &str {
        "Analyze a WiFi target and recommend the best attack strategy (WEP/WPA)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "ssid",
                ParamType::String,
                "Target network SSID (network name)",
            ))
            .param(ToolParam::required(
                "bssid",
                ParamType::String,
                "Target network BSSID (MAC address, e.g., '00:11:22:33:44:55')",
            ))
            .param(ToolParam::required(
                "security",
                ParamType::String,
                "Security type (e.g., 'WEP', 'WPA2-PSK', 'WPA')",
            ))
            .param(ToolParam::optional(
                "signal",
                ParamType::Integer,
                "Signal strength in dBm (e.g., -50). More negative = weaker signal",
                json!(-60),
            ))
            .param(ToolParam::optional(
                "clients",
                ParamType::Integer,
                "Number of connected clients visible on the network",
                json!(0),
            ))
            .param(ToolParam::optional(
                "channel",
                ParamType::Integer,
                "WiFi channel (1-14 for 2.4GHz)",
                json!(6),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        // Planning works on all platforms, execution is Desktop-only
        vec![
            Platform::Desktop,
            Platform::Android,
            Platform::Ios,
            Platform::Tui,
        ]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            // Parse parameters
            let ssid = params["ssid"]
                .as_str()
                .ok_or_else(|| {
                    pentest_core::error::Error::InvalidParams("ssid is required".into())
                })?
                .to_string();

            let bssid = params["bssid"]
                .as_str()
                .ok_or_else(|| {
                    pentest_core::error::Error::InvalidParams("bssid is required".into())
                })?
                .to_string();

            let security = params["security"]
                .as_str()
                .ok_or_else(|| {
                    pentest_core::error::Error::InvalidParams("security is required".into())
                })?
                .to_string();

            let signal = params["signal"].as_i64().unwrap_or(-60) as i32;
            let clients = params["clients"].as_u64().unwrap_or(0) as u32;
            let channel = params["channel"].as_u64().unwrap_or(6) as u8;

            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("🎯 AutoPwn Target Analysis");
            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("  SSID:     {}", ssid);
            tracing::info!("  BSSID:    {}", bssid);
            tracing::info!("  Security: {}", security);
            tracing::info!("  Signal:   {} dBm", signal);
            tracing::info!("  Clients:  {}", clients);
            tracing::info!("  Channel:  {}", channel);
            tracing::info!("───────────────────────────────────────────────────");

            // Check for default SSID
            let is_default = is_default_ssid(&ssid);
            if is_default {
                tracing::info!("🔍 Detected known vendor default SSID pattern");
            }

            // Select attack strategy
            let strategy = select_strategy(&ssid, &bssid, &security, signal, clients)?;

            // Calculate feasibility
            let feasibility = calculate_feasibility(&security, signal, clients, is_default);

            // Build attack plan
            let mut warnings = Vec::new();

            if signal < -70 {
                warnings.push("Weak signal - consider moving closer to target".to_string());
            }

            if clients == 0 {
                // WPA requires clients for handshake capture, WEP does not
                if security.to_uppercase().contains("WPA") {
                    warnings.push(
                        "No clients detected - WPA handshake capture REQUIRES a client to be connected or connecting. You can either wait for a client to join, or use deauth attack on an existing client.".to_string(),
                    );
                } else if security.to_uppercase().contains("WEP") {
                    // WEP doesn't need clients - fake auth + injection works
                    tracing::info!("  Note: WEP attack does not require clients (will use fake auth + injection)");
                } else {
                    warnings.push(
                        "No visible clients - attack success may be limited".to_string(),
                    );
                }
            }

            let plan = AttackPlan {
                target_ssid: ssid.clone(),
                target_bssid: bssid.clone(),
                channel,
                security: security.clone(),
                strategy: strategy.clone(),
                requires_monitor_mode: true,
                requires_mac_cloning: false,
                estimated_duration_sec: strategy.estimated_duration().as_secs(),
                warnings: warnings.clone(),
            };

            // Log recommendation
            tracing::info!("");
            match &strategy {
                AttackStrategy::Wep {
                    estimated_time_sec,
                    confidence,
                    target_ivs,
                } => {
                    tracing::info!("✓ WEP Network - Highly Feasible Attack");
                    tracing::info!("  Strategy:      Capture {} IVs + crack", target_ivs);
                    tracing::info!(
                        "  Est. Time:     {} minutes",
                        estimated_time_sec / 60
                    );
                    tracing::info!("  Confidence:    {:.0}%", confidence * 100.0);
                    tracing::info!(
                        "  Feasibility:   {:.0}% (signal + injection rate)",
                        feasibility * 100.0
                    );
                    tracing::info!("");
                    tracing::info!("📝 Attack Steps:");
                    tracing::info!("  1. Enable monitor mode");
                    tracing::info!("  2. Fake authentication");
                    tracing::info!("  3. ARP replay attack (generate IVs)");
                    tracing::info!("  4. Crack WEP key (live cracking)");
                }
                AttackStrategy::Wpa {
                    capture_mode,
                    crack_method,
                    estimated_time_sec,
                    confidence,
                } => {
                    tracing::info!("✓ WPA/WPA2 Network - Attack Feasible");
                    tracing::info!("  Capture Mode:  {:?}", capture_mode);
                    tracing::info!("  Crack Method:  {:?}", crack_method);
                    tracing::info!(
                        "  Est. Time:     {} minutes (capture + crack)",
                        estimated_time_sec / 60
                    );
                    tracing::info!("  Confidence:    {:.0}%", confidence * 100.0);
                    tracing::info!("  Feasibility:   {:.0}%", feasibility * 100.0);
                    tracing::info!("");
                    tracing::info!("📝 Attack Steps:");
                    tracing::info!("  1. Enable monitor mode");
                    tracing::info!("  2. Start packet capture");

                    match capture_mode {
                        CaptureMode::Passive => {
                            tracing::info!("  3. Wait for natural client reconnection");
                        }
                        CaptureMode::ActiveDeauth { .. } => {
                            tracing::info!("  3. Send deauth packets to force handshake");
                        }
                        CaptureMode::Broadcast => {
                            tracing::info!("  3. Broadcast deauth to all clients");
                        }
                    }

                    tracing::info!("  4. Verify handshake capture");

                    match crack_method {
                        CrackMethod::Dictionary { .. } => {
                            tracing::info!("  5. Dictionary attack with wordlist");
                        }
                        CrackMethod::MaskAttack { pattern } => {
                            tracing::info!("  5. Mask attack with pattern: {}", pattern);
                        }
                        _ => {
                            tracing::info!("  5. Crack captured handshake");
                        }
                    }
                }
                AttackStrategy::Unsupported { reason } => {
                    tracing::warn!("⚠ Attack Not Feasible");
                    tracing::warn!("  Reason: {}", reason);
                    tracing::info!("  Feasibility:   {:.0}%", feasibility * 100.0);
                }
            }

            // Log warnings
            if !warnings.is_empty() {
                tracing::info!("");
                tracing::warn!("⚠️  Warnings:");
                for warning in &warnings {
                    tracing::warn!("  • {}", warning);
                }
            }

            tracing::info!("═══════════════════════════════════════════════════");

            Ok(json!(plan))
        })
        .await
    }
}
