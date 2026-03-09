//! WiFi network scanning tool

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::tools::{execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

/// WiFi scanning tool
pub struct WifiScanTool;

#[async_trait]
impl PentestTool for WifiScanTool {
    fn name(&self) -> &str {
        "wifi_scan"
    }

    fn description(&self) -> &str {
        "Scan for nearby WiFi networks and get their details (SSID, BSSID, signal strength, channel, security)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::optional(
                "interface",
                ParamType::String,
                "Wireless interface to scan with (auto-detected if not specified)",
                json!(null),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Scan timeout in seconds",
                json!(10),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![
            Platform::Desktop,
            Platform::Tui,
        ]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let platform = get_platform();

            // Get interface parameter or auto-detect
            let interface = if let Some(iface) = params.get("interface").and_then(|v| v.as_str()) {
                iface.to_string()
            } else {
                detect_wireless_interface(&platform).await?
            };

            let timeout_secs = params
                .get("timeout")
                .and_then(|v| v.as_u64())
                .unwrap_or(10);

            tracing::info!("Scanning WiFi networks on interface: {}", interface);

            // Use 'iw dev <interface> scan' to scan for networks
            // Note: Inside bwrap user namespace, we're already root (UID 0), so no sudo needed
            let cmd = format!("iw dev {} scan 2>&1", interface);
            let output = platform
                .execute_command("sh", &["-c", &cmd], Duration::from_secs(timeout_secs + 5))
                .await?;

            if output.exit_code != 0 {
                return Err(Error::ToolExecution(format!(
                    "WiFi scan failed: {}. Make sure you have root privileges and the interface supports scanning.",
                    output.stderr
                )));
            }

            // Parse scan results
            let networks = parse_iw_scan_output(&output.stdout)?;

            Ok(json!({
                "networks": networks,
                "count": networks.len(),
                "interface": interface,
            }))
        })
        .await
    }
}

/// Detect first available wireless interface
async fn detect_wireless_interface(platform: &impl CommandExec) -> Result<String> {
    let output = platform
        .execute_command("sh", &["-c", "iw dev | grep Interface | awk '{print $2}' | head -1"], Duration::from_secs(5))
        .await?;

    if output.exit_code != 0 || output.stdout.trim().is_empty() {
        return Err(Error::ToolExecution(
            "No wireless interface found. Ensure a WiFi adapter is connected and 'iw' is installed.".to_string()
        ));
    }

    let interface = output.stdout.trim().to_string();
    if interface.is_empty() {
        return Err(Error::ToolExecution("No wireless interface detected".to_string()));
    }

    Ok(interface)
}

/// Parse 'iw scan' output into structured network data
fn parse_iw_scan_output(output: &str) -> Result<Vec<Value>> {
    let mut networks = Vec::new();
    let mut current_bssid: Option<String> = None;
    let mut current_ssid: Option<String> = None;
    let mut current_signal: Option<i32> = None;
    let mut current_freq: Option<u32> = None;
    let mut current_security: Vec<String> = Vec::new();

    for line in output.lines() {
        let line = line.trim();

        if line.starts_with("BSS ") {
            // Save previous network if we have one
            if let Some(bssid) = current_bssid.take() {
                if let Some(ssid) = current_ssid.take() {
                    if !ssid.is_empty() {
                        networks.push(json!({
                            "ssid": ssid,
                            "bssid": bssid,
                            "signal_strength": current_signal.unwrap_or(-100),
                            "frequency": current_freq.unwrap_or(0),
                            "channel": freq_to_channel(current_freq.unwrap_or(0)),
                            "security": if current_security.is_empty() { "Open".to_string() } else { current_security.join(", ") },
                        }));
                    }
                }
            }

            // Start new network entry
            current_signal = None;
            current_freq = None;
            current_security.clear();

            // Extract BSSID (MAC address) from "BSS aa:bb:cc:dd:ee:ff"
            if let Some(bssid_str) = line.split_whitespace().nth(1) {
                current_bssid = Some(bssid_str.trim_end_matches("(on").to_string());
            }
        } else if line.starts_with("SSID: ") {
            current_ssid = Some(line.strip_prefix("SSID: ").unwrap_or("").to_string());
        } else if line.starts_with("signal: ") {
            // Parse "signal: -65.00 dBm" -> -65
            if let Some(signal_str) = line.strip_prefix("signal: ") {
                if let Some(value) = signal_str.split_whitespace().next() {
                    if let Ok(signal) = value.parse::<f64>() {
                        current_signal = Some(signal as i32);
                    }
                }
            }
        } else if line.starts_with("freq: ") {
            // Parse "freq: 2412" -> 2412 MHz
            if let Some(freq_str) = line.strip_prefix("freq: ") {
                if let Ok(freq) = freq_str.trim().parse::<u32>() {
                    current_freq = Some(freq);
                }
            }
        } else if line.contains("WPA") || line.contains("WEP") || line.contains("RSN") {
            // Detect security types
            if line.contains("WPA2") && !current_security.contains(&"WPA2".to_string()) {
                current_security.push("WPA2".to_string());
            } else if line.contains("WPA") && !current_security.contains(&"WPA".to_string()) {
                current_security.push("WPA".to_string());
            }
            if line.contains("WEP") && !current_security.contains(&"WEP".to_string()) {
                current_security.push("WEP".to_string());
            }
        } else if line.contains("RSN:") || line.contains("Privacy") {
            // RSN = Robust Security Network (WPA2/WPA3)
            if !current_security.contains(&"WPA2".to_string()) && line.contains("RSN:") {
                current_security.push("WPA2".to_string());
            }
        }
    }

    // Don't forget the last network
    if let Some(bssid) = current_bssid {
        if let Some(ssid) = current_ssid {
            if !ssid.is_empty() {
                networks.push(json!({
                    "ssid": ssid,
                    "bssid": bssid,
                    "signal_strength": current_signal.unwrap_or(-100),
                    "frequency": current_freq.unwrap_or(0),
                    "channel": freq_to_channel(current_freq.unwrap_or(0)),
                    "security": if current_security.is_empty() { "Open".to_string() } else { current_security.join(", ") },
                }));
            }
        }
    }

    Ok(networks)
}

/// Convert frequency (MHz) to WiFi channel number
fn freq_to_channel(freq: u32) -> u32 {
    match freq {
        // 2.4 GHz band
        2412 => 1,
        2417 => 2,
        2422 => 3,
        2427 => 4,
        2432 => 5,
        2437 => 6,
        2442 => 7,
        2447 => 8,
        2452 => 9,
        2457 => 10,
        2462 => 11,
        2467 => 12,
        2472 => 13,
        2484 => 14,
        // 5 GHz band (simplified)
        5180 => 36,
        5200 => 40,
        5220 => 44,
        5240 => 48,
        5260 => 52,
        5280 => 56,
        5300 => 60,
        5320 => 64,
        5500 => 100,
        5520 => 104,
        5540 => 108,
        5560 => 112,
        5580 => 116,
        5660 => 132,
        5680 => 136,
        5700 => 140,
        5745 => 149,
        5765 => 153,
        5785 => 157,
        5805 => 161,
        5825 => 165,
        _ => 0, // Unknown
    }
}
