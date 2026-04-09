//! Detailed WiFi network scanning with client detection
//!
//! This tool enables monitor mode and uses airodump-ng to capture packets
//! for a period of time to detect connected clients on each network.
//! This is slower than wifi_scan but provides critical information for
//! WPA attack planning (client counts).

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::settings::load_settings;
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, SystemInfo as _, WifiAttackOps};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;
use tokio::process::Command;

use crate::util::{dbm_to_bars, dbm_to_quality};

/// Cleanup guard that ensures NetworkManager is restored even on error/panic
struct CleanupGuard {
    mon_interface: String,
    killed_network_manager: bool,
    cleaned: bool,
}

impl CleanupGuard {
    fn new(mon_interface: String, killed_network_manager: bool) -> Self {
        Self {
            mon_interface,
            killed_network_manager,
            cleaned: false,
        }
    }

    /// Manually trigger cleanup (also happens automatically on Drop)
    async fn cleanup(mut self) {
        // Manual cleanup - mark as cleaned so Drop won't run again
        self.run_cleanup().await;
        self.cleaned = true;
    }

    async fn run_cleanup(&self) {
        tracing::info!("🧹 Cleaning up and restoring network...");
        let platform = get_platform();
        if let Err(e) = platform
            .disable_monitor_mode(&self.mon_interface, self.killed_network_manager)
            .await
        {
            tracing::warn!("Failed to disable monitor mode: {}", e);
        }
    }
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if self.cleaned {
            return; // Already cleaned up manually
        }

        // If cleanup() wasn't called manually, we need to restore network
        // This happens on panic or early return
        tracing::warn!(
            "⚠️  CleanupGuard dropped without manual cleanup - restoring network synchronously"
        );

        // We can't use async in Drop, so we spawn a blocking task
        // This is a best-effort attempt to restore network on panic/early exit
        let mon_interface = self.mon_interface.clone();
        let killed_nm = self.killed_network_manager;

        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let platform = get_platform();
                tracing::info!("🧹 Emergency cleanup - restoring network...");
                if let Err(e) = platform
                    .disable_monitor_mode(&mon_interface, killed_nm)
                    .await
                {
                    tracing::error!("Failed to restore network in Drop: {}", e);
                } else {
                    tracing::info!("✓ Network restored via emergency cleanup");
                }
            });
        });
    }
}

/// Detailed WiFi scanning tool with client detection
pub struct WifiScanDetailedTool;

#[async_trait]
impl PentestTool for WifiScanDetailedTool {
    fn name(&self) -> &str {
        "wifi_scan_detailed"
    }

    fn description(&self) -> &str {
        "Scan for nearby WiFi networks with client detection (requires monitor mode, ~30-60 seconds)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::optional(
                "duration",
                ParamType::Integer,
                "Capture duration in seconds (default: 30)",
                json!(30),
            ))
            .param(ToolParam::optional(
                "allow_network_disruption",
                ParamType::Boolean,
                "Allow killing NetworkManager if required for monitor mode (will disconnect internet temporarily). Default: false",
                json!(false),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop] // Linux only for now (requires aircrack-ng)
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let duration_secs = params["duration"]
                .as_u64()
                .unwrap_or(30);

            let allow_network_disruption = params["allow_network_disruption"]
                .as_bool()
                .unwrap_or(false);

            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("📡 WiFi Detailed Scan with Client Detection");
            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("  Duration: {}s", duration_secs);
            tracing::info!("  Note: Requires monitor mode");
            if allow_network_disruption {
                tracing::info!("  Network disruption: AUTHORIZED (may kill NetworkManager)");
            } else {
                tracing::info!("  Network disruption: NOT authorized (will fail if required)");
            }
            tracing::info!("───────────────────────────────────────────────────");

            // Step 1: Run fast wifi_scan to get base network list
            tracing::info!("⚡ Step 1/4: Quick scan for access points...");
            let settings = load_settings();
            let selected_adapter = settings.wifi_adapter.clone();

            let platform = get_platform();
            let mut networks = platform.get_wifi_networks(selected_adapter.clone()).await?;

            tracing::info!("✓ Found {} networks", networks.len());

            // Step 2: Get interface and enable monitor mode
            let interface = selected_adapter.ok_or_else(|| {
                Error::InvalidParams(
                    "No WiFi adapter specified - select one in Settings first".into(),
                )
            })?;

            tracing::info!("");
            tracing::info!("⚡ Step 2/4: Enabling monitor mode on {}...", interface);
            let (mon_interface, killed_network_manager) = match platform.enable_monitor_mode(&interface, allow_network_disruption).await {
                Ok((iface, killed_nm)) => {
                    tracing::info!("✓ Monitor mode enabled: {}", iface);
                    if killed_nm {
                        tracing::warn!("⚠️  NetworkManager was killed to enable monitor mode");
                    }
                    (iface, killed_nm)
                }
                Err(e) => {
                    let error_msg = format!("Failed to enable monitor mode: {}", e);
                    tracing::error!("{}", error_msg);
                    if !allow_network_disruption {
                        tracing::info!("");
                        tracing::info!("💡 Tip: Your adapter may require network disruption to enable monitor mode.");
                        tracing::info!("   Try: wifi_scan_detailed(allow_network_disruption=true)");
                    }
                    return Err(Error::ToolExecution(error_msg));
                }
            };

            // Set up cleanup guard that ALWAYS runs
            let cleanup_guard = CleanupGuard::new(mon_interface.clone(), killed_network_manager);

            // Step 3: Capture packets with airodump-ng
            tracing::info!("");
            tracing::info!("⚡ Step 3/4: Capturing packets to detect clients ({}s)...", duration_secs);

            let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
            let output_dir = format!("/tmp/wifi-scan-{}", timestamp);
            std::fs::create_dir_all(&output_dir)
                .map_err(|e| Error::ToolExecution(format!("Failed to create output directory: {}", e)))?;

            let output_file = format!("{}/scan", output_dir);

            let client_counts = capture_with_client_detection(&mon_interface, &output_file, duration_secs).await?;

            // Step 4: Cleanup and merge results (cleanup_guard will handle restoration)
            tracing::info!("");
            tracing::info!("⚡ Step 4/4: Restoring network connectivity...");
            cleanup_guard.cleanup().await;
            tracing::info!("✓ Network restored");

            // Merge client counts into network list
            for network in &mut networks {
                if let Some(count) = client_counts.get(&network.bssid) {
                    network.clients = Some(*count);
                }
            }

            tracing::info!("");
            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("✓ Scan Complete");
            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("  Networks: {}", networks.len());
            tracing::info!("  With clients: {}", networks.iter().filter(|n| n.clients.unwrap_or(0) > 0).count());
            tracing::info!("═══════════════════════════════════════════════════");

            Ok(json!({
                "networks": networks.iter().map(|n| {
                    let signal_quality = dbm_to_quality(n.signal_strength);
                    let signal_bars = dbm_to_bars(n.signal_strength);

                    json!({
                        "ssid": n.ssid,
                        "bssid": n.bssid,
                        "signal_strength": n.signal_strength,
                        "signal_quality": signal_quality,
                        "signal_bars": signal_bars,
                        "frequency": n.frequency,
                        "channel": n.channel,
                        "security": n.security,
                        "clients": n.clients,
                    })
                }).collect::<Vec<_>>(),
                "count": networks.len(),
                "duration_sec": duration_secs,
            }))
        })
        .await
    }
}

/// Capture packets and detect clients per BSSID
async fn capture_with_client_detection(
    interface: &str,
    output_file: &str,
    duration_secs: u64,
) -> Result<HashMap<String, u32>> {
    use std::process::Stdio;

    // Start airodump-ng to capture all channels
    let child = Command::new("sudo")
        .args([
            "airodump-ng",
            "--output-format",
            "csv",
            "-w",
            output_file,
            interface,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            Error::ToolExecution(format!(
                "Failed to start airodump-ng (is it installed?): {}",
                e
            ))
        })?;

    let pid = child
        .id()
        .ok_or_else(|| Error::ToolExecution("Failed to get airodump-ng PID".into()))?;

    tracing::info!("  Capture started (PID: {})...", pid);

    // Let it run for specified duration
    let mut elapsed = 0;
    while elapsed < duration_secs {
        tokio::time::sleep(Duration::from_secs(5)).await;
        elapsed += 5;
        tracing::info!(
            "  Progress: {}s / {}s",
            elapsed.min(duration_secs),
            duration_secs
        );
    }

    // Stop capture
    tracing::info!("  Stopping capture...");
    let _ = Command::new("sudo")
        .args(["kill", &pid.to_string()])
        .output()
        .await;

    // Give it time to flush and write CSV
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // Parse CSV file
    let csv_file = format!("{}-01.csv", output_file);
    tracing::info!("  Parsing results from {}...", csv_file);

    // Check if CSV file exists
    if !std::path::Path::new(&csv_file).exists() {
        tracing::warn!("CSV file not found: {}", csv_file);
        tracing::warn!("airodump-ng may have failed to create output file");
        tracing::warn!("Possible reasons:");
        tracing::warn!("  - Monitor mode not enabled properly");
        tracing::warn!("  - No packets captured during scan");
        tracing::warn!("  - Permission issues");
        // Return empty client counts rather than failing
        return Ok(HashMap::new());
    }

    parse_airodump_csv(&csv_file).await
}

/// Parse airodump-ng CSV output to extract client counts per BSSID
async fn parse_airodump_csv(csv_path: &str) -> Result<HashMap<String, u32>> {
    let content = tokio::fs::read_to_string(csv_path)
        .await
        .map_err(|e| Error::ToolExecution(format!("Failed to read CSV: {}", e)))?;

    let mut client_counts: HashMap<String, u32> = HashMap::new();

    // airodump-ng CSV has two sections separated by blank line:
    // 1. Access Points (BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key)
    // 2. Clients (Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs)

    let sections: Vec<&str> = content.split("\r\n\r\n").collect();

    if sections.len() < 2 {
        tracing::warn!("CSV format unexpected, may not have client section");
        return Ok(client_counts);
    }

    // Parse clients section
    let clients_section = sections[1];
    let mut lines = clients_section.lines();

    // Skip header line
    if let Some(header) = lines.next() {
        if !header.contains("Station MAC") {
            tracing::warn!("Expected 'Station MAC' in clients header, got: {}", header);
        }
    }

    // Parse client lines
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split(',').map(|s| s.trim()).collect();

        // Field 5 is BSSID (0-indexed: Station MAC, First seen, Last seen, Power, # packets, BSSID, ...)
        if fields.len() >= 6 {
            let _client_mac = fields[0];
            let bssid = fields[5];

            // Skip if BSSID is "(not associated)" or empty
            if bssid.is_empty() || bssid.contains("not associated") {
                continue;
            }

            // Increment count for this BSSID
            *client_counts.entry(bssid.to_uppercase()).or_insert(0) += 1;
        }
    }

    tracing::info!("✓ Detected clients on {} networks", client_counts.len());
    for (bssid, count) in &client_counts {
        tracing::info!("  {} → {} clients", bssid, count);
    }

    Ok(client_counts)
}
