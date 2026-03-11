//! SMB/CIFS share enumeration tool

use async_trait::async_trait;
use pentest_core::error::{Error, Result};
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult, ToolSchema,
};
use serde_json::{json, Value};
use tokio::process::Command;

use crate::util::param_str;

/// SMB enumeration tool
pub struct SmbEnumTool;

impl SmbEnumTool {
    /// Enumerate shares using smbclient
    async fn enumerate_with_smbclient(host: &str, username: Option<&str>) -> Result<Vec<Value>> {
        let mut cmd = Command::new("smbclient");
        cmd.arg("-L").arg(host).arg("-N"); // -N = no password

        if let Some(user) = username {
            cmd.arg("-U").arg(user);
        }

        let output = cmd
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("smbclient not available: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::ToolExecution(format!(
                "smbclient failed: {}",
                stderr
            )));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let shares = Self::parse_smbclient_output(&stdout);

        Ok(shares)
    }

    /// Parse smbclient -L output
    fn parse_smbclient_output(output: &str) -> Vec<Value> {
        let mut shares = Vec::new();
        let mut in_shares_section = false;

        for line in output.lines() {
            let trimmed = line.trim();

            // Detect shares section
            if trimmed.starts_with("Sharename") {
                in_shares_section = true;
                continue;
            }

            // End of shares section
            if trimmed.starts_with("SMB") || trimmed.starts_with("Server") {
                in_shares_section = false;
            }

            if in_shares_section && !trimmed.is_empty() && !trimmed.starts_with("---") {
                // Parse line like: "IPC$            IPC       IPC Service (Samba Server)"
                let parts: Vec<&str> = trimmed.split_whitespace().collect();

                if parts.len() >= 2 {
                    let share_name = parts[0];
                    let share_type = parts[1];

                    shares.push(json!({
                        "name": share_name,
                        "type": share_type,
                        "comment": if parts.len() > 2 {
                            parts[2..].join(" ")
                        } else {
                            String::new()
                        },
                    }));
                }
            }
        }

        shares
    }

    /// Test anonymous access to a share
    async fn test_anonymous_access(host: &str, share: &str) -> bool {
        let output = Command::new("smbclient")
            .arg(format!("//{}/{}", host, share))
            .arg("-N") // No password
            .arg("-c")
            .arg("ls") // Try to list files
            .output()
            .await;

        if let Ok(result) = output {
            result.status.success()
        } else {
            false
        }
    }

    /// Enumerate shares using nmblookup/nmb (fallback)
    async fn enumerate_with_nmblookup(host: &str) -> Result<Vec<Value>> {
        // Try to get NetBIOS name
        let output = Command::new("nmblookup")
            .arg("-A")
            .arg(host)
            .output()
            .await
            .map_err(|e| Error::ToolExecution(format!("nmblookup not available: {}", e)))?;

        if !output.status.success() {
            return Err(Error::ToolExecution("nmblookup failed".into()));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);

        // Parse NetBIOS names
        let mut shares = Vec::new();
        for line in stdout.lines() {
            if line.contains("<00>") || line.contains("<20>") {
                // <00> = Workstation, <20> = Server
                if let Some(name) = line.split_whitespace().next() {
                    shares.push(json!({
                        "name": name,
                        "type": "NetBIOS",
                        "comment": "Discovered via nmblookup",
                    }));
                }
            }
        }

        Ok(shares)
    }
}

#[async_trait]
impl PentestTool for SmbEnumTool {
    fn name(&self) -> &str {
        "smb_enum"
    }

    fn description(&self) -> &str {
        "Enumerate SMB/CIFS shares on a target host and test for anonymous access"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "host",
                ParamType::String,
                "Target host IP or hostname",
            ))
            .param(ToolParam::optional(
                "username",
                ParamType::String,
                "Username for authentication (optional)",
                json!(""),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Android, Platform::Tui]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            let host = param_str(&params, "host");
            if host.is_empty() {
                return Err(Error::InvalidParams("host parameter is required".into()));
            }

            let username = param_str(&params, "username");
            let username_opt = if username.is_empty() {
                None
            } else {
                Some(username.as_str())
            };

            tracing::info!("Enumerating SMB shares on {}", host);

            // Try smbclient first
            let shares = match Self::enumerate_with_smbclient(&host, username_opt).await {
                Ok(shares) => shares,
                Err(e) => {
                    tracing::warn!("smbclient enumeration failed: {}, trying nmblookup", e);

                    // Fallback to nmblookup
                    Self::enumerate_with_nmblookup(&host).await?
                }
            };

            // Test anonymous access for each share
            let mut enriched_shares = Vec::new();

            for share in shares {
                if let Some(share_name) = share["name"].as_str() {
                    let anonymous_access = Self::test_anonymous_access(&host, share_name).await;

                    let mut enriched = share.clone();
                    if let Some(obj) = enriched.as_object_mut() {
                        obj.insert("anonymous_access".to_string(), json!(anonymous_access));
                    }

                    enriched_shares.push(enriched);

                    // Small delay
                    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                }
            }

            Ok(json!({
                "host": host,
                "shares": enriched_shares,
                "count": enriched_shares.len(),
            }))
        })
        .await
    }
}
