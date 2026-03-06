//! Bubblewrap (bwrap) sandbox executor
//!
//! Uses Linux namespaces for lightweight containerization.
//! Requires bwrap binary and user namespace support.

use super::config::{SandboxConfig, SandboxError, SandboxResult};
use crate::traits::CommandResult;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;

/// Subordinate UID/GID range for multi-uid mapping
#[derive(Debug, Clone, Copy)]
struct SubIdRange {
    start: u32,
    count: u32,
}

/// Bubblewrap executor for Linux namespace-based sandboxing
pub struct BwrapExecutor {
    config: SandboxConfig,
}

/// Get subordinate UID range from /etc/subuid for current user
async fn get_subuid_range() -> Option<SubIdRange> {
    let username = std::env::var("USER").ok()?;
    let content = tokio::fs::read_to_string("/etc/subuid").await.ok()?;

    for line in content.lines() {
        if let Some(range) = line.strip_prefix(&format!("{}:", username)) {
            let parts: Vec<&str> = range.split(':').collect();
            if parts.len() == 2 {
                let start = parts[0].parse::<u32>().ok()?;
                let count = parts[1].parse::<u32>().ok()?;
                return Some(SubIdRange { start, count });
            }
        }
    }
    None
}

/// Get subordinate GID range from /etc/subgid for current user
async fn get_subgid_range() -> Option<SubIdRange> {
    let username = std::env::var("USER").ok()?;
    let content = tokio::fs::read_to_string("/etc/subgid").await.ok()?;

    for line in content.lines() {
        if let Some(range) = line.strip_prefix(&format!("{}:", username)) {
            let parts: Vec<&str> = range.split(':').collect();
            if parts.len() == 2 {
                let start = parts[0].parse::<u32>().ok()?;
                let count = parts[1].parse::<u32>().ok()?;
                return Some(SubIdRange { start, count });
            }
        }
    }
    None
}

impl BwrapExecutor {
    /// Create a new bwrap executor
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }

    /// Check if bwrap is available and usable
    pub async fn is_available() -> bool {
        // Check for bwrap binary
        if !Self::bwrap_exists().await {
            tracing::debug!("bwrap binary not found");
            return false;
        }

        // Check for user namespace support
        if !Self::user_namespaces_enabled().await {
            tracing::debug!("User namespaces not enabled");
            return false;
        }

        true
    }

    /// Check if bwrap binary exists
    async fn bwrap_exists() -> bool {
        Command::new("which")
            .arg("bwrap")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Check if unprivileged user namespaces are enabled
    async fn user_namespaces_enabled() -> bool {
        // Check /proc/sys/kernel/unprivileged_userns_clone
        match tokio::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone").await {
            Ok(content) => content.trim() == "1",
            Err(_) => {
                // File might not exist on all systems; try a test invocation
                Self::test_bwrap().await
            }
        }
    }

    /// Test if bwrap can actually run
    async fn test_bwrap() -> bool {
        Command::new("bwrap")
            .args(["--ro-bind", "/", "/", "true"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Execute a command inside the bwrap sandbox
    pub async fn execute(
        &self,
        cmd: &str,
        timeout: Duration,
        working_dir: Option<&Path>,
    ) -> SandboxResult<CommandResult> {
        let rootfs = self.config.rootfs_dir();
        if !rootfs.join("bin").join("sh").exists() {
            return Err(SandboxError::RootfsSetupFailed(
                "Rootfs not initialized".to_string(),
            ));
        }

        let start = Instant::now();

        // Check if we can use multi-uid mapping
        let subuid_range = get_subuid_range().await;
        let subgid_range = get_subgid_range().await;
        let use_multi_mapping = subuid_range.is_some() && subgid_range.is_some();

        if use_multi_mapping {
            tracing::debug!("Using multi-UID mapping with unshare for bwrap sandbox");
        } else {
            tracing::debug!("Using single-UID mapping for bwrap sandbox (no /etc/subuid support)");
        }

        // Get host uid/gid using shell commands
        let host_uid = if let Ok(output) = Command::new("id").arg("-u").output().await {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        } else {
            "1000".to_string() // fallback
        };
        let host_gid = if let Ok(output) = Command::new("id").arg("-g").output().await {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        } else {
            "1000".to_string() // fallback
        };

        // Build bwrap arguments (same for both modes)
        let mut bwrap_args = vec![
            // Mount rootfs writable (we're root inside the sandbox, should be able to write anywhere)
            "--bind".to_string(),
            rootfs.to_string_lossy().to_string(),
            "/".to_string(),
            // Bind necessary system directories
            "--dev".to_string(),
            "/dev".to_string(),
            "--proc".to_string(),
            "/proc".to_string(),
            // DNS resolution
            "--ro-bind".to_string(),
            "/etc/resolv.conf".to_string(),
            "/etc/resolv.conf".to_string(),
        ];

        // User namespace setup (different for single vs multi-uid mapping)
        if use_multi_mapping {
            // For multi-uid: inherit the user namespace created by unshare
            bwrap_args.push("--userns".to_string());
            bwrap_args.push("0".to_string());
        } else {
            // For single-uid: create user namespace with single mapping
            bwrap_args.push("--unshare-user".to_string());
            bwrap_args.push("--uid".to_string());
            bwrap_args.push("0".to_string());
            bwrap_args.push("--gid".to_string());
            bwrap_args.push("0".to_string());
        }

        // Note: We don't use --cap-add here because it doesn't work with user namespaces.
        // Instead, we set file capabilities on tools (cap_net_raw+eip) during rootfs setup.

        // Network access (full host network for pentest tools)
        if self.config.network_access {
            bwrap_args.push("--share-net".to_string());
        } else {
            bwrap_args.push("--unshare-net".to_string());
        }

        // Mount workspace if specified
        let workspace_mount = working_dir.or(self.config.workspace_dir.as_deref());
        if let Some(workspace) = workspace_mount {
            if workspace.exists() {
                bwrap_args.push("--bind".to_string());
                bwrap_args.push(workspace.to_string_lossy().to_string());
                bwrap_args.push("/workspace".to_string());
            }
        }

        // Set working directory
        bwrap_args.push("--chdir".to_string());
        if workspace_mount.is_some() {
            bwrap_args.push("/workspace".to_string());
        } else {
            bwrap_args.push("/root".to_string());
        }

        // Die when parent dies
        bwrap_args.push("--die-with-parent".to_string());

        // Set environment variables
        for (key, value) in &self.config.env_vars {
            bwrap_args.push("--setenv".to_string());
            bwrap_args.push(key.clone());
            bwrap_args.push(value.clone());
        }

        // Execute with bash
        bwrap_args.push("/bin/bash".to_string());
        bwrap_args.push("-c".to_string());
        bwrap_args.push(cmd.to_string());

        // Build final command (either unshare + bwrap or just bwrap)
        let mut command = if use_multi_mapping {
            let subuid = subuid_range.unwrap();
            let subgid = subgid_range.unwrap();

            // Use unshare to create user namespace with multi-uid mapping
            let mut cmd = Command::new("unshare");
            cmd.arg("-U")
                .arg("--keep-caps")
                .arg(format!("--map-users=0:{}:1", &host_uid))
                .arg(format!("--map-users=1:{}:{}", subuid.start, subuid.count))
                .arg(format!("--map-groups=0:{}:1", &host_gid))
                .arg(format!("--map-groups=1:{}:{}", subgid.start, subgid.count))
                .arg("bwrap")
                .args(&bwrap_args);
            cmd
        } else {
            // Just use bwrap directly with single-uid mapping
            let mut cmd = Command::new("bwrap");
            cmd.args(&bwrap_args);
            cmd
        };

        command.stdout(Stdio::piped()).stderr(Stdio::piped());

        let child = command.spawn().map_err(SandboxError::Io)?;

        // Wait with timeout
        match tokio::time::timeout(timeout, crate::desktop::wait_for_child_output(child)).await {
            Ok(result) => {
                let (stdout, stderr, exit_code) = result?;
                Ok(CommandResult::success(
                    stdout,
                    stderr,
                    exit_code,
                    start.elapsed().as_millis() as u64,
                ))
            }
            Err(_) => {
                // Timeout - process will be killed due to die-with-parent
                Ok(CommandResult::timeout(
                    String::new(),
                    "Command timed out".to_string(),
                    start.elapsed().as_millis() as u64,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bwrap_availability_check() {
        // This test just checks the availability function runs
        let available = BwrapExecutor::is_available().await;
        println!("bwrap available: {}", available);
    }
}
