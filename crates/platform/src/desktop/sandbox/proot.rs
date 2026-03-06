//! Proot sandbox executor
//!
//! Universal fallback using ptrace-based filesystem remapping.
//! Works on any POSIX system without special privileges.

use super::config::{SandboxConfig, SandboxError, SandboxResult};
use crate::traits::CommandResult;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;

/// URLs for downloading static proot binaries (Linux only)
#[cfg(target_os = "linux")]
const PROOT_DOWNLOAD_URLS: &[(&str, &str)] = &[
    (
        "x86_64",
        "https://github.com/proot-me/proot/releases/download/v5.4.0/proot-v5.4.0-x86_64-static",
    ),
    (
        "aarch64",
        "https://github.com/proot-me/proot/releases/download/v5.4.0/proot-v5.4.0-aarch64-static",
    ),
];

/// Proot executor for universal sandbox support
pub struct ProotExecutor {
    config: SandboxConfig,
    proot_binary: PathBuf,
}

impl ProotExecutor {
    /// Create a new proot executor with the given config
    pub fn new(config: SandboxConfig, proot_binary: PathBuf) -> Self {
        Self {
            config,
            proot_binary,
        }
    }

    /// Check if proot is available (system or downloaded)
    pub async fn is_available(config: &SandboxConfig) -> bool {
        // Check system proot first
        if Self::system_proot_exists().await {
            return true;
        }

        // Check for downloaded proot
        config.proot_binary_path().exists()
    }

    /// Check if system proot exists
    async fn system_proot_exists() -> bool {
        Command::new("which")
            .arg("proot")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Get the proot binary path (system or downloaded)
    pub async fn get_proot_path(config: &SandboxConfig) -> SandboxResult<PathBuf> {
        // Try system proot first
        if Self::system_proot_exists().await {
            return Ok(PathBuf::from("proot"));
        }

        // Check for downloaded proot
        let downloaded = config.proot_binary_path();
        if downloaded.exists() {
            return Ok(downloaded);
        }

        // Need to download
        Err(SandboxError::NoBackendAvailable)
    }

    /// Download a static proot binary for the current architecture.
    /// Only works on Linux — proot binaries are Linux ELF executables.
    pub async fn download_proot(config: &SandboxConfig) -> SandboxResult<PathBuf> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = config;
            return Err(SandboxError::Download(
                "proot download is only supported on Linux".to_string(),
            ));
        }

        #[cfg(target_os = "linux")]
        {
            let arch = std::env::consts::ARCH;
            let url = PROOT_DOWNLOAD_URLS
                .iter()
                .find(|(a, _)| *a == arch)
                .map(|(_, url)| *url)
                .ok_or_else(|| {
                    SandboxError::Download(format!("No proot binary available for arch: {}", arch))
                })?;

            let dest = config.proot_binary_path();

            // Create parent directory
            if let Some(parent) = dest.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }

            tracing::info!("Downloading proot from {}", url);

            // Download using reqwest
            let response = reqwest::get(url)
                .await
                .map_err(|e| SandboxError::Download(e.to_string()))?;

            if !response.status().is_success() {
                return Err(SandboxError::Download(format!(
                    "HTTP error: {}",
                    response.status()
                )));
            }

            let bytes = response
                .bytes()
                .await
                .map_err(|e| SandboxError::Download(e.to_string()))?;

            // Write to file
            tokio::fs::write(&dest, &bytes).await?;

            // Make executable
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = tokio::fs::metadata(&dest).await?.permissions();
                perms.set_mode(0o755);
                tokio::fs::set_permissions(&dest, perms).await?;
            }

            tracing::info!("Downloaded proot to {}", dest.display());

            Ok(dest)
        }
    }

    /// Ensure proot is available, downloading if necessary
    pub async fn ensure_proot(config: &SandboxConfig) -> SandboxResult<PathBuf> {
        match Self::get_proot_path(config).await {
            Ok(path) => Ok(path),
            Err(_) => Self::download_proot(config).await,
        }
    }

    /// Execute a command inside the proot sandbox
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

        // Build proot arguments
        let mut args = vec![
            // Fake root (uid/gid 0)
            "-0".to_string(),
            // Set rootfs
            "-r".to_string(),
            rootfs.to_string_lossy().to_string(),
            // Bind necessary directories
            "-b".to_string(),
            "/dev".to_string(),
            "-b".to_string(),
            "/proc".to_string(),
            "-b".to_string(),
            "/sys".to_string(),
            // DNS resolution
            "-b".to_string(),
            "/etc/resolv.conf".to_string(),
        ];

        // Mount workspace if specified
        let workspace_mount = working_dir.or(self.config.workspace_dir.as_deref());
        if let Some(workspace) = workspace_mount {
            if workspace.exists() {
                args.push("-b".to_string());
                args.push(format!("{}:/workspace", workspace.to_string_lossy()));
            }
        }

        // Set working directory
        args.push("-w".to_string());
        if workspace_mount.is_some() {
            args.push("/workspace".to_string());
        } else {
            args.push("/root".to_string());
        }

        // Execute with bash
        args.push("/bin/bash".to_string());
        args.push("-c".to_string());
        args.push(cmd.to_string());

        // Spawn the process
        let mut command = Command::new(&self.proot_binary);
        command
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Set environment variables
        for (key, value) in &self.config.env_vars {
            command.env(key, value);
        }

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
            Err(_) => Ok(CommandResult::timeout(
                String::new(),
                "Command timed out".to_string(),
                start.elapsed().as_millis() as u64,
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_proot_availability_check() {
        let config = SandboxConfig::default();
        let available = ProotExecutor::is_available(&config).await;
        println!("proot available: {}", available);
    }
}
