//! Docker sandbox executor
//!
//! Uses Docker containers for sandboxed command execution.
//! Works on any platform with Docker installed (Docker Desktop, colima, OrbStack).
//! Provides real namespace isolation (more secure than proot's ptrace interception).

use super::config::{SandboxConfig, SandboxError, SandboxResult};
use crate::traits::CommandResult;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;

/// Docker image name used for the pentest sandbox
const DOCKER_IMAGE: &str = "pentest-blackarch:latest";

/// Target platform for the Docker image. BlackArch packages and the archlinux
/// base image are x86_64-only, so we pin to linux/amd64. On Apple Silicon Macs
/// this runs under Rosetta / QEMU emulation via Docker Desktop.
const DOCKER_PLATFORM: &str = "linux/amd64";

/// Embedded Dockerfile for building the pentest sandbox image.
/// Mirrors the existing rootfs setup: archlinux base + BlackArch repo + pacman sync.
const DOCKERFILE_CONTENTS: &str = r#"FROM --platform=linux/amd64 archlinux:latest

# Configure mirrors
RUN echo 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch' > /etc/pacman.d/mirrorlist && \
    echo 'Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch' >> /etc/pacman.d/mirrorlist

# Fix pacman.conf for container usage
RUN sed -i 's/^CheckSpace/#CheckSpace/' /etc/pacman.conf 2>/dev/null || true && \
    sed -i 's/^DownloadUser/#DownloadUser/' /etc/pacman.conf 2>/dev/null || true

# System update
RUN pacman -Syu --noconfirm --overwrite '*' 2>&1 || true

# Initialize pacman keyring
RUN pacman-key --init 2>/dev/null || true && \
    pacman-key --populate archlinux 2>/dev/null || true

# Add BlackArch repository
RUN echo '' >> /etc/pacman.conf && \
    echo '[blackarch]' >> /etc/pacman.conf && \
    echo 'Server = https://blackarch.org/blackarch/$repo/os/$arch' >> /etc/pacman.conf && \
    echo 'SigLevel = Optional TrustAll' >> /etc/pacman.conf

# Sync package databases
RUN pacman -Sy --noconfirm 2>&1 || true

WORKDIR /root
"#;

/// Docker executor for container-based sandboxing
pub struct DockerExecutor {
    config: SandboxConfig,
}

impl DockerExecutor {
    /// Create a new Docker executor
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }

    /// Check if Docker is available and the daemon is responsive
    pub async fn is_available() -> bool {
        // Check that the docker CLI exists and can report its version
        let version_ok = Command::new("docker")
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);

        if !version_ok {
            tracing::debug!("docker CLI not found or version check failed");
            return false;
        }

        // Check that the daemon is actually running (docker version succeeds even
        // without a daemon if the CLI is installed, but docker info will fail)
        let info_ok = Command::new("docker")
            .arg("info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);

        if !info_ok {
            tracing::debug!("Docker daemon not responsive (docker info failed)");
            return false;
        }

        true
    }

    /// Check if the pentest Docker image is already built
    pub async fn is_image_built() -> bool {
        Command::new("docker")
            .args(["image", "inspect", DOCKER_IMAGE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Ensure the Docker image exists, building it if necessary
    pub async fn ensure_image(&self) -> SandboxResult<()> {
        if Self::is_image_built().await {
            tracing::debug!("Docker image {} already exists", DOCKER_IMAGE);
            return Ok(());
        }

        tracing::info!("Building Docker image {}...", DOCKER_IMAGE);

        // Write the Dockerfile to data_dir
        let dockerfile_dir = self.config.data_dir.join("docker");
        tokio::fs::create_dir_all(&dockerfile_dir).await?;

        let dockerfile_path = dockerfile_dir.join("Dockerfile");
        tokio::fs::write(&dockerfile_path, DOCKERFILE_CONTENTS).await?;

        // Run docker build (pin platform to linux/amd64 for BlackArch compatibility)
        let output = Command::new("docker")
            .args([
                "build",
                "--platform",
                DOCKER_PLATFORM,
                "-t",
                DOCKER_IMAGE,
                "-f",
                &dockerfile_path.to_string_lossy(),
                &dockerfile_dir.to_string_lossy(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                SandboxError::RootfsSetupFailed(format!("Failed to run docker build: {}", e))
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(SandboxError::RootfsSetupFailed(format!(
                "Docker image build failed: {}",
                stderr.trim()
            )));
        }

        tracing::info!("Docker image {} built successfully", DOCKER_IMAGE);

        // Clean up Dockerfile
        tokio::fs::remove_file(&dockerfile_path).await.ok();

        Ok(())
    }

    /// Execute a command inside a Docker container
    pub async fn execute(
        &self,
        cmd: &str,
        timeout: Duration,
        working_dir: Option<&Path>,
    ) -> SandboxResult<CommandResult> {
        let start = Instant::now();

        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            // Pin platform for Apple Silicon compatibility
            "--platform".to_string(),
            DOCKER_PLATFORM.to_string(),
            // Security: drop all capabilities, only grant what pentest tools need
            "--cap-drop=ALL".to_string(),
            "--cap-add=NET_RAW".to_string(),
            // Prevent privilege escalation
            "--security-opt".to_string(),
            "no-new-privileges".to_string(),
        ];

        // Network access
        if !self.config.network_access {
            args.push("--network=none".to_string());
        }

        // Mount workspace if specified
        let workspace_mount = working_dir.or(self.config.workspace_dir.as_deref());
        if let Some(workspace) = workspace_mount {
            if workspace.exists() {
                args.push("-v".to_string());
                args.push(format!("{}:/workspace", workspace.to_string_lossy()));
                args.push("-w".to_string());
                args.push("/workspace".to_string());
            }
        }

        // Environment variables
        for (key, value) in &self.config.env_vars {
            args.push("-e".to_string());
            args.push(format!("{}={}", key, value));
        }

        // Image and command
        args.push(DOCKER_IMAGE.to_string());
        args.push("/bin/bash".to_string());
        args.push("-c".to_string());
        args.push(cmd.to_string());

        let mut command = Command::new("docker");
        command
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

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
    async fn test_docker_availability_check() {
        let available = DockerExecutor::is_available().await;
        println!("Docker available: {}", available);
    }

    #[tokio::test]
    async fn test_docker_image_check() {
        let built = DockerExecutor::is_image_built().await;
        println!("Docker image built: {}", built);
    }
}
