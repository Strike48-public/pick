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

/// Build the embedded Dockerfile for the current host arch. On x86_64 this is
/// byte-for-byte the original (vanilla Arch + strap.sh); on aarch64 it uses an
/// ArchLinuxARM base image (the official `archlinux` image has no arm64
/// manifest), ALARM mirrors + keyring, and appends the BlackArch aarch64 repo
/// directly (strap.sh assumes an x86_64 bootstrap).
fn dockerfile_contents() -> String {
    dockerfile_contents_for(super::arch::is_aarch64())
}

fn dockerfile_contents_for(aarch64: bool) -> String {
    let from = format!(
        "FROM --platform={} {}",
        super::arch::docker_platform_for(aarch64),
        super::arch::docker_base_image_for(aarch64),
    );
    let mirror_block = if aarch64 {
        "RUN echo 'Server = http://mirror.archlinuxarm.org/$arch/$repo' > /etc/pacman.d/mirrorlist"
            .to_string()
    } else {
        "RUN echo 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch' > /etc/pacman.d/mirrorlist && \\\n    echo 'Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch' >> /etc/pacman.d/mirrorlist".to_string()
    };
    let keyring = super::arch::keyring_for(aarch64);
    let blackarch_block = if aarch64 {
        "RUN printf '\\n[blackarch]\\nServer = https://blackarch.org/blackarch/$repo/os/$arch\\nSigLevel = Never\\n' >> /etc/pacman.conf".to_string()
    } else {
        "RUN curl -sL https://blackarch.org/strap.sh -o /tmp/strap.sh && \\\n    chmod +x /tmp/strap.sh && \\\n    /tmp/strap.sh && \\\n    rm /tmp/strap.sh".to_string()
    };
    format!(
        r#"{from}

# Configure mirrors
{mirror_block}

# Fix pacman.conf for container usage
RUN sed -i 's/^CheckSpace/#CheckSpace/' /etc/pacman.conf 2>/dev/null || true && \
    sed -i 's/^DownloadUser/#DownloadUser/' /etc/pacman.conf 2>/dev/null || true

# Initialize pacman keyring and system update
RUN pacman-key --init && \
    pacman-key --populate {keyring} && \
    pacman -Syu --noconfirm --overwrite '*'

# Add BlackArch repository and import its key
{blackarch_block}

# Sync package databases
RUN pacman -Sy --noconfirm

WORKDIR /root
"#
    )
}

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
        tokio::fs::write(&dockerfile_path, dockerfile_contents()).await?;

        // Select platform for the host arch (arm64 native on Apple Silicon, amd64 on Intel)
        let output = Command::new("docker")
            .args([
                "build",
                "--platform",
                super::arch::docker_platform(),
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
            // Select platform for the host arch (arm64 native on Apple Silicon, amd64 on Intel)
            "--platform".to_string(),
            super::arch::docker_platform().to_string(),
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

    // Today's x86_64 Dockerfile, verbatim — regression guard so the arch-aware
    // builder produces byte-for-byte-identical output on x86_64.
    const DOCKERFILE_X86_64_GOLDEN: &str = r#"FROM --platform=linux/amd64 archlinux:latest

# Configure mirrors
RUN echo 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch' > /etc/pacman.d/mirrorlist && \
    echo 'Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch' >> /etc/pacman.d/mirrorlist

# Fix pacman.conf for container usage
RUN sed -i 's/^CheckSpace/#CheckSpace/' /etc/pacman.conf 2>/dev/null || true && \
    sed -i 's/^DownloadUser/#DownloadUser/' /etc/pacman.conf 2>/dev/null || true

# Initialize pacman keyring and system update
RUN pacman-key --init && \
    pacman-key --populate archlinux && \
    pacman -Syu --noconfirm --overwrite '*'

# Add BlackArch repository and import its key
RUN curl -sL https://blackarch.org/strap.sh -o /tmp/strap.sh && \
    chmod +x /tmp/strap.sh && \
    /tmp/strap.sh && \
    rm /tmp/strap.sh

# Sync package databases
RUN pacman -Sy --noconfirm

WORKDIR /root
"#;

    #[test]
    fn x86_64_dockerfile_is_byte_for_byte_unchanged() {
        assert_eq!(dockerfile_contents_for(false), DOCKERFILE_X86_64_GOLDEN);
    }

    #[test]
    fn aarch64_dockerfile_uses_alarm_base_mirrors_and_keyring() {
        let d = dockerfile_contents_for(true);
        assert!(d.contains("FROM --platform=linux/arm64 menci/archlinuxarm:latest"));
        assert!(d.contains("mirror.archlinuxarm.org/$arch/$repo"));
        assert!(d.contains("pacman-key --populate archlinuxarm"));
        // ALARM: append the BlackArch repo directly rather than strap.sh (which
        // assumes an x86_64 bootstrap). $arch resolves to aarch64 in-container.
        assert!(d.contains("[blackarch]"));
        assert!(d.contains("https://blackarch.org/blackarch/$repo/os/$arch"));
        assert!(!d.contains("strap.sh"));
        assert!(!d.contains("archlinux:latest"));
        assert!(!d.contains("pkgbuild.com"));
    }

    #[test]
    fn docker_mirror_matches_shared_arch_helper() {
        // Docker inlines its mirror Server lines rather than reusing
        // arch::mirrorlist_for (it needs a `RUN echo` shape, not the newline-
        // joined mirrorlist). Guard against silent drift: the mirror host in the
        // Dockerfile must match the shared helper for each arch.
        use super::super::arch;
        // x86_64: pkgbuild mirror.
        assert!(arch::mirrorlist_for(false).contains("geo.mirror.pkgbuild.com"));
        assert!(dockerfile_contents_for(false).contains("geo.mirror.pkgbuild.com"));
        // aarch64: ALARM mirror.
        assert!(arch::mirrorlist_for(true).contains("mirror.archlinuxarm.org"));
        assert!(dockerfile_contents_for(true).contains("mirror.archlinuxarm.org"));
    }
}
