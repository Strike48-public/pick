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
use tokio::sync::OnceCell;

/// Cached result of the real bwrap usability probe. Computing it spawns a
/// throwaway bwrap process, and `is_available()` is called frequently (per tool
/// install, per shell spawn, during backend detection), so we probe once per
/// process. Availability does not change over a run.
static BWRAP_USABLE: OnceCell<bool> = OnceCell::const_new();

/// Bubblewrap executor for Linux namespace-based sandboxing
pub struct BwrapExecutor {
    config: SandboxConfig,
}

impl BwrapExecutor {
    /// Create a new bwrap executor
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }

    /// Check if bwrap is available and *actually usable*.
    ///
    /// This is authoritative: it always confirms with a real `bwrap` spawn
    /// rather than trusting `unprivileged_userns_clone` alone. On Ubuntu 24.04+
    /// that sysctl reads `1` while `kernel.apparmor_restrict_unprivileged_userns`
    /// separately denies the uid-map setup, so a sysctl-only check reports bwrap
    /// as available when every real invocation fails with "setting up uid map:
    /// Permission denied" (see #238). Getting this right lets `detect_backend`
    /// pick proot for *all* execution paths (shell and tool installs), instead of
    /// each path having to recover from a bwrap that never worked.
    pub async fn is_available() -> bool {
        *BWRAP_USABLE
            .get_or_init(|| async {
                // Cheap pre-filter: no binary => definitely unavailable.
                if !Self::bwrap_exists().await {
                    tracing::debug!("bwrap binary not found");
                    return false;
                }
                // Authoritative: attempt a real (unprivileged, uid-mapping) spawn.
                // This is the exact operation that AppArmor blocks, so it is the
                // only reliable signal.
                let usable = Self::test_bwrap().await;
                if !usable {
                    tracing::info!(
                        "bwrap present but not usable (user-namespace/uid-map setup denied); \
                         treating as unavailable so proot is used instead"
                    );
                }
                usable
            })
            .await
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

    /// Test if bwrap can actually run an unprivileged user namespace.
    ///
    /// Uses `--unshare-user --uid 0 --gid 0` so the probe exercises the exact
    /// uid-map setup that real sandbox commands need — a plain `--ro-bind`
    /// invocation would succeed even where uid mapping is denied, giving a false
    /// positive on AppArmor-restricted hosts (#238).
    async fn test_bwrap() -> bool {
        Command::new("bwrap")
            .args([
                "--unshare-user",
                "--uid",
                "0",
                "--gid",
                "0",
                "--ro-bind",
                "/",
                "/",
                "true",
            ])
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

        // Check if we're running as real root (sudo) — skip user namespace, add
        // capabilities. Use geteuid(2) via the shared helper rather than shelling
        // out to `id -u`: this gate unlocks `--cap-add ALL`, so it must not be
        // spoofable by a planted `id` on PATH (see #238 review).
        let is_root = super::is_effective_root();

        let mut bwrap_args = vec![
            "--bind".to_string(),
            rootfs.to_string_lossy().to_string(),
            "/".to_string(),
            "--dev".to_string(),
            "/dev".to_string(),
            "--proc".to_string(),
            "/proc".to_string(),
            "--ro-bind".to_string(),
            "/etc/resolv.conf".to_string(),
            "/etc/resolv.conf".to_string(),
        ];

        if is_root {
            // Real root: grant all capabilities for raw sockets etc.
            bwrap_args.push("--cap-add".to_string());
            bwrap_args.push("ALL".to_string());
            tracing::info!("[bwrap::execute] Running as root with --cap-add ALL");
        } else {
            // Unprivileged: use user namespace to fake root
            bwrap_args.push("--unshare-user".to_string());
            bwrap_args.push("--uid".to_string());
            bwrap_args.push("0".to_string());
            bwrap_args.push("--gid".to_string());
            bwrap_args.push("0".to_string());
        }

        // Network access
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

        tracing::info!(
            "[bwrap::execute] inner cmd passed to /bin/bash -c: {:?}",
            cmd
        );

        let mut command = Command::new("bwrap");
        command.args(&bwrap_args);

        command.stdout(Stdio::piped()).stderr(Stdio::piped());

        let child = command.spawn().map_err(SandboxError::Io)?;

        // Wait with timeout
        match tokio::time::timeout(timeout, crate::desktop::wait_for_child_output(child)).await {
            Ok(result) => {
                let (stdout, stderr, exit_code) = result?;
                tracing::info!(
                    "[bwrap::execute] exit_code={} stdout_len={} stderr_len={} stdout={:?} stderr={:?}",
                    exit_code,
                    stdout.len(),
                    stderr.len(),
                    &stdout[..stdout.len().min(500)],
                    &stderr[..stderr.len().min(500)],
                );
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
