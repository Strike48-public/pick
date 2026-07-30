//! Sandbox execution environment for desktop platforms
//!
//! Provides a sandboxed BlackArch Linux environment for executing
//! penetration testing commands. Uses bubblewrap (Linux namespaces)
//! as the primary backend, with proot as a universal fallback.

mod arch;
pub mod bwrap;
pub mod config;
pub mod docker;
pub mod probe;
pub mod proot;
pub mod rootfs;
pub mod wsl;
pub mod wsl_install;

use crate::traits::CommandResult;
use config::{SandboxBackend, SandboxConfig, SandboxError, SandboxResult};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;

/// Global sandbox manager instance
static SANDBOX_MANAGER: OnceCell<Arc<SandboxManager>> = OnceCell::const_new();

/// Return true if the current process is running as (effective) root.
///
/// Uses `geteuid(2)` directly rather than shelling out to `id -u`. The syscall
/// cannot be spoofed via `PATH` (an attacker-planted `id` on `PATH` printing
/// `0` previously could have flipped this to "root" and unlocked the
/// bwrap `--cap-add ALL` path), it never forks, and it can't fail. On non-Unix
/// desktops there is no uid concept, so we report non-root.
///
/// Shared with [`bwrap::BwrapExecutor::execute`], which uses the same check to
/// gate the `--cap-add ALL` capability grant — that gate is the one that most
/// needs a non-spoofable root check.
pub(crate) fn is_effective_root() -> bool {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` is always safe to call — it takes no arguments,
        // reads no memory, and cannot fail (POSIX guarantees success).
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

/// Decide the preferred sandbox backend based on privilege level.
///
/// - **root** -> force bwrap. Only root can grant real capabilities
///   (raw sockets via `--cap-add ALL`), and bwrap is the desktop backend
///   that carries them. Gated to Linux: bwrap is Linux-only, so on other
///   platforms we leave the preference unset and let `detect_backend` pick
///   the right backend (WSL, Docker, ...) instead of pinning an unavailable
///   one and logging a spurious "preferred backend not available" warning.
/// - **non-root** -> `None` (no forced preference). `detect_backend` then
///   auto-detects, and it prefers bwrap (fast native namespaces, works with
///   portable-pty) and uses proot only as a fallback when bwrap is
///   unavailable. This is the correct behavior even when the user selected
///   the "Proot" shell mode: that toggle means "run sandboxed" (vs "run on
///   the host"), not "use the proot binary specifically" — the UI never
///   exposes a bwrap-vs-proot choice. Pinning proot here is what broke the
///   interactive PTY shell with EACCES on non-root Linux desktops (see #238).
///
/// The residual risk of preferring bwrap — a host where bwrap passes
/// `is_available()` but fails to spawn at runtime — is covered by the
/// interactive shell's symmetric spawn fallback (bwrap <-> proot on EACCES),
/// so neither backend hard-fails when the other is usable.
fn preferred_backend_for(is_root: bool) -> Option<SandboxBackend> {
    if is_root {
        #[cfg(target_os = "linux")]
        {
            return Some(SandboxBackend::Bwrap);
        }
        #[cfg(not(target_os = "linux"))]
        {
            return None;
        }
    }
    None
}

/// Get or initialize the global sandbox manager
pub async fn get_sandbox_manager() -> SandboxResult<Arc<SandboxManager>> {
    tracing::debug!("[get_sandbox_manager] Attempting to get or initialize sandbox manager");
    let result = SANDBOX_MANAGER
        .get_or_try_init(|| async {
            tracing::info!("[get_sandbox_manager] Initializing new sandbox manager...");
            let mut config = SandboxConfig::default();

            // Choose the preferred backend from privilege level (see
            // `preferred_backend_for`). As real root we force bwrap for real
            // capabilities (raw sockets via --cap-add ALL). As non-root we leave
            // the preference unset so detect_backend auto-detects, preferring
            // bwrap and using proot only as a fallback. The interactive PTY
            // shell's symmetric EACCES fallback (see #238) rescues the rare case
            // where the selected backend can't actually spawn.
            let is_root = is_effective_root();
            config.preferred_backend = preferred_backend_for(is_root);
            tracing::info!(
                "[get_sandbox_manager] is_root={is_root} -> preferred_backend={:?}",
                config.preferred_backend
            );
            tracing::debug!(
                "[get_sandbox_manager] Config: data_dir={:?}, preferred_backend={:?}",
                config.data_dir,
                config.preferred_backend
            );
            let manager = SandboxManager::new(config).await?;
            tracing::info!("[get_sandbox_manager] Sandbox manager initialized successfully");
            Ok(Arc::new(manager))
        })
        .await
        .cloned();

    match &result {
        Ok(mgr) => tracing::debug!(
            "[get_sandbox_manager] Returning sandbox manager (backend={:?})",
            mgr.backend()
        ),
        Err(e) => tracing::error!("[get_sandbox_manager] Failed to initialize: {}", e),
    }
    result
}

/// Sandbox manager that orchestrates sandbox backend and rootfs
pub struct SandboxManager {
    config: SandboxConfig,
    backend: SandboxBackend,
    rootfs_manager: rootfs::RootfsManager,
    bwrap_executor: Option<bwrap::BwrapExecutor>,
    proot_executor: Option<proot::ProotExecutor>,
    wsl_executor: Option<wsl::WslExecutor>,
    docker_executor: Option<docker::DockerExecutor>,
}

impl SandboxManager {
    /// Create a new sandbox manager with auto-detected backend
    pub async fn new(config: SandboxConfig) -> SandboxResult<Self> {
        let backend = Self::detect_backend(&config).await?;

        tracing::info!("Using sandbox backend: {}", backend);

        let rootfs_manager = rootfs::RootfsManager::new(config.clone());

        let bwrap_executor = if backend == SandboxBackend::Bwrap {
            Some(bwrap::BwrapExecutor::new(config.clone()))
        } else {
            None
        };

        let proot_executor = if backend == SandboxBackend::Proot {
            let proot_path = proot::ProotExecutor::ensure_proot(&config).await?;
            Some(proot::ProotExecutor::new(config.clone(), proot_path))
        } else {
            None
        };

        let wsl_executor = if backend == SandboxBackend::Wsl {
            Some(wsl::WslExecutor::new(config.clone()))
        } else {
            None
        };

        let docker_executor = if backend == SandboxBackend::Docker {
            Some(docker::DockerExecutor::new(config.clone()))
        } else {
            None
        };

        Ok(Self {
            config,
            backend,
            rootfs_manager,
            bwrap_executor,
            proot_executor,
            wsl_executor,
            docker_executor,
        })
    }

    /// Detect the best available sandbox backend
    ///
    /// Prefers bwrap on desktop for performance (native namespaces vs ptrace).
    /// Note: Raw sockets (CAP_NET_RAW) don't work in unprivileged sandboxes with either
    /// bwrap or proot. Tools like nmap -sS require actual root or setuid binaries.
    async fn detect_backend(config: &SandboxConfig) -> SandboxResult<SandboxBackend> {
        tracing::debug!(
            "[detect_backend] Starting backend detection, preferred={:?}",
            config.preferred_backend
        );

        if let Some(preferred) = config.preferred_backend {
            tracing::debug!("[detect_backend] Checking preferred backend: {}", preferred);
            match preferred {
                SandboxBackend::Bwrap if bwrap::BwrapExecutor::is_available().await => {
                    tracing::info!("[detect_backend] Using preferred backend: bwrap");
                    return Ok(SandboxBackend::Bwrap);
                }
                SandboxBackend::Proot if proot::ProotExecutor::is_available(config).await => {
                    tracing::info!("[detect_backend] Using preferred backend: proot");
                    return Ok(SandboxBackend::Proot);
                }
                SandboxBackend::Wsl if wsl::WslExecutor::is_available().await => {
                    tracing::info!("[detect_backend] Using preferred backend: wsl");
                    return Ok(SandboxBackend::Wsl);
                }
                SandboxBackend::Docker if docker::DockerExecutor::is_available().await => {
                    tracing::info!("[detect_backend] Using preferred backend: docker");
                    return Ok(SandboxBackend::Docker);
                }
                _ => {
                    tracing::warn!(
                        "[detect_backend] Preferred backend {} not available, auto-detecting",
                        preferred
                    );
                }
            }
        }

        // On Windows, prefer WSL2
        #[cfg(target_os = "windows")]
        {
            tracing::debug!("[detect_backend] Checking if WSL2 is available...");
            if wsl::WslExecutor::is_available().await {
                tracing::info!("[detect_backend] Detected WSL2, using it as backend");
                return Ok(SandboxBackend::Wsl);
            }
            tracing::debug!("[detect_backend] WSL2 not available");
        }

        // Prefer bwrap on desktop - it works with portable-pty and pacman
        tracing::debug!("[detect_backend] Checking if bwrap is available...");
        if bwrap::BwrapExecutor::is_available().await {
            tracing::info!("[detect_backend] Detected bwrap, using it as backend");
            return Ok(SandboxBackend::Bwrap);
        }
        tracing::debug!("[detect_backend] bwrap not available");

        // On Linux, prefer proot over Docker. proot uses ptrace (no per-command
        // container spin-up), works on normal desktops that lack Docker, and fits
        // the connector's many-small-commands pattern; selecting Docker here means
        // a `docker run` per `which`/tool probe. Docker stays as the last-resort
        // Linux fallback below. This block is Linux-only because proot is a Linux
        // ELF binary — other platforms (macOS) fall through to Docker.
        #[cfg(target_os = "linux")]
        {
            tracing::debug!("[detect_backend] Checking if proot is available...");
            if proot::ProotExecutor::is_available(config).await {
                tracing::info!("[detect_backend] Detected proot, using it as backend");
                return Ok(SandboxBackend::Proot);
            }
            tracing::debug!("[detect_backend] proot not available locally");

            // Download proot as the final local option before falling to Docker.
            tracing::info!("[detect_backend] proot not local, attempting to download proot...");
            if proot::ProotExecutor::download_proot(config).await.is_ok() {
                tracing::info!("[detect_backend] proot downloaded successfully");
                return Ok(SandboxBackend::Proot);
            }
            tracing::error!("[detect_backend] Failed to download proot");
        }

        // Docker: last-resort backend on Linux, and the primary sandbox on macOS
        // (where proot, a Linux ELF, cannot run). Works on any platform with a
        // running Docker daemon.
        tracing::debug!("[detect_backend] Checking if Docker is available...");
        if docker::DockerExecutor::is_available().await {
            tracing::info!("[detect_backend] Detected Docker, using it as backend");
            return Ok(SandboxBackend::Docker);
        }
        tracing::debug!("[detect_backend] Docker not available");

        #[cfg(target_os = "macos")]
        tracing::error!(
            "[detect_backend] No sandbox backend available on macOS. Docker is required — install Docker Desktop, OrbStack, or colima and ensure the daemon is running."
        );
        #[cfg(not(target_os = "macos"))]
        tracing::error!(
            "[detect_backend] No sandbox backend available (tried bwrap, docker, proot, wsl)"
        );
        Err(SandboxError::NoBackendAvailable)
    }

    /// Check if the sandbox is ready (rootfs initialized)
    pub fn is_ready(&self) -> bool {
        self.rootfs_manager.is_ready()
    }

    /// Get the current backend type
    pub fn backend(&self) -> SandboxBackend {
        self.backend
    }

    /// Ensure the sandbox environment is fully set up
    pub async fn ensure_ready(&self) -> SandboxResult<()> {
        // Docker manages its own image lifecycle — skip rootfs checks
        if self.backend == SandboxBackend::Docker {
            if let Some(docker) = &self.docker_executor {
                tracing::info!("[SandboxManager::ensure_ready] Calling docker.ensure_image()...");
                match docker.ensure_image().await {
                    Ok(()) => {
                        tracing::info!("[SandboxManager::ensure_ready] ensure_image() succeeded")
                    }
                    Err(e) => {
                        tracing::error!(
                            "[SandboxManager::ensure_ready] ensure_image() FAILED: {}",
                            e
                        );
                        return Err(e);
                    }
                }
                tracing::info!("[SandboxManager::ensure_ready] Docker image ready");
            }
            return Ok(());
        }

        // WSL manages its own distro lifecycle — skip rootfs checks
        if self.backend == SandboxBackend::Wsl {
            if let Some(wsl) = &self.wsl_executor {
                tracing::info!("[SandboxManager::ensure_ready] Calling wsl.ensure_distro()...");
                match wsl.ensure_distro().await {
                    Ok(()) => {
                        tracing::info!("[SandboxManager::ensure_ready] ensure_distro() succeeded")
                    }
                    Err(e) => {
                        tracing::error!(
                            "[SandboxManager::ensure_ready] ensure_distro() FAILED: {}",
                            e
                        );
                        return Err(e);
                    }
                }
                // Safety net: ensure the host-side marker exists even if ensure_distro()
                // is modified later and forgets to write it.
                let marker_path = self.config.data_dir.join(".wsl-ready");
                if !marker_path.exists() {
                    let distro_name = self.config.wsl_distro_name();
                    match std::fs::write(&marker_path, distro_name) {
                        Ok(()) => tracing::info!(
                            "[SandboxManager::ensure_ready] Wrote WSL ready marker at {}",
                            marker_path.display()
                        ),
                        Err(e) => tracing::warn!(
                            "[SandboxManager::ensure_ready] Failed to write WSL ready marker: {}",
                            e
                        ),
                    }
                }
                tracing::info!("[SandboxManager::ensure_ready] WSL distro ready");
            }
            return Ok(());
        }

        if !self.is_ready() {
            tracing::warn!("[SandboxManager::ensure_ready] Rootfs not ready, downloading now...");
            self.rootfs_manager.ensure_rootfs().await?;
            tracing::info!("[SandboxManager::ensure_ready] Rootfs setup complete");
        } else {
            tracing::debug!("[SandboxManager::ensure_ready] Rootfs already ready");
        }
        Ok(())
    }

    /// Execute a command in the sandbox
    pub async fn execute(
        &self,
        cmd: &str,
        timeout: Duration,
        working_dir: Option<&Path>,
    ) -> SandboxResult<CommandResult> {
        tracing::debug!(
            "[SandboxManager::execute] Ensuring rootfs is ready for command: {}",
            cmd
        );
        self.ensure_ready().await?;
        tracing::debug!(
            "[SandboxManager::execute] Rootfs ready, executing command with backend: {}",
            self.backend
        );

        match self.backend {
            SandboxBackend::Bwrap => {
                self.bwrap_executor
                    .as_ref()
                    .expect("bwrap executor not initialized")
                    .execute(cmd, timeout, working_dir)
                    .await
            }
            SandboxBackend::Proot => {
                self.proot_executor
                    .as_ref()
                    .expect("proot executor not initialized")
                    .execute(cmd, timeout, working_dir)
                    .await
            }
            SandboxBackend::Wsl => {
                self.wsl_executor
                    .as_ref()
                    .expect("wsl executor not initialized")
                    .execute(cmd, timeout, working_dir)
                    .await
            }
            SandboxBackend::Docker => {
                self.docker_executor
                    .as_ref()
                    .expect("docker executor not initialized")
                    .execute(cmd, timeout, working_dir)
                    .await
            }
        }
    }

    /// Get the sandbox configuration
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ignored: this touches the network. On a host without bwrap/proot (e.g. a
    // CI runner), `detect_backend` falls through to `download_proot`, which now
    // that the SHA pins are populated actually fetches the binary over HTTP.
    // The test has no assertions (it only prints the detected backend), so it
    // provides no regression value in CI while risking a slow/stalled download.
    // Run explicitly (`--ignored`) on a machine where a real backend probe is
    // wanted. The timeout added to `download_proot` bounds the stall regardless.
    #[tokio::test]
    #[ignore = "hits the network via download_proot; no assertions — run with --ignored"]
    async fn test_sandbox_backend_detection() {
        let config = SandboxConfig::default();
        let result = SandboxManager::detect_backend(&config).await;
        match result {
            Ok(backend) => println!("Detected backend: {}", backend),
            Err(e) => println!("No backend available: {}", e),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn root_prefers_bwrap_for_real_capabilities() {
        // Real root on Linux should force bwrap so tools get raw-socket
        // capabilities via --cap-add ALL.
        assert_eq!(preferred_backend_for(true), Some(SandboxBackend::Bwrap));
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn root_does_not_pin_unavailable_bwrap_off_linux() {
        // bwrap is Linux-only; pinning it elsewhere would only produce a
        // spurious "preferred backend not available" warning. Leave it unset
        // so detect_backend can choose WSL/Docker/etc.
        assert_eq!(preferred_backend_for(true), None);
    }

    #[test]
    fn non_root_leaves_backend_unset_for_auto_detect() {
        // Non-root must NOT pin proot (regression guard for #238): returning
        // None lets detect_backend prefer bwrap (fast, works with portable-pty)
        // and fall back to proot only if bwrap is unavailable. Selecting the
        // "Proot" shell mode does not change this — the shell's symmetric EACCES
        // fallback covers a backend that is chosen but can't spawn.
        assert_eq!(preferred_backend_for(false), None);
    }
}
