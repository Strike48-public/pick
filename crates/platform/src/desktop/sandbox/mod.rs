//! Sandbox execution environment for desktop platforms
//!
//! Provides a sandboxed BlackArch Linux environment for executing
//! penetration testing commands. Uses bubblewrap (Linux namespaces)
//! as the primary backend, with proot as a universal fallback.

pub mod bwrap;
pub mod config;
pub mod docker;
pub mod proot;
pub mod rootfs;
pub mod wsl;

use crate::traits::CommandResult;
use config::{SandboxBackend, SandboxConfig, SandboxError, SandboxResult};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::OnceCell;

/// Global sandbox manager instance
static SANDBOX_MANAGER: OnceCell<Arc<SandboxManager>> = OnceCell::const_new();

/// Get or initialize the global sandbox manager
pub async fn get_sandbox_manager() -> SandboxResult<Arc<SandboxManager>> {
    tracing::debug!("[get_sandbox_manager] Attempting to get or initialize sandbox manager");
    let result = SANDBOX_MANAGER
        .get_or_try_init(|| async {
            tracing::info!("[get_sandbox_manager] Initializing new sandbox manager...");
            let config = SandboxConfig::default();
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

        // Try Docker (works on any platform with Docker installed)
        tracing::debug!("[detect_backend] Checking if Docker is available...");
        if docker::DockerExecutor::is_available().await {
            tracing::info!("[detect_backend] Detected Docker, using it as backend");
            return Ok(SandboxBackend::Docker);
        }
        tracing::debug!("[detect_backend] Docker not available");

        // Try proot if available locally
        tracing::debug!("[detect_backend] Checking if proot is available...");
        if proot::ProotExecutor::is_available(config).await {
            tracing::info!("[detect_backend] Detected proot, using it as backend");
            return Ok(SandboxBackend::Proot);
        }
        tracing::debug!("[detect_backend] proot not available locally");

        // Download proot as final fallback (Linux only — proot is a Linux ELF binary)
        #[cfg(target_os = "linux")]
        {
            tracing::info!(
                "[detect_backend] No backend found locally, downloading proot as fallback..."
            );
            if proot::ProotExecutor::download_proot(config).await.is_ok() {
                tracing::info!("[detect_backend] proot downloaded successfully");
                return Ok(SandboxBackend::Proot);
            }
            tracing::error!("[detect_backend] Failed to download proot");
        }

        tracing::error!(
            "[detect_backend] No sandbox backend available (bwrap, docker, proot, wsl, or download all failed)"
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

    #[tokio::test]
    async fn test_sandbox_backend_detection() {
        let config = SandboxConfig::default();
        let result = SandboxManager::detect_backend(&config).await;
        match result {
            Ok(backend) => println!("Detected backend: {}", backend),
            Err(e) => println!("No backend available: {}", e),
        }
    }
}
