//! BlackArch rootfs management
//!
//! Handles downloading, extracting, and managing the BlackArch minimal rootfs.

use super::config::{SandboxConfig, SandboxError, SandboxResult};
use std::path::{Path, PathBuf};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;

/// Global lock to prevent concurrent rootfs setup
static SETUP_LOCK: tokio::sync::OnceCell<Mutex<()>> = tokio::sync::OnceCell::const_new();

/// URL for the Arch Linux bootstrap tarball (used as base)
const ARCH_BOOTSTRAP_URL: &str =
    "https://geo.mirror.pkgbuild.com/iso/latest/archlinux-bootstrap-x86_64.tar.zst";

/// Alternative URL for older mirrors without zst (also used by WSL import which doesn't support .tar.zst)
pub(super) const ARCH_BOOTSTRAP_URL_GZ: &str =
    "https://archive.archlinux.org/iso/2024.01.01/archlinux-bootstrap-2024.01.01-x86_64.tar.gz";

/// BlackArch repository strap script
const BLACKARCH_STRAP_URL: &str = "https://blackarch.org/strap.sh";

/// Rootfs manager for BlackArch environment
pub struct RootfsManager {
    config: SandboxConfig,
}

impl RootfsManager {
    /// Create a new rootfs manager
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }

    /// Check if the rootfs is ready
    pub fn is_ready(&self) -> bool {
        let rootfs = self.config.rootfs_dir();
        let has_basics = rootfs.join("bin").join("bash").exists()
            && rootfs.join("usr").join("bin").join("pacman").exists();

        if !has_basics {
            return false;
        }

        // Check if rootfs has been through the initial system update
        // (version marker to detect old rootfs that need upgrading)
        let version_marker = rootfs.join(".rootfs_version");
        if !version_marker.exists() {
            tracing::info!("Rootfs exists but lacks version marker - needs initial update");
            return false;
        }

        true
    }

    /// Ensure the rootfs is set up and ready
    pub async fn ensure_rootfs(&self) -> SandboxResult<PathBuf> {
        let rootfs = self.config.rootfs_dir();

        // Fast path: check without lock
        if self.is_ready() {
            tracing::debug!("Rootfs already initialized at {}", rootfs.display());
            return Ok(rootfs);
        }

        // Acquire global lock to prevent concurrent setup
        let lock = SETUP_LOCK.get_or_init(|| async { Mutex::new(()) }).await;
        let _guard = lock.lock().await;

        // Double-check after acquiring lock (another caller may have finished setup)
        if self.is_ready() {
            tracing::debug!("Rootfs initialized by another caller");
            return Ok(rootfs);
        }

        tracing::info!("Setting up BlackArch rootfs at {}", rootfs.display());

        // Create data directory
        tokio::fs::create_dir_all(&self.config.data_dir).await?;

        // Download and extract base Arch rootfs
        self.download_and_extract_rootfs(&rootfs).await?;

        // Initialize pacman keyring
        self.init_pacman_keyring(&rootfs).await?;

        // Add BlackArch repository
        self.add_blackarch_repo(&rootfs).await?;

        // Configure mirrors
        self.sync_packages(&rootfs).await?;

        // Fix pacman.conf for sandbox usage
        self.fix_pacman_config(&rootfs).await?;

        // Perform initial system update to resolve package conflicts
        // (e.g., gcc-libs split into libgcc + libstdc++)
        self.initial_system_update(&rootfs).await?;

        // Initialize pacman database (sync repos)
        self.initial_pacman_sync(&rootfs).await?;

        // Set file capabilities on pentest tools that need raw sockets
        self.set_tool_capabilities(&rootfs).await?;

        // Create version marker to indicate this rootfs has been updated
        let version_marker = rootfs.join(".rootfs_version");
        tokio::fs::write(&version_marker, "1\n").await?;

        tracing::info!("BlackArch rootfs setup complete");

        Ok(rootfs)
    }

    /// Download and extract the base Arch rootfs
    async fn download_and_extract_rootfs(&self, rootfs: &Path) -> SandboxResult<()> {
        let tarball_path = self.config.data_dir.join("arch-bootstrap.tar.zst");

        if !tarball_path.exists() {
            tracing::info!("Downloading Arch bootstrap...");
            if self
                .download_file(ARCH_BOOTSTRAP_URL, &tarball_path)
                .await
                .is_err()
            {
                tracing::info!("Trying gzip fallback...");
                let gz_path = self.config.data_dir.join("arch-bootstrap.tar.gz");
                self.download_file(ARCH_BOOTSTRAP_URL_GZ, &gz_path).await?;
                tokio::fs::rename(&gz_path, &tarball_path).await?;
            }
        }

        tracing::info!("Extracting rootfs...");
        tokio::fs::create_dir_all(rootfs).await?;

        let tarball_str = tarball_path.to_string_lossy();
        let extract_result = if tarball_str.ends_with(".zst") {
            Command::new("tar")
                .args([
                    "--zstd",
                    "-xf",
                    &tarball_str,
                    "-C",
                    &self.config.data_dir.to_string_lossy(),
                    "--no-same-owner",
                ])
                .status()
                .await
        } else {
            Command::new("tar")
                .args([
                    "-xzf",
                    &tarball_str,
                    "-C",
                    &self.config.data_dir.to_string_lossy(),
                    "--no-same-owner",
                ])
                .status()
                .await
        };

        match extract_result {
            Ok(status) => {
                if !status.success() {
                    tracing::warn!("Tar extraction completed with warnings (exit code {}), this is usually due to permission issues with symlinks that don't affect functionality", status.code().unwrap_or(-1));
                }
            }
            Err(e) => {
                return Err(SandboxError::RootfsSetupFailed(format!(
                    "Failed to extract rootfs: {}",
                    e
                )));
            }
        }

        // The archive extracts to a subdirectory, move contents up
        let extracted_dir = self.config.data_dir.join("root.x86_64");
        if extracted_dir.exists() && extracted_dir != *rootfs {
            if rootfs.exists() {
                tokio::fs::remove_dir_all(rootfs).await.ok();
            }
            tokio::fs::rename(&extracted_dir, rootfs).await?;
        }

        tokio::fs::remove_file(&tarball_path).await.ok();

        // Verify essential components were extracted
        if !rootfs.join("bin").join("bash").exists() {
            return Err(SandboxError::RootfsSetupFailed(
                "Rootfs extraction incomplete - /bin/bash not found".to_string(),
            ));
        }
        if !rootfs.join("usr").join("bin").join("pacman").exists() {
            return Err(SandboxError::RootfsSetupFailed(
                "Rootfs extraction incomplete - /usr/bin/pacman not found".to_string(),
            ));
        }

        tracing::info!("Rootfs extraction completed successfully");
        Ok(())
    }

    /// Initialize the pacman keyring
    async fn init_pacman_keyring(&self, rootfs: &Path) -> SandboxResult<()> {
        tracing::info!("Initializing pacman keyring...");

        let pacman_gnupg = rootfs.join("etc/pacman.d/gnupg");
        tokio::fs::create_dir_all(&pacman_gnupg).await?;

        // Initialize keyring and populate with Arch Linux keys
        let init_script = r#"
set -e
pacman-key --init
pacman-key --populate archlinux
        "#;

        match self.run_in_rootfs(rootfs, init_script).await {
            Ok(output) => {
                tracing::info!("Pacman keyring initialized successfully: {}", output.trim());
            }
            Err(e) => {
                tracing::warn!("Pacman keyring initialization had errors: {}", e);
                // Try to continue anyway - some errors might be non-fatal
            }
        }

        Ok(())
    }

    /// Add BlackArch repository to the rootfs
    async fn add_blackarch_repo(&self, rootfs: &Path) -> SandboxResult<()> {
        tracing::info!("Adding BlackArch repository...");

        let strap_path = rootfs.join("tmp/strap.sh");
        tokio::fs::create_dir_all(rootfs.join("tmp")).await?;
        self.download_file(BLACKARCH_STRAP_URL, &strap_path).await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tokio::fs::metadata(&strap_path).await?.permissions();
            perms.set_mode(0o755);
            tokio::fs::set_permissions(&strap_path, perms).await?;
        }

        let pacman_conf = rootfs.join("etc/pacman.conf");
        if pacman_conf.exists() {
            let mut content = tokio::fs::read_to_string(&pacman_conf).await?;

            if !content.contains("[blackarch]") {
                content.push_str(
                    r#"

[blackarch]
Server = https://blackarch.org/blackarch/$repo/os/$arch
SigLevel = Optional TrustAll
"#,
                );
                tokio::fs::write(&pacman_conf, content).await?;
            }
        }

        Ok(())
    }

    /// Configure mirrors
    async fn sync_packages(&self, rootfs: &Path) -> SandboxResult<()> {
        tracing::info!("Configuring mirrors...");

        let mirrorlist = rootfs.join("etc/pacman.d/mirrorlist");
        tokio::fs::write(
            &mirrorlist,
            "Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n\
             Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch\n",
        )
        .await?;

        Ok(())
    }

    /// Fix pacman.conf for sandbox usage
    async fn fix_pacman_config(&self, rootfs: &Path) -> SandboxResult<()> {
        tracing::info!("Fixing pacman.conf for sandbox usage...");

        let pacman_conf = rootfs.join("etc/pacman.conf");
        if !pacman_conf.exists() {
            return Ok(());
        }

        let mut content = tokio::fs::read_to_string(&pacman_conf).await?;
        let mut changed = false;

        // Comment out DownloadUser (not needed with multi-uid mapping, but cleaner)
        if content.contains("\nDownloadUser") && !content.contains("\n#DownloadUser") {
            content = content.replace("\nDownloadUser", "\n#DownloadUser");
            changed = true;
        }

        if changed {
            tokio::fs::write(&pacman_conf, content).await?;
            tracing::info!("pacman.conf updated");
        }

        Ok(())
    }

    /// Perform initial system update to resolve package conflicts
    async fn initial_system_update(&self, rootfs: &Path) -> SandboxResult<()> {
        tracing::info!("Performing initial system update to resolve package conflicts...");

        // We need to run pacman -Syu with --overwrite to handle package splits
        // (e.g., gcc-libs → libgcc + libstdc++)
        // Use proot or arch-chroot instead of bwrap because bwrap's user namespace
        // doesn't support chown operations that pacman needs

        let update_script = "pacman -Syu --noconfirm --overwrite '*'";

        tracing::info!("Running system update inside rootfs (this may take several minutes)...");

        let result = self.run_in_rootfs(rootfs, update_script).await;

        match result {
            Ok(output) => {
                tracing::info!("System update completed: {}", output.trim());
            }
            Err(e) => {
                tracing::warn!("System update had errors: {}, but continuing", e);
                // Don't fail here - the update might have partially succeeded
            }
        }

        Ok(())
    }

    /// Sync pacman databases to initialize /var/lib/pacman directories
    async fn initial_pacman_sync(&self, rootfs: &Path) -> SandboxResult<()> {
        tracing::info!("Initializing pacman databases...");

        // Use proot or arch-chroot instead of bwrap because bwrap's user namespace
        // doesn't support chown operations that pacman needs
        let sync_script = "pacman -Sy --noconfirm";

        tracing::info!("Syncing package databases...");

        let result = self.run_in_rootfs(rootfs, sync_script).await;

        match result {
            Ok(output) => {
                tracing::info!("Pacman database sync completed: {}", output.trim());
            }
            Err(e) => {
                tracing::warn!("Pacman sync had errors: {}, but continuing", e);
                // Don't fail here - the directories might have been created
            }
        }

        Ok(())
    }

    /// Set file capabilities on pentest tools that need raw sockets
    async fn set_tool_capabilities(&self, rootfs: &Path) -> SandboxResult<()> {
        tracing::info!("Setting capabilities on pentest tools...");

        // Run setcap INSIDE the sandbox where we're root
        let script = r#"
# List of tools that need cap_net_raw for raw socket access
TOOLS="/usr/bin/nmap /usr/bin/masscan /usr/bin/hping3"

for tool in $TOOLS; do
    if [ -f "$tool" ]; then
        setcap cap_net_raw+eip "$tool" 2>/dev/null && echo "Set cap_net_raw on $tool" || echo "Failed to set cap on $tool"
    fi
done
        "#;

        match self.run_in_rootfs(rootfs, script).await {
            Ok(output) => {
                tracing::info!("Capability setup output: {}", output.trim());
            }
            Err(e) => {
                tracing::warn!("Failed to set tool capabilities: {}", e);
                // Don't fail - capabilities are nice to have but not critical for basic operation
            }
        }

        Ok(())
    }

    /// Run a command inside the rootfs (using arch-chroot, chroot, proot, or bwrap)
    async fn run_in_rootfs(&self, rootfs: &Path, script: &str) -> SandboxResult<String> {
        // Try arch-chroot first (requires root or arch-install-scripts)
        let output = Command::new("arch-chroot")
            .args([rootfs.to_string_lossy().as_ref(), "/bin/bash", "-c", script])
            .output()
            .await;

        if let Ok(output) = output {
            if output.status.success() {
                return Ok(String::from_utf8_lossy(&output.stdout).to_string());
            }
        }

        // Try chroot (requires root)
        let output = Command::new("chroot")
            .args([rootfs.to_string_lossy().as_ref(), "/bin/bash", "-c", script])
            .output()
            .await;

        if let Ok(output) = output {
            if output.status.success() {
                return Ok(String::from_utf8_lossy(&output.stdout).to_string());
            }
        }

        // Try proot (works without root, good for pacman operations)
        if let Ok(proot_path) = super::proot::ProotExecutor::ensure_proot(&self.config).await {
            tracing::info!("Using proot for rootfs command execution");
            let output = Command::new(&proot_path)
                .args([
                    "-0", // Fake root privileges
                    "-r",
                    rootfs.to_string_lossy().as_ref(),
                    "-w",
                    "/root",
                    "/bin/bash",
                    "-c",
                    script,
                ])
                .output()
                .await;

            if let Ok(output) = output {
                if output.status.success() {
                    return Ok(String::from_utf8_lossy(&output.stdout).to_string());
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    tracing::warn!("proot command failed: stdout={}, stderr={}", stdout, stderr);
                    // Continue to try bwrap
                }
            }
        }

        // Fall back to bwrap with multi-uid mapping (our best option on desktop without proot/root)
        tracing::info!("Using bwrap with multi-uid mapping for rootfs command execution");

        // Use the BwrapExecutor to run the command
        let executor = super::bwrap::BwrapExecutor::new(self.config.clone());
        let result = executor
            .execute(script, std::time::Duration::from_secs(300), None)
            .await?;

        if result.exit_code == 0 {
            Ok(result.stdout)
        } else {
            Err(SandboxError::RootfsSetupFailed(format!(
                "bwrap command failed: stdout={}, stderr={}",
                result.stdout, result.stderr
            )))
        }
    }

    /// Download a file from URL to destination
    pub(super) async fn download_file(&self, url: &str, dest: &Path) -> SandboxResult<()> {
        tracing::debug!("Downloading {} to {}", url, dest.display());

        let response = reqwest::get(url)
            .await
            .map_err(|e| SandboxError::Download(format!("Failed to download {}: {}", url, e)))?;

        if !response.status().is_success() {
            return Err(SandboxError::Download(format!(
                "HTTP error downloading {}: {}",
                url,
                response.status()
            )));
        }

        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        let mut file = tokio::fs::File::create(dest).await?;
        let bytes = response
            .bytes()
            .await
            .map_err(|e| SandboxError::Download(e.to_string()))?;
        file.write_all(&bytes).await?;

        Ok(())
    }
}
