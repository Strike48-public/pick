//! BlackArch rootfs management
//!
//! Handles downloading, extracting, and managing the BlackArch minimal rootfs.

use super::arch;
use super::config::{SandboxConfig, SandboxError, SandboxResult};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio::sync::Mutex;

/// Global lock to prevent concurrent rootfs setup
static SETUP_LOCK: tokio::sync::OnceCell<Mutex<()>> = tokio::sync::OnceCell::const_new();

    /// Which host paths the proot guest sees. gpg's key generation hangs
    /// when /proc or /dev are bound (reproduced on the 2025.12.01 cut: init
    /// completes in seconds unbound, hangs forever bound), while pacman's
    /// commit needs /proc (its /etc/mtab points there) and every mirror
    /// fetch needs DNS (the bootstrap ships a comment-only resolv.conf) —
    /// so the callers choose.
    enum Binds {
        /// Nothing bound. gpg/keygen steps.
        None,
        /// Host resolv.conf only. Steps that need DNS but touch no gpg
        /// agent sockets (strap.sh).
        Resolv,
        /// /proc + /dev + resolv.conf. pacman steps (sync/upgrade/commit).
        Full,
    }


/// URL for the Arch Linux bootstrap tarball (used as base).
///
/// Dated archive copy, NOT the mirror's rolling `/iso/latest/`: a pin is only
/// meaningful against an immutable URL. (Recent cuts ship `.tar.zst`; GNU tar
/// `-a` auto-selects the decompressor from the filename, and `zstd` is
/// ubiquitous on the Linux hosts this backend runs on — pacman itself links
/// against it.) Vetted one-time against the archive's published GPG `.sig`
/// (Pierre Schmitz, `3E80CA1A 8B89F69C BA57D98A 76A5EF90 54449A5C`). Bumping
/// the cut is a deliberate act: vet the new `.sig`, then update URL + pin
/// together — and note the cut must be RECENT enough that its shipped
/// `archlinux-keyring` can verify today's repo signatures for the first
/// `pacman -Syu` (a too-old cut fails with "unknown trust" before it can
/// upgrade the keyring itself; the 2024.01.01 cut did exactly that).
const ARCH_BOOTSTRAP_URL: &str =
    "https://archive.archlinux.org/iso/2025.12.01/archlinux-bootstrap-2025.12.01-x86_64.tar.zst";
const ARCH_BOOTSTRAP_SHA256: &str =
    "48277d938a439976564f9e5b795e8668b7f1920c9bbbc30eb28a4a65f8832bdf";

/// BlackArch repository strap script. Rolling upstream URL, frozen by the
/// pin below (verified one-time against the blackarch/blackarch git source).
/// strap.sh is EXECUTED inside the rootfs, so a mismatch is a hard failure —
/// the caller's manual-repo fallback still applies.
const BLACKARCH_STRAP_URL: &str = "https://blackarch.org/strap.sh";
const BLACKARCH_STRAP_SHA256: &str =
    "dc0737cc75d64d03e9ec2212f989f17cdcf0162c2db5980e256093e293abfb8b";

/// Name of the wrapper directory the base archive extracts into, if any. The
/// x86_64 Arch bootstrap archive nests everything under `root.x86_64/`; the
/// ALARM aarch64 tarball extracts flat, so there is no wrapper to move.
fn extracted_subdir_for(aarch64: bool) -> Option<&'static str> {
    if aarch64 {
        None
    } else {
        Some("root.x86_64")
    }
}

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
        //
        // But refresh the keyring package FIRST: a bootstrap cut is only as
        // new as its shipped `archlinux-keyring`, and packager keys expire.
        // A stale keyring makes the first full `-Syu` abort on an
        // expired-key signature BEFORE the transaction could upgrade the
        // keyring itself (the classic Arch deadlock; hit with the 2025.12.01
        // cut whose 20251116 keyring predated a packager-key expiry). A
        // dedicated keyring-only sync breaks it: the keyring package is
        // signed by the current release keys, and every later package
        // verifies against the fresh keyring. Failure here is tolerated —
        // the -Syu below warns-and-continues like always.
        self.refresh_pacman_keyring(&rootfs).await?;

        self.initial_system_update(&rootfs).await?;

        // Initialize pacman database (sync repos)
        self.initial_pacman_sync(&rootfs).await?;

        // Set file capabilities on pentest tools that need raw sockets
        self.set_tool_capabilities(&rootfs).await?;

        // pacman's provisioning (installing the `filesystem` package via
        // arch-chroot/bwrap) can reset the rootfs ROOT dir back to its packaged
        // mode 0555. Restore owner-write before writing the completion marker —
        // otherwise the marker write itself fails on the read-only root, the
        // marker never appears, is_ready() stays false, and every launch
        // re-provisions from scratch (and later bwrap spawns fail EPERM too).
        Self::make_owner_writable(&rootfs);

        // Create version marker to indicate this rootfs has been updated
        let version_marker = rootfs.join(".rootfs_version");
        tokio::fs::write(&version_marker, "1\n").await?;

        tracing::info!("BlackArch rootfs setup complete");

        Ok(rootfs)
    }

    /// Recursively delete `path`, first making the whole tree writable.
    ///
    /// The Arch bootstrap archive packs some directories read-only (e.g.
    /// `etc/ca-certificates/extracted/cadir` is mode 0555). A plain
    /// `remove_dir_all` cannot delete files inside a read-only dir, and — worse —
    /// re-extracting the tarball ON TOP of a leftover read-only `cadir` from an
    /// interrupted run fails with `tar: Cannot create symlink ... Permission
    /// denied`, permanently wedging every later provision. So before deleting we
    /// walk the tree and restore write permission on every directory.
    fn force_remove_dir_all(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::symlink_metadata(path) {
                // Only chmod real directories (not symlinks) so we can descend.
                if meta.file_type().is_dir() {
                    let mut perms = meta.permissions();
                    perms.set_mode(perms.mode() | 0o700);
                    let _ = std::fs::set_permissions(path, perms);
                    if let Ok(entries) = std::fs::read_dir(path) {
                        for entry in entries.flatten() {
                            Self::force_remove_dir_all(&entry.path());
                        }
                    }
                }
            }
        }
        let _ = std::fs::remove_dir_all(path);
        // remove_dir_all leaves nothing on success; a file (non-dir) path or a
        // symlink needs remove_file.
        let _ = std::fs::remove_file(path);
    }

    /// Recursively add the owner-write bit to every directory under `path`
    /// (and `path` itself). The Arch/ALARM archives pack some directories
    /// read-only (0555), including the rootfs root; proot/bwrap need to create
    /// mount points and pacman needs to write databases inside the tree, so a
    /// read-only dir makes the sandbox fail at spawn/first-write with
    /// "Permission denied". Only directories are touched (files keep their
    /// modes); symlinks are skipped so we don't chase them out of the tree.
    fn make_owner_writable(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let Ok(meta) = std::fs::symlink_metadata(path) else {
                return;
            };
            if !meta.file_type().is_dir() {
                return;
            }
            let mut perms = meta.permissions();
            perms.set_mode(perms.mode() | 0o700);
            let _ = std::fs::set_permissions(path, perms);
            if let Ok(entries) = std::fs::read_dir(path) {
                for entry in entries.flatten() {
                    Self::make_owner_writable(&entry.path());
                }
            }
        }
    }

    /// Download and extract the base Arch rootfs
    async fn download_and_extract_rootfs(&self, rootfs: &Path) -> SandboxResult<()> {
        tokio::fs::create_dir_all(rootfs).await?;

        // aarch64: ArchLinuxARM ships a flat .tar.gz that untars directly into
        // the rootfs dir (no `root.<arch>` wrapper like the x86_64 bootstrap).
        if arch::is_aarch64() {
            let tarball_path = self.config.data_dir.join("alarm-rootfs.tar.gz");
            // A cached tarball is trusted only if it verifies against the
            // baked pin: an interrupted download — or a leftover of the old
            // plaintext-HTTP fetch this PR exists to stop trusting — must not
            // reach extraction (#624).
            if !usable_cache(&tarball_path, arch::ALARM_AARCH64_ROOTFS_SHA256).await {
                tracing::info!("Downloading ArchLinuxARM aarch64 rootfs...");
                self.download_file(
                    arch::ALARM_AARCH64_ROOTFS,
                    &tarball_path,
                    arch::ALARM_AARCH64_ROOTFS_SHA256,
                )
                .await?;
            }
            tracing::info!("Extracting ALARM rootfs...");
            // --delay-directory-restore: see the x86_64 branch below — ALARM
            // packs the same read-only cadir, so defer dir-perm restore or the
            // symlinks inside it fail to extract.
            let status = Command::new("tar")
                .args([
                    "--delay-directory-restore",
                    "-xzf",
                    &tarball_path.to_string_lossy(),
                    "-C",
                    &rootfs.to_string_lossy(),
                    "--no-same-owner",
                ])
                .status()
                .await
                .map_err(|e| {
                    SandboxError::RootfsSetupFailed(format!("Failed to extract ALARM rootfs: {e}"))
                })?;
            if !status.success() {
                tracing::warn!(
                    "ALARM tar extraction exit code {} (usually harmless symlink perms)",
                    status.code().unwrap_or(-1)
                );
            }
            tokio::fs::remove_file(&tarball_path).await.ok();

            // Ensure the extracted tree is owner-writable (the archive root is
            // packed 0555; proot/bwrap and pacman need to write inside it).
            Self::make_owner_writable(rootfs);

            if !rootfs.join("bin").join("bash").exists()
                && !rootfs.join("usr").join("bin").join("bash").exists()
            {
                return Err(SandboxError::RootfsSetupFailed(
                    "ALARM rootfs extraction incomplete - bash not found".to_string(),
                ));
            }
            if !rootfs.join("usr").join("bin").join("pacman").exists() {
                return Err(SandboxError::RootfsSetupFailed(
                    "ALARM rootfs extraction incomplete - pacman not found".to_string(),
                ));
            }
            tracing::info!("ALARM rootfs extraction completed successfully");
            return Ok(());
        }

        let tarball_path = self.config.data_dir.join("arch-bootstrap.tar.zst");

        // Same refuse-unverified contract as the ALARM branch: a cached
        // tarball is extracted only if it verifies against the baked pin —
        // a truncated or tampered leftover must be re-downloaded, not
        // extracted (#624, jtomek's review on #625).
        if !usable_cache(&tarball_path, ARCH_BOOTSTRAP_SHA256).await {
            tracing::info!("Downloading Arch bootstrap...");
            self.download_file(
                ARCH_BOOTSTRAP_URL,
                &tarball_path,
                ARCH_BOOTSTRAP_SHA256,
            )
            .await?;
        }

        tracing::info!("Extracting rootfs...");

        // Remove any leftover staging dir from a previous interrupted extract.
        // The archive nests everything under `root.x86_64/`, and re-extracting
        // over a leftover read-only `cadir` there fails (tar can't recreate the
        // symlinks), so start from a clean staging dir every time.
        if let Some(subdir) = extracted_subdir_for(false) {
            let staging = self.config.data_dir.join(subdir);
            if staging.exists() {
                tracing::info!(
                    "Removing stale extraction staging dir {}",
                    staging.display()
                );
                Self::force_remove_dir_all(&staging);
            }
        }

        // --delay-directory-restore: the Arch bootstrap packs read-only dirs
        // (e.g. etc/ca-certificates/extracted/cadir, mode 0555) BEFORE the
        // symlinks that live inside them. Without this flag GNU tar creates the
        // dir read-only, then can't write its own children -> "Cannot create
        // symlink ... Permission denied" and the extract aborts, leaving a
        // broken rootfs. The flag defers directory permission restoration until
        // after contents are written (reproduced on the 2024.01.01 bootstrap
        // cut this path downloads).
        let tarball_str = tarball_path.to_string_lossy();
        let extract_result = Command::new("tar")
            .args([
                "--delay-directory-restore",
                "-xaf",
                &tarball_str,
                "-C",
                &self.config.data_dir.to_string_lossy(),
                "--no-same-owner",
            ])
            .status()
            .await;

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

        // The archive packs its dirs (including the `root.x86_64` root itself)
        // as mode 0555 (read-only). This bites in THREE places, so restore
        // owner-write on every directory in the extracted tree BEFORE anything
        // else touches it:
        //   1. renaming the staging dir into place needs write on that dir
        //      (`rename` updates its `..`), else the move fails Permission denied
        //      and the whole provision aborts — leaving a broken 0555 rootfs that
        //      is never repaired;
        //   2. bwrap/proot must create mount points inside the rootfs at spawn;
        //   3. pacman must write /var/lib/pacman.
        // Do it on the staging dir first (fixes the rename), then again on the
        // final rootfs after the move (belt and suspenders / no-move case).
        if let Some(subdir) = extracted_subdir_for(false) {
            let extracted_dir = self.config.data_dir.join(subdir);
            if extracted_dir.exists() {
                Self::make_owner_writable(&extracted_dir);
                if extracted_dir != *rootfs {
                    if rootfs.exists() {
                        // force-remove: a prior rootfs also contains read-only dirs.
                        Self::force_remove_dir_all(rootfs);
                    }
                    tokio::fs::rename(&extracted_dir, rootfs).await?;
                }
            }
        }

        Self::make_owner_writable(rootfs);

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
        let init_script = format!(
            "set -e\npacman-key --init\npacman-key --populate {}\n",
            arch::pacman_keyring()
        );

        match self.run_in_rootfs(rootfs, &init_script, Binds::None).await {
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
    ///
    /// On aarch64 this still runs strap.sh (unlike WSL/Docker which append
    /// `[blackarch]` directly). strap.sh may assume an x86_64 bootstrap; if it
    /// misbehaves on arm64 the `Err` fallback appends the repo manually. This
    /// arm64-Linux path is unverified (no arm64 Linux test hardware yet) — verify
    /// when a box exists.
    async fn add_blackarch_repo(&self, rootfs: &Path) -> SandboxResult<()> {
        tracing::info!("Adding BlackArch repository...");

        let strap_path = rootfs.join("tmp/strap.sh");
        tokio::fs::create_dir_all(rootfs.join("tmp")).await?;
        self.download_file(
            BLACKARCH_STRAP_URL,
            &strap_path,
            BLACKARCH_STRAP_SHA256,
        )
        .await?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = tokio::fs::metadata(&strap_path).await?.permissions();
            perms.set_mode(0o755);
            tokio::fs::set_permissions(&strap_path, perms).await?;
        }

        // Run strap.sh inside the rootfs to properly import the BlackArch keyring
        let strap_script = r#"
set -e
/tmp/strap.sh
"#;

        match self.run_in_rootfs(rootfs, strap_script, Binds::Resolv).await {
            Ok(output) => {
                tracing::info!("BlackArch strap.sh completed: {}", output.trim());
            }
            Err(e) => {
                tracing::warn!(
                    "BlackArch strap.sh failed: {}, falling back to manual config",
                    e
                );
                // Fall back to manual repo config if strap.sh fails
                let pacman_conf = rootfs.join("etc/pacman.conf");
                if pacman_conf.exists() {
                    let mut content = tokio::fs::read_to_string(&pacman_conf).await?;
                    if !content.contains("[blackarch]") {
                        content.push_str(
                            "\n\n[blackarch]\nServer = https://blackarch.org/blackarch/$repo/os/$arch\nSigLevel = Optional TrustAll\n",
                        );
                        tokio::fs::write(&pacman_conf, content).await?;
                    }
                }
            }
        }

        // Clean up
        tokio::fs::remove_file(&strap_path).await.ok();

        Ok(())
    }

    /// Configure mirrors
    async fn sync_packages(&self, rootfs: &Path) -> SandboxResult<()> {
        tracing::info!("Configuring mirrors...");

        let mirrorlist = rootfs.join("etc/pacman.d/mirrorlist");
        tokio::fs::write(&mirrorlist, arch::pacman_mirrorlist()).await?;

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

        // Force an external downloader (#248/#252). pacman 7's internal parallel
        // downloader is a silent no-op under proot — it reports success but the
        // synced DBs are never usable — so DB/package fetches must go through
        // curl to be deterministic. Only add it once, under [options].
        if !content.contains("XferCommand") {
            let xfer = "XferCommand = /usr/bin/curl -L -f -o %o %u";
            if let Some(idx) = content.find("[options]") {
                // Insert right after the [options] header line.
                let insert_at = content[idx..]
                    .find('\n')
                    .map(|nl| idx + nl + 1)
                    .unwrap_or(content.len());
                content.insert_str(insert_at, &format!("{xfer}\n"));
            } else {
                // No [options] section (unexpected) — append a minimal one.
                content.push_str(&format!("\n[options]\n{xfer}\n"));
            }
            changed = true;
        }

        if changed {
            tokio::fs::write(&pacman_conf, content).await?;
            tracing::info!("pacman.conf updated (DownloadUser + curl XferCommand)");
        }

        Ok(())
    }

    /// Perform initial system update to resolve package conflicts
    /// Refresh the `archlinux-keyring` package before the first full upgrade.
    ///
    /// See the call site for why: a bootstrap cut's baked-in keyring ages,
    /// and an expired packager key deadlocks the first `pacman -Syu`.
    async fn refresh_pacman_keyring(&self, rootfs: &Path) -> SandboxResult<()> {
        tracing::info!("Refreshing archlinux-keyring before the initial upgrade...");

        let script = "pacman -Sy archlinux-keyring --noconfirm";
        let result = self.run_in_rootfs(rootfs, script, Binds::Full).await;

        match result {
            Ok(output) => {
                tracing::info!("Keyring refresh completed: {}", output.trim());
            }
            Err(e) => {
                tracing::warn!("Keyring refresh failed (continuing): {e}");
            }
        }

        Ok(())
    }

    async fn initial_system_update(&self, rootfs: &Path) -> SandboxResult<()> {
        tracing::info!("Performing initial system update to resolve package conflicts...");

        // We need to run pacman -Syu with --overwrite to handle package splits
        // (e.g., gcc-libs → libgcc + libstdc++)
        // Use proot or arch-chroot instead of bwrap because bwrap's user namespace
        // doesn't support chown operations that pacman needs

        let update_script = "pacman -Syu --noconfirm --overwrite '*'";

        tracing::info!("Running system update inside rootfs (this may take several minutes)...");

        let result = self.run_in_rootfs(rootfs, update_script, Binds::Full).await;

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

        let result = self.run_in_rootfs(rootfs, sync_script, Binds::Full).await;

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

        match self.run_in_rootfs(rootfs, script, Binds::None).await {
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
    async fn run_in_rootfs(&self, rootfs: &Path, script: &str, binds: Binds) -> SandboxResult<String> {
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
                ]
                .into_iter()
                // Bind the pieces the step needs from the host: pacman's
                // commit reads /etc/mtab -> /proc, and every mirror fetch
                // needs DNS (the bootstrap ships a comment-only
                // resolv.conf). See Binds for why gpg/keygen steps get
                // nothing.
                .chain(match binds {
                    Binds::None => vec![].into_iter(),
                    Binds::Resolv => vec!["-b", "/etc/resolv.conf"].into_iter(),
                    Binds::Full => {
                        vec!["-b", "/proc", "-b", "/dev", "-b", "/etc/resolv.conf"].into_iter()
                    }
                })
                .chain(
                    [
                        "-w",
                        "/root",
                        // Fixed guest PATH: without this the guest inherits
                        // the host's PATH, which on hosts like NixOS points
                        // at store paths that do not exist inside the
                        // rootfs — every pacman invocation then fails
                        // "command not found" and the (tolerated-failure)
                        // first-boot steps silently skip.
                        "/usr/bin/env",
                        "-i",
                        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        "HOME=/root",
                        // -i: a clean environment. Inheriting host vars like
                        // LD_LIBRARY_PATH into a foreign rootfs makes the
                        // guest's own binaries load the host's libraries
                        // (gpg-agent hung forever on a NixOS host until
                        // this was cleared).
                        "/bin/bash",
                        "-c",
                        script,
                    ]
                    .into_iter(),
                )
                .collect::<Vec<_>>())
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

        // Fall back to simple bwrap (single-uid mapping, no unshare)
        tracing::info!("Using simple bwrap for rootfs command execution");

        let rootfs_str = rootfs.to_string_lossy().to_string();
        let wrapped_script = format!(
            "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin && {}",
            script
        );

        let output = Command::new("bwrap")
            .args([
                "--bind",
                &rootfs_str,
                "/",
                "--dev",
                "/dev",
                "--proc",
                "/proc",
                "--tmpfs",
                "/tmp",
                "--ro-bind",
                "/etc/resolv.conf",
                "/etc/resolv.conf",
                "--unshare-user",
                "--uid",
                "0",
                "--gid",
                "0",
                "--share-net",
                "--die-with-parent",
                "/usr/bin/bash",
                "-c",
                &wrapped_script,
            ])
            .output()
            .await
            .map_err(|e| SandboxError::RootfsSetupFailed(format!("Failed to run bwrap: {}", e)))?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            Err(SandboxError::RootfsSetupFailed(format!(
                "bwrap command failed: stdout={}, stderr={}",
                stdout, stderr
            )))
        }
    }

    /// Download a file from URL to destination, streaming the body to disk.
    ///
    /// `expected_sha256` is REQUIRED: the body must match the pinned
    /// lowercase-hex SHA-256 (an empty pin is refused up front — unverifiable
    /// artifacts are refused, proot.rs contract). Making the pin a required
    /// argument means a caller cannot accidentally drop verification by
    /// passing `None` — the compile fails instead (jtomek's review on #625:
    /// every call-site pin could be set to `None` with all tests still
    /// green). The body streams into a sibling `.part` file in bounded
    /// memory (the ALARM rootfs is ~800 MB) while being hashed
    /// incrementally; the hash is checked after the stream and only then is
    /// the file renamed to `dest` (verify-then-publish, the `proot.rs`
    /// ordering). An interrupted or refused run leaves no unverified and no
    /// half-written file at `dest`.
    pub(super) async fn download_file(
        &self,
        url: &str,
        dest: &Path,
        expected_sha256: &str,
    ) -> SandboxResult<()> {
        tracing::debug!("Downloading {} to {}", url, dest.display());

        if expected_sha256.is_empty() {
            return Err(SandboxError::Download(
                "no pinned SHA-256; refusing to use an unverified artifact (see #624)".into(),
            ));
        }

        // reqwest::get has no timeout: a stalled mirror would hang first-run
        // forever (the proot.rs #294 hang). Bound the CONNECT here and the
        // IDLE time between chunks below — a fixed whole-request cap is
        // deliberately NOT used, it would kill a slow-but-healthy 800 MB
        // download on a weak link.
        const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
        const CHUNK_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
        let client = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|e| SandboxError::Download(e.to_string()))?;
        let response =
            client.get(url).send().await.map_err(|e| {
                SandboxError::Download(format!("Failed to download {}: {}", url, e))
            })?;

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

        // Stream into a sibling `.part` file: bounded memory, and `dest`
        // only ever appears via the final rename.
        let part = dest.with_file_name(format!(
            "{}.part",
            dest.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        ));
        let mut file = tokio::fs::File::create(&part).await?;
        let mut hasher = Sha256::new();

        let mut stream = response;
        loop {
            let next = match tokio::time::timeout(CHUNK_IDLE_TIMEOUT, stream.chunk()).await {
                Ok(Ok(next)) => next,
                Ok(Err(e)) => return Err(SandboxError::Download(e.to_string())),
                Err(_) => {
                    return Err(SandboxError::Download(format!(
                        "download stalled (no data for {}s): {}",
                        CHUNK_IDLE_TIMEOUT.as_secs(),
                        url
                    )))
                }
            };
            let chunk = match next {
                Some(chunk) => chunk,
                None => break,
            };
            hasher.update(&chunk);
            file.write_all(&chunk).await?;
        }
        // Make the `.part` durable before it can be promoted to `dest`.
        file.flush().await?;
        file.sync_all().await?;
        drop(file);

        // Pinned artifacts are checked before publish: a mismatch removes
        // the `.part` and never creates `dest` (refuse unverified).
        {
            let actual = format!("{:x}", hasher.finalize());
            if !actual.eq_ignore_ascii_case(expected_sha256) {
                let _ = tokio::fs::remove_file(&part).await;
                return Err(SandboxError::Download(format!(
                    "SHA-256 mismatch: expected {expected_sha256}, got {actual}"
                )));
            }
            tracing::debug!("SHA-256 verified for {}", url);
        }

        tokio::fs::rename(&part, dest).await?;

        Ok(())
    }
}

/// Lowercase hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Verify `bytes` against a pinned lowercase-hex SHA-256. An empty pin or a
/// mismatch is an error: unverified artifacts are refused (proot.rs contract).
fn check_sha256(bytes: &[u8], expected: &str) -> SandboxResult<()> {
    if expected.is_empty() {
        return Err(SandboxError::Download(
            "no pinned SHA-256; refusing to use an unverified artifact (see #624)".into(),
        ));
    }
    let actual = sha256_hex(bytes);
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(SandboxError::Download(format!(
            "SHA-256 mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

/// Decide whether a cached download at `path` may be reused.
///
/// The cached file must verify against the (required) pin; a missing,
/// corrupt, or unverified file (a truncated download, or a leftover of the
/// old plaintext-HTTP fetch) is removed so the caller re-downloads. The pin
/// is a required argument so dropping verification fails to compile rather
/// than silently trusting a file (jtomek's review on #625).
///
/// The file is streamed through the hasher in bounded memory — the ALARM
/// rootfs is ~800 MB and `tokio::fs::read` would buffer all of it.
pub(super) async fn usable_cache(path: &Path, pin: &str) -> bool {
    use tokio::io::AsyncReadExt;

    let mut file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(_) => return false,
    };

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        match file.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => hasher.update(&buf[..n]),
            Err(_) => {
                tracing::warn!(
                    "Cached rootfs at {} could not be read for the pin check — re-downloading",
                    path.display()
                );
                let _ = tokio::fs::remove_file(path).await;
                return false;
            }
        }
    }

    if format!("{:x}", hasher.finalize()).eq_ignore_ascii_case(pin) {
        true
    } else {
        tracing::warn!(
            "Cached rootfs at {} failed the pinned SHA-256 check — re-downloading",
            path.display()
        );
        let _ = tokio::fs::remove_file(path).await;
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_bootstrap_archive_has_wrapper_dir_aarch64_is_flat() {
        // The x86_64 Arch bootstrap tarball extracts into a `root.x86_64/`
        // wrapper dir that must then be moved up. The ALARM aarch64 tarball
        // extracts flat (no wrapper), so no move is needed.
        assert_eq!(extracted_subdir_for(false), Some("root.x86_64"));
        assert_eq!(extracted_subdir_for(true), None);
    }

    #[test]
    fn rootfs_download_urls_are_https() {
        // #624: every URL handed to download_file must be HTTPS. The ALARM
        // rootfs moved from plaintext http://os.archlinuxarm.org to a pinned
        // release asset; this keeps it (and any future URL) honest.
        for url in [
            ARCH_BOOTSTRAP_URL,
            BLACKARCH_STRAP_URL,
            arch::ALARM_AARCH64_ROOTFS,
            super::super::wsl::ARCHWSL_ROOTFS_URL,
        ] {
            assert!(url.starts_with("https://"), "not HTTPS: {url}");
        }
    }

    #[tokio::test]
    async fn download_file_mismatched_pin_leaves_no_file() {
        // Review (625): skipping the verify step, or leaving a half-written
        // or unverified file at `dest`, must be caught. Serve a fixed body
        // from a local listener; a wrong pin is refused with NOTHING left
        // on disk (`dest` is only ever created by the post-verify rename),
        // the right pin lands the file byte-exact.
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let body: Arc<Vec<u8>> = Arc::new(b"definitely-not-the-pinned-rootfs".to_vec());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = Arc::clone(&body);
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut req = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    let n = sock.read(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if req.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    served.len()
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
                sock.write_all(&served).await.unwrap();
            }
        });

        let tmp = tempfile::tempdir().unwrap();
        let dest = tmp.path().join("alarm-rootfs.tar.gz");
        let manager = RootfsManager::new(SandboxConfig {
            data_dir: tmp.path().to_path_buf(),
            ..Default::default()
        });

        // Wrong pin: refused, and nothing is left at dest (nor a .part).
        let err = manager
            .download_file(
                &format!("http://{addr}/rootfs"),
                &dest,
                &"0".repeat(64),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, SandboxError::Download(_)), "got: {err:?}");
        assert!(
            !dest.exists(),
            "a mismatched pinned download must leave no file"
        );
        assert!(
            !dest.with_file_name("alarm-rootfs.tar.gz.part").exists(),
            "no stray .part file either"
        );

        // Correct pin: the file lands with exactly the served bytes.
        let good_pin = sha256_hex(&body);
        manager
            .download_file(&format!("http://{addr}/rootfs"), &dest, &good_pin)
            .await
            .unwrap();
        assert_eq!(tokio::fs::read(&dest).await.unwrap(), body.as_slice());
        let _ = server.await;
    }

    #[tokio::test]
    async fn usable_cache_refuses_unverified_file_and_reuses_verified() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("alarm-rootfs.tar.gz");
        let pin = sha256_hex(b"the-pinned-bytes");

        // Missing file: not usable.
        assert!(!usable_cache(&path, &pin).await);

        // Planted (unverified) file: refused AND removed — the attack/tamper
        // case from the review (a planted tarball must not be extracted).
        tokio::fs::write(&path, b"planted").await.unwrap();
        assert!(!usable_cache(&path, &pin).await);
        assert!(!path.exists(), "an unverified cached file must be removed");

        // Verified file: reusable.
        tokio::fs::write(&path, b"the-pinned-bytes").await.unwrap();
        assert!(usable_cache(&path, &pin).await);
    }

    #[test]
    fn alarm_rootfs_pin_is_baked() {
        // Fail in CI rather than ship an unverifiable 829 MB rootfs (proot.rs
        // contract: empty/unbaked pin = refuse).
        let pin = arch::ALARM_AARCH64_ROOTFS_SHA256;
        assert_eq!(pin.len(), 64, "pin must be 64 hex chars: {pin:?}");
        assert!(
            pin.bytes().all(|b| b.is_ascii_hexdigit()) && pin == pin.to_lowercase(),
            "pin must be lowercase hex: {pin:?}"
        );
    }

    #[test]
    fn sandbox_pins_are_baked() {
        // #626: every sandbox download is pinned — fail in CI rather than
        // ship an unverifiable artifact (proot.rs contract).
        for (name, pin) in [
            ("arch bootstrap", ARCH_BOOTSTRAP_SHA256),
            ("blackarch strap.sh", BLACKARCH_STRAP_SHA256),
            (
                "archwsl-fs rootfs",
                super::super::wsl::ARCHWSL_ROOTFS_SHA256,
            ),
            ("alarm aarch64 rootfs", arch::ALARM_AARCH64_ROOTFS_SHA256),
        ] {
            assert_eq!(pin.len(), 64, "{name} pin must be 64 hex chars: {pin:?}");
            assert!(
                pin.bytes().all(|b| b.is_ascii_hexdigit()) && pin == pin.to_lowercase(),
                "{name} pin must be lowercase hex: {pin:?}"
            );
        }
    }

    #[test]
    fn bootstrap_url_is_a_dated_archive_copy() {
        // A pin is only meaningful against an immutable URL — the bootstrap
        // must stay on a dated archive copy, never a rolling mirror path.
        assert!(
            ARCH_BOOTSTRAP_URL.contains("/iso/")
                && !ARCH_BOOTSTRAP_URL.contains("/latest/")
                && ARCH_BOOTSTRAP_URL.contains("archlinux.org/iso/2"),
            "bootstrap URL must be a dated archive copy: {ARCH_BOOTSTRAP_URL}"
        );
        assert!(
            !ARCH_BOOTSTRAP_URL.contains("/latest/"),
            "rolling URL: {ARCH_BOOTSTRAP_URL}"
        );
    }

    #[test]
    fn sha256_hex_known_vector() {
        // NIST: SHA-256("abc")
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn check_sha256_accepts_match_rejects_mismatch_and_empty_pin() {
        let data = b"rootfs-bytes";
        let pin = sha256_hex(data);
        assert!(check_sha256(data, &pin).is_ok());
        assert!(check_sha256(data, &"0".repeat(64)).is_err());
        assert!(check_sha256(data, "").is_err());
    }
}
