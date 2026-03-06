//! WSL2 sandbox executor
//!
//! Uses Windows Subsystem for Linux 2 to run a BlackArch Linux distro.
//! Preferred backend on Windows — auto-imports a distro from a bootstrap tarball.

use super::config::{SandboxConfig, SandboxError, SandboxResult};
use crate::traits::CommandResult;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tokio::process::Command;

/// WSL distro version marker inside the distro filesystem
#[cfg(target_os = "windows")]
const WSL_SETUP_MARKER: &str = "/root/.pentest-setup-complete";

/// ArchWSL-FS rootfs — pre-built for WSL (v1 & v2), flat, no repacking needed.
/// https://github.com/yuk7/ArchWSL-FS
const ARCHWSL_ROOTFS_URL: &str =
    "https://github.com/yuk7/ArchWSL-FS/releases/download/25030400/rootfs.tar.gz";

/// WSL2 executor for Windows
pub struct WslExecutor {
    config: SandboxConfig,
}

impl WslExecutor {
    /// Create a new WSL executor
    pub fn new(config: SandboxConfig) -> Self {
        Self { config }
    }

    /// Check if WSL2 is available on this system.
    ///
    /// Returns `false` immediately on non-Windows platforms.
    pub async fn is_available() -> bool {
        #[cfg(not(target_os = "windows"))]
        {
            false
        }
        #[cfg(target_os = "windows")]
        {
            Command::new("wsl.exe")
                .arg("--status")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false)
        }
    }

    /// Check if our distro has already been imported into WSL.
    pub async fn is_distro_imported(&self) -> bool {
        #[cfg(not(target_os = "windows"))]
        {
            false
        }
        #[cfg(target_os = "windows")]
        {
            let distro_name = self.config.wsl_distro_name();
            let output = match Command::new("wsl.exe")
                .args(["--list", "--quiet"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
                .await
            {
                Ok(o) => o,
                Err(_) => return false,
            };

            // wsl --list outputs UTF-16LE on Windows
            let text = Self::decode_wsl_output(&output.stdout);
            text.lines()
                .any(|line| line.trim().eq_ignore_ascii_case(distro_name))
        }
    }

    /// Import a tarball as a WSL distro. Tries WSL2 first, falls back to WSL1
    /// if Hyper-V / Virtual Machine Platform is unavailable (e.g. inside a VM
    /// without nested virtualisation).
    pub async fn import_distro(&self, tarball: &Path) -> SandboxResult<()> {
        let distro_name = self.config.wsl_distro_name();
        let install_dir = self.config.wsl_install_dir();

        tokio::fs::create_dir_all(&install_dir).await?;

        tracing::info!(
            "[import_distro] Importing WSL distro '{}' from {}",
            distro_name,
            tarball.display()
        );

        // Try WSL2 first
        let output = Self::run_wsl_import(distro_name, &install_dir, tarball, "2").await?;
        let stdout = Self::decode_wsl_output(&output.stdout);
        let stderr = Self::decode_wsl_output(&output.stderr);
        tracing::info!(
            "[import_distro] WSL2 attempt: exit={}, stdout={}, stderr={}",
            output.status,
            stdout.trim(),
            stderr.trim()
        );

        if output.status.success() {
            tracing::info!(
                "[import_distro] WSL distro '{}' imported as WSL2",
                distro_name
            );
            return Ok(());
        }

        // Check if it failed because Hyper-V is unavailable — fall back to WSL1
        let combined = format!("{} {}", stdout, stderr);
        let hyper_v_missing = combined.contains("HYPERV_NOT_INSTALLED")
            || combined.contains("Virtual Machine Platform")
            || combined.contains("virtualization");

        tracing::info!(
            "[import_distro] hyper_v_missing={}, will{}fall back to WSL1",
            hyper_v_missing,
            if hyper_v_missing { " " } else { " NOT " }
        );

        if !hyper_v_missing {
            return Err(SandboxError::WslDistroError(format!(
                "wsl --import --version 2 failed ({}): {}",
                output.status,
                stderr.trim()
            )));
        }

        tracing::warn!("[import_distro] WSL2 unavailable (no Hyper-V), falling back to WSL1");

        // WSL2 import may have left a broken registration — unregister before retry
        let _ = Command::new("wsl.exe")
            .args(["--unregister", distro_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .await;

        let output = Self::run_wsl_import(distro_name, &install_dir, tarball, "1").await?;
        let stdout = Self::decode_wsl_output(&output.stdout);
        let stderr = Self::decode_wsl_output(&output.stderr);
        tracing::info!(
            "[import_distro] WSL1 attempt: exit={}, stdout={}, stderr={}",
            output.status,
            stdout.trim(),
            stderr.trim()
        );

        if !output.status.success() {
            let combined = format!("{} {}", stdout, stderr);
            let wsl1_not_enabled = combined.contains("WSL1_NOT_SUPPORTED")
                || combined.contains("Windows Subsystem for Linux");

            if wsl1_not_enabled {
                return Err(SandboxError::WslDistroError(
                    "WSL is not enabled. Open PowerShell as Administrator and run:\n\n\
                     dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart\n\n\
                     Then restart your computer and try again."
                        .to_string(),
                ));
            }

            return Err(SandboxError::WslDistroError(format!(
                "wsl --import --version 1 also failed ({}): {}",
                output.status,
                stderr.trim()
            )));
        }

        tracing::info!(
            "[import_distro] WSL distro '{}' imported as WSL1 (fallback)",
            distro_name
        );
        Ok(())
    }

    /// Run `wsl.exe --import` with the given version.
    async fn run_wsl_import(
        distro_name: &str,
        install_dir: &Path,
        tarball: &Path,
        version: &str,
    ) -> SandboxResult<std::process::Output> {
        Command::new("wsl.exe")
            .args([
                "--import",
                distro_name,
                &install_dir.to_string_lossy(),
                &tarball.to_string_lossy(),
                "--version",
                version,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| SandboxError::WslDistroError(format!("Failed to run wsl --import: {}", e)))
    }

    /// Run the initial setup inside the distro (pacman keyring, BlackArch repo, system update).
    ///
    /// The setup script is written to a temp file and executed via WSL rather than
    /// passed as a `-c` argument, because Windows cmd strips `$` characters from
    /// command-line arguments before bash sees them.
    pub async fn setup_distro(&self) -> SandboxResult<()> {
        let distro_name = self.config.wsl_distro_name();

        tracing::info!("Running initial setup in WSL distro '{}'", distro_name);

        // Write setup script to a temp file on the Windows filesystem.
        // This avoids Windows cmd mangling $ signs in wsl.exe -c "..." args.
        let script_path = self.config.data_dir.join("wsl-setup.sh");
        let setup_script = r#"#!/bin/bash
set -e

# Configure DNS (WSL usually handles this, but just in case)
if [ ! -f /etc/resolv.conf ] || ! grep -q nameserver /etc/resolv.conf 2>/dev/null; then
    echo 'nameserver 8.8.8.8' > /etc/resolv.conf
    echo 'nameserver 8.8.4.4' >> /etc/resolv.conf
fi

# Configure mirrors — $repo and $arch are pacman variables, not shell
cat > /etc/pacman.d/mirrorlist << 'MIRRORS'
Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch
Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch
MIRRORS

# Fix pacman.conf for WSL
sed -i 's/^CheckSpace/#CheckSpace/' /etc/pacman.conf 2>/dev/null || true
sed -i 's/^DownloadUser/#DownloadUser/' /etc/pacman.conf 2>/dev/null || true
sed -i 's/^#DisableSandbox/DisableSandbox/' /etc/pacman.conf 2>/dev/null || true

# Add DisableSandbox if not present (pacman 7.0+)
if ! grep -q 'DisableSandbox' /etc/pacman.conf 2>/dev/null; then
    sed -i '/^\[options\]/a DisableSandbox' /etc/pacman.conf
fi

# Set SigLevel to Never (avoids keyring issues)
sed -i 's/^SigLevel.*/SigLevel = Never/' /etc/pacman.conf 2>/dev/null || true

# Initialize pacman keyring
pacman-key --init 2>/dev/null || true
pacman-key --populate archlinux 2>/dev/null || true

# Add BlackArch repository if not present
if ! grep -q '\[blackarch\]' /etc/pacman.conf 2>/dev/null; then
    cat >> /etc/pacman.conf << 'BLACKARCH'

[blackarch]
Server = https://blackarch.org/blackarch/$repo/os/$arch
SigLevel = Never
BLACKARCH
fi

# System update
pacman -Syu --noconfirm --overwrite '*' 2>&1 || true

# Sync package databases
pacman -Sy --noconfirm 2>&1 || true

# Mark setup as complete
touch /root/.pentest-setup-complete
echo "WSL distro setup complete"
"#;

        tokio::fs::write(&script_path, setup_script).await?;

        // Convert Windows path to WSL path so wsl.exe can find the script
        let wsl_script_path = Self::windows_to_wsl_path(&script_path.to_string_lossy());

        let output = Command::new("wsl.exe")
            .args(["-d", distro_name, "--", "/bin/bash", &wsl_script_path])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(|e| {
                SandboxError::WslDistroError(format!("Failed to run setup in WSL distro: {}", e))
            })?;

        // Clean up script file
        tokio::fs::remove_file(&script_path).await.ok();

        let stdout = Self::decode_wsl_output(&output.stdout);
        let stderr = Self::decode_wsl_output(&output.stderr);

        tracing::info!(
            "[setup_distro] exit={}, stdout:\n{}\nstderr:\n{}",
            output.status,
            stdout.trim(),
            stderr.trim()
        );

        if !output.status.success() {
            let combined = format!("{} {}", stdout, stderr);
            // Fatal WSL errors — the distro can't even start
            let is_fatal = combined.contains("0xd000020c")
                || combined.contains("CreateInstance")
                || combined.contains("WSL_E_");

            if is_fatal {
                tracing::error!("[setup_distro] Fatal WSL error — distro cannot start");
                return Err(SandboxError::WslDistroError(format!(
                    "WSL distro failed to start: {}",
                    combined.trim()
                )));
            }

            tracing::warn!(
                "[setup_distro] Setup had errors but continuing (partial setup may suffice)"
            );
        }

        Ok(())
    }

    /// Ensure the WSL distro is imported and set up.
    pub async fn ensure_distro(&self) -> SandboxResult<()> {
        if self.is_distro_imported().await {
            // Check if setup has been completed
            if self.is_setup_complete().await {
                tracing::debug!("WSL distro already imported and set up");
                // Recovery: write host marker if missing (handles previous setup without marker)
                self.write_wsl_ready_marker_if_missing().await;
                return Ok(());
            }
            tracing::info!("WSL distro imported but not yet set up, running setup...");
            self.setup_distro().await?;
            self.write_wsl_ready_marker().await;
            return Ok(());
        }

        tracing::info!("[ensure_distro] WSL distro not found, downloading and importing...");

        // Use ArchWSL-FS rootfs — pre-built for WSL (v1 & v2), flat rootfs,
        // no repacking needed. https://github.com/yuk7/ArchWSL-FS
        let rootfs_path = self.config.data_dir.join("archwsl-rootfs.tar.gz");

        // Delete suspiciously small files (likely truncated/corrupted downloads)
        if rootfs_path.exists() {
            if let Ok(meta) = tokio::fs::metadata(&rootfs_path).await {
                if meta.len() < 1_000_000 {
                    tracing::warn!(
                        "[ensure_distro] Cached rootfs is only {} bytes — likely corrupted, re-downloading",
                        meta.len()
                    );
                    tokio::fs::remove_file(&rootfs_path).await.ok();
                }
            }
        }
        if !rootfs_path.exists() {
            tracing::info!("[ensure_distro] Downloading ArchWSL rootfs...");
            let rootfs_manager = super::rootfs::RootfsManager::new(self.config.clone());
            rootfs_manager
                .download_file(ARCHWSL_ROOTFS_URL, &rootfs_path)
                .await?;
            tracing::info!("[ensure_distro] Download complete");
        } else {
            tracing::info!(
                "[ensure_distro] Rootfs already cached at {}",
                rootfs_path.display()
            );
        }

        // Import directly into WSL (no repack needed — ArchWSL rootfs is already flat)
        tracing::info!("[ensure_distro] Starting WSL import...");
        self.import_distro(&rootfs_path).await?;
        tracing::info!("[ensure_distro] WSL import succeeded");

        // Clean up tarball
        tokio::fs::remove_file(&rootfs_path).await.ok();

        // Run initial setup
        tracing::info!(
            "[ensure_distro] Starting distro setup (pacman, blackarch repo, system update)..."
        );
        self.setup_distro().await?;
        tracing::info!("[ensure_distro] Distro setup complete");

        // Write host-side marker so the UI can detect readiness without shelling out to wsl.exe
        self.write_wsl_ready_marker().await;
        tracing::info!("[ensure_distro] All done — WSL BlackArch ready");

        Ok(())
    }

    /// Write the `.wsl-ready` host-side marker file so the UI can detect WSL readiness.
    async fn write_wsl_ready_marker(&self) {
        let marker_path = self.config.data_dir.join(".wsl-ready");
        let distro_name = self.config.wsl_distro_name();
        match tokio::fs::write(&marker_path, distro_name).await {
            Ok(()) => tracing::info!("Wrote WSL ready marker at {}", marker_path.display()),
            Err(e) => tracing::warn!("Failed to write WSL ready marker: {}", e),
        }
    }

    /// Write the `.wsl-ready` marker only if it doesn't already exist (recovery path).
    async fn write_wsl_ready_marker_if_missing(&self) {
        let marker_path = self.config.data_dir.join(".wsl-ready");
        if !marker_path.exists() {
            tracing::info!("WSL ready marker missing, writing recovery marker");
            self.write_wsl_ready_marker().await;
        }
    }

    /// Check if the distro setup has been completed (marker file exists).
    async fn is_setup_complete(&self) -> bool {
        #[cfg(not(target_os = "windows"))]
        {
            false
        }
        #[cfg(target_os = "windows")]
        {
            let distro_name = self.config.wsl_distro_name();
            let output = Command::new("wsl.exe")
                .args(["-d", distro_name, "--", "test", "-f", WSL_SETUP_MARKER])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await;

            output.map(|s| s.success()).unwrap_or(false)
        }
    }

    /// Execute a command inside the WSL distro.
    pub async fn execute(
        &self,
        cmd: &str,
        timeout: Duration,
        working_dir: Option<&Path>,
    ) -> SandboxResult<CommandResult> {
        let distro_name = self.config.wsl_distro_name();
        let start = Instant::now();

        let mut args = vec!["-d", distro_name];

        // Set working directory if provided
        let wsl_cwd;
        if let Some(dir) = working_dir {
            wsl_cwd = Self::windows_to_wsl_path(&dir.to_string_lossy());
            args.push("--cd");
            args.push(&wsl_cwd);
        }

        args.extend_from_slice(&["--", "/bin/bash", "-c", cmd]);

        let mut command = Command::new("wsl.exe");
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
            Err(_) => {
                // Timeout — terminate the distro to kill the running command
                let _ = Command::new("wsl.exe")
                    .args(["--terminate", distro_name])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .await;

                Ok(CommandResult::timeout(
                    String::new(),
                    "Command timed out".to_string(),
                    start.elapsed().as_millis() as u64,
                ))
            }
        }
    }

    /// Convert a Windows path (e.g. `C:\Users\foo`) to a WSL path (`/mnt/c/Users/foo`).
    pub fn windows_to_wsl_path(win_path: &str) -> String {
        // Handle drive letter prefix: C:\... → /mnt/c/...
        if win_path.len() >= 2 && win_path.as_bytes()[1] == b':' {
            let drive = (win_path.as_bytes()[0] as char).to_ascii_lowercase();
            let rest = &win_path[2..];
            let unix_rest = rest.replace('\\', "/");
            format!("/mnt/{}{}", drive, unix_rest)
        } else {
            // Already a unix-ish path or relative — just swap backslashes
            win_path.replace('\\', "/")
        }
    }

    /// Decode WSL output which may be UTF-16LE (on Windows) or UTF-8.
    ///
    /// Windows `wsl.exe` emits UTF-16LE — sometimes with a BOM, sometimes without.
    /// Actual WSL process output (from inside the distro) is UTF-8.
    fn decode_wsl_output(bytes: &[u8]) -> String {
        if bytes.is_empty() {
            return String::new();
        }

        // Check for UTF-16LE BOM (0xFF 0xFE)
        if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0xFE {
            let u16s: Vec<u16> = bytes[2..]
                .chunks_exact(2)
                .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                .collect();
            return String::from_utf16_lossy(&u16s);
        }

        // Detect UTF-16LE without BOM: even-length, every other byte (high byte of
        // each u16) is 0x00 for ASCII-range text. This is the common case for
        // wsl.exe error messages.
        if bytes.len() >= 2 && bytes.len().is_multiple_of(2) {
            let looks_utf16le = bytes
                .chunks_exact(2)
                .take(32) // sample first 32 code units
                .all(|chunk| chunk[1] == 0 && chunk[0] != 0);
            if looks_utf16le {
                let u16s: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
                    .collect();
                return String::from_utf16_lossy(&u16s);
            }
        }

        // Otherwise treat as UTF-8
        String::from_utf8_lossy(bytes).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_to_wsl_path_drive_letter() {
        assert_eq!(
            WslExecutor::windows_to_wsl_path(r"C:\Users\foo\project"),
            "/mnt/c/Users/foo/project"
        );
    }

    #[test]
    fn test_windows_to_wsl_path_lowercase_drive() {
        assert_eq!(WslExecutor::windows_to_wsl_path(r"d:\work"), "/mnt/d/work");
    }

    #[test]
    fn test_windows_to_wsl_path_root_drive() {
        assert_eq!(WslExecutor::windows_to_wsl_path(r"C:\"), "/mnt/c/");
    }

    #[test]
    fn test_windows_to_wsl_path_unix_passthrough() {
        assert_eq!(
            WslExecutor::windows_to_wsl_path("/home/user/project"),
            "/home/user/project"
        );
    }

    #[test]
    fn test_windows_to_wsl_path_mixed_separators() {
        assert_eq!(
            WslExecutor::windows_to_wsl_path(r"C:\Users/foo\bar"),
            "/mnt/c/Users/foo/bar"
        );
    }

    #[test]
    fn test_decode_wsl_output_utf8() {
        let input = b"hello world\n";
        assert_eq!(WslExecutor::decode_wsl_output(input), "hello world\n");
    }

    #[test]
    fn test_decode_wsl_output_utf16le_bom() {
        // UTF-16LE BOM + "hi\n"
        let mut bytes = vec![0xFF, 0xFE]; // BOM
        bytes.extend_from_slice(&[b'h', 0, b'i', 0, b'\n', 0]);
        assert_eq!(WslExecutor::decode_wsl_output(&bytes), "hi\n");
    }

    #[tokio::test]
    async fn test_wsl_availability_check() {
        // On non-Windows this should return false
        let available = WslExecutor::is_available().await;
        #[cfg(not(target_os = "windows"))]
        assert!(!available, "WSL should not be available on non-Windows");
        println!("WSL available: {}", available);
    }

    #[tokio::test]
    #[ignore]
    async fn test_wsl_distro_lifecycle() {
        // Integration test — requires Windows with WSL2 enabled
        let config = SandboxConfig::default();
        let executor = WslExecutor::new(config);

        assert!(
            WslExecutor::is_available().await,
            "WSL must be available for this test"
        );

        executor
            .ensure_distro()
            .await
            .expect("Failed to ensure distro");

        assert!(executor.is_distro_imported().await, "Distro not imported");

        let result = executor
            .execute("echo HELLO_WSL", Duration::from_secs(10), None)
            .await
            .expect("Execute failed");

        assert!(result.stdout.contains("HELLO_WSL"));
    }
}
