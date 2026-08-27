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

/// Release tag hosting the openat2-capable proot binaries (#248/#252). The
/// `build-proot.yml` workflow publishes `proot-<arch>` + `proot-<arch>.sha256`
/// under this tag on Strike48-public/pick. Bump this (and the SHA-256 values in
/// [`PROOT_DOWNLOADS`]) when republishing under a new `proot-openat2-vN` tag.
#[cfg(target_os = "linux")]
const PROOT_RELEASE_TAG: &str = "proot-openat2-v1";

/// Per-architecture proot download: (arch, url, expected SHA-256 hex).
///
/// The SHA-256 is verified after download and before the binary is made
/// executable; a mismatch (or an empty placeholder) fails the download rather
/// than running an unverified binary — closing the supply-chain gap the old
/// unchecked `reqwest::get -> write -> chmod` had.
#[cfg(target_os = "linux")]
struct ProotDownload {
    arch: &'static str,
    url: &'static str,
    /// Lowercase hex SHA-256. EMPTY = not yet filled from a published build;
    /// treated as "unverifiable" and refused by `verify_sha256`.
    sha256: &'static str,
}

#[cfg(target_os = "linux")]
const PROOT_DOWNLOADS: &[ProotDownload] = &[
    ProotDownload {
        arch: "x86_64",
        url: "https://github.com/Strike48-public/pick/releases/download/proot-openat2-v1/proot-x86_64",
        // Published by build-proot.yml (run 29788507360); verified against the
        // release's proot-x86_64.sha256 and the binary itself.
        sha256: "2b5e31b7da36b7319eb82483d176cf5ffd6ffbd89480934deb1eb258aca521c4",
    },
    ProotDownload {
        arch: "aarch64",
        url: "https://github.com/Strike48-public/pick/releases/download/proot-openat2-v1/proot-aarch64",
        // Published by build-proot.yml (run 29788507360); verified against the
        // release's proot-aarch64.sha256 and the binary itself.
        sha256: "fddb92926ed9384bedd67db532518d5284fa6bbd7cc2d530672801b871288473",
    },
];

/// Verify `bytes` hashes to the expected lowercase-hex SHA-256. An empty
/// `expected` means the checksum has not been pinned yet (see #252); we refuse
/// rather than run an unverified binary.
#[cfg(target_os = "linux")]
fn verify_sha256(bytes: &[u8], expected: &str, arch: &str) -> SandboxResult<()> {
    if expected.is_empty() {
        return Err(SandboxError::Download(format!(
            "no pinned SHA-256 for proot ({arch}); refusing to run an unverified binary. \
             See #252: fill PROOT_DOWNLOADS[{arch}].sha256 from the published build."
        )));
    }
    use sha2::{Digest, Sha256};
    let actual = format!("{:x}", Sha256::digest(bytes));
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(SandboxError::Download(format!(
            "proot ({arch}) SHA-256 mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

/// Proot executor for universal sandbox support
#[derive(Debug, Clone)]
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
            Err(SandboxError::Download(
                "proot download is only supported on Linux".to_string(),
            ))
        }

        #[cfg(target_os = "linux")]
        {
            let arch = std::env::consts::ARCH;
            let download = PROOT_DOWNLOADS
                .iter()
                .find(|d| d.arch == arch)
                .ok_or_else(|| {
                    SandboxError::Download(format!("No proot binary available for arch: {arch}"))
                })?;

            let dest = config.proot_binary_path();

            // Create parent directory
            if let Some(parent) = dest.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }

            tracing::info!(
                "Downloading openat2-capable proot ({}) from {} [{}]",
                arch,
                download.url,
                PROOT_RELEASE_TAG
            );

            // Download using reqwest with explicit timeouts. A bare
            // `reqwest::get` has no timeout, so a stalled connect or read hangs
            // the caller forever (fail-hang) — it manifested as a 6-hour CI
            // hang once the pins were filled and this path actually ran. Bound
            // both the connect and the whole request so a stall fails closed
            // (SandboxError::Download) instead of blocking indefinitely (#294).
            let client = reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(15))
                .timeout(Duration::from_secs(120))
                .build()
                .map_err(|e| SandboxError::Download(e.to_string()))?;
            let response = client
                .get(download.url)
                .send()
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

            // Verify the SHA-256 BEFORE writing/executing. Fails closed on an
            // unpinned or mismatched checksum — never run an unverified binary.
            verify_sha256(&bytes, download.sha256, arch)?;

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

            tracing::info!("Downloaded + verified proot to {}", dest.display());

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

        // Bind .pick/resources for shared wordlists/tools between host and proot
        if let Ok(home) = std::env::var("HOME") {
            let host_resources = PathBuf::from(&home).join(".pick").join("resources");
            // Create directory if it doesn't exist
            if !host_resources.exists() {
                let _ = std::fs::create_dir_all(&host_resources);
            }
            if host_resources.exists() {
                args.push("-b".to_string());
                args.push(format!(
                    "{}:/root/.pick/resources",
                    host_resources.to_string_lossy()
                ));
            }
        }

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

    // SHA-256 of the 5 bytes "hello", precomputed:
    //   printf 'hello' | sha256sum
    #[cfg(target_os = "linux")]
    const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_sha256_accepts_matching_digest() {
        assert!(verify_sha256(b"hello", HELLO_SHA256, "x86_64").is_ok());
        // Case-insensitive hex comparison.
        assert!(verify_sha256(b"hello", &HELLO_SHA256.to_uppercase(), "x86_64").is_ok());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_sha256_rejects_mismatch() {
        let bad = "0000000000000000000000000000000000000000000000000000000000000000";
        assert!(verify_sha256(b"hello", bad, "x86_64").is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn verify_sha256_refuses_empty_pin() {
        // An unpinned checksum must fail closed, never run unverified.
        assert!(verify_sha256(b"hello", "", "x86_64").is_err());
    }

    // Guard the shipped pins: every PROOT_DOWNLOADS entry must carry a
    // well-formed (64-hex-char, lowercase) SHA-256. Catches a regression to the
    // empty placeholder or a truncated/typo'd hash at test time — before it
    // degrades the connector to "refuses to run an unverified binary" in the
    // field. (Does not fetch the network; it only asserts the pins are shaped
    // like real digests.)
    #[cfg(target_os = "linux")]
    #[test]
    fn every_proot_download_has_a_wellformed_pinned_sha256() {
        assert!(!PROOT_DOWNLOADS.is_empty(), "no proot downloads configured");
        for d in PROOT_DOWNLOADS {
            assert_eq!(
                d.sha256.len(),
                64,
                "proot ({}) SHA-256 must be 64 hex chars, got {}",
                d.arch,
                d.sha256.len()
            );
            assert!(
                d.sha256.chars().all(|c| c.is_ascii_hexdigit()),
                "proot ({}) SHA-256 has non-hex chars: {}",
                d.arch,
                d.sha256
            );
            assert!(
                d.sha256.chars().all(|c| !c.is_ascii_uppercase()),
                "proot ({}) SHA-256 should be lowercase hex",
                d.arch
            );
            // And it must actually satisfy verify_sha256's own well-formedness
            // path (non-empty pin) — i.e. it would not fail closed.
            let mismatch = verify_sha256(b"not the real binary", d.sha256, d.arch);
            assert!(
                matches!(mismatch, Err(SandboxError::Download(_))),
                "expected a mismatch error (pin is well-formed but data differs)"
            );
        }
    }
}
