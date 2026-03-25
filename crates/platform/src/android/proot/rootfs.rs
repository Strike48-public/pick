//! Rootfs downloading, extraction, and configuration
//!
//! Handles downloading the Arch Linux proot-distro tarball, extracting it,
//! and applying BlackArch + proot compatibility configuration.

use pentest_core::error::{Error, Result};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::OnceLock;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use super::{ensure_binaries, get_files_dir, get_native_lib_dir};

/// Arch Linux rootfs URLs — using Termux proot-distro tarballs.
/// These are complete systems with coreutils, SSL certs, working pacman,
/// and DisableSandbox already set in pacman.conf (required for proot).
const ARCH_ROOTFS_AARCH64: &str =
    "https://github.com/termux/proot-distro/releases/download/v4.34.2/archlinux-aarch64-pd-v4.34.2.tar.xz";
const ARCH_ROOTFS_X86_64: &str =
    "https://github.com/termux/proot-distro/releases/download/v4.34.2/archlinux-x86_64-pd-v4.34.2.tar.xz";

/// SHA256 hashes for integrity verification of known rootfs archives.
/// Leave empty to skip verification (e.g. while hashes are not yet known).
const ARCH_ROOTFS_SHA256_AARCH64: &str = "";
const ARCH_ROOTFS_SHA256_X86_64: &str = "";

/// BlackArch repository configuration
const BLACKARCH_REPO_CONFIG: &str = r#"
[blackarch]
Server = https://blackarch.org/blackarch/$repo/os/$arch
SigLevel = Never
"#;

/// Global rootfs setup lock to prevent concurrent setup
static ROOTFS_SETUP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn get_setup_lock() -> &'static Mutex<()> {
    ROOTFS_SETUP_LOCK.get_or_init(|| Mutex::new(()))
}

/// Get the rootfs directory path
pub(crate) fn get_rootfs_dir() -> Result<PathBuf> {
    Ok(get_files_dir()?.join("blackarch-rootfs"))
}

/// Check if the rootfs has been extracted (binaries exist)
fn is_rootfs_extracted() -> bool {
    if let Ok(rootfs) = get_rootfs_dir() {
        // On x86_64 Arch, /bin is a symlink to usr/bin, so check both locations
        let has_bash = rootfs.join("usr").join("bin").join("bash").exists()
            || rootfs.join("bin").join("bash").exists();
        let has_pacman = rootfs.join("usr").join("bin").join("pacman").exists();
        has_bash && has_pacman
    } else {
        false
    }
}

/// Check if the BlackArch rootfs is fully set up (extracted + configured)
pub(crate) fn is_rootfs_ready() -> bool {
    if let Ok(rootfs) = get_rootfs_dir() {
        rootfs.join(".setup-complete").exists()
    } else {
        false
    }
}

/// Delete the entire rootfs so the next `ensure_rootfs` call rebuilds from scratch.
pub async fn destroy_rootfs() -> Result<()> {
    let rootfs = get_rootfs_dir()?;
    if rootfs.exists() {
        tracing::info!("Destroying rootfs at {}", rootfs.display());
        tokio::fs::remove_dir_all(&rootfs).await.map_err(|e| {
            Error::ToolExecution(format!("Failed to remove rootfs: {}", e))
        })?;
    }
    Ok(())
}

/// Detect the device architecture
fn detect_arch() -> &'static str {
    let arch = std::env::consts::ARCH;
    tracing::info!("Detected architecture: {}", arch);
    match arch {
        "aarch64" => "aarch64",
        "arm" => "armv7h",
        "x86_64" => "x86_64",
        "x86" => "x86_64", // x86 emulators can run x86_64
        other => {
            tracing::warn!("Unknown architecture '{}', defaulting to aarch64", other);
            "aarch64"
        }
    }
}

/// Get the rootfs URL for the current architecture.
///
/// If the `PROOT_ROOTFS_URL` environment variable is set, its value is used
/// instead of the built-in URL. This allows operators to mirror the tarball
/// locally or pin a different release without rebuilding.
fn get_rootfs_url() -> String {
    if let Ok(url) = std::env::var("PROOT_ROOTFS_URL") {
        if !url.is_empty() {
            tracing::info!("Using PROOT_ROOTFS_URL override: {}", url);
            return url;
        }
    }
    match detect_arch() {
        "x86_64" => ARCH_ROOTFS_X86_64.to_string(),
        // armv7 uses the same aarch64 build (proot handles translation)
        _ => ARCH_ROOTFS_AARCH64.to_string(),
    }
}

/// Get the expected SHA256 hash for the current architecture's rootfs.
///
/// Returns `None` when a custom URL is provided via `PROOT_ROOTFS_URL`
/// (we cannot know the hash of an arbitrary tarball) or when the built-in
/// hash constant is empty (hash not yet populated).
fn get_rootfs_expected_sha256() -> Option<&'static str> {
    // Custom URL — skip verification
    if std::env::var("PROOT_ROOTFS_URL")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        return None;
    }
    let hash = match detect_arch() {
        "x86_64" => ARCH_ROOTFS_SHA256_X86_64,
        _ => ARCH_ROOTFS_SHA256_AARCH64,
    };
    if hash.is_empty() {
        None
    } else {
        Some(hash)
    }
}

/// Send a progress message (if sender provided)
async fn send_progress(tx: &Option<tokio::sync::mpsc::Sender<String>>, msg: &str) {
    if let Some(tx) = tx {
        let _ = tx.send(msg.to_string()).await;
    }
}

/// Download a file from URL to destination with optional progress
async fn download_file(
    url: &str,
    dest: &PathBuf,
    progress: &Option<tokio::sync::mpsc::Sender<String>>,
) -> Result<()> {
    tracing::info!("Downloading {} to {}", url, dest.display());

    let response = reqwest::get(url)
        .await
        .map_err(|e| Error::ToolExecution(format!("Download failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(Error::ToolExecution(format!(
            "HTTP error: {}",
            response.status()
        )));
    }

    let content_length = response.content_length();

    if let Some(parent) = dest.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    // Stream to disk instead of buffering entire file in memory
    let mut file = tokio::fs::File::create(dest).await?;
    let mut stream = response.bytes_stream();
    let mut total: u64 = 0;
    let mut last_report: u64 = 0;
    use futures::StreamExt;
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|e| Error::ToolExecution(format!("Download read failed: {}", e)))?;
        file.write_all(&chunk).await?;
        total += chunk.len() as u64;
        // Report every ~5MB
        if total - last_report >= 5_000_000 {
            last_report = total;
            let mb = total / 1_000_000;
            let msg = if let Some(len) = content_length {
                format!(
                    "\r\x1b[K  Downloading rootfs... {} / {} MB",
                    mb,
                    len / 1_000_000
                )
            } else {
                format!("\r\x1b[K  Downloading rootfs... {} MB", mb)
            };
            send_progress(progress, &msg).await;
        }
    }
    file.flush().await?;

    tracing::info!("Downloaded {} bytes to {}", total, dest.display());

    Ok(())
}

/// Ensure the BlackArch rootfs is set up (no progress reporting).
pub async fn ensure_rootfs() -> Result<PathBuf> {
    ensure_rootfs_with_progress(None).await
}

/// Ensure the BlackArch rootfs is set up, with optional progress callback.
///
/// Uses Termux proot-distro Arch Linux tarballs which provide a complete
/// system (coreutils, SSL certs, working pacman with DisableSandbox).
/// We add the BlackArch repo on top.
pub async fn ensure_rootfs_with_progress(
    progress: Option<tokio::sync::mpsc::Sender<String>>,
) -> Result<PathBuf> {
    let rootfs = get_rootfs_dir()?;

    if is_rootfs_ready() {
        return Ok(rootfs);
    }

    let _lock = get_setup_lock().lock().await;

    // Re-check under lock
    if is_rootfs_ready() {
        return Ok(rootfs);
    }

    tracing::info!("Setting up BlackArch rootfs at {}", rootfs.display());

    let files_dir = get_files_dir()?;
    ensure_binaries()?;

    // If rootfs was extracted but config never completed, skip to config
    if !is_rootfs_extracted() {
        // Clean up any incomplete extraction
        if rootfs.exists() {
            tracing::info!("Removing incomplete rootfs");
            tokio::fs::remove_dir_all(&rootfs).await.ok();
        }
        // Also clean up old-style root.x86_64 if present
        let old_extracted = files_dir.join("root.x86_64");
        if old_extracted.exists() {
            tokio::fs::remove_dir_all(&old_extracted).await.ok();
        }

        let tarball = files_dir.join("archlinux-rootfs.tar.xz");

        if !tarball.exists() {
            let url = get_rootfs_url();
            tracing::info!("Downloading Arch Linux from {}", url);
            send_progress(&progress, "\r\n  Downloading BlackArch rootfs...\r\n").await;
            download_file(&url, &tarball, &progress).await?;
            send_progress(&progress, "\r\n  Download complete.\r\n").await;

            // Verify SHA256 integrity when a known hash is available.
            // Custom URLs (via PROOT_ROOTFS_URL) and empty hash constants
            // skip verification so operators can use their own tarballs.
            if let Some(expected_hash) = get_rootfs_expected_sha256() {
                send_progress(&progress, "  Verifying download integrity...\r\n").await;
                let tarball_for_hash = tarball.clone();
                let computed =
                    tokio::task::spawn_blocking(move || -> std::result::Result<String, Error> {
                        let mut hasher = Sha256::new();
                        let mut file = std::fs::File::open(&tarball_for_hash).map_err(|e| {
                            Error::ToolExecution(format!(
                                "Failed to open tarball for hashing: {}",
                                e
                            ))
                        })?;
                        std::io::copy(&mut file, &mut hasher).map_err(|e| {
                            Error::ToolExecution(format!(
                                "Failed to read tarball for hashing: {}",
                                e
                            ))
                        })?;
                        let hash = hasher.finalize();
                        Ok(format!("{:x}", hash))
                    })
                    .await
                    .map_err(|e| Error::ToolExecution(format!("hash task panicked: {}", e)))??;

                if computed != expected_hash {
                    tracing::error!(
                        "SHA256 mismatch: expected {} but got {}",
                        expected_hash,
                        computed,
                    );
                    // Remove the corrupt/tampered file so the next attempt re-downloads
                    tokio::fs::remove_file(&tarball).await.ok();
                    return Err(Error::ToolExecution(format!(
                        "Rootfs integrity check failed: SHA256 mismatch (expected {}, got {})",
                        expected_hash, computed,
                    )));
                }
                tracing::info!("SHA256 verified: {}", computed);
                send_progress(&progress, "  Integrity check passed.\r\n").await;
            }
        }

        // proot-distro tarballs extract directly (no subdirectory)
        tokio::fs::create_dir_all(&rootfs).await?;

        tracing::info!("Extracting rootfs (pure Rust xz+tar)...");
        send_progress(&progress, "  Extracting rootfs...\r\n").await;
        // Use Rust tar + xz2 crates instead of busybox tar.
        // Android's seccomp kills busybox xz decompression when spawned from an app process.
        // proot-distro tarballs have a top-level dir (e.g. archlinux-x86_64/)
        // so we strip the first path component.
        let tarball_path = tarball.clone();
        let rootfs_path = rootfs.clone();
        let extract_progress = progress.clone();
        tokio::task::spawn_blocking(move || -> std::result::Result<(), Error> {
            let file = std::fs::File::open(&tarball_path)
                .map_err(|e| Error::ToolExecution(format!("Failed to open tarball: {}", e)))?;
            let xz_decoder = xz2::read::XzDecoder::new(file);
            let mut archive = tar::Archive::new(xz_decoder);

            let mut count: u64 = 0;
            for entry in archive
                .entries()
                .map_err(|e| Error::ToolExecution(format!("tar entries: {}", e)))?
            {
                let mut entry =
                    entry.map_err(|e| Error::ToolExecution(format!("tar entry: {}", e)))?;
                // Strip first component (e.g. archlinux-x86_64/)
                let path = entry
                    .path()
                    .map_err(|e| Error::ToolExecution(format!("entry path: {}", e)))?;
                let stripped: PathBuf = path.components().skip(1).collect();
                if stripped.as_os_str().is_empty() {
                    continue; // skip the top-level directory entry itself
                }
                let dest = rootfs_path.join(&stripped);
                entry.unpack(&dest).map_err(|e| {
                    Error::ToolExecution(format!("unpack {}: {}", stripped.display(), e))
                })?;
                count += 1;
                if count.is_multiple_of(5000) {
                    tracing::info!("Extracted {} files...", count);
                    if let Some(ref tx) = extract_progress {
                        let _ = tx.blocking_send(format!("\r\x1b[K  Extracted {} files...", count));
                    }
                }
            }
            tracing::info!("Extraction complete: {} files", count);
            Ok(())
        })
        .await
        .map_err(|e| Error::ToolExecution(format!("extraction task panicked: {}", e)))?
        .map_err(|e| Error::ToolExecution(format!("extraction failed: {}", e)))?;

        // Clean up tarball
        tokio::fs::remove_file(&tarball).await.ok();
        // Also clean up old tarballs from previous approach
        tokio::fs::remove_file(&files_dir.join("archlinux-bootstrap.tar.gz"))
            .await
            .ok();
        tokio::fs::remove_file(&files_dir.join("archlinux-arm.tar.gz"))
            .await
            .ok();

        tracing::info!("Rootfs extracted successfully");
        send_progress(&progress, "\r\n  Extraction complete.\r\n").await;
    } else {
        tracing::info!("Rootfs already extracted, applying config...");
    }

    // --- Idempotent configuration (always runs if .setup-complete is missing) ---

    // Ensure /var/lib/pacman exists (bootstrap may not have it)
    tokio::fs::create_dir_all(rootfs.join("var/lib/pacman"))
        .await
        .ok();

    // Remove profile scripts that break under proot (dup() not implemented)
    let profile_d = rootfs.join("etc/profile.d");
    for noisy in &["80-systemd-osc-context.sh", "debuginfod.sh"] {
        tokio::fs::remove_file(profile_d.join(noisy)).await.ok();
    }

    // Configure pacman.conf for proot compatibility
    let pacman_conf = rootfs.join("etc/pacman.conf");
    if pacman_conf.exists() {
        let mut content = tokio::fs::read_to_string(&pacman_conf).await?;
        let mut changed = false;

        // Disable signature verification — GPGME doesn't work reliably in proot
        // (scdaemon hangs, socket IPC issues). This is a security trade-off but
        // acceptable for a sandboxed proot environment on Android.
        if !content.contains("SigLevel = Never") {
            content = content.replace(
                "SigLevel    = Required DatabaseOptional",
                "SigLevel = Never",
            );
            content = content.replace("SigLevel = Required DatabaseOptional", "SigLevel = Never");
            changed = true;
            tracing::info!(
                "Disabled pacman signature verification (GPGME incompatible with proot)"
            );
        }

        // Disable DownloadUser — proot can't setuid/setgid to the alpm user,
        // which causes the database lock operation to fail. Comment it out.
        if content.contains("\nDownloadUser") && !content.contains("\n#DownloadUser") {
            content = content.replace("\nDownloadUser", "\n#DownloadUser");
            changed = true;
            tracing::info!("Disabled DownloadUser for proot compatibility (no setuid)");
        }

        // Add BlackArch repository
        if !content.contains("[blackarch]") {
            content.push_str(BLACKARCH_REPO_CONFIG);
            changed = true;
            tracing::info!("Added BlackArch repo to pacman.conf");
        }

        if changed {
            tokio::fs::write(&pacman_conf, content).await?;
        }
    }

    // Disable scdaemon (smartcard daemon) — it hangs in proot during GPG operations
    let gnupg_dir = rootfs.join("etc/pacman.d/gnupg");
    tokio::fs::create_dir_all(&gnupg_dir).await.ok();
    let gpg_agent_conf = gnupg_dir.join("gpg-agent.conf");
    if !gpg_agent_conf.exists() {
        tokio::fs::write(&gpg_agent_conf, "disable-scdaemon\n")
            .await
            .ok();
        tracing::info!("Disabled scdaemon for proot compatibility");
    }

    // Install syscall_compat.so — Android's seccomp blocks dup2/access/pipe but
    // glibc uses them. This LD_PRELOAD library overrides to use dup3/faccessat/pipe2.
    let lib_dir = get_native_lib_dir()?;
    let compat_src = lib_dir.join("libsyscall_compat.so");
    if compat_src.exists() {
        let local_lib = rootfs.join("usr/local/lib");
        tokio::fs::create_dir_all(&local_lib).await.ok();
        tokio::fs::copy(&compat_src, local_lib.join("syscall_compat.so"))
            .await
            .ok();
        tracing::info!("Installed syscall_compat.so for Android seccomp compatibility");
    } else {
        tracing::warn!("libsyscall_compat.so not found — bash redirects may fail");
    }

    // Write resolv.conf directly (Android has no /etc/resolv.conf to bind-mount)
    let resolv_conf = rootfs.join("etc/resolv.conf");
    tokio::fs::write(&resolv_conf, "nameserver 8.8.8.8\nnameserver 8.8.4.4\n").await?;
    tracing::info!("Wrote resolv.conf with Google DNS");

    // Sync package databases so tools can install packages on first use
    tracing::info!("Syncing pacman package databases...");
    send_progress(&progress, "  Syncing package databases...\r\n").await;
    match run_in_rootfs(&rootfs, "pacman", &["-Sy", "--noconfirm"]).await {
        Ok(output) => {
            tracing::info!("pacman -Sy completed: {}", String::from_utf8_lossy(&output.stdout));
            send_progress(&progress, "  Package databases synced.\r\n").await;
        }
        Err(e) => {
            // Non-fatal — tools will try again on first use
            tracing::warn!("pacman -Sy failed (non-fatal): {}", e);
            send_progress(&progress, "  Warning: package database sync failed, tools may need manual sync.\r\n").await;
        }
    }

    // Install essential pentest packages
    tracing::info!("Installing essential pentest tools...");
    send_progress(&progress, "  Installing pentest tools (aircrack-ng, nmap, etc.)...\r\n").await;
    match run_in_rootfs(
        &rootfs,
        "pacman",
        &[
            "-S",
            "--noconfirm",
            "--needed",
            "aircrack-ng",
            "iw",
            "nmap",
            "macchanger",
            "tcpdump",
            "wireless_tools",
        ],
    )
    .await
    {
        Ok(output) => {
            tracing::info!(
                "Package install completed: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            send_progress(&progress, "  Pentest tools installed.\r\n").await;
        }
        Err(e) => {
            // Non-fatal — user can install manually later
            tracing::warn!("Package install failed (non-fatal): {}", e);
            send_progress(
                &progress,
                "  Warning: some tools failed to install. You can install them manually.\r\n",
            )
            .await;
        }
    }

    // Mark setup as complete
    tokio::fs::write(rootfs.join(".setup-complete"), "1").await?;

    tracing::info!("BlackArch rootfs setup complete");
    send_progress(&progress, "  Setup complete!\r\n\r\n").await;

    Ok(rootfs)
}

/// Run a command inside the proot rootfs during setup (before .setup-complete exists).
/// Unlike execute_in_proot, this doesn't call ensure_rootfs (avoiding recursion).
async fn run_in_rootfs(
    rootfs: &std::path::Path,
    cmd: &str,
    args: &[&str],
) -> Result<std::process::Output> {
    let (proot, _) = ensure_binaries()?;
    let lib_dir = get_native_lib_dir()?;
    let tmp_dir = rootfs.parent().unwrap_or(rootfs).join("proot-tmp");
    tokio::fs::create_dir_all(&tmp_dir).await.ok();

    let loader = proot.parent().map(|d| d.join("libproot_loader.so"));
    let talloc = proot.parent().map(|d| d.join("libtalloc.so"));
    let compat = rootfs.join("usr/local/lib/syscall_compat.so");

    let mut command = tokio::process::Command::new(&proot);
    if let Some(ref ldr) = loader {
        if ldr.exists() {
            command.env("PROOT_LOADER", ldr);
        }
    }
    if let Some(ref t) = talloc {
        if t.exists() {
            let ld_path = format!(
                "{}:{}",
                t.parent().unwrap().display(),
                lib_dir.display()
            );
            command.env("LD_LIBRARY_PATH", ld_path);
        }
    }
    if compat.exists() {
        command.env("LD_PRELOAD", &compat);
    }
    command.env("PROOT_TMP_DIR", &tmp_dir);

    command
        .arg("-0") // fake root
        .arg("-r").arg(rootfs)
        .arg("-b").arg("/dev")
        .arg("-b").arg("/proc")
        .arg("-b").arg("/sys")
        .arg("-w").arg("/root")
        .arg(cmd)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());

    let output = tokio::time::timeout(
        std::time::Duration::from_secs(120),
        command.output(),
    )
    .await
    .map_err(|_| Error::ToolExecution("pacman -Sy timed out after 120s".to_string()))?
    .map_err(|e| Error::ToolExecution(format!("proot exec failed: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!("Command {cmd} failed: {stderr}");
    }

    Ok(output)
}
