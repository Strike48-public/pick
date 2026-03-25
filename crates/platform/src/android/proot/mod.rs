//! Android proot command execution with BlackArch Linux
//!
//! Provides command execution via proot with a BlackArch Linux rootfs.
//! Users install packages themselves via pacman. Binary locations obtained via JNI.
//!
//! This module is split into submodules:
//! - `rootfs` — Rootfs downloading, extraction, and configuration
//! - `pacman` — Pacman package manager compatibility fixes

mod pacman;
mod rootfs;

use super::jni_bridge::with_jni;
use crate::traits::CommandResult;
use pentest_core::error::{Error, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

// Re-export public API from submodules
pub use pacman::ensure_pacman_compatible;
pub use rootfs::{destroy_rootfs, ensure_rootfs, ensure_rootfs_with_progress};

/// Get the app's native library directory (where .so files from jniLibs live).
pub(super) fn get_native_lib_dir() -> Result<PathBuf> {
    with_jni(|env, ctx| {
        let app_info = env
            .call_method(
                ctx,
                "getApplicationInfo",
                "()Landroid/content/pm/ApplicationInfo;",
                &[],
            )
            .and_then(|v| v.l())
            .map_err(|e| Error::ToolExecution(format!("getApplicationInfo: {e}")))?;

        let native_dir = env
            .get_field(&app_info, "nativeLibraryDir", "Ljava/lang/String;")
            .and_then(|v| v.l())
            .map_err(|e| Error::ToolExecution(format!("nativeLibraryDir: {e}")))?;

        let dir_str = super::jni_bridge::jstring_to_string(env, &native_dir);
        Ok(PathBuf::from(dir_str))
    })
}

/// Get the app's internal files directory.
pub(super) fn get_files_dir() -> Result<PathBuf> {
    with_jni(|env, ctx| {
        let files_dir = env
            .call_method(ctx, "getFilesDir", "()Ljava/io/File;", &[])
            .and_then(|v| v.l())
            .map_err(|e| Error::ToolExecution(format!("getFilesDir: {e}")))?;

        let abs_path = env
            .call_method(&files_dir, "getAbsolutePath", "()Ljava/lang/String;", &[])
            .and_then(|v| v.l())
            .map_err(|e| Error::ToolExecution(format!("getAbsolutePath: {e}")))?;

        let path_str = super::jni_bridge::jstring_to_string(env, &abs_path);
        Ok(PathBuf::from(path_str))
    })
}

/// Check that proot and busybox binaries exist in the native lib dir.
pub fn ensure_binaries() -> Result<(PathBuf, PathBuf)> {
    let lib_dir = get_native_lib_dir()?;
    let proot = lib_dir.join("libproot.so");
    let busybox = lib_dir.join("libbusybox.so");

    if !proot.exists() {
        return Err(Error::ToolExecution(format!(
            "proot binary not found at {}",
            proot.display()
        )));
    }
    if !busybox.exists() {
        return Err(Error::ToolExecution(format!(
            "busybox binary not found at {}",
            busybox.display()
        )));
    }

    Ok((proot, busybox))
}

/// Create a symlink for a busybox applet and return a Command that runs it.
/// Busybox dispatches based on argv[0], so we create a symlink named after the
/// applet pointing to libbusybox.so. The symlink is created in the app's files dir.
fn busybox_command(busybox: &Path, applet: &str) -> Result<tokio::process::Command> {
    let files_dir = get_files_dir()?;
    let link_dir = files_dir.join("busybox-applets");
    std::fs::create_dir_all(&link_dir).ok();

    let applet_link = link_dir.join(applet);
    #[cfg(unix)]
    {
        // Always remove and recreate — the busybox path can change on app update
        std::fs::remove_file(&applet_link).ok();
        std::os::unix::fs::symlink(busybox, &applet_link).map_err(|e| {
            Error::ToolExecution(format!(
                "Failed to create busybox symlink for {}: {}",
                applet, e
            ))
        })?;
    }

    Ok(tokio::process::Command::new(applet_link))
}

/// Execute a command inside the proot BlackArch environment
pub async fn execute_in_proot(
    cmd: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<CommandResult> {
    let (proot, _) = ensure_binaries()?;
    let rootfs = ensure_rootfs().await?;

    let full_cmd = if args.is_empty() {
        cmd.to_string()
    } else {
        format!("{} {}", cmd, args.join(" "))
    };

    let start = Instant::now();

    // proot needs a writable temp dir on Android
    let tmp_dir = rootfs.parent().unwrap_or(&rootfs).join("proot-tmp");
    tokio::fs::create_dir_all(&tmp_dir).await.ok();

    // Point proot to its unbundled loader (lives next to the binary in jniLibs)
    let loader = proot.parent().map(|d| d.join("libproot_loader.so"));

    let mut command = tokio::process::Command::new(&proot);
    if let Some(ref ldr) = loader {
        if ldr.exists() {
            command.env("PROOT_LOADER", ldr);
        }
    }
    // Termux proot is dynamically linked against libtalloc.so.2
    // Android only packages lib*.so files, so we ship libtalloc.so and create
    // a symlink libtalloc.so.2 -> libtalloc.so at runtime
    if let Some(lib_dir) = proot.parent() {
        let talloc = lib_dir.join("libtalloc.so");
        let talloc_versioned = lib_dir.join("libtalloc.so.2");
        if talloc.exists() && !talloc_versioned.exists() {
            let _ = std::os::unix::fs::symlink(&talloc, &talloc_versioned);
        }
        command.env("LD_LIBRARY_PATH", lib_dir);
    }

    let rootfs_lossy = rootfs.to_string_lossy().to_string();
    let l2s_dir = rootfs.join(".l2s");
    std::fs::create_dir_all(&l2s_dir).ok();

    let result = tokio::time::timeout(
        timeout,
        command
            .args([
                "-0",
                "--link2symlink",
                "--kill-on-exit",
                "--sysvipc", // emulate System V IPC (required for pacman locking)
                "-r",
                &rootfs_lossy,
                "-b",
                "/dev",
                "-b",
                "/proc",
                "-b",
                "/sys",
                "-b",
                "/dev/urandom:/dev/random",
                "-b",
                "/proc/self/fd:/dev/fd",
                "-w",
                "/root",
            ])
            .arg("/bin/bash")
            .arg("-c")
            .arg(&full_cmd)
            .env("HOME", "/root")
            .env("USER", "root")
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("TERM", "xterm-256color")
            .env("PROOT_TMP_DIR", &tmp_dir)
            .env("TMPDIR", &tmp_dir)
            .env("PROOT_L2S_DIR", l2s_dir.to_string_lossy().as_ref())
            .output(),
    )
    .await;

    let duration_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(output)) => Ok(CommandResult::success(
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
            output.status.code().unwrap_or(-1),
            duration_ms,
        )),
        Ok(Err(e)) => Err(Error::ToolExecution(format!("proot execution failed: {e}"))),
        Err(_) => Ok(CommandResult::timeout(
            String::new(),
            "Command timed out".to_string(),
            duration_ms,
        )),
    }
}

/// Execute a busybox applet directly (no proot)
pub async fn execute_busybox(
    applet: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<CommandResult> {
    let (_, busybox) = ensure_binaries()?;
    let start = Instant::now();

    let result = tokio::time::timeout(
        timeout,
        busybox_command(&busybox, applet)?.args(args).output(),
    )
    .await;

    let duration_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(output)) => Ok(CommandResult::success(
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
            output.status.code().unwrap_or(-1),
            duration_ms,
        )),
        Ok(Err(e)) => Err(Error::ToolExecution(format!(
            "busybox execution failed: {e}"
        ))),
        Err(_) => Ok(CommandResult::timeout(
            String::new(),
            String::new(),
            duration_ms,
        )),
    }
}

/// Execute a command — tries proot first, falls back to busybox, then direct execution.
pub async fn execute_command(cmd: &str, args: &[&str], timeout: Duration) -> Result<CommandResult> {
    // Try proot first
    tracing::debug!("execute_command: trying proot backend for '{}'", cmd);
    match execute_in_proot(cmd, args, timeout).await {
        Ok(result) => {
            tracing::debug!("execute_command: proot backend succeeded for '{}'", cmd);
            return Ok(result);
        }
        Err(e) => {
            tracing::debug!("execute_command: proot failed ({}), trying busybox", e);
        }
    }

    // Fallback to busybox
    tracing::debug!("execute_command: trying busybox backend for '{}'", cmd);
    match execute_busybox(cmd, args, timeout).await {
        Ok(result) if result.exit_code == 0 => {
            tracing::debug!("execute_command: busybox backend succeeded for '{}'", cmd);
            return Ok(result);
        }
        Ok(result) => {
            tracing::debug!(
                "execute_command: busybox failed (non-zero exit code {}), trying direct",
                result.exit_code
            );
        }
        Err(e) => {
            tracing::debug!("execute_command: busybox failed ({}), trying direct", e);
        }
    }

    // Final fallback to direct execution
    tracing::debug!("execute_command: trying direct backend for '{}'", cmd);
    let start = Instant::now();
    let result = tokio::time::timeout(
        timeout,
        tokio::process::Command::new(cmd).args(args).output(),
    )
    .await;

    let duration_ms = start.elapsed().as_millis() as u64;

    match result {
        Ok(Ok(output)) => {
            tracing::debug!("execute_command: direct backend succeeded for '{}'", cmd);
            Ok(CommandResult::success(
                String::from_utf8_lossy(&output.stdout).into_owned(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
                output.status.code().unwrap_or(-1),
                duration_ms,
            ))
        }
        Ok(Err(e)) => {
            tracing::debug!(
                "execute_command: direct backend failed ({}) — all backends exhausted for '{}'",
                e,
                cmd
            );
            Err(Error::ToolExecution(format!(
                "Command execution failed: {e}"
            )))
        }
        Err(_) => {
            tracing::debug!("execute_command: direct backend timed out for '{}'", cmd);
            Ok(CommandResult::timeout(
                String::new(),
                String::new(),
                duration_ms,
            ))
        }
    }
}
