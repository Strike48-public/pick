//! BlackArch environment setup manager

use pentest_core::settings::settings_dir;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// Process-global setup progress — survives liveview session reconnects.
/// None = not running; Some(f) = in progress (0.0–1.0, or -1.0 = indeterminate).
static GLOBAL_PROGRESS: OnceLock<Mutex<Option<f64>>> = OnceLock::new();

fn global_progress() -> &'static Mutex<Option<f64>> {
    GLOBAL_PROGRESS.get_or_init(|| Mutex::new(None))
}

/// Read the current setup progress from the global (usable by any session).
pub fn get_download_progress() -> Option<f64> {
    global_progress().lock().ok().and_then(|g| *g)
}

#[cfg(feature = "shell-ws")]
pub(crate) fn set_global_progress(p: Option<f64>) {
    if let Ok(mut g) = global_progress().lock() {
        *g = p;
    }
}

/// Default destination directory (kept for settings compat).
pub fn distros_dir() -> PathBuf {
    let dir = settings_dir().join("distros");
    let _ = std::fs::create_dir_all(&dir);
    dir
}

/// Check whether the BlackArch sandbox rootfs is fully set up on disk.
/// Mirrors the check in `RootfsManager::is_ready()` without needing the platform crate.
pub fn is_blackarch_ready() -> bool {
    let data_dir = sandbox_data_dir();

    // Check bwrap/proot sentinel (Linux/macOS)
    let rootfs_ready = data_dir
        .join("blackarch-rootfs")
        .join(".rootfs_version")
        .exists();

    // On Windows, also check the host-side WSL marker written after ensure_distro()
    #[cfg(target_os = "windows")]
    let wsl_ready = data_dir.join(".wsl-ready").exists();
    #[cfg(not(target_os = "windows"))]
    let wsl_ready = false;

    // On macOS, Docker image existence counts as ready
    let docker_ready = is_docker_image_ready();

    rootfs_ready || wsl_ready || docker_ready
}

/// Check if the Docker pentest image exists (non-blocking best-effort).
fn is_docker_image_ready() -> bool {
    std::process::Command::new("docker")
        .args(["image", "inspect", "pentest-blackarch:latest"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Resolve the sandbox data directory, matching `default_data_dir()` in the platform crate.
fn sandbox_data_dir() -> PathBuf {
    #[cfg(target_os = "windows")]
    {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local_app_data).join("pentest-sandbox");
        }
    }

    let base = if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
        PathBuf::from(xdg)
    } else if let Ok(home) = std::env::var("HOME") {
        PathBuf::from(home).join(".local").join("share")
    } else {
        PathBuf::from("/tmp")
    };
    base.join("pentest-sandbox")
}
