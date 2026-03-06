//! Pacman package manager configuration and compatibility
//!
//! Handles cleaning up stale workarounds from previous builds and ensuring
//! pacman.conf is correctly configured for proot compatibility on Android.

use pentest_core::error::Result;

use super::rootfs::get_rootfs_dir;

/// Clean up stale workarounds from previous builds (idempotent).
pub async fn ensure_pacman_compatible() -> Result<()> {
    let rootfs = get_rootfs_dir()?;
    if !rootfs.exists() {
        return Ok(());
    }

    // Clean up old noflock wrapper + shim from previous builds
    let old_wrapper = rootfs.join("usr/local/bin/pacman");
    if old_wrapper.exists() {
        tokio::fs::remove_file(&old_wrapper).await.ok();
    }
    let old_noflock = rootfs.join("usr/local/lib/noflock.so");
    if old_noflock.exists() {
        tokio::fs::remove_file(&old_noflock).await.ok();
    }

    // Fix pacman.conf: ensure SigLevel = Never everywhere (GPGME doesn't work in proot)
    // and DisableSandbox is set (Android kernels don't support Landlock)
    let pacman_conf = rootfs.join("etc/pacman.conf");
    if pacman_conf.exists() {
        let mut content = tokio::fs::read_to_string(&pacman_conf).await?;
        let mut changed = false;

        // Fix blackarch repo to use SigLevel = Never
        if content.contains("SigLevel = Optional TrustAll") {
            content = content.replace("SigLevel = Optional TrustAll", "SigLevel = Never");
            changed = true;
        }

        // Disable DownloadUser — proot can't setuid to the alpm user, causing lock failures
        if content.contains("\nDownloadUser") && !content.contains("\n#DownloadUser") {
            content = content.replace("\nDownloadUser", "\n#DownloadUser");
            changed = true;
            tracing::info!("Disabled DownloadUser for proot compatibility");
        }

        // Ensure DisableSandbox is set (pacman 7.0+ Landlock doesn't work on Android)
        if !content.contains("DisableSandbox") {
            content = content.replace("[options]\n", "[options]\nDisableSandbox\n");
            changed = true;
            tracing::info!("Added DisableSandbox for proot compatibility");
        }

        if changed {
            tokio::fs::write(&pacman_conf, content).await?;
        }
    }

    // Remove stale pacman lock file
    let lock_file = rootfs.join("var/lib/pacman/db.lck");
    if lock_file.exists() {
        tokio::fs::remove_file(&lock_file).await.ok();
    }

    Ok(())
}
