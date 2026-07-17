//! Shared pacman install helper for sandbox installers.
//!
//! Every sandbox tool install must refresh the package databases before
//! installing. The rootfs setup syncs the DBs once ([`crate`]'s rootfs
//! bootstrap runs `pacman -Syu`), but that sync is best-effort and goes stale:
//! once the `core`/`extra`/`blackarch` sync DBs are missing or outdated, a bare
//! `pacman -S <pkg>` fails with
//! `database file for 'core' does not exist (use '-Sy' to download)`.
//!
//! Routing all sandbox installs through [`install`] guarantees the `-y` refresh
//! happens first, mirroring what the Docker and WSL backends already do before
//! their own installs.

use pentest_core::error::{Error, Result};
use pentest_platform::{get_platform, CommandExec};
use std::time::Duration;

/// Build the `pacman` argument vector for a sandbox package install.
///
/// The leading `-Sy` refreshes the package databases before resolving the
/// target, which is the whole point: it prevents the "database file for 'core'
/// does not exist" failure on a rootfs whose sync DBs have gone stale. This is
/// a deliberate `-Sy` (not `-Syu`): the rootfs is fully upgraded once at setup,
/// and a per-tool full-system upgrade would be slow and surprising. `--needed`
/// makes re-runs idempotent (pacman skips an already-current package).
pub(crate) fn install_args(pkg: &str) -> [&str; 4] {
    ["-Sy", "--noconfirm", "--needed", pkg]
}

/// Install `pkg` inside the sandbox via `pacman -Sy --noconfirm --needed`.
///
/// Returns a `ToolExecution` error carrying pacman's stderr on non-zero exit.
/// The caller is responsible for the pre-install "already present?" check and
/// the post-install "binary on PATH?" verification — this helper owns only the
/// database-refresh-and-install step that every sandbox installer shares.
pub(crate) async fn install(pkg: &str, timeout: Duration) -> Result<()> {
    let platform = get_platform();
    let result = platform
        .execute_command("pacman", &install_args(pkg), timeout)
        .await?;

    if result.exit_code != 0 {
        return Err(Error::ToolExecution(format!(
            "Failed to install {pkg}: {}",
            result.stderr
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_args_refresh_db_before_installing() {
        // The leading operation must be -Sy (refresh + sync), never a bare -S:
        // a bare -S is exactly the bug that fails on a stale sync DB.
        let args = install_args("python-bloodhound");
        assert_eq!(args[0], "-Sy", "must refresh databases before install");
        assert!(args.contains(&"--noconfirm"), "install must be unattended");
        assert_eq!(
            args.last().copied(),
            Some("python-bloodhound"),
            "package name must be the final argument"
        );
    }

    #[test]
    fn install_args_never_uses_bare_dash_s() {
        let args = install_args("metasploit");
        assert!(
            !args.contains(&"-S"),
            "bare -S skips the DB refresh and reintroduces the stale-DB failure"
        );
    }
}
