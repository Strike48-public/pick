//! Generic package-based installer.
//!
//! For tools that are a single BlackArch package in sandbox mode but need a
//! specific host install path (pipx, go, distro package) in native mode. In
//! sandbox mode it installs via `pacman -S`; in native mode it verifies the
//! binary is on PATH and otherwise returns the host install instructions
//! rather than guessing at the operator's package manager.

use super::{InstallEvent, ProgressSink, ToolInstaller};
use pentest_core::error::{Error, Result};
use pentest_platform::{get_platform, CommandExec};
use std::time::Duration;

use crate::installers::sandbox_enabled;

/// A tool installed from a single package in the sandbox, with host-specific
/// manual instructions for native mode.
pub struct PackageInstaller {
    id: &'static str,
    display_name: &'static str,
    binary_name: &'static str,
    pacman_package: &'static str,
    host_instructions: &'static str,
}

impl PackageInstaller {
    /// Certipy — Active Directory Certificate Services (AD CS) attack tool.
    pub fn certipy() -> Self {
        Self {
            id: "certipy",
            display_name: "Certipy (AD CS)",
            binary_name: "certipy",
            pacman_package: "certipy",
            host_instructions:
                "Install on the host with: pipx install certipy-ad  (requires pipx).",
        }
    }

    /// NetExec (nxc) — maintained successor to CrackMapExec.
    pub fn netexec() -> Self {
        Self {
            id: "netexec",
            display_name: "NetExec (nxc)",
            binary_name: "nxc",
            pacman_package: "netexec",
            host_instructions:
                "Install on the host with: pipx install git+https://github.com/Pennyw0rth/NetExec",
        }
    }

    /// Kerbrute — Kerberos user enumeration and password spraying.
    pub fn kerbrute() -> Self {
        Self {
            id: "kerbrute",
            display_name: "Kerbrute",
            binary_name: "kerbrute",
            pacman_package: "kerbrute",
            host_instructions:
                "Install on the host with: go install github.com/ropnop/kerbrute@latest \
                 (then ensure $GOPATH/bin is on PATH), or download a release binary from \
                 https://github.com/ropnop/kerbrute/releases",
        }
    }
}

#[async_trait::async_trait]
impl ToolInstaller for PackageInstaller {
    fn id(&self) -> &str {
        self.id
    }

    fn display_name(&self) -> &str {
        self.display_name
    }

    async fn is_installed(&self) -> bool {
        let platform = get_platform();
        platform
            .execute_command("which", &[self.binary_name], Duration::from_secs(5))
            .await
            .map(|r| r.exit_code == 0)
            .unwrap_or(false)
    }

    async fn install(&self, progress: &ProgressSink) -> Result<()> {
        if self.is_installed().await {
            progress(InstallEvent::step(format!(
                "{} already installed",
                self.display_name
            )));
            return Ok(());
        }

        if !sandbox_enabled() {
            // Native mode: we don't guess the host package manager. Surface the
            // tool-specific instructions so the operator installs it once.
            return Err(Error::ToolExecution(format!(
                "{} is not installed and sandbox is disabled. {}",
                self.display_name, self.host_instructions
            )));
        }

        progress(InstallEvent::step(format!(
            "Installing {} via pacman ({})...",
            self.display_name, self.pacman_package
        )));

        // -Sy refreshes the package DBs first; a bare -S fails on a rootfs whose
        // sync DBs have gone stale (see installers::pacman).
        super::pacman::install(self.pacman_package, Duration::from_secs(600)).await?;

        if !self.is_installed().await {
            return Err(Error::ToolExecution(format!(
                "{} reported installed but binary '{}' is not on PATH",
                self.display_name, self.binary_name
            )));
        }

        progress(InstallEvent::step(format!(
            "{} installed",
            self.display_name
        )));
        Ok(())
    }

    fn manual_instructions(&self) -> Option<String> {
        Some(self.host_instructions.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn factories_set_expected_ids_and_binaries() {
        let c = PackageInstaller::certipy();
        assert_eq!(c.id(), "certipy");
        assert_eq!(c.binary_name, "certipy");

        let n = PackageInstaller::netexec();
        assert_eq!(n.id(), "netexec");
        assert_eq!(n.binary_name, "nxc"); // NetExec's binary is `nxc`

        let k = PackageInstaller::kerbrute();
        assert_eq!(k.id(), "kerbrute");
        assert_eq!(k.pacman_package, "kerbrute");
    }

    #[test]
    fn manual_instructions_present() {
        assert!(PackageInstaller::certipy()
            .manual_instructions()
            .unwrap()
            .contains("pipx"));
    }
}
