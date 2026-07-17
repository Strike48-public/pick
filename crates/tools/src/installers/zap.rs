//! OWASP ZAP installer.
//!
//! ZAP is the FOSS DAST engine Pick drives headlessly via its REST API (see
//! the `zap` tool). In sandbox mode it installs from the `zaproxy` package; in
//! native mode ZAP ships as a vendor tarball / snap / package, so we verify the
//! launcher is present and otherwise return install instructions rather than
//! guessing the host's package manager.

use super::{InstallEvent, ProgressSink, ToolInstaller};
use pentest_core::error::{Error, Result};
use pentest_platform::{get_platform, CommandExec};
use std::time::Duration;

use crate::installers::sandbox_enabled;

/// Candidate launcher names across distros/packaging (BlackArch ships `zap`,
/// some packages ship `zaproxy`, the tarball ships `zap.sh`).
const ZAP_BINARIES: &[&str] = &["zaproxy", "zap.sh", "zap"];

const HOST_INSTRUCTIONS: &str = "Install OWASP ZAP on the host: download the Linux installer from \
     https://www.zaproxy.org/download/ (or `snap install zaproxy --classic`), \
     and ensure `zap.sh` / `zaproxy` is on PATH.";

pub struct ZapInstaller;

impl ZapInstaller {
    async fn launcher_present() -> bool {
        let platform = get_platform();
        for bin in ZAP_BINARIES {
            if platform
                .execute_command("which", &[bin], Duration::from_secs(5))
                .await
                .map(|r| r.exit_code == 0)
                .unwrap_or(false)
            {
                return true;
            }
        }
        false
    }
}

#[async_trait::async_trait]
impl ToolInstaller for ZapInstaller {
    fn id(&self) -> &str {
        "zap"
    }

    fn display_name(&self) -> &str {
        "OWASP ZAP (DAST)"
    }

    async fn is_installed(&self) -> bool {
        Self::launcher_present().await
    }

    async fn install(&self, progress: &ProgressSink) -> Result<()> {
        if Self::launcher_present().await {
            progress(InstallEvent::step("OWASP ZAP already installed"));
            return Ok(());
        }

        if !sandbox_enabled() {
            return Err(Error::ToolExecution(format!(
                "OWASP ZAP is not installed and sandbox is disabled. {HOST_INSTRUCTIONS}"
            )));
        }

        progress(InstallEvent::step(
            "Installing OWASP ZAP via pacman (zaproxy)...",
        ));
        // -Sy refreshes the package DBs first; a bare -S fails on a rootfs whose
        // sync DBs have gone stale (see installers::pacman).
        super::pacman::install("zaproxy", Duration::from_secs(600)).await?;

        if !Self::launcher_present().await {
            return Err(Error::ToolExecution(
                "zaproxy installed but no ZAP launcher found on PATH".to_string(),
            ));
        }

        progress(InstallEvent::step("OWASP ZAP installed"));
        Ok(())
    }

    fn manual_instructions(&self) -> Option<String> {
        Some(HOST_INSTRUCTIONS.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_and_binaries() {
        assert_eq!(ZapInstaller.id(), "zap");
        assert!(ZAP_BINARIES.contains(&"zap.sh"));
    }

    #[test]
    fn manual_instructions_present() {
        assert!(ZapInstaller
            .manual_instructions()
            .unwrap()
            .contains("zaproxy.org"));
    }
}
