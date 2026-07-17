//! BloodHound installer (data collection client).
//!
//! "BloodHound" spans two things: the BloodHound CE web app (a Docker-Compose
//! stack with a neo4j graph database) and the Python collector
//! (`bloodhound-python`) that gathers AD data. The connector's job is data
//! collection, so this installer targets the collector (pacman / pipx). The
//! full CE web app + neo4j is a persistent service stack and is surfaced as a
//! manual step, not auto-installed, because it requires Docker and long-running
//! containers the connector does not manage.

use super::{InstallEvent, ProgressSink, ToolInstaller};
use pentest_core::error::{Error, Result};
use std::time::Duration;

use crate::installers::sandbox_enabled;

/// Binary the collector package installs. The BlackArch package
/// `bloodhound-ce-python` provides the `bloodhound-ce-python` collector (the
/// v5/CE data collector). The old `python-bloodhound` / `bloodhound-python`
/// names do not exist in the current repos — using them caused
/// `error: target not found: python-bloodhound`.
const COLLECTOR_BINARY: &str = "bloodhound-ce-python";

/// BlackArch package that provides [`COLLECTOR_BINARY`].
const COLLECTOR_PACKAGE: &str = "bloodhound-ce-python";

const HOST_INSTRUCTIONS: &str =
    "Install the collector on the host with: pipx install bloodhound-ce  (provides `bloodhound-ce-python`). \
     For the BloodHound CE UI + neo4j graph, run the official Docker Compose stack from \
     https://github.com/SpecterOps/BloodHound (docker compose up); that service is not auto-managed \
     by the connector.";

pub struct BloodHoundInstaller;

impl BloodHoundInstaller {
    async fn collector_present() -> bool {
        super::binary_on_path(COLLECTOR_BINARY).await
    }
}

#[async_trait::async_trait]
impl ToolInstaller for BloodHoundInstaller {
    fn id(&self) -> &str {
        "bloodhound"
    }

    fn display_name(&self) -> &str {
        "BloodHound (AD collector)"
    }

    async fn is_installed(&self) -> bool {
        Self::collector_present().await
    }

    async fn install(&self, progress: &ProgressSink) -> Result<()> {
        if Self::collector_present().await {
            progress(InstallEvent::step(format!(
                "{COLLECTOR_BINARY} already installed"
            )));
            return Ok(());
        }

        if !sandbox_enabled() {
            return Err(Error::ToolExecution(format!(
                "{COLLECTOR_BINARY} is not installed and sandbox is disabled. {HOST_INSTRUCTIONS}"
            )));
        }

        progress(InstallEvent::step(format!(
            "Installing BloodHound collector via pacman ({COLLECTOR_PACKAGE})..."
        )));
        // -Sy refreshes the package DBs first; a bare -S fails on a rootfs whose
        // sync DBs have gone stale (see installers::pacman).
        super::pacman::install(COLLECTOR_PACKAGE, Duration::from_secs(600)).await?;

        if !Self::collector_present().await {
            return Err(Error::ToolExecution(format!(
                "{COLLECTOR_PACKAGE} installed but {COLLECTOR_BINARY} is not on PATH"
            )));
        }

        progress(InstallEvent::step("BloodHound collector installed"));
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
    fn id_is_bloodhound() {
        assert_eq!(BloodHoundInstaller.id(), "bloodhound");
    }

    #[test]
    fn manual_instructions_mention_neo4j_stack() {
        let instr = BloodHoundInstaller.manual_instructions().unwrap();
        assert!(instr.contains("Docker Compose") || instr.contains("docker compose"));
    }

    #[test]
    fn collector_package_and_binary_are_the_real_repo_names() {
        // Regression: the old `python-bloodhound` package name does not exist
        // in the BlackArch repos and caused `target not found`. The real
        // package/binary is `bloodhound-ce-python`.
        assert_eq!(COLLECTOR_PACKAGE, "bloodhound-ce-python");
        assert_eq!(COLLECTOR_BINARY, "bloodhound-ce-python");
        assert_ne!(COLLECTOR_PACKAGE, "python-bloodhound");
    }
}
