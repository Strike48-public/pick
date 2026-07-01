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
use pentest_platform::{get_platform, CommandExec};
use std::time::Duration;

use crate::installers::sandbox_enabled;

const COLLECTOR_BINARY: &str = "bloodhound-python";

const HOST_INSTRUCTIONS: &str =
    "Install the collector on the host with: pipx install bloodhound  (provides `bloodhound-python`). \
     For the BloodHound CE UI + neo4j graph, run the official Docker Compose stack from \
     https://github.com/SpecterOps/BloodHound (docker compose up); that service is not auto-managed \
     by the connector.";

pub struct BloodHoundInstaller;

impl BloodHoundInstaller {
    async fn collector_present() -> bool {
        let platform = get_platform();
        platform
            .execute_command("which", &[COLLECTOR_BINARY], Duration::from_secs(5))
            .await
            .map(|r| r.exit_code == 0)
            .unwrap_or(false)
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
            progress(InstallEvent::step("bloodhound-python already installed"));
            return Ok(());
        }

        if !sandbox_enabled() {
            return Err(Error::ToolExecution(format!(
                "bloodhound-python is not installed and sandbox is disabled. {HOST_INSTRUCTIONS}"
            )));
        }

        progress(InstallEvent::step(
            "Installing BloodHound collector via pacman (python-bloodhound)...",
        ));
        let platform = get_platform();
        let result = platform
            .execute_command(
                "pacman",
                &["-S", "--noconfirm", "python-bloodhound"],
                Duration::from_secs(600),
            )
            .await?;

        if result.exit_code != 0 {
            return Err(Error::ToolExecution(format!(
                "Failed to install python-bloodhound: {}",
                result.stderr
            )));
        }

        if !Self::collector_present().await {
            return Err(Error::ToolExecution(
                "python-bloodhound installed but bloodhound-python is not on PATH".to_string(),
            ));
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
}
