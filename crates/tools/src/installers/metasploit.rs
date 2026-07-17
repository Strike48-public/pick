//! Metasploit Framework installer.
//!
//! In sandbox mode, installs the `metasploit` package via pacman. In native
//! mode, Metasploit is large (~2GB, Ruby + Postgres) and best installed via the
//! official omnibus installer, so we verify `msfconsole` is present and
//! otherwise return instructions.
//!
//! Note: the `metasploit` tool drives MSF in batch mode (msfvenom + resource
//! scripts). Persistent meterpreter sessions need separate session
//! infrastructure not provided here.

use super::{InstallEvent, ProgressSink, ToolInstaller};
use pentest_core::error::{Error, Result};
use std::time::Duration;

use crate::installers::sandbox_enabled;

const HOST_INSTRUCTIONS: &str = "Install Metasploit on the host with the official installer: \
     curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/\
metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall  \
     (then run `msfdb init` for database support). Requires ~2GB.";

pub struct MetasploitInstaller;

impl MetasploitInstaller {
    async fn msfconsole_present() -> bool {
        super::binary_on_path("msfconsole").await
    }
}

#[async_trait::async_trait]
impl ToolInstaller for MetasploitInstaller {
    fn id(&self) -> &str {
        "metasploit"
    }

    fn display_name(&self) -> &str {
        "Metasploit Framework"
    }

    async fn is_installed(&self) -> bool {
        Self::msfconsole_present().await
    }

    async fn install(&self, progress: &ProgressSink) -> Result<()> {
        if Self::msfconsole_present().await {
            progress(InstallEvent::step("Metasploit already installed"));
            return Ok(());
        }

        if !sandbox_enabled() {
            return Err(Error::ToolExecution(format!(
                "Metasploit is not installed and sandbox is disabled. {HOST_INSTRUCTIONS}"
            )));
        }

        progress(InstallEvent::step(
            "Installing Metasploit via pacman (this is large, ~2GB)...",
        ));
        // -Sy refreshes the package DBs first; a bare -S fails on a rootfs whose
        // sync DBs have gone stale (see installers::pacman). Metasploit is a
        // large package, so allow a generous timeout.
        super::pacman::install("metasploit", Duration::from_secs(1800)).await?;

        if !Self::msfconsole_present().await {
            return Err(Error::ToolExecution(
                "metasploit installed but msfconsole is not on PATH".to_string(),
            ));
        }

        progress(InstallEvent::step("Metasploit installed"));
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
    fn id_is_metasploit() {
        assert_eq!(MetasploitInstaller.id(), "metasploit");
    }

    #[test]
    fn manual_instructions_mention_msfdb() {
        assert!(MetasploitInstaller
            .manual_instructions()
            .unwrap()
            .contains("msfdb init"));
    }
}
