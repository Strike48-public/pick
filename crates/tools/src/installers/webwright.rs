//! Webwright installer.
//!
//! Webwright is a pip/uv-installed Python package plus a Playwright Chromium
//! browser — not a pacman package. This wraps the same steps the connector
//! already performs in [`crate::webwright::install`], exposed through the
//! generic [`ToolInstaller`] interface so the catalog UI can drive it.

use super::{InstallEvent, ProgressSink, ToolInstaller};
use pentest_core::error::{Error, Result};
use pentest_platform::{get_platform, CommandExec};
use std::time::Duration;

/// GitHub URL for the webwright package (matches `webwright::install`).
const WEBWRIGHT_GIT_URL: &str = "https://github.com/microsoft/webwright.git";

pub struct WebwrightInstaller;

impl WebwrightInstaller {
    async fn import_ok() -> bool {
        let platform = get_platform();
        platform
            .execute_command(
                "python3",
                &["-c", "import webwright"],
                Duration::from_secs(10),
            )
            .await
            .map(|r| r.exit_code == 0)
            .unwrap_or(false)
    }
}

#[async_trait::async_trait]
impl ToolInstaller for WebwrightInstaller {
    fn id(&self) -> &str {
        "webwright"
    }

    fn display_name(&self) -> &str {
        "Webwright (AI browser automation)"
    }

    async fn is_installed(&self) -> bool {
        Self::import_ok().await
    }

    async fn install(&self, progress: &ProgressSink) -> Result<()> {
        let platform = get_platform();

        if Self::import_ok().await {
            progress(InstallEvent::step("webwright already installed"));
            return Ok(());
        }

        // Prefer uv (fast), fall back to pip / python -m pip. Mirrors the
        // existing webwright::install flow but with progress reporting.
        progress(InstallEvent::step(
            "Installing webwright (Python package)...",
        ));

        let uv_available = platform
            .execute_command("which", &["uv"], Duration::from_secs(5))
            .await
            .map(|r| r.exit_code == 0)
            .unwrap_or(false);

        let git_spec = format!("git+{WEBWRIGHT_GIT_URL}");

        let result = if uv_available {
            platform
                .execute_command(
                    "uv",
                    &["pip", "install", "--system", &git_spec],
                    Duration::from_secs(300),
                )
                .await?
        } else {
            platform
                .execute_command(
                    "pip",
                    &["install", "--break-system-packages", &git_spec],
                    Duration::from_secs(300),
                )
                .await?
        };

        // Fall back to `python3 -m pip` if the chosen path failed (pip may not
        // be a standalone binary on every host).
        if result.exit_code != 0 {
            let fallback = platform
                .execute_command(
                    "python3",
                    &["-m", "pip", "install", "--break-system-packages", &git_spec],
                    Duration::from_secs(300),
                )
                .await?;
            if fallback.exit_code != 0 {
                return Err(Error::ToolExecution(format!(
                    "Failed to install webwright: {}",
                    fallback.stderr
                )));
            }
        }

        if !Self::import_ok().await {
            return Err(Error::ToolExecution(
                "webwright installed but failed to import".to_string(),
            ));
        }
        progress(InstallEvent::step(
            "webwright installed; installing Chromium...",
        ));

        // Playwright Chromium is required for the browser to launch. Best-effort
        // but reported — a failure here leaves webwright importable but unable
        // to drive a browser, so we surface it as an error.
        let pw = platform
            .execute_command(
                "playwright",
                &["install", "chromium"],
                Duration::from_secs(420),
            )
            .await;

        match pw {
            Ok(r) if r.exit_code == 0 => {
                progress(InstallEvent::step("Playwright Chromium installed"));
                Ok(())
            }
            Ok(r) => Err(Error::ToolExecution(format!(
                "webwright installed but Playwright Chromium failed (exit {}): {}",
                r.exit_code, r.stderr
            ))),
            Err(e) => Err(Error::ToolExecution(format!(
                "webwright installed but Playwright Chromium failed: {e}"
            ))),
        }
    }

    fn manual_instructions(&self) -> Option<String> {
        Some(format!(
            "pip install git+{WEBWRIGHT_GIT_URL}  (or: uv pip install --system git+{WEBWRIGHT_GIT_URL}), \
             then: playwright install chromium"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_and_url() {
        assert_eq!(WebwrightInstaller.id(), "webwright");
        assert!(WEBWRIGHT_GIT_URL.starts_with("https://"));
        assert!(WEBWRIGHT_GIT_URL.contains("webwright"));
    }

    #[test]
    fn manual_instructions_mention_playwright() {
        assert!(WebwrightInstaller
            .manual_instructions()
            .unwrap()
            .contains("playwright install chromium"));
    }
}
