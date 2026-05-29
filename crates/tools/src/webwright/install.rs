//! Auto-installation of Webwright in the sandbox environment.
//!
//! When running inside proot/bwrap, automatically installs webwright from
//! GitHub if not already present. When running natively (no sandbox),
//! prints instructions for manual installation.

use pentest_core::error::{Error, Result};
use pentest_platform::CommandExec;
use std::time::Duration;
use tracing::{info, warn};

/// GitHub URL for Microsoft's webwright package.
const WEBWRIGHT_GIT_URL: &str = "https://github.com/microsoft/webwright.git";

/// Check if webwright is importable, install if not.
///
/// In sandbox mode (proot/bwrap): auto-installs from GitHub using pip/uv.
/// In native mode (DISABLE_SANDBOX=true): returns error with install instructions.
pub async fn ensure_webwright_installed(platform: &impl CommandExec) -> Result<()> {
    // Check if webwright is already importable
    let check = platform
        .execute_command(
            "python3",
            &["-c", "import webwright"],
            Duration::from_secs(10),
        )
        .await?;

    if check.exit_code == 0 {
        info!("webwright is already installed");
        return Ok(());
    }

    // Not installed — check if we're in a sandbox
    #[cfg(not(target_os = "android"))]
    {
        if !pentest_platform::is_sandbox_enabled() {
            warn!("webwright not found and sandbox is disabled");
            return Err(Error::ToolExecution(
                "Webwright is not installed. Install it manually:\n\n\
                 pip install git+https://github.com/microsoft/webwright.git\n\n\
                 Or with uv:\n\
                 uv pip install git+https://github.com/microsoft/webwright.git\n\n\
                 Also install Playwright browsers:\n\
                 playwright install chromium"
                    .to_string(),
            ));
        }
    }

    // In sandbox — try uv first (faster), fall back to pip
    info!("webwright not found, attempting auto-install...");

    // Try uv first
    let uv_check = platform
        .execute_command("which", &["uv"], Duration::from_secs(5))
        .await?;

    let install_result = if uv_check.exit_code == 0 {
        info!("Installing webwright via uv...");
        platform
            .execute_command(
                "uv",
                &[
                    "pip",
                    "install",
                    "--system",
                    &format!("git+{}", WEBWRIGHT_GIT_URL),
                ],
                Duration::from_secs(120),
            )
            .await?
    } else {
        info!("Installing webwright via pip...");
        platform
            .execute_command(
                "pip",
                &[
                    "install",
                    "--break-system-packages",
                    &format!("git+{}", WEBWRIGHT_GIT_URL),
                ],
                Duration::from_secs(120),
            )
            .await?
    };

    if install_result.exit_code != 0 {
        // pip might not exist either — try python3 -m pip
        let fallback = platform
            .execute_command(
                "python3",
                &[
                    "-m",
                    "pip",
                    "install",
                    "--break-system-packages",
                    &format!("git+{}", WEBWRIGHT_GIT_URL),
                ],
                Duration::from_secs(120),
            )
            .await?;

        if fallback.exit_code != 0 {
            return Err(Error::ToolExecution(format!(
                "Failed to auto-install webwright.\n\
                 pip output: {}\n\
                 Please install manually: pip install git+{}",
                fallback.stderr, WEBWRIGHT_GIT_URL
            )));
        }
    }

    // Verify installation succeeded
    let verify = platform
        .execute_command(
            "python3",
            &["-c", "import webwright; print('ok')"],
            Duration::from_secs(10),
        )
        .await?;

    if verify.exit_code != 0 {
        return Err(Error::ToolExecution(format!(
            "webwright installed but failed to import: {}",
            verify.stderr
        )));
    }

    info!("webwright installed successfully");

    // Install Playwright browsers (best-effort, non-blocking)
    info!("Installing Playwright Chromium browser...");
    let pw_install = platform
        .execute_command(
            "playwright",
            &["install", "chromium"],
            Duration::from_secs(300),
        )
        .await;

    match pw_install {
        Ok(r) if r.exit_code == 0 => info!("Playwright Chromium installed"),
        Ok(r) => warn!(
            "Playwright browser install returned {}: {}",
            r.exit_code, r.stderr
        ),
        Err(e) => warn!(
            "Playwright browser install failed: {} (browser may not work)",
            e
        ),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn webwright_git_url_is_valid() {
        assert!(super::WEBWRIGHT_GIT_URL.starts_with("https://"));
        assert!(super::WEBWRIGHT_GIT_URL.contains("microsoft/webwright"));
    }
}
