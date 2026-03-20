//! Tool installation helpers
//!
//! Provides utilities for ensuring external tools are available in the sandbox
//! environment, installing them via pacman if necessary.
//!
//! When sandbox is disabled (DISABLE_SANDBOX=true), assumes tools are already
//! installed on the host system and skips pacman installation.

use pentest_core::error::{Error, Result};
use pentest_platform::CommandExec;
use std::time::Duration;
use tracing::{info, warn};

#[cfg(not(target_os = "android"))]
use pentest_platform::is_sandbox_enabled;

/// Check if a tool binary is available in the sandbox, install if not.
///
/// # Arguments
/// * `platform` - Command execution platform (sandbox-aware)
/// * `binary_name` - Name of the binary to check (e.g., "ffuf")
/// * `pacman_package` - Package name in BlackArch repository (e.g., "ffuf")
///
/// # Returns
/// Ok(()) if the tool is available or was successfully installed
///
/// # Example
/// ```no_run
/// # async fn example() -> pentest_core::error::Result<()> {
/// use pentest_platform::get_platform;
/// use pentest_tools::external::install::ensure_tool_installed;
///
/// let platform = get_platform();
/// ensure_tool_installed(&platform, "ffuf", "ffuf").await?;
/// # Ok(())
/// # }
/// ```
pub async fn ensure_tool_installed(
    platform: &impl CommandExec,
    binary_name: &str,
    pacman_package: &str,
) -> Result<()> {
    // Check if binary exists
    let check = platform
        .execute_command("which", &[binary_name], Duration::from_secs(5))
        .await?;

    if check.exit_code == 0 {
        info!("Tool '{}' is already installed", binary_name);
        return Ok(());
    }

    // If sandbox is disabled, tools should be pre-installed on the host
    #[cfg(not(target_os = "android"))]
    {
        if !is_sandbox_enabled() {
            warn!(
                "Tool '{}' not found on host system (sandbox disabled). Please install it manually: sudo apt-get install {}",
                binary_name, binary_name
            );
            return Err(Error::ToolExecution(format!(
                "Tool '{}' not found. When sandbox is disabled, tools must be pre-installed on the host system.",
                binary_name
            )));
        }
    }

    // Install via pacman (only when sandbox is enabled)
    info!(
        "Installing '{}' via pacman package '{}'...",
        binary_name, pacman_package
    );
    let install = platform
        .execute_command(
            "pacman",
            &["-S", "--noconfirm", pacman_package],
            Duration::from_secs(300),
        )
        .await?;

    if install.exit_code != 0 {
        warn!(
            "Failed to install '{}': {} (stderr: {})",
            pacman_package, install.stdout, install.stderr
        );
        return Err(Error::ToolExecution(format!(
            "Failed to install {}: {}",
            pacman_package, install.stderr
        )));
    }

    info!("Successfully installed '{}'", binary_name);
    Ok(())
}

/// Check if a single tool binary is installed
pub async fn is_tool_installed(platform: &impl CommandExec, binary_name: &str) -> Result<bool> {
    let check = platform
        .execute_command("which", &[binary_name], Duration::from_secs(5))
        .await?;
    Ok(check.exit_code == 0)
}

/// Check if multiple tools are installed, returning a list of missing tools
pub async fn check_tools_installed(
    platform: &impl CommandExec,
    tools: &[(&str, &str)], // (binary_name, pacman_package)
) -> Result<Vec<String>> {
    let mut missing = Vec::new();

    for (binary_name, _) in tools {
        if !is_tool_installed(platform, binary_name).await? {
            missing.push(binary_name.to_string());
        }
    }

    Ok(missing)
}

/// Install multiple tools in parallel (batch install)
pub async fn install_tools_batch(platform: &impl CommandExec, packages: &[&str]) -> Result<()> {
    if packages.is_empty() {
        return Ok(());
    }

    // If sandbox is disabled, skip batch installation
    #[cfg(not(target_os = "android"))]
    {
        if !is_sandbox_enabled() {
            warn!(
                "Sandbox disabled - skipping batch install of {} packages (tools should be pre-installed on host)",
                packages.len()
            );
            return Ok(());
        }
    }

    info!("Batch installing {} packages...", packages.len());

    let mut args = vec!["-S", "--noconfirm"];
    args.extend_from_slice(packages);

    let install = platform
        .execute_command("pacman", &args, Duration::from_secs(600))
        .await?;

    if install.exit_code != 0 {
        return Err(Error::ToolExecution(format!(
            "Failed to batch install packages: {}",
            install.stderr
        )));
    }

    info!("Successfully installed {} packages", packages.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests require a functional sandbox environment
    // and should be run with integration test flag

    #[tokio::test]
    #[ignore] // Requires sandbox environment
    async fn test_ensure_tool_installed() {
        let platform = pentest_platform::get_platform();
        let result = ensure_tool_installed(&platform, "ls", "coreutils").await;
        assert!(result.is_ok());
    }
}
