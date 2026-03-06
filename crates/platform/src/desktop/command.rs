//! Desktop command execution implementation
//!
//! Commands are executed in a sandboxed BlackArch Linux environment
//! using bubblewrap (Linux namespaces) or proot as the execution backend.
//! The sandbox can be disabled via `set_use_sandbox(false)`.

use super::sandbox;
use crate::traits::CommandResult;
use pentest_core::error::{Error, Result};
use std::path::Path;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::process::Command;
use tokio::time::timeout;

/// Global flag to control whether to use sandbox for command execution.
/// When false, commands execute directly on the host system.
static USE_SANDBOX: AtomicBool = AtomicBool::new(true);

/// Set whether to use sandbox for command execution.
/// Call this based on the user's ShellMode setting.
pub fn set_use_sandbox(use_sandbox: bool) {
    USE_SANDBOX.store(use_sandbox, Ordering::SeqCst);
    tracing::info!(
        "Sandbox execution: {}",
        if use_sandbox { "enabled" } else { "disabled" }
    );
}

/// Check if sandbox is enabled
pub fn is_sandbox_enabled() -> bool {
    USE_SANDBOX.load(Ordering::SeqCst)
}

/// Execute a command in the sandboxed BlackArch environment
pub async fn execute_command(
    cmd: &str,
    args: &[&str],
    timeout_duration: Duration,
) -> Result<CommandResult> {
    execute_command_in_dir(cmd, args, timeout_duration, None).await
}

/// Execute a command in the sandboxed BlackArch environment with a working directory
pub async fn execute_command_in_dir(
    cmd: &str,
    args: &[&str],
    timeout_duration: Duration,
    working_dir: Option<&Path>,
) -> Result<CommandResult> {
    // If sandbox is disabled, execute directly
    if !is_sandbox_enabled() {
        tracing::debug!("Sandbox disabled, executing directly: {} {:?}", cmd, args);
        return execute_command_direct(cmd, args, timeout_duration, working_dir).await;
    }

    // Build the full command string
    let full_cmd = if args.is_empty() {
        cmd.to_string()
    } else {
        // Shell-escape arguments for safety
        let escaped_args: Vec<String> = args.iter().map(|a| shell_escape(a)).collect();
        format!("{} {}", cmd, escaped_args.join(" "))
    };

    // Try sandboxed execution first
    tracing::info!(
        "[execute_command] Sandbox enabled, attempting to get sandbox manager for: {}",
        cmd
    );
    match sandbox::get_sandbox_manager().await {
        Ok(manager) => {
            tracing::info!("[execute_command] Sandbox manager obtained, backend={}, is_ready={}, executing: {}",
                manager.backend(), manager.is_ready(), cmd);
            match manager
                .execute(&full_cmd, timeout_duration, working_dir)
                .await
            {
                Ok(result) => {
                    tracing::info!("[execute_command] Sandbox execution succeeded for: {}", cmd);
                    return Ok(result);
                }
                Err(e) => {
                    tracing::warn!("[execute_command] Sandbox execution failed for '{}': {}, falling back to direct", cmd, e);
                    // Fall through to direct execution as last resort
                }
            }
        }
        Err(e) => {
            tracing::warn!(
                "[execute_command] Sandbox manager initialization failed for '{}': {}, falling back to direct execution",
                cmd, e
            );
            // Fall through to direct execution
        }
    }

    // Fallback: direct execution (only if sandbox fails)
    tracing::warn!(
        "[execute_command] Using direct host execution fallback for: {}",
        cmd
    );
    execute_command_direct(cmd, args, timeout_duration, working_dir).await
}

/// Direct command execution (used as fallback or for internal operations)
pub(crate) async fn execute_command_direct(
    cmd: &str,
    args: &[&str],
    timeout_duration: Duration,
    working_dir: Option<&Path>,
) -> Result<CommandResult> {
    let start = Instant::now();

    let mut command = Command::new(cmd);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(dir) = working_dir {
        command.current_dir(dir);
    }

    let child = command.spawn().map_err(Error::Io)?;

    match timeout(timeout_duration, super::wait_for_child_output(child)).await {
        Ok(result) => {
            let (stdout, stderr, exit_code) = result?;
            Ok(CommandResult::success(
                stdout,
                stderr,
                exit_code,
                start.elapsed().as_millis() as u64,
            ))
        }
        Err(_) => {
            // Timeout occurred
            Ok(CommandResult::timeout(
                String::new(),
                "Command timed out".to_string(),
                start.elapsed().as_millis() as u64,
            ))
        }
    }
}

/// Shell-escape a string for safe inclusion in a command.
#[must_use]
fn shell_escape(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }

    // If the string contains no special characters, return as-is
    if s.chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '.' || c == '/')
    {
        return s.to_string();
    }

    // Otherwise, wrap in single quotes and escape any single quotes
    format!("'{}'", s.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_escape() {
        assert_eq!(shell_escape(""), "''");
        assert_eq!(shell_escape("simple"), "simple");
        assert_eq!(shell_escape("with space"), "'with space'");
        assert_eq!(shell_escape("with'quote"), "'with'\\''quote'");
        assert_eq!(shell_escape("-flag"), "-flag");
        assert_eq!(shell_escape("path/to/file.txt"), "path/to/file.txt");
    }
}
