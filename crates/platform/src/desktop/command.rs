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
/// Can be disabled via DISABLE_SANDBOX=true environment variable.
static USE_SANDBOX: AtomicBool = AtomicBool::new(true);

/// Initialize sandbox state from environment on first access
fn init_sandbox_from_env() {
    use std::sync::Once;
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        if let Ok(val) = std::env::var("DISABLE_SANDBOX") {
            if val.to_lowercase() == "true" || val == "1" {
                USE_SANDBOX.store(false, Ordering::SeqCst);
                tracing::info!("Sandbox disabled via DISABLE_SANDBOX environment variable");
            }
        }
    });
}

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
    init_sandbox_from_env();
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

    tracing::info!(
        "[execute_command] cmd={:?} args={:?} full_cmd={:?}",
        cmd,
        args,
        full_cmd
    );

    // Try sandboxed execution. The sandbox is enabled, so the operator expects
    // the command to run *inside* it. We fail closed: a sandbox init or execution
    // error is surfaced to the caller rather than silently retried on the host.
    // Dropping to the host here would be a fail-open — a command the operator
    // believed was contained could run against the host with only a `warn!` as
    // signal (GitHub issue #256). The deliberate host path lives above, behind
    // the `!is_sandbox_enabled()` check (Native shell mode / DISABLE_SANDBOX).
    //
    // Note the executors return `Ok(CommandResult)` even for a nonzero exit or a
    // timeout (a command that *ran* but failed); `Err(SandboxError)` is reserved
    // for infrastructure failures (rootfs missing, spawn failure, no backend). So
    // failing closed here only rejects genuine sandbox breakage, never a
    // legitimate tool run that exited nonzero.
    tracing::info!(
        "[execute_command] Sandbox enabled, attempting to get sandbox manager for: {}",
        cmd
    );
    let attempt = match sandbox::get_sandbox_manager().await {
        Ok(manager) => {
            tracing::info!("[execute_command] Sandbox manager obtained, backend={}, is_ready={}, executing: {}",
                manager.backend(), manager.is_ready(), cmd);
            match manager
                .execute(&full_cmd, timeout_duration, working_dir)
                .await
            {
                Ok(result) => SandboxAttempt::Executed(result),
                Err(e) => SandboxAttempt::ExecFailed(e.to_string()),
            }
        }
        Err(e) => SandboxAttempt::InitFailed(e.to_string()),
    };

    resolve_enabled_attempt(cmd, attempt)
}

/// Outcome of a sandboxed execution attempt when the sandbox is enabled.
enum SandboxAttempt {
    /// The sandbox ran the command (the `CommandResult` may still carry a
    /// nonzero exit code or a timeout — that is a *successful* sandbox run).
    Executed(CommandResult),
    /// The sandbox manager was obtained but executing the command failed
    /// (rootfs not set up, backend spawn failure, ...).
    ExecFailed(String),
    /// The sandbox manager could not be initialized (no backend available, ...).
    InitFailed(String),
}

/// Decide the result of an enabled-sandbox attempt, failing closed.
///
/// A successful sandbox run (even one that exited nonzero) is returned as-is.
/// An init or execution *failure* is surfaced as an [`Error::ToolExecution`]
/// rather than falling back to host execution. This is the fail-closed
/// containment guarantee for issue #256; the corresponding fail-open behavior
/// used to `warn!` and run `execute_command_direct` on the host.
fn resolve_enabled_attempt(cmd: &str, attempt: SandboxAttempt) -> Result<CommandResult> {
    match attempt {
        SandboxAttempt::Executed(result) => {
            tracing::info!("[execute_command] Sandbox execution succeeded for: {}", cmd);
            Ok(result)
        }
        SandboxAttempt::ExecFailed(e) => {
            tracing::error!(
                "[execute_command] Sandbox execution failed for '{}': {} — failing closed (not running on host)",
                cmd, e
            );
            Err(Error::ToolExecution(format!(
                "sandbox execution failed for '{cmd}': {e}. Refusing to run on the host; \
                 switch to Native shell mode (or set DISABLE_SANDBOX=true) to run unsandboxed."
            )))
        }
        SandboxAttempt::InitFailed(e) => {
            tracing::error!(
                "[execute_command] Sandbox manager initialization failed for '{}': {} — failing closed (not running on host)",
                cmd, e
            );
            Err(Error::ToolExecution(format!(
                "sandbox unavailable for '{cmd}': {e}. Refusing to run on the host; \
                 switch to Native shell mode (or set DISABLE_SANDBOX=true) to run unsandboxed."
            )))
        }
    }
}

/// Direct command execution on the **host**.
///
/// Reached only via the deliberate host path in [`execute_command_in_dir`]:
/// when the sandbox is disabled (Native shell mode / `DISABLE_SANDBOX=true`).
/// A sandbox *failure* no longer falls back here — the enabled path fails closed
/// (see [`resolve_enabled_attempt`] and GitHub issue #256), so this function is
/// never a silent host escape hatch for an enabled sandbox.
///
/// Because it always runs on the host, the Linux-only `which` binary-probe is
/// rewritten to the host-appropriate command (`where` on Windows) via
/// [`crate::common::host_which_command`]. The sandbox *success* path does not
/// come through here — it sends the command into a Linux environment
/// (WSL2/proot/bwrap) where `which` is correct. See GitHub issue #183.
pub(crate) async fn execute_command_direct(
    cmd: &str,
    args: &[&str],
    timeout_duration: Duration,
    working_dir: Option<&Path>,
) -> Result<CommandResult> {
    let start = Instant::now();

    // Host-only: `which` does not exist on Windows; use `where` there instead.
    // We match the bare literal "which" (not "./which" or an absolute path)
    // because every probe caller passes the literal string. Callers check only
    // the exit code (0 = found); `where` shares that contract, though it may
    // print multiple paths — fine, since stdout is not parsed. See #183.
    let host_cmd = if cmd == "which" {
        crate::common::host_which_command()
    } else {
        cmd
    };

    let mut command = Command::new(host_cmd);
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

    // ── Fail-closed containment (GitHub issue #256) ──────────────────────
    //
    // These guard the enabled-sandbox decision: an init or execution failure
    // must be surfaced to the caller, never silently retried on the host.
    // Guard check: replacing either error arm below with a host result (the
    // old fail-open behavior) turns `sandbox_exec_failure_fails_closed` and
    // `sandbox_init_failure_fails_closed` red.

    #[test]
    fn sandbox_exec_failure_fails_closed() {
        let result = resolve_enabled_attempt(
            "nmap",
            SandboxAttempt::ExecFailed("rootfs not initialized".to_string()),
        );
        let err = result.expect_err("sandbox exec failure must not run on the host");
        // Fail-closed: surfaced as a tool-execution error, not an Ok result.
        assert!(matches!(err, Error::ToolExecution(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("nmap") && msg.contains("Refusing to run on the host"),
            "error should name the command and state host refusal, got: {msg}"
        );
    }

    #[test]
    fn sandbox_init_failure_fails_closed() {
        let result = resolve_enabled_attempt(
            "masscan",
            SandboxAttempt::InitFailed("No sandbox backend available".to_string()),
        );
        let err = result.expect_err("sandbox init failure must not run on the host");
        assert!(matches!(err, Error::ToolExecution(_)));
        assert!(err.to_string().contains("masscan"));
    }

    #[test]
    fn successful_sandbox_run_passes_through() {
        let cr = CommandResult::success("out".into(), String::new(), 0, 5);
        let result = resolve_enabled_attempt("id", SandboxAttempt::Executed(cr));
        let out = result.expect("a successful sandbox run must pass through");
        assert_eq!(out.exit_code, 0);
        assert_eq!(out.stdout, "out");
    }

    #[test]
    fn nonzero_exit_is_a_successful_run_not_a_sandbox_failure() {
        // A command that *ran* in the sandbox but exited nonzero (or timed out)
        // is a successful sandbox run: the executor returns Ok(CommandResult),
        // so it must pass through unchanged and NOT be treated as a fail-closed
        // error. This is why the enabled path keys off Err(SandboxError), not
        // the exit code.
        let cr = CommandResult::success(String::new(), "boom".into(), 2, 5);
        let result = resolve_enabled_attempt("false", SandboxAttempt::Executed(cr));
        let out = result.expect("nonzero-exit run is still a successful sandbox run");
        assert_eq!(out.exit_code, 2);
        assert!(!out.timed_out);

        let timed_out = CommandResult::timeout(String::new(), "slow".into(), 100);
        let result = resolve_enabled_attempt("sleep", SandboxAttempt::Executed(timed_out));
        let out = result.expect("a sandbox timeout is still a successful sandbox run");
        assert!(out.timed_out);
    }
}
