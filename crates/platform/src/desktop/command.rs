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

/// Whether the sandbox was *permanently* disabled by the `DISABLE_SANDBOX`
/// environment variable. When `true`, [`set_use_sandbox`] becomes a no-op so
/// the env setting cannot be overridden by the UI shell-mode toggle.
static DISABLED_BY_ENV: AtomicBool = AtomicBool::new(false);

/// Initialize sandbox state from environment on first access.
///
/// If `DISABLE_SANDBOX=true` (or `=1`) is set, both `USE_SANDBOX` and
/// `DISABLED_BY_ENV` are set so that later [`set_use_sandbox`] calls are
/// silently ignored.
fn init_sandbox_from_env() {
    use std::sync::Once;
    static INIT: Once = Once::new();

    INIT.call_once(|| {
        if let Ok(val) = std::env::var("DISABLE_SANDBOX") {
            if val.to_lowercase() == "true" || val == "1" {
                USE_SANDBOX.store(false, Ordering::SeqCst);
                DISABLED_BY_ENV.store(true, Ordering::SeqCst);
                tracing::info!(
                    "Sandbox disabled via DISABLE_SANDBOX environment variable; UI toggle will be ignored"
                );
            }
        }
    });
}

/// Set whether to use sandbox for command execution.
/// Call this based on the user's ShellMode setting.
///
/// This is a **no-op** (with a warning) when the `DISABLE_SANDBOX` environment
/// variable permanently disabled the sandbox — the env setting always wins.
pub fn set_use_sandbox(use_sandbox: bool) {
    // Ensure the env has been read before we check DISABLED_BY_ENV.
    // `init_sandbox_from_env` is backed by `std::sync::Once`, so after the
    // first call this is a single atomic load — cheap enough for every
    // UI-shell-mode toggle.
    init_sandbox_from_env();

    if DISABLED_BY_ENV.load(Ordering::SeqCst) {
        if use_sandbox {
            tracing::warn!(
                "Ignoring set_use_sandbox(true): sandbox was disabled via DISABLE_SANDBOX env var"
            );
        }
        return;
    }

    USE_SANDBOX.store(use_sandbox, Ordering::SeqCst);
    tracing::info!(
        "Sandbox execution: {}",
        if use_sandbox { "enabled" } else { "disabled" }
    );
}

/// Check if sandbox is enabled
pub fn is_sandbox_enabled() -> bool {
    init_sandbox_from_env();

    // When the env disabled the sandbox, always return false regardless of
    // what the UI may have subsequently tried to set.
    if DISABLED_BY_ENV.load(Ordering::SeqCst) {
        return false;
    }

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
    // If sandbox is disabled, execute on the host.
    if !is_sandbox_enabled() {
        // Redact args: a differential-authz identity run splices a credential
        // (`-H "Authorization: Bearer <token>"`, `-u user:pass`) into argv, so the
        // raw args can carry a secret. Log the redacted form (#317 review HIGH).
        tracing::debug!(
            "Sandbox disabled, executing directly: {} {}",
            cmd,
            pentest_core::provenance::redact(&format!("{args:?}"))
        );

        // Parity with the sandbox path, which runs `bash -c "<cmd> <args>"`:
        // when `cmd` is a full shell line (pipes, redirects, globs, or just a
        // command with spaces — the shape the execute_command tool passes,
        // e.g. `ps aux | head -n 11`), run it through a shell so those work.
        // Without this, Native/DISABLE_SANDBOX execution does `Command::new`
        // on the whole string and fails instantly with ENOENT ("no such
        // binary"). Bare-binary callers (`which`, the `sh -c ...` probes) have
        // no shell metacharacters in `cmd`, so they keep direct argv exec and
        // their positional-parameter semantics.
        if needs_shell(cmd) {
            let full_cmd = if args.is_empty() {
                cmd.to_string()
            } else {
                let escaped: Vec<String> = args.iter().map(|a| shell_escape(a)).collect();
                format!("{} {}", cmd, escaped.join(" "))
            };
            #[cfg(windows)]
            {
                return execute_command_direct(
                    "cmd",
                    &["/C", &full_cmd],
                    timeout_duration,
                    working_dir,
                )
                .await;
            }
            #[cfg(not(windows))]
            {
                return execute_command_direct(
                    "sh",
                    &["-c", &full_cmd],
                    timeout_duration,
                    working_dir,
                )
                .await;
            }
        }

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

    // Redact args/full_cmd before logging: on a differential-authz identity run
    // these carry the injected credential, and any log sink (journald/Quickwit)
    // would otherwise capture it in plaintext (#317 review HIGH). `cmd` is just
    // the binary name. NOTE: passing a secret as an argv element also exposes it
    // in the process table (`ps` / `/proc/<pid>/cmdline`) for the lifetime of the
    // child — inherent to header-via-argv; `curl -H @file` avoids it. Tracked for
    // the differential-authz feature rollout (gated on matrix#3354).
    tracing::info!(
        "[execute_command] cmd={:?} args={} full_cmd={}",
        cmd,
        pentest_core::provenance::redact(&format!("{args:?}")),
        pentest_core::provenance::redact(&full_cmd)
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
/// True when `cmd` is a shell line (not a bare executable name) and therefore
/// must be run through a shell for pipes / redirects / globs / multiple words
/// to work. Mirrors what the sandbox path gets for free by always running
/// `bash -c`. A bare binary name (`nmap`, `which`, `sh`) has none of these and
/// is left to direct argv exec so probe callers keep their positional semantics.
fn needs_shell(cmd: &str) -> bool {
    cmd.chars().any(|c| {
        c.is_whitespace()
            || matches!(
                c,
                '|' | '&'
                    | ';'
                    | '<'
                    | '>'
                    | '('
                    | ')'
                    | '$'
                    | '`'
                    | '*'
                    | '?'
                    | '{'
                    | '}'
                    | '['
                    | ']'
                    | '~'
                    | '\\'
                    | '"'
                    | '\''
            )
    })
}

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
    fn needs_shell_detects_shell_lines_but_not_bare_binaries() {
        // Bare binaries / probe callers -> direct argv exec (no shell).
        assert!(!needs_shell("nmap"));
        assert!(!needs_shell("which"));
        assert!(!needs_shell("sh"));
        assert!(!needs_shell("execute_command"));
        // Full shell lines the execute_command tool passes -> must shell-wrap.
        assert!(needs_shell("ps aux --sort=-%cpu | head -n 11"));
        assert!(needs_shell("ls -la"));
        assert!(needs_shell("echo hi > out.txt"));
        assert!(needs_shell("cat /etc/hosts | grep localhost"));
        assert!(needs_shell("ls *.rs"));
    }

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

    // ── Log redaction for differential-authz identity runs (#317 review HIGH) ──
    //
    // execute_command / execute_command_in_dir log `args` and `full_cmd` at
    // info/debug. On an identity run those carry an injected credential, so both
    // sites now redact via `pentest_core::provenance::redact` before logging.
    // This test guards that `redact` actually strips a credential from the exact
    // string shapes the log statements build (`format!("{args:?}")` and the
    // shell-escaped `full_cmd`) — i.e. the redactor is effective on this input,
    // not that the call sites invoke it (that wiring is verified by reading the
    // two `tracing!` calls above; asserting on emitted log lines would need a
    // tracing-capture harness this crate doesn't set up).
    #[test]
    fn injected_credential_is_redacted_before_logging() {
        let secret = "sk-super-secret-token-abcdef1234567890";
        let args = vec![
            "-H",
            "Authorization: Bearer sk-super-secret-token-abcdef1234567890",
            "https://target.example",
        ];

        // The `args={:?}` form the log line builds.
        let logged_args = pentest_core::provenance::redact(&format!("{args:?}"));
        assert!(
            !logged_args.contains(secret),
            "credential must be redacted from logged args: {logged_args}"
        );

        // The `full_cmd` form (shell-escaped join, as built above).
        let escaped: Vec<String> = args.iter().map(|a| shell_escape(a)).collect();
        let full_cmd = format!("curl {}", escaped.join(" "));
        let logged_full = pentest_core::provenance::redact(&full_cmd);
        assert!(
            !logged_full.contains(secret),
            "credential must be redacted from logged full_cmd: {logged_full}"
        );
    }
}
