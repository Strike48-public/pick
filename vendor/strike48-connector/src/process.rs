//! Async process execution utilities for connector implementations.
//!
//! Provides non-blocking wrappers around external command execution using
//! `tokio::process::Command`. These helpers ensure that long-running commands
//! (nmap, recon tools, scripts) never block tokio worker threads, keeping
//! heartbeats and metrics flowing even during multi-minute operations.
//!
//! # Why This Matters
//!
//! Using `std::process::Command` inside an async `execute()` blocks the tokio
//! worker thread for the entire command duration. With limited worker threads
//! (typically `num_cpus`), a few concurrent commands can starve the runtime,
//! causing heartbeat failures and connection drops.
//!
//! `tokio::process::Command` waits for child processes via async I/O
//! (kqueue/epoll), so the tokio task yields while waiting. Thousands of
//! concurrent commands use zero extra OS threads.
//!
//! # Examples
//!
//! ```rust,ignore
//! use strike48_connector::process::{run_command, run_command_with_timeout};
//! use std::time::Duration;
//!
//! // Simple command
//! let output = run_command("echo", &["hello", "world"]).await?;
//! println!("stdout: {}", output.stdout);
//!
//! // With timeout (recommended for untrusted input)
//! let output = run_command_with_timeout(
//!     "nmap", &["-sV", "target.com"],
//!     Duration::from_secs(300),
//! ).await?;
//!
//! // With environment variables and working directory
//! let output = run_command_opts("python3", &["script.py"], CommandOptions {
//!     timeout: Some(Duration::from_secs(60)),
//!     working_dir: Some("/tmp/workdir".into()),
//!     env: vec![("API_KEY".into(), "secret".into())],
//!     ..Default::default()
//! }).await?;
//! ```

use crate::error::{ConnectorError, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;

/// Output from a completed command.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// Standard output as a UTF-8 string (lossy conversion).
    pub stdout: String,
    /// Standard error as a UTF-8 string (lossy conversion).
    pub stderr: String,
    /// Process exit code. `None` if the process was killed by a signal.
    pub exit_code: Option<i32>,
    /// Whether the command exited successfully (exit code 0).
    pub success: bool,
}

/// Options for customizing command execution.
#[derive(Debug, Clone, Default)]
pub struct CommandOptions {
    /// Maximum time the command is allowed to run.
    /// The child process is killed if it exceeds this duration.
    pub timeout: Option<Duration>,
    /// Working directory for the command.
    pub working_dir: Option<PathBuf>,
    /// Additional environment variables (merged with inherited env).
    pub env: Vec<(String, String)>,
    /// If true, don't inherit the parent process's environment.
    pub clear_env: bool,
    /// Optional stdin data to pipe to the command.
    pub stdin_data: Option<Vec<u8>>,
}

/// Run an external command asynchronously and capture its output.
///
/// Uses `tokio::process::Command` internally, so the calling tokio task
/// yields while the child process runs. No OS threads are blocked.
///
/// # Errors
///
/// Returns `ConnectorError::Other` if the command fails to start
/// (e.g., binary not found).
pub async fn run_command(program: &str, args: &[&str]) -> Result<CommandOutput> {
    run_command_opts(program, args, CommandOptions::default()).await
}

/// Run an external command with a timeout.
///
/// If the command doesn't complete within `timeout`, the child process
/// is killed and a `ConnectorError::Timeout` is returned.
pub async fn run_command_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<CommandOutput> {
    run_command_opts(
        program,
        args,
        CommandOptions {
            timeout: Some(timeout),
            ..Default::default()
        },
    )
    .await
}

/// Run an external command with full customization.
///
/// # Cancellation
///
/// The child is spawned with `kill_on_drop(true)` and, on Unix, in its own
/// process group. If this future is dropped before the command completes — a
/// timeout, a server `matrix.deadline_ms`, or a `matrix.cancel` abort — the
/// direct child is killed and (Unix) its whole process group is SIGKILLed, so
/// a grandchild spawned under a shell (`run_shell("sleep N; …")`) dies with
/// the job instead of re-parenting to PID 1. A command that completes normally
/// leaves any children it intentionally detached untouched. Non-Unix targets
/// kill only the direct child.
pub async fn run_command_opts(
    program: &str,
    args: &[&str],
    options: CommandOptions,
) -> Result<CommandOutput> {
    let mut cmd = Command::new(program);
    cmd.args(args);

    if options.clear_env {
        cmd.env_clear();
    }

    for (key, value) in &options.env {
        cmd.env(key, value);
    }

    if let Some(ref dir) = options.working_dir {
        cmd.current_dir(dir);
    }

    if options.stdin_data.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    }

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    // Kill the child when this future is dropped — by the timeout below, a
    // server deadline or a `matrix.cancel` abort. Without it the process
    // outlives the job.
    cmd.kill_on_drop(true);
    // `kill_on_drop` kills only the direct child. A child spawned under a
    // shell (`run_shell("sleep N; true")`) leaves the `sleep` grandchild
    // re-parented to PID 1 when the future is dropped. On Unix, put the child
    // in its own process group so the drop guard below can SIGKILL the whole
    // group (grandchildren included). See the `ProcessGroupKillGuard`.
    //
    // NON-UNIX (Windows) FALLBACK: the `process_group(0)` call and the
    // `ProcessGroupKillGuard` are `#[cfg(unix)]`-only — there is no portable
    // process-group / `killpg` equivalent here. On Windows a dropped-before-
    // completion future (abort / deadline / timeout) therefore kills ONLY the
    // direct child via `kill_on_drop(true)` (set unconditionally above); a
    // grandchild spawned under a shell can survive. Full process-tree teardown
    // on Windows (a Job Object, or `taskkill /T /F`) is tracked in
    // https://github.com/Strike48/sdk-rs/issues/73 and is NOT implemented
    // here: it requires a real Windows host to verify.
    //
    // KNOWN LIMIT (Unix): `process_group(0)` also moves the child out of the
    // terminal's foreground process group. For a connector started from an
    // interactive shell, Ctrl-C no longer reaches a running tool, and a tool
    // that reads the tty gets SIGTTIN. Headless connectors (Docker, systemd)
    // are unaffected.
    // Severity: the Matrix-dispatched connector runs headless on Linux, so the
    // primary cancel path is Unix and fully covered by the group kill below.
    #[cfg(unix)]
    cmd.process_group(0);

    let mut child = cmd
        .spawn()
        .map_err(|e| ConnectorError::Other(format!("Failed to spawn '{program}': {e}")))?;

    // Arm a guard that SIGKILLs the child's whole process group if this
    // future is dropped before the command completes (abort / deadline /
    // timeout). Disarmed on normal completion so a finished command's
    // grandchildren are left alone, exactly as before this change.
    #[cfg(unix)]
    let mut process_group_guard = ProcessGroupKillGuard::new(child.id());

    if let Some(data) = options.stdin_data {
        use std::io::ErrorKind;
        use tokio::io::AsyncWriteExt;
        if let Some(mut stdin) = child.stdin.take() {
            if let Err(e) = stdin.write_all(&data).await
                && e.kind() != ErrorKind::BrokenPipe
            {
                return Err(ConnectorError::Other(format!(
                    "Failed to write stdin to '{program}': {e}"
                )));
            }
            drop(stdin);
        }
    }

    let output_future = child.wait_with_output();

    let output = if let Some(timeout) = options.timeout {
        match tokio::time::timeout(timeout, output_future).await {
            Ok(result) => result.map_err(|e| {
                ConnectorError::Other(format!("Command '{program}' I/O error: {e}"))
            })?,
            Err(_) => {
                return Err(ConnectorError::Timeout(format!(
                    "Command '{program}' timed out after {timeout:?}"
                )));
            }
        }
    } else {
        output_future
            .await
            .map_err(|e| ConnectorError::Other(format!("Command '{program}' I/O error: {e}")))?
    };

    // The command completed and we hold its output: do NOT kill the process
    // group on the way out (a long-running grandchild the tool deliberately
    // detached is its own business). Only a dropped-before-completion future
    // escalates to a group kill.
    #[cfg(unix)]
    process_group_guard.disarm();

    Ok(CommandOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code(),
        success: output.status.success(),
    })
}

/// Drop guard that SIGKILLs a child's process group when a
/// [`run_command_opts`] future is dropped before the command completes.
///
/// `run_command_opts` spawns the child with `process_group(0)` (Unix), so the
/// child is the leader of a fresh group whose id equals its pid. While the
/// guard is armed (a grandchild may still be alive, which keeps the group id
/// reserved) `kill(-pgid, SIGKILL)` reaches the whole subtree — the shell and
/// any `sleep`/pipeline it spawned. The guard is disarmed on normal
/// completion, so a finished command's intentionally-detached children are
/// left running. `kill_on_drop(true)` still handles the direct child.
#[cfg(unix)]
struct ProcessGroupKillGuard {
    /// `Some(pgid)` while armed; `None` once disarmed or if the pid is unknown.
    pgid: Option<i32>,
}

#[cfg(unix)]
impl ProcessGroupKillGuard {
    fn new(child_pid: Option<u32>) -> Self {
        Self {
            pgid: child_pid.map(|pid| pid as i32),
        }
    }

    fn disarm(&mut self) {
        self.pgid = None;
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupKillGuard {
    fn drop(&mut self) {
        if let Some(pgid) = self.pgid {
            // SAFETY: `kill(2)` with a negative pid targets the process group
            // `pgid`, which is our own child's group (created via
            // `process_group(0)`). While armed at least the direct child was
            // spawned into it, so the group id is ours; a stale group simply
            // yields ESRCH, which we ignore.
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
    }
}

/// Run a shell command via the system shell (`sh -c` on Unix).
///
/// Useful for commands that need shell features like pipes, redirection,
/// or glob expansion.
///
/// # Security Warning
///
/// Never pass unsanitized user input directly. Use [`run_command`] with
/// explicit arguments instead when possible.
pub async fn run_shell(command: &str) -> Result<CommandOutput> {
    run_command("sh", &["-c", command]).await
}

/// Run a shell command with a timeout.
pub async fn run_shell_with_timeout(command: &str, timeout: Duration) -> Result<CommandOutput> {
    run_command_with_timeout("sh", &["-c", command], timeout).await
}

/// Convenience function to run a command and return stdout, failing on non-zero exit.
///
/// Returns the trimmed stdout string on success.
pub async fn run_command_stdout(program: &str, args: &[&str]) -> Result<String> {
    let output = run_command(program, args).await?;
    if !output.success {
        return Err(ConnectorError::Other(format!(
            "Command '{program}' failed (exit {}): {}",
            output.exit_code.unwrap_or(-1),
            output.stderr.trim()
        )));
    }
    Ok(output.stdout.trim().to_string())
}

/// Build a command with a fluent API for more complex configurations.
///
/// # Examples
///
/// ```rust,ignore
/// use strike48_connector::process::CommandBuilder;
/// use std::time::Duration;
///
/// let output = CommandBuilder::new("nmap")
///     .args(&["-sV", "-p", "1-1000", "target.com"])
///     .timeout(Duration::from_secs(300))
///     .working_dir("/tmp")
///     .env("NMAP_PRIVILEGED", "1")
///     .run()
///     .await?;
/// ```
pub struct CommandBuilder {
    program: String,
    args: Vec<String>,
    options: CommandOptions,
}

impl CommandBuilder {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            options: CommandOptions::default(),
        }
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn args(mut self, args: &[&str]) -> Self {
        self.args.extend(args.iter().map(|s| s.to_string()));
        self
    }

    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = Some(timeout);
        self
    }

    pub fn working_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.options.working_dir = Some(dir.into());
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.env.push((key.into(), value.into()));
        self
    }

    pub fn envs(mut self, vars: HashMap<String, String>) -> Self {
        self.options.env.extend(vars);
        self
    }

    pub fn clear_env(mut self) -> Self {
        self.options.clear_env = true;
        self
    }

    pub fn stdin(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.options.stdin_data = Some(data.into());
        self
    }

    /// Run the command and return the output.
    pub async fn run(self) -> Result<CommandOutput> {
        let args: Vec<&str> = self.args.iter().map(|s| s.as_str()).collect();
        run_command_opts(&self.program, &args, self.options).await
    }

    /// Run the command and return trimmed stdout, failing on non-zero exit.
    pub async fn run_stdout(self) -> Result<String> {
        let program = self.program.clone();
        let output = self.run().await?;
        if !output.success {
            return Err(ConnectorError::Other(format!(
                "Command '{program}' failed (exit {}): {}",
                output.exit_code.unwrap_or(-1),
                output.stderr.trim()
            )));
        }
        Ok(output.stdout.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_run_command_echo() {
        let output = run_command("echo", &["hello", "world"]).await.unwrap();
        assert!(output.success);
        assert_eq!(output.stdout.trim(), "hello world");
        assert_eq!(output.exit_code, Some(0));
    }

    #[tokio::test]
    async fn test_run_command_nonexistent() {
        let result = run_command("nonexistent_binary_xyz", &[]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_run_command_exit_code() {
        let output = run_command("sh", &["-c", "exit 42"]).await.unwrap();
        assert!(!output.success);
        assert_eq!(output.exit_code, Some(42));
    }

    #[tokio::test]
    async fn test_run_command_stderr() {
        let output = run_command("sh", &["-c", "echo error >&2"]).await.unwrap();
        assert!(output.success);
        assert_eq!(output.stderr.trim(), "error");
    }

    #[tokio::test]
    async fn test_run_command_with_timeout_success() {
        let output = run_command_with_timeout("echo", &["fast"], Duration::from_secs(5))
            .await
            .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout.trim(), "fast");
    }

    #[tokio::test]
    async fn test_run_command_with_timeout_exceeded() {
        let result = run_command_with_timeout("sleep", &["10"], Duration::from_millis(100)).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("timed out"));
    }

    #[tokio::test]
    async fn test_run_shell() {
        let output = run_shell("echo $((2 + 3))").await.unwrap();
        assert!(output.success);
        assert_eq!(output.stdout.trim(), "5");
    }

    #[tokio::test]
    async fn test_run_command_stdout_helper() {
        let stdout = run_command_stdout("echo", &["hello"]).await.unwrap();
        assert_eq!(stdout, "hello");
    }

    #[tokio::test]
    async fn test_run_command_stdout_fails_on_error() {
        let result = run_command_stdout("sh", &["-c", "echo fail >&2; exit 1"]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_command_builder() {
        let output = CommandBuilder::new("echo")
            .args(&["hello", "builder"])
            .timeout(Duration::from_secs(5))
            .run()
            .await
            .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout.trim(), "hello builder");
    }

    #[tokio::test]
    async fn test_command_builder_with_env() {
        let output = CommandBuilder::new("sh")
            .args(&["-c", "echo $MY_VAR"])
            .env("MY_VAR", "test_value")
            .run()
            .await
            .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout.trim(), "test_value");
    }

    #[tokio::test]
    async fn test_command_with_stdin() {
        let output = run_command_opts(
            "cat",
            &[],
            CommandOptions {
                stdin_data: Some(b"piped input".to_vec()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(output.success);
        assert_eq!(output.stdout, "piped input");
    }

    #[tokio::test]
    async fn test_stdin_broken_pipe_tolerated() {
        let output = run_command_opts(
            "head",
            &["-c", "1"],
            CommandOptions {
                stdin_data: Some(b"lots of data that head will not fully read".to_vec()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(output.success);
    }

    #[tokio::test]
    async fn test_concurrent_commands_no_thread_starvation() {
        use std::time::Instant;

        let start = Instant::now();
        let mut handles = Vec::new();

        for i in 0..20 {
            handles.push(tokio::spawn(async move {
                run_command_with_timeout("sleep", &["1"], Duration::from_secs(5))
                    .await
                    .unwrap();
                i
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await.unwrap());
        }

        let elapsed = start.elapsed();

        assert_eq!(results.len(), 20);
        // 20 concurrent `sleep 1` should complete in ~1-2 seconds, not 20 seconds
        assert!(
            elapsed < Duration::from_secs(5),
            "20 concurrent sleeps took {:?} — thread starvation detected",
            elapsed
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_the_future_kills_grandchild_processes() {
        // A unique argument so the probe finds only this test's grandchild.
        let tag = format!("{}", 8_000_000 + std::process::id());
        // `sh -c "sleep <tag>; true"`: `sh` is the direct child, `sleep` is a
        // grandchild. `kill_on_drop(true)` kills only `sh`; without a
        // process-group kill the `sleep` re-parents to PID 1 and survives.
        let script = format!("sleep {tag}; true");
        let _ =
            tokio::time::timeout(std::time::Duration::from_millis(300), run_shell(&script)).await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let ps = std::process::Command::new("ps")
            .args(["-axo", "stat,command"])
            .output()
            .expect("ps");
        let still_running = String::from_utf8_lossy(&ps.stdout)
            .lines()
            .any(|l| l.ends_with(&format!("sleep {tag}")) && !l.starts_with('Z'));
        assert!(
            !still_running,
            "the grandchild (sleep) must die with the job's process group"
        );
    }

    /// The other half of the guard contract: a command that COMPLETES
    /// normally disarms the group kill, so a child it deliberately detached
    /// keeps running. Without `disarm()` the guard would SIGKILL the group on
    /// the way out and take the detached `sleep` with it.
    #[cfg(unix)]
    #[tokio::test]
    async fn completed_command_leaves_detached_children_alone() {
        let tag = format!("{}", 9_000_000 + std::process::id());
        // Background `sleep` with its stdio detached (so `wait_with_output`
        // is not held open by the inherited pipes) and print its pid.
        let script = format!("sleep {tag} >/dev/null 2>&1 & echo $!");
        let out = run_shell(&script).await.expect("shell completes");
        let pid: i32 = out.stdout.trim().parse().expect("background pid");
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // SAFETY: signal 0 only probes whether `pid` exists; it sends nothing.
        let alive = unsafe { libc::kill(pid, 0) } == 0;
        // Clean up before asserting so a failure does not leak the sleeper.
        // SAFETY: `pid` is the detached sleep this test just started.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
        assert!(
            alive,
            "a command that completed must not kill the child it detached"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn dropping_the_future_kills_the_child() {
        // A unique argument so the probe finds only this child.
        let tag = format!("{}", 7_000_000 + std::process::id());
        let args = [tag.as_str()];
        // Let it spawn, then drop it the way an abort or deadline does.
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            run_command("sleep", &args),
        )
        .await;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let ps = std::process::Command::new("ps")
            .args(["-axo", "stat,command"])
            .output()
            .expect("ps");
        let still_running = String::from_utf8_lossy(&ps.stdout)
            .lines()
            .any(|l| l.ends_with(&format!("sleep {tag}")) && !l.starts_with('Z'));
        assert!(!still_running, "the child must die with its future");
    }
}
