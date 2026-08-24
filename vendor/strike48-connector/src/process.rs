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

    let mut child = cmd
        .spawn()
        .map_err(|e| ConnectorError::Other(format!("Failed to spawn '{program}': {e}")))?;

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

    Ok(CommandOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code(),
        success: output.status.success(),
    })
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
}
