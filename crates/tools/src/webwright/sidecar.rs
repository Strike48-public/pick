//! Webwright sidecar process management.
//!
//! Manages a long-lived Python process that runs inside the proot sandbox.
//! Communicates via JSON lines over stdin/stdout for real-time progress
//! streaming and warm browser reuse between tasks.

use pentest_core::error::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::process::Stdio;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{broadcast, Mutex};

use super::constants;

/// Messages sent from Pick to the Webwright sidecar.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SidecarCommand {
    /// Start an autonomous exploration task.
    StartTask {
        mode: String,
        task: String,
        url: String,
        max_steps: u32,
        output_dir: String,
        task_id: String,
    },
    /// Execute a pre-written Playwright script. The sidecar writes the script
    /// to `<output_dir>/script.py` and runs it; the `url` is purely informational
    /// (the script itself drives any navigation).
    ExecuteScript {
        script: String,
        url: String,
        output_dir: String,
        task_id: String,
    },
    /// Cancel the current task.
    Cancel,
    /// Shut down the sidecar gracefully.
    Shutdown,
}

/// Messages sent from the Webwright sidecar to Pick.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SidecarEvent {
    /// Sidecar is ready to accept commands.
    Ready,
    /// Agent completed one step.
    Step {
        n: u32,
        action: String,
        screenshot: Option<String>,
    },
    /// A vulnerability or finding was discovered.
    Finding {
        severity: String,
        title: String,
        detail: String,
    },
    /// A replayable script was generated.
    ScriptGenerated { path: String },
    /// A network request/response was captured.
    NetworkEvent { request: Value, response: Value },
    /// Task completed.
    Complete { summary: String, artifacts: Value },
    /// Task failed.
    Error { message: String },
    /// Task was cancelled.
    Cancelled,
    /// Sidecar acknowledged shutdown.
    ShutdownAck,
}

impl SidecarCommand {
    /// Serialize to JSON line (newline-terminated).
    pub fn to_json_line(&self) -> String {
        match serde_json::to_string(self) {
            Ok(mut s) => {
                s.push('\n');
                s
            }
            Err(e) => {
                tracing::error!("[webwright-sidecar] failed to serialize command: {}", e);
                String::from("{}\n")
            }
        }
    }
}

impl SidecarEvent {
    /// Parse from a JSON line.
    pub fn from_json_line(line: &str) -> Option<Self> {
        serde_json::from_str(line.trim()).ok()
    }
}

/// Manages the sidecar Python process.
pub struct SidecarProcess {
    child: Arc<Mutex<Option<Child>>>,
    stdin: Arc<Mutex<Option<tokio::process::ChildStdin>>>,
    event_tx: broadcast::Sender<SidecarEvent>,
    is_ready: Arc<Mutex<bool>>,
}

impl SidecarProcess {
    /// Spawn the sidecar process inside the proot sandbox.
    ///
    /// Assumes `install::ensure_webwright_installed` has already written the sidecar
    /// server script to `<rootfs>/tmp/webwright_sidecar_server.py` and that
    /// `env_exports` already sets `OPENAI_BASE_URL` and `OPENAI_API_KEY`.
    pub async fn spawn(env_exports: &str) -> Result<Self> {
        let (event_tx, _) = broadcast::channel(constants::SIDECAR_EVENT_CHANNEL_CAPACITY);

        // Build the proot command that runs the sidecar server.
        let rootfs = constants::rootfs_dir();
        let proot_bin = constants::proot_binary_path();
        let rootfs_str = rootfs.to_string_lossy().to_string();

        // env_exports (from build_env_exports) sets OPENAI_BASE_URL and OPENAI_API_KEY
        // to the values that route to Pick's LLM proxy with the session_token as
        // bearer. Do NOT re-export those here — earlier versions hardcoded
        // OPENAI_API_KEY='pick-internal' after env_exports, clobbering the real
        // session token and breaking auth for headless StrikeKit runs.
        let cmd_str = format!(
            "export PATH=/usr/bin:/usr/local/bin:/bin:/sbin; \
             {} \
             export PLAYWRIGHT_CHROMIUM_SANDBOX=0; \
             python3 {}",
            env_exports,
            constants::sidecar_server_sandbox_path()
        );

        let mut child = Command::new(&proot_bin)
            .args([
                "-0",
                "-r",
                &rootfs_str,
                "-b",
                "/dev",
                "-b",
                "/proc",
                "-b",
                "/sys",
                "-b",
                "/etc/resolv.conf",
                "-w",
                "/tmp",
                "/bin/bash",
                "-c",
                &cmd_str,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // SIGKILL the proot child (and the Chromium subtree underneath) when the
            // SidecarProcess is dropped. Without this an early return from
            // try_sidecar_execution would orphan a browser process per failed task.
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| Error::ToolExecution(format!("Failed to spawn sidecar: {}", e)))?;

        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let process = Self {
            child: Arc::new(Mutex::new(Some(child))),
            stdin: Arc::new(Mutex::new(stdin)),
            event_tx: event_tx.clone(),
            is_ready: Arc::new(Mutex::new(false)),
        };

        // Drain stderr to tracing to prevent pipe buffer deadlock.
        if let Some(stderr) = stderr {
            tokio::spawn(async move {
                let reader = BufReader::new(stderr);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::debug!(target: "webwright_sidecar_stderr", "{}", line);
                }
            });
        }

        // Spawn event reader task
        if let Some(stdout) = stdout {
            let tx = event_tx.clone();
            let is_ready = process.is_ready.clone();
            tokio::spawn(async move {
                let reader = BufReader::new(stdout);
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if let Some(event) = SidecarEvent::from_json_line(&line) {
                        if matches!(event, SidecarEvent::Ready) {
                            *is_ready.lock().await = true;
                        }
                        let _ = tx.send(event);
                    }
                }
            });
        }

        // Wait for ready signal.
        let deadline = tokio::time::Instant::now()
            + tokio::time::Duration::from_secs(constants::SIDECAR_READY_TIMEOUT_SECS);
        loop {
            if *process.is_ready.lock().await {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                return Err(Error::ToolExecution(format!(
                    "Sidecar did not become ready in {}s",
                    constants::SIDECAR_READY_TIMEOUT_SECS
                )));
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(
                constants::SIDECAR_READY_POLL_INTERVAL_MS,
            ))
            .await;
        }

        tracing::info!("[webwright-sidecar] process spawned and ready");
        Ok(process)
    }

    /// Send a command to the sidecar.
    pub async fn send(&self, cmd: SidecarCommand) -> Result<()> {
        let mut stdin = self.stdin.lock().await;
        if let Some(ref mut writer) = *stdin {
            writer
                .write_all(cmd.to_json_line().as_bytes())
                .await
                .map_err(|e| Error::ToolExecution(format!("Failed to write to sidecar: {}", e)))?;
            writer.flush().await.ok();
            Ok(())
        } else {
            Err(Error::ToolExecution("Sidecar stdin not available".into()))
        }
    }

    /// Subscribe to events from the sidecar.
    pub fn subscribe(&self) -> broadcast::Receiver<SidecarEvent> {
        self.event_tx.subscribe()
    }

    /// Check if the sidecar is ready.
    pub async fn is_ready(&self) -> bool {
        *self.is_ready.lock().await
    }

    /// Shutdown the sidecar gracefully.
    pub async fn shutdown(&self) {
        let _ = self.send(SidecarCommand::Shutdown).await;
        // Give it a moment to exit
        tokio::time::sleep(tokio::time::Duration::from_millis(
            constants::SIDECAR_SHUTDOWN_GRACE_MS,
        ))
        .await;
        // Force kill if still running
        if let Some(mut child) = self.child.lock().await.take() {
            let _ = child.kill().await;
        }
    }

    /// Check if the process is still alive.
    pub async fn is_alive(&self) -> bool {
        if let Some(ref mut child) = *self.child.lock().await {
            child.try_wait().ok().flatten().is_none()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_serializes_to_json_line() {
        let cmd = SidecarCommand::StartTask {
            mode: "explore".to_string(),
            task: "test XSS".to_string(),
            url: "https://target.com".to_string(),
            max_steps: 50,
            output_dir: "/tmp/webwright/test".to_string(),
            task_id: "test-123".to_string(),
        };
        let line = cmd.to_json_line();
        assert!(line.ends_with('\n'));
        assert!(line.contains("start_task"));
        assert!(line.contains("test XSS"));
    }

    #[test]
    fn event_deserializes_step() {
        let line = r#"{"type":"step","n":3,"action":"clicking login button","screenshot":null}"#;
        let event = SidecarEvent::from_json_line(line).unwrap();
        match event {
            SidecarEvent::Step { n, action, .. } => {
                assert_eq!(n, 3);
                assert_eq!(action, "clicking login button");
            }
            _ => panic!("Expected Step event"),
        }
    }

    #[test]
    fn event_deserializes_complete() {
        let line =
            r#"{"type":"complete","summary":"Found 3 vulns","artifacts":{"scripts":["a.py"]}}"#;
        let event = SidecarEvent::from_json_line(line).unwrap();
        match event {
            SidecarEvent::Complete { summary, .. } => {
                assert_eq!(summary, "Found 3 vulns");
            }
            _ => panic!("Expected Complete event"),
        }
    }

    #[test]
    fn event_deserializes_ready() {
        let line = r#"{"type":"ready"}"#;
        let event = SidecarEvent::from_json_line(line).unwrap();
        assert!(matches!(event, SidecarEvent::Ready));
    }
}
