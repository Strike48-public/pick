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
    /// Execute a pre-written script.
    ExecuteScript {
        script: String,
        url: String,
        output_dir: String,
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
        let mut s = serde_json::to_string(self).unwrap_or_default();
        s.push('\n');
        s
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
    pub async fn spawn(env_exports: &str, proxy_port: u16) -> Result<Self> {
        let (event_tx, _) = broadcast::channel(100);

        // Build the proot command that runs the sidecar server
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        let rootfs = format!("{}/.local/share/pentest-sandbox/blackarch-rootfs", home);
        let proot_bin = format!("{}/.local/share/pentest-sandbox/bin/proot", home);

        // The sidecar_server.py is embedded in the rootfs at a known path
        let server_script = include_str!("sidecar_server.py");
        let script_path = format!("{}/tmp/webwright_sidecar_server.py", rootfs);
        std::fs::write(&script_path, server_script)
            .map_err(|e| Error::ToolExecution(format!("Failed to write sidecar script: {}", e)))?;

        let cmd_str = format!(
            "export PATH=/usr/bin:/usr/local/bin:/bin:/sbin; \
             {} \
             export OPENAI_BASE_URL='http://127.0.0.1:{}/v1'; \
             export OPENAI_API_KEY='pick-internal'; \
             export PLAYWRIGHT_CHROMIUM_SANDBOX=0; \
             python3 /tmp/webwright_sidecar_server.py",
            env_exports, proxy_port
        );

        let mut child = Command::new(&proot_bin)
            .args([
                "-0",
                "-r",
                &rootfs,
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
            .spawn()
            .map_err(|e| Error::ToolExecution(format!("Failed to spawn sidecar: {}", e)))?;

        let stdin = child.stdin.take();
        let stdout = child.stdout.take();

        let process = Self {
            child: Arc::new(Mutex::new(Some(child))),
            stdin: Arc::new(Mutex::new(stdin)),
            event_tx: event_tx.clone(),
            is_ready: Arc::new(Mutex::new(false)),
        };

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

        // Wait for ready signal (up to 10s)
        let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(10);
        loop {
            if *process.is_ready.lock().await {
                break;
            }
            if tokio::time::Instant::now() > deadline {
                return Err(Error::ToolExecution(
                    "Sidecar did not become ready in 10s".into(),
                ));
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
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
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
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
