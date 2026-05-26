//! Webwright sidecar protocol for real-time updates.
//!
//! Communicates with a long-lived Webwright process via JSON lines
//! over stdin/stdout. Enables live progress streaming, warm browser
//! reuse, and future interactive steering.

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    },
    /// Execute a pre-written script.
    ExecuteScript { script: String, url: String },
    /// Cancel the current task.
    Cancel,
}

/// Messages sent from the Webwright sidecar to Pick.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SidecarEvent {
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
    fn event_deserializes_finding() {
        let line = r#"{"type":"finding","severity":"high","title":"XSS in search","detail":"Reflected XSS via q param"}"#;
        let event = SidecarEvent::from_json_line(line).unwrap();
        match event {
            SidecarEvent::Finding {
                severity, title, ..
            } => {
                assert_eq!(severity, "high");
                assert_eq!(title, "XSS in search");
            }
            _ => panic!("Expected Finding event"),
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
    fn cancel_command_serializes() {
        let cmd = SidecarCommand::Cancel;
        let line = cmd.to_json_line();
        assert!(line.contains("cancel"));
    }
}
