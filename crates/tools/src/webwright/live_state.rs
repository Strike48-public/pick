//! Global live state for webwright execution progress.
//!
//! Provides a shared channel between the tool execution (sidecar) and the UI.
//! The chat panel subscribes to updates and renders them reactively.

use serde::{Deserialize, Serialize};
use std::sync::LazyLock;
use tokio::sync::watch;

/// A single log entry in the rolling progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub step: u32,
    pub action: String,
    pub timestamp: u64,
}

/// A single progress update from a running webwright task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebwrightProgress {
    /// Current step number (0 = initializing)
    pub step: u32,
    /// Human-readable description of what's happening
    pub action: String,
    /// Base64-encoded screenshot at this step (if available)
    pub screenshot: Option<String>,
    /// Accumulated findings so far
    pub findings: Vec<WebwrightFinding>,
    /// Rolling log of steps (latest at end, max 20)
    pub log: Vec<LogEntry>,
    /// Whether the task is still running
    pub running: bool,
    /// Task ID (for matching to the right widget)
    pub task_id: String,
}

/// A finding discovered during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebwrightFinding {
    pub severity: String,
    pub title: String,
}

impl Default for WebwrightProgress {
    fn default() -> Self {
        Self {
            step: 0,
            action: String::new(),
            screenshot: None,
            findings: Vec::new(),
            log: Vec::new(),
            running: false,
            task_id: String::new(),
        }
    }
}

/// Global watch channel for live webwright progress.
/// The sender is used by the sidecar event loop.
/// The receiver is cloned by the chat panel to render live updates.
static PROGRESS: LazyLock<(watch::Sender<WebwrightProgress>, watch::Receiver<WebwrightProgress>)> =
    LazyLock::new(|| watch::channel(WebwrightProgress::default()));

/// Get a receiver for live progress updates (used by UI).
pub fn subscribe() -> watch::Receiver<WebwrightProgress> {
    PROGRESS.1.clone()
}

/// Push a progress update (used by sidecar event loop).
pub fn update(progress: WebwrightProgress) {
    let _ = PROGRESS.0.send(progress);
}

/// Signal that execution has started.
pub fn start(task_id: &str) {
    let _ = PROGRESS.0.send(WebwrightProgress {
        step: 0,
        action: "initializing...".to_string(),
        screenshot: None,
        findings: Vec::new(),
        log: Vec::new(),
        running: true,
        task_id: task_id.to_string(),
    });
}

/// Signal that execution has completed.
pub fn complete(task_id: &str) {
    let _ = PROGRESS.0.send(WebwrightProgress {
        running: false,
        task_id: task_id.to_string(),
        ..WebwrightProgress::default()
    });
}
