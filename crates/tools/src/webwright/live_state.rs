//! Global live state for webwright execution progress.
//!
//! Supports multiple concurrent tasks keyed by task_id.
//! Each tool call widget subscribes to its own task's progress.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use tokio::sync::watch;

/// A single log entry in the rolling progress.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub step: u32,
    pub action: String,
}

/// A finding discovered during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebwrightFinding {
    pub severity: String,
    pub title: String,
}

/// Progress state for a single webwright task.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebwrightProgress {
    pub step: u32,
    pub action: String,
    /// Base64-encoded screenshot at this step (most recent)
    pub screenshot: Option<String>,
    /// All screenshots captured so far (base64, most recent first)
    pub screenshots: Vec<String>,
    pub findings: Vec<WebwrightFinding>,
    /// Rolling log (last 20 entries)
    pub log: Vec<LogEntry>,
    pub running: bool,
    pub task_id: String,
}

type TaskRegistry = HashMap<
    String,
    (
        watch::Sender<WebwrightProgress>,
        watch::Receiver<WebwrightProgress>,
    ),
>;

/// Registry of active task progress channels (sender + one receiver for peeking).
static TASKS: LazyLock<Mutex<TaskRegistry>> = LazyLock::new(|| Mutex::new(HashMap::new()));

/// Get or create a receiver for a specific task's progress.
pub fn subscribe(task_id: &str) -> watch::Receiver<WebwrightProgress> {
    let mut tasks = TASKS.lock().unwrap();
    let (tx, _rx) = tasks
        .entry(task_id.to_string())
        .or_insert_with(|| watch::channel(WebwrightProgress::default()));
    tx.subscribe()
}

/// Get the current state for a task.
pub fn peek(task_id: &str) -> WebwrightProgress {
    let tasks = TASKS.lock().unwrap();
    tasks
        .get(task_id)
        .map(|(_, rx)| rx.borrow().clone())
        .unwrap_or_default()
}

/// Check if ANY task is currently running.
pub fn any_running() -> bool {
    let tasks = TASKS.lock().unwrap();
    tasks.values().any(|(_, rx)| rx.borrow().running)
}

/// Get all currently running task IDs.
pub fn running_tasks() -> Vec<String> {
    let tasks = TASKS.lock().unwrap();
    tasks
        .iter()
        .filter(|(_, (_, rx))| rx.borrow().running)
        .map(|(id, _)| id.clone())
        .collect()
}

/// Push a progress update for a specific task.
pub fn update(task_id: &str, progress: WebwrightProgress) {
    let mut tasks = TASKS.lock().unwrap();
    let (tx, _) = tasks
        .entry(task_id.to_string())
        .or_insert_with(|| watch::channel(WebwrightProgress::default()));
    let _ = tx.send(progress);
}

/// Signal that a task has started.
pub fn start(task_id: &str) {
    update(
        task_id,
        WebwrightProgress {
            step: 0,
            action: "initializing...".to_string(),
            running: true,
            task_id: task_id.to_string(),
            ..Default::default()
        },
    );
}

/// Signal that a task has completed.
pub fn complete(task_id: &str) {
    let tasks = TASKS.lock().unwrap();
    if let Some((tx, _)) = tasks.get(task_id) {
        let _ = tx.send(WebwrightProgress {
            running: false,
            task_id: task_id.to_string(),
            ..Default::default()
        });
    }
}
