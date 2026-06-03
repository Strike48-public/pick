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

type TaskChannel = (
    watch::Sender<WebwrightProgress>,
    watch::Receiver<WebwrightProgress>,
);

/// Registry of active task progress channels (sender + one receiver for peeking).
static TASKS: LazyLock<Mutex<HashMap<String, TaskChannel>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Maps request_id (tool call ID) → webwright task_id so widgets can find their task.
static REQUEST_TO_TASK: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Register a mapping from request_id to task_id.
pub fn register_request(request_id: &str, task_id: &str) {
    REQUEST_TO_TASK
        .lock()
        .unwrap()
        .insert(request_id.to_string(), task_id.to_string());
}

/// Look up the task_id for a given request_id.
pub fn task_for_request(request_id: &str) -> Option<String> {
    let map = REQUEST_TO_TASK.lock().unwrap();
    let result = map.get(request_id).cloned();
    if result.is_none() {
        // Diagnostic: surface every miss so we can see what the widget is asking for
        // vs what the executor registered. Spammy but only fires when the binding fails.
        let known: Vec<&String> = map.keys().collect();
        tracing::warn!(
            "[live_state] task_for_request MISS: query={:?}, registered_keys={:?}",
            request_id,
            known
        );
    }
    result
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widget_lookup_resolves_via_tool_call_id() {
        // Simulates the chat-panel widget flow:
        // - Platform sends tc.id = "call_abc" in the conversation message
        // - Pick registers binding under that tool_call_id → workspace task_id
        // - Widget looks up task_for_request("call_abc") to find its live stream
        let tool_call_id = "call_widget_lookup_test_abc";
        let workspace_task_id = "ws-widget-lookup-test-uuid";

        register_request(tool_call_id, workspace_task_id);

        assert_eq!(
            task_for_request(tool_call_id),
            Some(workspace_task_id.to_string()),
            "widget must resolve its live stream via the tool_call_id used in chat messages"
        );
    }

    #[test]
    fn dual_registration_supports_legacy_request_id_lookup() {
        // Older platform versions don't forward tool_call_id; webwright registers
        // under request_id as a fallback. Verify both keys resolve to the same task.
        let tool_call_id = "call_dual_reg_xyz";
        let request_id = "agent-99999999";
        let workspace_task_id = "ws-dual-reg-uuid";

        register_request(tool_call_id, workspace_task_id);
        register_request(request_id, workspace_task_id);

        assert_eq!(task_for_request(tool_call_id), Some(workspace_task_id.to_string()));
        assert_eq!(task_for_request(request_id), Some(workspace_task_id.to_string()));
    }

    #[test]
    fn missing_binding_returns_none() {
        assert_eq!(task_for_request("never-registered-id-zzz"), None);
    }
}
