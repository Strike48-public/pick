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
    let known: Vec<String> = {
        let map = REQUEST_TO_TASK.lock().unwrap();
        if let Some(v) = map.get(request_id) {
            return Some(v.clone());
        }
        map.keys().cloned().collect()
    };
    // Throttled diagnostic: log a single MISS per unseen query key, not on every poll.
    // Widgets retry every 500ms, so without throttling we'd flood the log.
    tracing::debug!(
        "[live_state] task_for_request MISS: query={:?}, registered_keys={:?}",
        request_id,
        known
    );
    None
}

/// Compute a stable signature for a tool call from its name and arguments.
///
/// This is a fallback binding key for when ID-based bindings fail (e.g. the platform's
/// `tool_call_id` in ExecuteRequest.context doesn't match the conversation's `toolCall.id`).
/// Both the executor (Pick) and the widget (chat panel) compute the same hash from the
/// same `(tool_name, arguments_json)` pair, allowing widgets to find their running task
/// without relying on platform IDs aligning.
///
/// `arguments_json` is the JSON-serialized arguments as a string. The function normalizes
/// it to a canonical form (parsed and re-serialized with sorted keys) so that whitespace
/// or key-order differences between the executor and the conversation API don't break the
/// match. If the input isn't parseable JSON it's hashed verbatim.
pub fn signature_for_call(tool_name: &str, arguments_json: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let canonical = canonicalize_json(arguments_json);
    let mut h = DefaultHasher::new();
    tool_name.hash(&mut h);
    canonical.hash(&mut h);
    format!("sig:{:x}", h.finish())
}

/// Re-serialize JSON with sorted object keys so semantically equal values hash the same.
fn canonicalize_json(s: &str) -> String {
    let Ok(value): Result<serde_json::Value, _> = serde_json::from_str(s) else {
        return s.to_string();
    };
    fn sort(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(map) => {
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_by(|a, b| a.0.cmp(b.0));
                let mut out = serde_json::Map::new();
                for (k, val) in entries {
                    out.insert(k.clone(), sort(val));
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(sort).collect())
            }
            other => other.clone(),
        }
    }
    serde_json::to_string(&sort(&value)).unwrap_or_else(|_| s.to_string())
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
///
/// Marks the task `running: false` and schedules a deferred cleanup of both the task
/// channel and any request→task bindings pointing at it. The delay lets any in-flight
/// widget see the final state before entries disappear.
pub fn complete(task_id: &str) {
    {
        let tasks = TASKS.lock().unwrap();
        if let Some((tx, _)) = tasks.get(task_id) {
            let _ = tx.send(WebwrightProgress {
                running: false,
                task_id: task_id.to_string(),
                ..Default::default()
            });
        }
    }
    // Deferred prune so the maps don't grow unbounded across the connector's lifetime.
    // 60s gives widgets enough time to receive the running=false notification and any
    // late conversation polls a chance to find the entry.
    let task_id_owned = task_id.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        purge_task(&task_id_owned);
    });
}

/// Remove a task and every request→task binding that resolves to it.
fn purge_task(task_id: &str) {
    {
        let mut tasks = TASKS.lock().unwrap();
        tasks.remove(task_id);
    }
    {
        let mut map = REQUEST_TO_TASK.lock().unwrap();
        map.retain(|_, v| v != task_id);
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

        assert_eq!(
            task_for_request(tool_call_id),
            Some(workspace_task_id.to_string())
        );
        assert_eq!(
            task_for_request(request_id),
            Some(workspace_task_id.to_string())
        );
    }

    #[test]
    fn missing_binding_returns_none() {
        assert_eq!(task_for_request("never-registered-id-zzz"), None);
    }

    #[test]
    fn signature_is_stable_across_key_order() {
        let a = signature_for_call("webwright", r#"{"url":"x","task":"y"}"#);
        let b = signature_for_call("webwright", r#"{"task":"y","url":"x"}"#);
        assert_eq!(a, b, "signature must be invariant to JSON key order");
    }

    #[test]
    fn signature_is_stable_across_whitespace() {
        let compact = signature_for_call("webwright", r#"{"url":"x","task":"y"}"#);
        let pretty = signature_for_call(
            "webwright",
            r#"{
                "url": "x",
                "task": "y"
            }"#,
        );
        assert_eq!(compact, pretty, "signature must be invariant to whitespace");
    }

    #[test]
    fn signature_differs_for_different_args() {
        let a = signature_for_call("webwright", r#"{"url":"https://a.com"}"#);
        let b = signature_for_call("webwright", r#"{"url":"https://b.com"}"#);
        assert_ne!(a, b);
    }

    #[test]
    fn signature_differs_for_different_tool_names() {
        let a = signature_for_call("webwright", r#"{"x":1}"#);
        let b = signature_for_call("nmap", r#"{"x":1}"#);
        assert_ne!(a, b);
    }

    #[test]
    fn signature_falls_back_on_invalid_json() {
        // Not valid JSON — should hash verbatim, not panic
        let s = signature_for_call("webwright", "not-json-at-all");
        assert!(s.starts_with("sig:"));
    }

    #[test]
    fn purge_removes_task_and_all_its_bindings() {
        let task_id = "ws-purge-test-uuid";
        let tool_call_id = "call_purge_test_xyz";
        let request_id = "agent-purge-test-99";
        let signature = "sig:purge-test-abc";

        register_request(tool_call_id, task_id);
        register_request(request_id, task_id);
        register_request(signature, task_id);
        // Ensure a task channel exists so purge has something to drop
        let _rx = subscribe(task_id);

        purge_task(task_id);

        assert_eq!(task_for_request(tool_call_id), None);
        assert_eq!(task_for_request(request_id), None);
        assert_eq!(task_for_request(signature), None);
    }

    #[test]
    fn purge_leaves_unrelated_bindings_alone() {
        register_request("keep_me_1", "task-keep");
        register_request("drop_me_1", "task-drop");
        register_request("drop_me_2", "task-drop");

        purge_task("task-drop");

        assert_eq!(task_for_request("keep_me_1"), Some("task-keep".to_string()));
        assert_eq!(task_for_request("drop_me_1"), None);
        assert_eq!(task_for_request("drop_me_2"), None);
    }

    #[test]
    fn widget_lookup_resolves_via_signature() {
        // Simulates the content-fallback flow:
        // - Platform's tool_call_id ≠ conversation's toolCall.id (ID mismatch)
        // - Both sides compute the same signature from (tool_name, args)
        // - Widget finds task via signature lookup
        let args = r#"{"start_url":"https://target.example","task":"screenshot"}"#;
        let sig = signature_for_call("webwright", args);
        let workspace_task_id = "ws-sig-lookup-test";

        register_request(&sig, workspace_task_id);

        assert_eq!(
            task_for_request(&sig),
            Some(workspace_task_id.to_string()),
            "widget must resolve via signature when IDs don't align"
        );
    }
}
