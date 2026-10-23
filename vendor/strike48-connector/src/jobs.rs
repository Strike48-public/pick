//! In-flight job tracking and the platform `matrix.cancel` capability.
//!
//! Matrix dispatches tool work as [`crate::types::ExecuteRequest`]s with a
//! unique caller-supplied `request_id`. The SDK runs each request in a
//! tokio task (see the runners' message loops); historically the task handle
//! was discarded, which meant a dispatched job could not be recalled once
//! handed to the runtime.
//!
//! This module fixes that with two primitives:
//!
//! 1. [`JobRegistry`] — a long-lived `request_id → running task` map that
//!    survives stream reconnects (it hangs off the runner, not the per-stream
//!    handler). Each tracked job holds a [`JobTicket`] that removes its entry
//!    when the task finishes for any reason.
//!
//! 2. The reserved [`CANCEL_CAPABILITY`] (`"matrix.cancel"`) — a platform
//!    capability the SDK intercepts *before* it reaches connector-authored
//!    tools. Matrix recalls an in-flight job by dispatching a normal
//!    `ExecuteRequest` with `capability_id = "matrix.cancel"` and a JSON
//!    payload naming the job:
//!
//!    ```json
//!    {"cancel_request_id": "agent-123"}
//!    ```
//!
//!    The reply is a normal [`crate::types::ExecuteResponse`] using the
//!    existing `success` / `error` vocabulary — no new wire types:
//!
//!    - `success: true`  → the task was found and aborted ("observed and stopped").
//!    - `success: false`, `error: "unknown request_id: <id>"` → the job was
//!      never seen by this SDK instance, or already finished ("cancel not
//!      observed"). Cancel is idempotent: repeating it returns the same
//!      unknown/already-gone outcome.
//!
//! ## Exactly one answer per job
//!
//! A job and a cancel for it race for the job's registry entry. Whoever
//! removes the entry first owns the outcome:
//!
//! - the cancel wins → the cancel replies `success: true` and the job's own
//!   `ExecuteResponse` is never sent (the job checks [`JobTicket::complete`]
//!   before sending, and the abort drops it at its next await point);
//! - the job wins → it sends its real result and a later cancel replies
//!   `unknown request_id`.
//!
//! So Matrix never receives both "stopped" and a real result for one job.
//!
//! ## Cancellation semantics
//!
//! Cancellation is an abort: the task's work future is dropped at its next
//! await point. Pure-async work (HTTP, sockets, timers) stops with it.
//! Child processes stop only if the tool spawned them with
//! `Command::kill_on_drop(true)` (the SDK's own [`crate::process`] helpers
//! do); otherwise they outlive the abort. A cooperative cancellation token
//! for tools that need cleanup is a possible follow-up (it requires a
//! `BaseConnector` trait addition).
//!
//! ## Reserved namespace
//!
//! Capability IDs prefixed `matrix.` are reserved for platform verbs and
//! must not be used by connector-authored tools. The reservation is an SDK
//! convention (the proto has no field for it): registration drops such tools
//! from the advertised `tool_schemas` with a warning, since dispatch would
//! never reach them.

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::{ConnectorError, Result};
use crate::types::{ExecuteResponse, PayloadEncoding};

/// Reserved platform capability for recalling an in-flight `ExecuteRequest`.
///
/// Matrix dispatches `ExecuteRequest { capability_id: "matrix.cancel", payload:
/// `{"cancel_request_id": "<id>"}` }. The SDK intercepts it before connector
/// tools and aborts the tracked task. See [module docs](self) for the reply
/// contract.
pub const CANCEL_CAPABILITY: &str = "matrix.cancel";

/// Payload key carrying the `request_id` of the job to recall.
pub const CANCEL_REQUEST_ID_KEY: &str = "cancel_request_id";

/// Alias accepted in the cancel payload for robustness.
pub const CANCEL_REQUEST_ID_KEY_ALT: &str = "request_id";

/// Error string returned when a cancel names a job this SDK instance does not
/// have in flight (never seen, already finished, or already cancelled).
pub const UNKNOWN_REQUEST_ERROR_PREFIX: &str = "unknown request_id";

/// Error string returned when a cancel payload does not name a job.
pub const INVALID_CANCEL_PAYLOAD_ERROR: &str = "invalid cancel payload: missing cancel_request_id";

/// True when a capability name falls in the reserved `matrix.` platform
/// namespace and must not be used by connector-authored tools.
pub fn is_reserved_capability(name: &str) -> bool {
    name.starts_with("matrix.")
}

/// A tracked in-flight job.
pub struct RunningJob {
    /// Abort handle for the spawned task running the runner's request
    /// handler, obtained via `futures::future::AbortHandle::new_pair()`
    /// *before* spawning so the registry entry is always inserted before the
    /// task can run (and hence before it can finish) — no insert/complete
    /// race.
    pub abort: futures::future::AbortHandle,
    /// When the job was accepted (for logs / future observability).
    pub started_at: Instant,
    /// Distinguishes two jobs that reuse one `request_id`, so a finishing
    /// job never removes a newer job's entry.
    generation: u64,
}

impl RunningJob {
    /// Build an entry for [`JobRegistry::insert`].
    pub fn new(abort: futures::future::AbortHandle) -> Self {
        Self {
            abort,
            started_at: Instant::now(),
            generation: 0,
        }
    }
}

/// Outcome of a cancel attempt. Maps onto the existing `ExecuteResponse`
/// vocabulary — no new wire types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CancelOutcome {
    /// The tracked task was found and aborted.
    Stopped { request_id: String },
    /// No such job in flight: never seen, already finished, or already
    /// cancelled. Honest "cancel not observed".
    Unknown { request_id: String },
}

impl CancelOutcome {
    /// Build the wire response for this outcome. `reply_request_id` is the
    /// `request_id` of the *cancel request itself* (the response echoes it,
    /// as with every `ExecuteResponse`).
    pub fn into_execute_response(self, reply_request_id: String) -> ExecuteResponse {
        match self {
            CancelOutcome::Stopped { request_id } => {
                let payload = serde_json::json!({
                    "cancelled": true,
                    "request_id": request_id,
                });
                ExecuteResponse {
                    request_id: reply_request_id,
                    success: true,
                    payload: serde_json::to_vec(&payload).unwrap_or_default(),
                    payload_encoding: PayloadEncoding::Json,
                    error: String::new(),
                    duration_ms: 0,
                }
            }
            CancelOutcome::Unknown { request_id } => {
                let payload = serde_json::json!({
                    "cancelled": false,
                    "request_id": request_id,
                });
                ExecuteResponse {
                    request_id: reply_request_id,
                    success: false,
                    payload: serde_json::to_vec(&payload).unwrap_or_default(),
                    payload_encoding: PayloadEncoding::Json,
                    error: format!("{UNKNOWN_REQUEST_ERROR_PREFIX}: {request_id}"),
                    duration_ms: 0,
                }
            }
        }
    }
}

/// Extract the target `request_id` from a `matrix.cancel` payload.
///
/// Accepts [`CANCEL_REQUEST_ID_KEY`] and, for robustness, the generic
/// [`CANCEL_REQUEST_ID_KEY_ALT`]. Returns `None` for unparsable payloads —
/// the caller replies with a `bad cancel payload` error rather than guessing.
pub fn parse_cancel_target(payload: &[u8]) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(payload).ok()?;
    value
        .get(CANCEL_REQUEST_ID_KEY)
        .or_else(|| value.get(CANCEL_REQUEST_ID_KEY_ALT))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Long-lived registry of in-flight jobs, keyed by Matrix-supplied
/// `request_id`. Lives on the runner so it survives stream reconnects (a
/// network blip must not forget running jobs — they keep running and their
/// entries stay cancellable after re-registering).
#[derive(Clone, Default)]
pub struct JobRegistry {
    inner: Arc<Mutex<HashMap<String, RunningJob>>>,
    next_generation: Arc<AtomicU64>,
}

impl JobRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Track a job. Prefer [`JobRegistry::track`], which also hands back the
    /// [`JobTicket`] that removes the entry again.
    pub fn insert(&self, request_id: String, mut job: RunningJob) -> u64 {
        let generation = self.next_generation.fetch_add(1, Ordering::Relaxed) + 1;
        job.generation = generation;
        self.inner
            .lock()
            .expect("job registry poisoned")
            .insert(request_id, job);
        generation
    }

    /// Register a job about to be spawned. Returns the ticket the task must
    /// hold and the registration to wrap its work in
    /// (`futures::future::Abortable::new(work, registration)`). The entry is
    /// inserted before this returns, so a cancel can never race past it.
    pub(crate) fn track(
        &self,
        request_id: String,
    ) -> (JobTicket, futures::future::AbortRegistration) {
        let (abort, registration) = futures::future::AbortHandle::new_pair();
        let generation = self.insert(request_id.clone(), RunningJob::new(abort));
        let ticket = JobTicket {
            registry: self.clone(),
            request_id,
            generation,
        };
        (ticket, registration)
    }

    /// Remove the entry for `request_id` unconditionally.
    pub fn remove(&self, request_id: &str) {
        self.inner
            .lock()
            .expect("job registry poisoned")
            .remove(request_id);
    }

    /// Remove the entry for `request_id` only if it is still the job of
    /// `generation`. Returns true when it removed it.
    fn remove_generation(&self, request_id: &str, generation: u64) -> bool {
        let mut map = self.inner.lock().expect("job registry poisoned");
        match map.get(request_id) {
            Some(job) if job.generation == generation => {
                map.remove(request_id);
                true
            }
            _ => false,
        }
    }

    /// Number of jobs currently tracked.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("job registry poisoned").len()
    }

    /// True when no jobs are tracked.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Abort the job named `request_id`, if tracked.
    ///
    /// Removing the entry is what claims the outcome (see the module docs):
    /// present → `Stopped`, and the job will not send its own result;
    /// absent → `Unknown` (never seen, already finished, already cancelled).
    pub fn cancel(&self, request_id: &str) -> CancelOutcome {
        let job = self
            .inner
            .lock()
            .expect("job registry poisoned")
            .remove(request_id);
        match job {
            Some(job) => {
                job.abort.abort();
                CancelOutcome::Stopped {
                    request_id: request_id.to_string(),
                }
            }
            None => CancelOutcome::Unknown {
                request_id: request_id.to_string(),
            },
        }
    }

    /// Answer a `matrix.cancel` request: parse the payload, cancel the named
    /// job and build the reply on the cancel's own `request_id`. An
    /// unparsable payload is answered with [`INVALID_CANCEL_PAYLOAD_ERROR`] —
    /// never guessed.
    pub(crate) fn answer_cancel(
        &self,
        cancel_request_id: String,
        payload: &[u8],
    ) -> ExecuteResponse {
        match parse_cancel_target(payload) {
            Some(target) => {
                let outcome = self.cancel(&target);
                match &outcome {
                    CancelOutcome::Stopped { request_id } => tracing::info!(
                        job = %request_id,
                        cancel_request = %cancel_request_id,
                        "matrix.cancel: job aborted"
                    ),
                    CancelOutcome::Unknown { request_id } => tracing::warn!(
                        job = %request_id,
                        cancel_request = %cancel_request_id,
                        "matrix.cancel: job not in flight"
                    ),
                }
                outcome.into_execute_response(cancel_request_id)
            }
            None => {
                tracing::warn!(
                    cancel_request = %cancel_request_id,
                    "matrix.cancel: payload missing cancel_request_id"
                );
                ExecuteResponse {
                    request_id: cancel_request_id,
                    success: false,
                    payload: crate::utils::error_response(INVALID_CANCEL_PAYLOAD_ERROR)
                        .unwrap_or_default(),
                    payload_encoding: PayloadEncoding::Json,
                    error: INVALID_CANCEL_PAYLOAD_ERROR.to_string(),
                    duration_ms: 0,
                }
            }
        }
    }
}

/// Held by a tracked job's task. Removes the job's registry entry when the
/// task finishes for any reason (success, error, deadline, abort).
pub struct JobTicket {
    registry: JobRegistry,
    request_id: String,
    generation: u64,
}

impl JobTicket {
    /// Claim the job's outcome before sending its result. Returns false when
    /// a cancel already claimed it; the caller must then not send a result
    /// (the cancel's `success: true` reply is the job's answer).
    pub fn complete(&self) -> bool {
        self.registry
            .remove_generation(&self.request_id, self.generation)
    }
}

impl Drop for JobTicket {
    fn drop(&mut self) {
        self.registry
            .remove_generation(&self.request_id, self.generation);
    }
}

/// Wrap an `ExecuteResponse` as the wire message the multi-connector
/// runners send on their outbound channel.
pub(crate) fn execute_response_message(
    response: ExecuteResponse,
) -> strike48_proto::proto::StreamMessage {
    use strike48_proto::proto;
    proto::StreamMessage {
        message: Some(proto::stream_message::Message::ExecuteResponse(
            proto::ExecuteResponse {
                request_id: response.request_id,
                success: response.success,
                payload: response.payload,
                payload_encoding: response.payload_encoding as i32,
                error: response.error,
                duration_ms: response.duration_ms as i64,
            },
        )),
    }
}

/// Read the server-imposed deadline (`context["matrix.deadline_ms"]`).
/// Absent, unparsable or zero → no deadline.
pub fn deadline_from_context(context: &HashMap<String, String>) -> Option<Duration> {
    context
        .get(crate::context::keys::MATRIX_DEADLINE_MS)
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
}

/// Run a connector execution under the request's deadline, if any. When the
/// deadline passes the future is dropped (see the module docs for what that
/// stops) and the result is a [`ConnectorError::Timeout`].
pub(crate) async fn run_with_deadline<T, F>(context: &HashMap<String, String>, fut: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    match deadline_from_context(context) {
        Some(deadline) => match tokio::time::timeout(deadline, fut).await {
            Ok(result) => result,
            Err(_) => {
                tracing::warn!(
                    deadline_ms = deadline.as_millis() as u64,
                    "job exceeded matrix.deadline_ms; dropping execution"
                );
                Err(ConnectorError::Timeout(format!(
                    "deadline exceeded: matrix.deadline_ms={}ms",
                    deadline.as_millis()
                )))
            }
        },
        None => fut.await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spawn a task that sleeps for `ms` and register it.
    fn spawn_sleeper(registry: &JobRegistry, id: &str, ms: u64) {
        let (ticket, reg) = registry.track(id.to_string());
        tokio::spawn(futures::future::Abortable::new(
            async move {
                let _ticket = ticket;
                tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
            },
            reg,
        ));
    }

    #[tokio::test]
    async fn cancel_known_job_stops_it_and_reports_stopped() {
        let registry = JobRegistry::new();
        spawn_sleeper(&registry, "agent-1", 60_000);
        assert_eq!(registry.len(), 1);

        let outcome = registry.cancel("agent-1");
        assert_eq!(
            outcome,
            CancelOutcome::Stopped {
                request_id: "agent-1".into()
            }
        );
        assert!(registry.is_empty());

        // Give the aborted task a moment to observe the abort and settle.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    #[tokio::test]
    async fn cancel_unknown_job_reports_unknown() {
        let registry = JobRegistry::new();
        assert_eq!(
            registry.cancel("agent-nope"),
            CancelOutcome::Unknown {
                request_id: "agent-nope".into()
            }
        );
    }

    #[tokio::test]
    async fn cancel_is_idempotent_second_cancel_is_unknown() {
        let registry = JobRegistry::new();
        spawn_sleeper(&registry, "agent-2", 60_000);
        assert_eq!(
            registry.cancel("agent-2"),
            CancelOutcome::Stopped {
                request_id: "agent-2".into()
            }
        );
        assert_eq!(
            registry.cancel("agent-2"),
            CancelOutcome::Unknown {
                request_id: "agent-2".into()
            }
        );
    }

    #[tokio::test]
    async fn finished_job_removes_itself_via_ticket() {
        let registry = JobRegistry::new();
        spawn_sleeper(&registry, "agent-3", 20);
        assert_eq!(registry.len(), 1);
        // Wait past the sleep; the ticket must have removed the entry.
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        assert!(registry.is_empty(), "finished job must self-remove");
    }

    #[test]
    fn completed_job_makes_a_later_cancel_unknown() {
        let registry = JobRegistry::new();
        let (ticket, _reg) = registry.track("agent-4".into());
        assert!(
            ticket.complete(),
            "the job owns its outcome when no cancel came first"
        );
        assert_eq!(
            registry.cancel("agent-4"),
            CancelOutcome::Unknown {
                request_id: "agent-4".into()
            }
        );
    }

    #[test]
    fn cancelled_job_may_not_send_its_result() {
        let registry = JobRegistry::new();
        let (ticket, _reg) = registry.track("agent-5".into());
        assert_eq!(
            registry.cancel("agent-5"),
            CancelOutcome::Stopped {
                request_id: "agent-5".into()
            }
        );
        assert!(
            !ticket.complete(),
            "the cancel already answered for this job"
        );
    }

    #[test]
    fn old_ticket_does_not_remove_a_reused_request_id() {
        let registry = JobRegistry::new();
        let (old, _r1) = registry.track("agent-6".into());
        let (new, _r2) = registry.track("agent-6".into());
        drop(old);
        assert_eq!(registry.len(), 1, "the newer job's entry must survive");
        assert!(new.complete());
        assert!(registry.is_empty());
    }

    #[test]
    fn answer_cancel_builds_replies_on_the_cancel_id() {
        let registry = JobRegistry::new();
        let (_ticket, _reg) = registry.track("agent-7".into());

        let stopped = registry.answer_cancel("c-1".into(), br#"{"cancel_request_id":"agent-7"}"#);
        assert!(stopped.success);
        assert_eq!(stopped.request_id, "c-1");

        let unknown = registry.answer_cancel("c-2".into(), br#"{"cancel_request_id":"agent-7"}"#);
        assert!(!unknown.success);
        assert!(unknown.error.starts_with(UNKNOWN_REQUEST_ERROR_PREFIX));

        let invalid = registry.answer_cancel("c-3".into(), b"{}");
        assert!(!invalid.success);
        assert_eq!(invalid.error, INVALID_CANCEL_PAYLOAD_ERROR);
    }

    #[test]
    fn deadline_reads_positive_milliseconds_only() {
        let ctx = |v: &str| {
            HashMap::from([(
                crate::context::keys::MATRIX_DEADLINE_MS.to_string(),
                v.to_string(),
            )])
        };
        assert_eq!(
            deadline_from_context(&ctx("1500")),
            Some(Duration::from_millis(1500))
        );
        assert_eq!(deadline_from_context(&ctx("0")), None);
        assert_eq!(deadline_from_context(&ctx("soon")), None);
        assert_eq!(deadline_from_context(&HashMap::new()), None);
    }

    #[tokio::test]
    async fn run_with_deadline_times_out_slow_work() {
        let ctx = HashMap::from([(
            crate::context::keys::MATRIX_DEADLINE_MS.to_string(),
            "50".to_string(),
        )]);
        let slow = async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok::<_, ConnectorError>(())
        };
        assert!(matches!(
            run_with_deadline(&ctx, slow).await,
            Err(ConnectorError::Timeout(_))
        ));
        let fast = async { Ok::<_, ConnectorError>(7) };
        assert_eq!(run_with_deadline(&ctx, fast).await.unwrap(), 7);
    }

    struct ReservedToolConnector;
    impl crate::connector::BaseConnector for ReservedToolConnector {
        fn connector_type(&self) -> &str {
            "reserved_test"
        }
        fn version(&self) -> &str {
            "0.0.0"
        }
        fn behaviors(&self) -> Vec<crate::types::ConnectorBehavior> {
            vec![crate::types::ConnectorBehavior::Tool]
        }
        fn capabilities(&self) -> Vec<crate::types::TaskTypeSchema> {
            ["matrix.cancel", "nmap_scan"]
                .iter()
                .map(|name| crate::types::TaskTypeSchema {
                    task_type_id: name.to_string(),
                    name: name.to_string(),
                    description: "test".into(),
                    ..Default::default()
                })
                .collect()
        }
        fn execute(
            &self,
            _: serde_json::Value,
            _: Option<&str>,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<serde_json::Value>> + Send + '_>>
        {
            Box::pin(async { Ok(serde_json::json!({})) })
        }
    }

    #[test]
    fn registration_does_not_advertise_reserved_tools() {
        let metadata = crate::connector::build_registration_metadata(&ReservedToolConnector);
        let schemas: serde_json::Value =
            serde_json::from_str(&metadata["tool_schemas"]).expect("tool_schemas json");
        let names: Vec<&str> = schemas
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["nmap_scan"]);
    }

    #[test]
    fn reserved_namespace_flags_platform_prefix_only() {
        assert!(is_reserved_capability("matrix.cancel"));
        assert!(is_reserved_capability("matrix.anything"));
        assert!(!is_reserved_capability("matrixify_scan"));
        assert!(!is_reserved_capability("nmap_scan"));
        assert!(!is_reserved_capability(""));
        assert!(!is_reserved_capability("Matrix.cancel"));
    }

    #[test]
    fn parse_cancel_target_reads_primary_key() {
        let payload = br#"{"cancel_request_id": "agent-9"}"#;
        assert_eq!(parse_cancel_target(payload).as_deref(), Some("agent-9"));
    }

    #[test]
    fn parse_cancel_target_reads_alias_key() {
        let payload = br#"{"request_id": "agent-9"}"#;
        assert_eq!(parse_cancel_target(payload).as_deref(), Some("agent-9"));
    }

    #[test]
    fn parse_cancel_target_rejects_garbage() {
        assert_eq!(parse_cancel_target(b"not json"), None);
        assert_eq!(parse_cancel_target(br#"{"other": 1}"#), None);
        assert_eq!(parse_cancel_target(br#"{"cancel_request_id": 42}"#), None);
    }

    #[test]
    fn outcome_maps_to_wire_vocabulary() {
        let stopped = CancelOutcome::Stopped {
            request_id: "a".into(),
        }
        .into_execute_response("r".into());
        assert!(stopped.success);
        assert_eq!(stopped.request_id, "r");
        let body: serde_json::Value =
            serde_json::from_slice(&stopped.payload).expect("json payload");
        assert_eq!(body["cancelled"], serde_json::json!(true));
        assert_eq!(body["request_id"], serde_json::json!("a"));

        let unknown = CancelOutcome::Unknown {
            request_id: "a".into(),
        }
        .into_execute_response("r".into());
        assert!(!unknown.success);
        assert!(unknown.error.starts_with(UNKNOWN_REQUEST_ERROR_PREFIX));
        assert!(unknown.error.contains("a"));
    }
}
