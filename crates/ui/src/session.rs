//! Global session token store.
//!
//! Provides a process-wide auth token that the ChatPanel (and any other
//! component) can read without needing a Dioxus signal prop chain.
//! The connector writes the Matrix access token here after browser OAuth
//! succeeds; the ChatPanel reads it in `make_client`.

use pentest_core::evidence::EvidenceNode;
use pentest_core::tools::ToolRegistry;
use std::sync::{Arc, LazyLock, PoisonError, RwLock};
use tokio::sync::RwLock as TokioRwLock;

/// Recover from a poisoned session lock. A poison means some earlier thread
/// panicked while holding the write lock, so the inner data *may* be
/// inconsistent. We log loudly and keep going — every caller here either
/// reads a cheap clone or appends to a Vec, so partial writes do not leave
/// dangling state that would cause further panics.
fn recover_poisoned<T>(err: PoisonError<T>, name: &'static str) -> T {
    tracing::error!(
        lock = name,
        "session lock was poisoned (a previous holder panicked); continuing with recovered state"
    );
    err.into_inner()
}

static AUTH_TOKEN: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new(String::new()));
static TENANT_ID: LazyLock<RwLock<String>> = LazyLock::new(|| RwLock::new(String::new()));
static CONNECTOR_NAME: LazyLock<RwLock<String>> =
    LazyLock::new(|| RwLock::new("pentest-connector".to_string()));
static TOOL_NAMES: LazyLock<RwLock<Vec<String>>> = LazyLock::new(|| RwLock::new(Vec::new()));
static ACTION_REGISTRY: LazyLock<pentest_tools::registry::QuickActionRegistry> =
    LazyLock::new(pentest_tools::create_action_registry);

type SharedToolRegistry = Arc<RwLock<Option<Arc<TokioRwLock<ToolRegistry>>>>>;
static TOOL_REGISTRY: LazyLock<SharedToolRegistry> = LazyLock::new(|| Arc::new(RwLock::new(None)));

/// Process-wide evidence graph that the Generate Report action in the chat
/// panel reads out (via [`evidence_snapshot`]) and gates into the report.
///
/// Populated in production by [`drain_tool_evidence_into_graph`], which the
/// connector calls after every tool execution to forward the tool-side buffer
/// (`pentest_tools::evidence_producer::PENDING_EVIDENCE`) into this graph. The
/// Validator round-trip then transitions each node's `validation_status` via
/// [`apply_validator_verdicts`] before the report gate will publish it. This is
/// the bridge that pick#172 identified as missing.
///
/// Kept as a flat `Vec` rather than an index because the orchestrator gate
/// iterates the whole graph anyway, and the UI never looks up nodes by id.
///
/// LOCK ORDERING: the only place that touches two evidence locks is
/// [`drain_tool_evidence_into_graph`], and it fully releases the tool-side
/// `PENDING_EVIDENCE` lock (inside `drain_pending_evidence`) *before* it
/// acquires this one — the locks are never held simultaneously, so there is no
/// deadlock even under concurrent tool execution. Any future code that needs
/// both must keep that order (PENDING_EVIDENCE first, EVIDENCE_GRAPH second).
static EVIDENCE_GRAPH: LazyLock<RwLock<Vec<EvidenceNode>>> =
    LazyLock::new(|| RwLock::new(Vec::new()));

/// Read the current session auth token (Matrix access token for GraphQL).
pub fn get_auth_token() -> String {
    AUTH_TOKEN
        .read()
        .unwrap_or_else(|e| recover_poisoned(e, "AUTH_TOKEN"))
        .clone()
}

/// Store a new session auth token.
pub fn set_auth_token(token: &str) {
    let mut guard = AUTH_TOKEN
        .write()
        .unwrap_or_else(|e| recover_poisoned(e, "AUTH_TOKEN"));
    guard.clear();
    guard.push_str(token);
}

/// Read the current tenant/realm name (e.g. "non-prod").
pub fn get_tenant_id() -> String {
    TENANT_ID
        .read()
        .unwrap_or_else(|e| recover_poisoned(e, "TENANT_ID"))
        .clone()
}

/// Store the tenant/realm name.
pub fn set_tenant_id(tenant: &str) {
    let mut guard = TENANT_ID
        .write()
        .unwrap_or_else(|e| recover_poisoned(e, "TENANT_ID"));
    guard.clear();
    guard.push_str(tenant);
}

/// Read the connector name (gateway identity in Matrix).
pub fn get_connector_name() -> String {
    CONNECTOR_NAME
        .read()
        .unwrap_or_else(|e| recover_poisoned(e, "CONNECTOR_NAME"))
        .clone()
}

/// Store the connector name.
pub fn set_connector_name(name: &str) {
    let mut guard = CONNECTOR_NAME
        .write()
        .unwrap_or_else(|e| recover_poisoned(e, "CONNECTOR_NAME"));
    guard.clear();
    guard.push_str(name);
}

/// Read the registered connector tool names.
pub fn get_tool_names() -> Vec<String> {
    TOOL_NAMES
        .read()
        .unwrap_or_else(|e| recover_poisoned(e, "TOOL_NAMES"))
        .clone()
}

/// Store the registered connector tool names.
pub fn set_tool_names(names: Vec<String>) {
    let mut guard = TOOL_NAMES
        .write()
        .unwrap_or_else(|e| recover_poisoned(e, "TOOL_NAMES"));
    *guard = names;
}

/// Get the global quick action registry.
pub fn get_action_registry() -> &'static pentest_tools::registry::QuickActionRegistry {
    &ACTION_REGISTRY
}

/// Store the tool registry for global access from UI components.
pub fn set_tool_registry(registry: Arc<TokioRwLock<ToolRegistry>>) {
    let mut guard = TOOL_REGISTRY
        .write()
        .unwrap_or_else(|e| recover_poisoned(e, "TOOL_REGISTRY"));
    *guard = Some(registry);
}

/// Get a reference to the tool registry for executing tools from UI components.
pub fn get_tool_registry() -> Option<Arc<TokioRwLock<ToolRegistry>>> {
    TOOL_REGISTRY
        .read()
        .unwrap_or_else(|e| recover_poisoned(e, "TOOL_REGISTRY"))
        .as_ref()
        .cloned()
}

/// Snapshot the current evidence graph. Cheap clone — the graph is
/// typically small (dozens of nodes at most) and the snapshot avoids
/// leaking the internal lock into async code.
///
/// The snapshot is **point-in-time**: nodes pushed after this call returns
/// are invisible to the caller until the next snapshot. This is by design —
/// `on_generate_report` takes a snapshot at button-press time so the
/// manifest reflects the operator's intent at that moment, not whatever
/// races in during the handoff to the Report Agent.
pub fn evidence_snapshot() -> Vec<EvidenceNode> {
    EVIDENCE_GRAPH
        .read()
        .unwrap_or_else(|e| recover_poisoned(e, "EVIDENCE_GRAPH"))
        .clone()
}

/// Append a node to the evidence graph.
///
/// Called by [`drain_tool_evidence_into_graph`] for each finding a tool
/// produces. Prefer that drain helper at call sites; this is the low-level
/// primitive it (and tests) build on.
pub fn push_evidence(node: EvidenceNode) {
    EVIDENCE_GRAPH
        .write()
        .unwrap_or_else(|e| recover_poisoned(e, "EVIDENCE_GRAPH"))
        .push(node);
}

/// Drain the tool-side evidence buffer into the report evidence graph.
///
/// This is the production bridge pick#172 identified as missing. Tools push
/// findings into `pentest_tools::evidence_producer::PENDING_EVIDENCE` as a side
/// effect of execution; that buffer is process-global and unbounded-until-cap,
/// so it must be drained into the report graph or the findings never reach
/// [`evidence_snapshot`] / `gate_for_report`.
///
/// The connector calls this after every tool run (see
/// `liveview_connector::tools`). Draining the *whole* buffer each time is safe
/// under the parallel-tool execution the connector allows: the `RwLock`
/// serializes the take, so no node is lost or double-counted.
///
/// Returns the number of nodes forwarded, for logging and tests. A zero return
/// is normal — most tool runs produce no evidence.
pub fn drain_tool_evidence_into_graph() -> usize {
    let drained = pentest_tools::evidence_producer::drain_pending_evidence();
    let count = drained.len();
    if count > 0 {
        let mut graph = EVIDENCE_GRAPH
            .write()
            .unwrap_or_else(|e| recover_poisoned(e, "EVIDENCE_GRAPH"));
        graph.extend(drained);
    }
    count
}

/// Clear the evidence graph. Called at the start of a new engagement
/// (`begin_scan` completion) so findings from a prior scan do not bleed into
/// the next report.
pub fn clear_evidence() {
    EVIDENCE_GRAPH
        .write()
        .unwrap_or_else(|e| recover_poisoned(e, "EVIDENCE_GRAPH"))
        .clear();
}

/// Outcome of applying a batch of Validator verdicts to the evidence graph.
///
/// The UI surfaces these counts so the operator can tell whether every node was
/// adjudicated before generating the report. Unmatched ids and still-pending
/// nodes are the two ways the round-trip can fail; both are reported explicitly
/// rather than swallowed (pick#184 fail-closed spirit).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerdictApplyReport {
    /// Number of verdicts that matched a node and transitioned it.
    pub applied: usize,
    /// Verdict `node_id`s that matched no node in the graph. A non-empty list
    /// means the Validator invented or mistyped an id — a correctness problem.
    pub unmatched_verdict_ids: Vec<String>,
    /// Node ids still `Pending` after the batch (the Validator returned no
    /// verdict for them). `gate_for_report` will refuse while any remain.
    pub still_pending_ids: Vec<String>,
}

impl VerdictApplyReport {
    /// Whether every node in the graph now has a terminal verdict. When true,
    /// `gate_for_report` will accept the graph.
    pub fn is_fully_adjudicated(&self) -> bool {
        self.still_pending_ids.is_empty()
    }
}

/// Apply a batch of Validator verdicts to the evidence graph in place.
///
/// Each verdict is matched to a node by `node_id` and drives the node through
/// its lifecycle transition (`apply_validator_decision` / `reject_as_false_
/// positive` / `mark_info_only`). This is the production writeback pick#174
/// (seam 3) identified as test-only.
///
/// A `revised`/`confirmed` verdict without a severity falls back to the node's
/// current severity, which `apply_validator_decision` treats as a confirmation.
/// The parser (`parse_validator_verdicts`) already rejects `revised` without a
/// severity, so that fallback only applies to `confirmed`.
///
/// Returns a [`VerdictApplyReport`] describing what matched and what is still
/// outstanding. Nothing is dropped silently.
pub fn apply_validator_verdicts(
    verdicts: &[pentest_core::orchestrator::Verdict],
) -> VerdictApplyReport {
    use pentest_core::orchestrator::VerdictDecision;

    let mut graph = EVIDENCE_GRAPH
        .write()
        .unwrap_or_else(|e| recover_poisoned(e, "EVIDENCE_GRAPH"));

    let mut report = VerdictApplyReport::default();

    for verdict in verdicts {
        match graph.iter_mut().find(|n| n.id == verdict.node_id) {
            Some(node) => {
                match verdict.decision {
                    VerdictDecision::Confirmed | VerdictDecision::Revised => {
                        // Confirmed without explicit severity means "keep current severity"
                        let severity = verdict.severity.unwrap_or(node.current_severity());
                        node.apply_validator_decision(severity, verdict.rationale.clone());
                    }
                    VerdictDecision::FalsePositive => {
                        node.reject_as_false_positive(verdict.rationale.clone());
                    }
                    VerdictDecision::InfoOnly => {
                        node.mark_info_only(verdict.rationale.clone());
                    }
                }
                report.applied += 1;
            }
            None => {
                tracing::warn!(
                    node_id = %verdict.node_id,
                    "validator verdict references a node id not present in the evidence graph; \
                     ignoring it"
                );
                report.unmatched_verdict_ids.push(verdict.node_id.clone());
            }
        }
    }

    report.still_pending_ids = graph
        .iter()
        .filter(|n| n.validation_status == pentest_core::evidence::ValidationStatus::Pending)
        .map(|n| n.id.clone())
        .collect();

    if !report.still_pending_ids.is_empty() {
        tracing::warn!(
            pending = report.still_pending_ids.len(),
            "evidence graph still has pending nodes after applying validator verdicts; \
             the report gate will refuse until they are adjudicated"
        );
    }

    report
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use pentest_core::export::Severity;
    use std::sync::Mutex;

    // EVIDENCE_GRAPH and PENDING_EVIDENCE are process-global statics. cargo runs
    // tests in parallel threads, so a drain in one test can steal another's
    // freshly-pushed node and `clear_evidence` can wipe the whole graph. These
    // tests exercise exactly those shared buffers, so we serialize them behind a
    // module-local lock and tag nodes with unique ids. (Poison is irrelevant —
    // we only need mutual exclusion, so we recover the guard and continue.)
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn node(id: &str) -> EvidenceNode {
        EvidenceNode::new(
            id,
            "finding",
            "Open port 22/tcp",
            "SSH service detected",
            "10.0.0.1",
            Severity::Medium,
            "initial rationale",
        )
    }

    fn snapshot_contains(id: &str) -> bool {
        evidence_snapshot().iter().any(|n| n.id == id)
    }

    #[test]
    fn drain_forwards_tool_buffer_into_report_graph() {
        let _guard = serial();
        let id = "session-bridge-forward-1";
        // A tool pushed a finding into the tool-side buffer...
        pentest_tools::evidence_producer::push_evidence(node(id))
            .expect("buffer should accept one node");
        assert!(
            !snapshot_contains(id),
            "node must not reach the report graph until it is drained"
        );

        // ...the connector drains it into the report graph.
        let forwarded = drain_tool_evidence_into_graph();

        assert!(forwarded >= 1, "at least our node should be forwarded");
        assert!(
            snapshot_contains(id),
            "drained node must appear in the report evidence snapshot"
        );
    }

    #[test]
    fn drain_with_empty_buffer_forwards_nothing_new() {
        let _guard = serial();
        // Ensure the tool buffer is empty for our purposes, then draining must
        // not invent our node.
        let id = "session-bridge-empty-1";
        let _ = drain_tool_evidence_into_graph();
        assert!(
            !snapshot_contains(id),
            "draining an empty buffer must not surface an unpushed node"
        );
    }

    #[test]
    fn clear_evidence_drops_forwarded_nodes() {
        let _guard = serial();
        let id = "session-bridge-clear-1";
        pentest_tools::evidence_producer::push_evidence(node(id))
            .expect("buffer should accept one node");
        drain_tool_evidence_into_graph();
        assert!(
            snapshot_contains(id),
            "node should be in the graph pre-clear"
        );

        clear_evidence();

        assert!(
            !snapshot_contains(id),
            "clear_evidence must empty the report graph for a fresh engagement"
        );
    }

    // --- Verdict writeback (pick#174 seam 3) ---

    use pentest_core::evidence::ValidationStatus;
    use pentest_core::orchestrator::{Verdict, VerdictDecision};

    fn verdict(node_id: &str, decision: VerdictDecision, severity: Option<Severity>) -> Verdict {
        Verdict {
            node_id: node_id.to_string(),
            decision,
            severity,
            rationale: "test rationale".to_string(),
            confidence: 0.9,
        }
    }

    fn status_of(id: &str) -> Option<ValidationStatus> {
        evidence_snapshot()
            .into_iter()
            .find(|n| n.id == id)
            .map(|n| n.validation_status)
    }

    #[test]
    fn writeback_applies_each_decision_type() {
        let _guard = serial();
        clear_evidence();
        push_evidence(node("wb-confirmed"));
        push_evidence(node("wb-revised"));
        push_evidence(node("wb-fp"));
        push_evidence(node("wb-info"));

        let report = apply_validator_verdicts(&[
            verdict(
                "wb-confirmed",
                VerdictDecision::Confirmed,
                Some(Severity::Medium),
            ),
            verdict("wb-revised", VerdictDecision::Revised, Some(Severity::High)),
            verdict("wb-fp", VerdictDecision::FalsePositive, None),
            verdict("wb-info", VerdictDecision::InfoOnly, None),
        ]);

        assert_eq!(report.applied, 4);
        assert!(report.unmatched_verdict_ids.is_empty());
        assert!(report.still_pending_ids.is_empty());
        assert!(report.is_fully_adjudicated());

        assert_eq!(status_of("wb-confirmed"), Some(ValidationStatus::Confirmed));
        assert_eq!(status_of("wb-revised"), Some(ValidationStatus::Revised));
        assert_eq!(status_of("wb-fp"), Some(ValidationStatus::FalsePositive));
        assert_eq!(status_of("wb-info"), Some(ValidationStatus::InfoOnly));
    }

    #[test]
    fn writeback_reports_unmatched_verdict_ids() {
        let _guard = serial();
        clear_evidence();
        push_evidence(node("wb-real"));

        // node() starts at Medium; confirm at Medium so the status is a clean
        // Confirmed (this test is about the unmatched id, not severity revision).
        let report = apply_validator_verdicts(&[
            verdict(
                "wb-real",
                VerdictDecision::Confirmed,
                Some(Severity::Medium),
            ),
            verdict(
                "wb-ghost",
                VerdictDecision::Confirmed,
                Some(Severity::Medium),
            ),
        ]);

        assert_eq!(report.applied, 1);
        assert_eq!(report.unmatched_verdict_ids, vec!["wb-ghost".to_string()]);
        assert_eq!(status_of("wb-real"), Some(ValidationStatus::Confirmed));
    }

    #[test]
    fn writeback_reports_nodes_left_pending() {
        let _guard = serial();
        clear_evidence();
        push_evidence(node("wb-adjudicated"));
        push_evidence(node("wb-forgotten"));

        // The Validator only ruled on one of the two nodes.
        let report = apply_validator_verdicts(&[verdict(
            "wb-adjudicated",
            VerdictDecision::Confirmed,
            Some(Severity::Medium),
        )]);

        assert_eq!(report.applied, 1);
        assert_eq!(report.still_pending_ids, vec!["wb-forgotten".to_string()]);
        assert!(
            !report.is_fully_adjudicated(),
            "a forgotten pending node must block full adjudication"
        );
    }

    #[test]
    fn writeback_confirmed_without_severity_uses_current() {
        let _guard = serial();
        clear_evidence();
        // node() starts at Medium.
        push_evidence(node("wb-nosev"));

        let report =
            apply_validator_verdicts(&[verdict("wb-nosev", VerdictDecision::Confirmed, None)]);

        assert_eq!(report.applied, 1);
        // Confirmed at the same (current) severity stays Confirmed, not Revised.
        assert_eq!(status_of("wb-nosev"), Some(ValidationStatus::Confirmed));
    }
}
