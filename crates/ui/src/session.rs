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
}
