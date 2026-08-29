//! End-to-end regression test for the evidence pipeline (pick#172, pick#174).
//!
//! This is the production-path test the issue explicitly asked for: prove that a
//! real tool's finding travels all the way to the report gate. It exercises the
//! seams that were unwired in production, without a network or a live agent:
//!
//! 1. A tool produces evidence and pushes it into `PENDING_EVIDENCE`
//!    (here via the real `evidence_from_nmap` builder + `push_evidence`, the
//!    same calls `nmap.rs` makes in production).
//! 2. The connector's bridge drains that buffer into the report graph
//!    (`session::drain_tool_evidence_into_graph`).
//! 3. The report gate refuses while the drained node is still `Pending`
//!    (`gate_for_report` -> `GateError::PendingNodes`) — proving evidence
//!    actually reached the gate rather than silently vanishing.
//! 4. A Validator verdict is parsed and applied
//!    (`parse_validator_verdicts` -> `session::apply_validator_verdicts`).
//! 5. The gate now accepts the graph and the finding appears in the manifest.
//!
//! Before pick#172/#174 were wired, step 3 would have seen an empty graph (the
//! drained node never reached it), so the finding could never appear in a
//! report. This test fails closed if any of those seams regress.

use pentest_core::evidence::EvidenceNode;
use pentest_core::export::Severity;
use pentest_core::orchestrator::{
    build_pending_evidence_manifest, gate_for_report, parse_validator_verdicts, EngagementInfo,
    GateError,
};
use pentest_core::provenance::{ProbeCommand, Provenance};
use pentest_core::tools::{PentestTool, ToolContext, ToolOutcome};
use pentest_tools::evidence_producer::{
    evidence_from_default_creds, evidence_from_execute_command, evidence_from_http_request,
    evidence_from_nmap, evidence_from_port_scan, evidence_from_web_vuln_scan, push_evidence,
};
use pentest_tools::ExecuteCommandTool;
use pentest_ui::session;
use serde_json::{json, Value};
use std::sync::{Mutex, MutexGuard};

fn engagement() -> EngagementInfo {
    EngagementInfo::new("10.0.0.0/24", chrono::Utc::now())
}

/// Every test in this binary touches the same process-global evidence state
/// (`PENDING_EVIDENCE` in `pentest-tools`, `EVIDENCE_GRAPH` in `pentest-ui`).
/// `cargo test` runs tests in one binary on parallel threads, so without a
/// shared guard they would race on that global state and flake. Each test
/// takes this lock for its whole body and clears the graph at both ends.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    // Recover from a poisoned lock: a panic in one test must not wedge the rest.
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

/// Build one nmap evidence node for a single open port and push it into the
/// tool buffer, mirroring exactly what the production nmap wrapper does. Returns
/// the generated node id so the caller can assert on it.
fn push_nmap_finding(host_ip: &str, port: u16, service: &str, version: &str) -> String {
    let nmap_json: Value = json!({
        "hosts": [{
            "ip": host_ip,
            "ports": [{
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": service,
                "version": version
            }]
        }]
    });
    let provenance = Provenance::new(
        "nmap",
        "7.95",
        ProbeCommand::from_exact(format!("nmap -sV {host_ip}")),
        format!("Nmap scan report for {host_ip}\n{port}/tcp open {service} {version}"),
    );
    let nodes = evidence_from_nmap(&nmap_json, host_ip, provenance);
    assert_eq!(
        nodes.len(),
        1,
        "one open port should yield one evidence node"
    );
    let node_id = nodes[0].id.clone();
    for node in nodes {
        push_evidence(node).expect("tool buffer should accept the finding");
    }
    node_id
}

/// Format a Validator reply that confirms every supplied node id at `medium`.
fn confirm_all(node_ids: &[String]) -> String {
    let verdicts: Vec<String> = node_ids
        .iter()
        .map(|id| {
            format!(
                "{{\"node_id\": \"{id}\", \"decision\": \"confirmed\", \
                 \"severity\": \"medium\", \"rationale\": \"reproduced\", \
                 \"confidence\": 0.9}}"
            )
        })
        .collect();
    format!(
        "Adjudicated every finding.\n\n```json\n{{\"verdicts\": [{}], \
         \"summary\": {{\"reviewed\": {}}}}}\n```",
        verdicts.join(", "),
        node_ids.len()
    )
}

#[test]
fn tool_finding_reaches_the_report_after_validation() {
    let _guard = serial();
    // A fresh engagement starts by clearing the graph, exactly as the connector
    // does on `begin_scan`.
    session::clear_evidence();

    // (1) A real tool produces evidence. This is the same `evidence_from_nmap`
    // builder the production nmap wrapper uses, fed synthetic scan JSON so the
    // test needs no network and is deterministic.
    let nmap_json = json!({
        "hosts": [{
            "ip": "10.0.0.1",
            "ports": [{
                "port": 22,
                "protocol": "tcp",
                "state": "open",
                "service": "ssh",
                "version": "OpenSSH 8.9"
            }]
        }]
    });
    let provenance = Provenance::new(
        "nmap",
        "7.95",
        ProbeCommand::from_exact("nmap -sV 10.0.0.1"),
        "Nmap scan report for 10.0.0.1\n22/tcp open ssh OpenSSH 8.9",
    );
    let nodes = evidence_from_nmap(&nmap_json, "10.0.0.1", provenance);
    assert_eq!(
        nodes.len(),
        1,
        "one open port should yield one evidence node"
    );
    let node_id = nodes[0].id.clone();
    for node in nodes {
        push_evidence(node).expect("tool buffer should accept the finding");
    }

    // (2) The connector bridge drains the tool buffer into the report graph.
    let forwarded = session::drain_tool_evidence_into_graph();
    assert!(
        forwarded >= 1,
        "the finding should be forwarded to the graph"
    );

    // (3) The gate must SEE the node — and refuse because it is still Pending.
    // This is the proof that evidence reached the gate (a pre-#172 empty graph
    // would have returned an empty manifest here, not PendingNodes).
    let snapshot = session::evidence_snapshot();
    match gate_for_report(&snapshot, engagement()) {
        Err(GateError::PendingNodes { pending_ids }) => {
            assert!(
                pending_ids.contains(&node_id),
                "the drained nmap finding must be the pending node blocking the gate"
            );
        }
        other => panic!("expected PendingNodes before validation, got {other:?}"),
    }

    // (4) The Validator adjudicates. Build the seed it would receive, then parse
    // a representative verdict reply and apply it — the real parse+writeback
    // path, not a hand-mutated node.
    let pending_manifest = build_pending_evidence_manifest(&snapshot, engagement());
    assert_eq!(pending_manifest.nodes.len(), 1);

    let validator_reply = format!(
        "Adjudicated the open SSH port.\n\n```json\n{{\
         \"verdicts\": [{{\"node_id\": \"{node_id}\", \"decision\": \"confirmed\", \
         \"severity\": \"medium\", \"rationale\": \"SSH reachable, default port\", \
         \"confidence\": 0.9}}], \"summary\": {{\"reviewed\": 1}}}}\n```"
    );
    let verdicts = parse_validator_verdicts(&validator_reply).expect("verdict reply should parse");
    let apply = session::apply_validator_verdicts(&verdicts);
    assert_eq!(apply.applied, 1);
    assert!(
        apply.is_fully_adjudicated(),
        "no nodes should remain pending after the verdict"
    );

    // (5) The gate now accepts the graph and the finding is in the manifest.
    let snapshot = session::evidence_snapshot();
    let manifest = gate_for_report(&snapshot, engagement())
        .expect("gate should accept a fully-adjudicated graph");
    assert_eq!(
        manifest.findings.len(),
        1,
        "the confirmed nmap finding must appear in the report manifest"
    );
    assert_eq!(manifest.findings[0].id, node_id);

    // Leave the shared graph clean for any other test in this binary.
    session::clear_evidence();
}

/// Evidence from several tool runs must accumulate in the graph across
/// successive drains, and every finding must survive to the report manifest
/// after validation. This guards the "drain after each tool run" contract: a
/// regression that dropped earlier evidence on a later drain would show up as a
/// missing finding here.
#[test]
fn multiple_tools_drain_to_report_sequentially() {
    let _guard = serial();
    session::clear_evidence();

    // (1) First tool run: nmap finds SSH. Drain immediately, as the connector
    // does after each tool completes.
    let ssh_id = push_nmap_finding("10.0.0.1", 22, "ssh", "OpenSSH 8.9");
    let forwarded_first = session::drain_tool_evidence_into_graph();
    assert_eq!(forwarded_first, 1, "first drain forwards exactly one node");

    // (2) Second tool run: nmap finds HTTP on another host. Drain again — the
    // earlier SSH node must still be in the graph.
    let http_id = push_nmap_finding("10.0.0.2", 80, "http", "nginx 1.25");
    let forwarded_second = session::drain_tool_evidence_into_graph();
    assert_eq!(
        forwarded_second, 1,
        "second drain forwards exactly one node"
    );

    let snapshot = session::evidence_snapshot();
    assert_eq!(
        snapshot.len(),
        2,
        "both findings must accumulate in the graph across drains"
    );

    // (3) Validate both findings at once, then the gate must publish both.
    let verdicts = parse_validator_verdicts(&confirm_all(&[ssh_id.clone(), http_id.clone()]))
        .expect("verdict reply should parse");
    let apply = session::apply_validator_verdicts(&verdicts);
    assert_eq!(apply.applied, 2);
    assert!(
        apply.is_fully_adjudicated(),
        "both nodes should be adjudicated"
    );

    let snapshot = session::evidence_snapshot();
    let manifest =
        gate_for_report(&snapshot, engagement()).expect("gate should accept both findings");
    let ids: Vec<&String> = manifest.findings.iter().map(|f| &f.id).collect();
    assert_eq!(manifest.findings.len(), 2, "both findings reach the report");
    assert!(
        ids.contains(&&ssh_id),
        "SSH finding must be in the manifest"
    );
    assert!(
        ids.contains(&&http_id),
        "HTTP finding must be in the manifest"
    );

    session::clear_evidence();
}

/// The `drain_tool_evidence_into_graph` docs claim the drain is safe under
/// concurrent tool execution: tools may be pushing into `PENDING_EVIDENCE`
/// while the connector drains. This test demonstrates that property instead of
/// merely asserting it — many producer threads push while a drainer thread runs
/// concurrently, and afterwards every pushed node must be accounted for exactly
/// once (none lost, none duplicated) across what the drainer forwarded plus
/// whatever remains buffered for the final drain.
#[test]
fn drain_is_safe_under_concurrent_tool_execution() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let _guard = serial();
    session::clear_evidence();

    const PRODUCERS: usize = 8;
    const PER_PRODUCER: usize = 25;
    let total_pushed = PRODUCERS * PER_PRODUCER;

    let stop = Arc::new(AtomicBool::new(false));

    // Producer threads: each pushes PER_PRODUCER distinct nmap findings.
    let mut producers = Vec::new();
    for p in 0..PRODUCERS {
        producers.push(std::thread::spawn(move || {
            for i in 0..PER_PRODUCER {
                // Unique host/port per push keeps node ids distinct and human-readable.
                let host = format!("10.0.{p}.{i}");
                push_nmap_finding(&host, 8000 + i as u16, "http", "nginx 1.25");
            }
        }));
    }

    // Drainer thread: repeatedly drains into the graph while producers run,
    // accumulating a running count of everything it forwarded.
    let drainer_stop = Arc::clone(&stop);
    let drainer = std::thread::spawn(move || {
        let mut drained = 0usize;
        while !drainer_stop.load(Ordering::Relaxed) {
            drained += session::drain_tool_evidence_into_graph();
            std::thread::yield_now();
        }
        drained
    });

    for producer in producers {
        producer.join().expect("producer thread should not panic");
    }
    // All producers are done; tell the drainer to finish its loop.
    stop.store(true, Ordering::Relaxed);
    let drained_during = drainer.join().expect("drainer thread should not panic");

    // A final drain sweeps up anything pushed after the drainer's last pass.
    let drained_after = session::drain_tool_evidence_into_graph();

    // Every pushed node must be forwarded exactly once: nothing lost to a race,
    // nothing double-counted.
    assert_eq!(
        drained_during + drained_after,
        total_pushed,
        "every pushed node must be forwarded exactly once across concurrent drains"
    );
    // And the graph must hold exactly those nodes.
    let snapshot = session::evidence_snapshot();
    assert_eq!(
        snapshot.len(),
        total_pushed,
        "the graph must contain every forwarded node with no duplicates"
    );

    session::clear_evidence();
}

/// pick#184 fail-closed grounding, on the production path. Two guarantees, end
/// to end without a network or a live agent:
///
/// 1. A tool that fails to complete a probe surfaces a structured `Failed`
///    outcome the model can trust — proven by running the real
///    `ExecuteCommandTool` with a command that exits nonzero and prints
///    nothing.
/// 2. A finding with no tool-output provenance cannot reach the report — proven
///    by adjudicating an ungrounded node to Confirmed and asserting the real
///    `gate_for_report` refuses it with `UngroundedFindings`.
///
/// Before #184 the first was an indistinguishable `success:true` empty and the
/// second passed the gate silently.
#[tokio::test]
async fn failed_tool_is_flagged_and_ungrounded_finding_cannot_reach_report() {
    // Run host-direct. With the sandbox enabled and no backend (CI runner), the
    // command below falls through to download_proot + rootfs extraction, which
    // hangs a non-root runner. Disabling the sandbox takes the host path — CI
    // also sets DISABLE_SANDBOX=true, this covers a bare local `cargo test`.
    pentest_platform::set_use_sandbox(false);

    // (1) Run a real command that exits nonzero with empty stdout. On a host
    // without command exec this returns Skipped; either way the outcome must
    // NOT be a trustworthy `Ran`, and `success` must be false. This half
    // touches no shared global evidence state, so it needs no serial guard —
    // which also keeps us from holding a std Mutex across the `.await`.
    let result = ExecuteCommandTool
        .execute(
            json!({ "command": "false", "args": [], "timeout_seconds": 10 }),
            &ToolContext::default(),
        )
        .await
        .expect("execute_command returns Ok(ToolResult) even on failure");
    // Assert `!= Ran` rather than `== Failed` on purpose: both outcomes are
    // correct depending on the host. With command exec available, "false"
    // exits nonzero with empty stdout → Failed; without it, the tool returns
    // Skipped before running. Either way it is not a trustworthy completed
    // probe, which is all #184 requires here.
    assert_ne!(
        result.outcome,
        ToolOutcome::Ran,
        "a nonzero-exit empty command must not be reported as a completed probe"
    );
    assert!(
        !result.success,
        "a failed/skipped probe must not be a success"
    );

    // (2) An ungrounded finding must never reach the report. This half touches
    // the shared evidence graph, so take the serial guard now — after the await
    // above, so no lock is held across it.
    let _guard = serial();
    session::clear_evidence();

    // Simulate the Red Team asserting a finding with no backing tool result: a
    // node with no provenance. It is validated to Confirmed (clearing the
    // Pending gate) so the ONLY thing between it and the report is grounding.
    let mut ungrounded = EvidenceNode::new(
        "ungrounded-claim",
        "finding",
        "Fabricated admin panel",
        "Model asserted this with no tool output backing it.",
        "10.0.0.9",
        Severity::High,
        "no grounding",
    );
    // No `.with_provenance(...)` — this is the whole point.
    ungrounded.apply_validator_decision(Severity::High, "validator waved it through");
    assert!(ungrounded.is_publishable_finding());
    push_evidence(ungrounded).expect("push to buffer");
    session::drain_tool_evidence_into_graph();

    let snapshot = session::evidence_snapshot();
    match gate_for_report(&snapshot, engagement()) {
        Err(GateError::UngroundedFindings { ids }) => {
            assert!(
                ids.contains(&"ungrounded-claim".to_string()),
                "the ungrounded finding must be named as the blocker, got {ids:?}"
            );
        }
        other => panic!("gate must fail closed on an ungrounded finding, got {other:?}"),
    }

    session::clear_evidence();
}

/// pick#52 coverage promotion: the three web wrappers (`web_vuln_scan`,
/// `default_creds`, `http_request`) build a full `Provenance` today but never
/// promoted it into the evidence graph, so their findings could never reach a
/// report. This exercises the exact builders their `execute()` tails now call,
/// proving each one's evidence travels tool-buffer -> graph -> gate -> manifest,
/// the same production path the nmap test above guards.
#[test]
fn web_wrapper_findings_reach_the_report_after_validation() {
    let _guard = serial();
    session::clear_evidence();

    let mut node_ids = Vec::new();

    // web_vuln_scan: one node per finding.
    let wvs_data = json!({
        "url": "http://10.0.0.1",
        "findings": [
            {"type": "ADMIN_PANEL_EXPOSED", "severity": "MEDIUM", "path": "/admin",
             "status_code": 200, "details": "Admin panel accessible at http://10.0.0.1/admin"},
            {"type": "NO_HTTPS_REDIRECT", "severity": "MEDIUM",
             "details": "Site does not redirect HTTP to HTTPS"}
        ]
    });
    let wvs_prov = Provenance::new(
        "web_vuln_scan",
        "0.6",
        ProbeCommand::from_exact("curl -sI http://10.0.0.1/admin"),
        "[{\"type\":\"ADMIN_PANEL_EXPOSED\"}]",
    );
    for node in evidence_from_web_vuln_scan(&wvs_data, "http://10.0.0.1", wvs_prov) {
        node_ids.push(node.id.clone());
        push_evidence(node).expect("tool buffer should accept the web_vuln_scan finding");
    }

    // default_creds: one node per successful login (the failed attempt yields none).
    let dc_data = json!({
        "host": "10.0.0.1",
        "port": 22,
        "service": "ssh",
        "attempts": [
            {"username": "root", "password": "<redacted>", "status": "FAILED"},
            {"username": "admin", "password": "<redacted>", "status": "SUCCESS"}
        ],
        "successful": 1,
        "total_tested": 2
    });
    let dc_prov = Provenance::new(
        "sshpass+openssh",
        "0.6",
        ProbeCommand::from_exact("sshpass -p '<redacted>' ssh admin@10.0.0.1 exit"),
        "[{\"username\":\"admin\",\"password\":\"<redacted>\",\"status\":\"SUCCESS\"}]",
    );
    for node in evidence_from_default_creds(&dc_data, dc_prov) {
        node_ids.push(node.id.clone());
        push_evidence(node).expect("tool buffer should accept the default_creds finding");
    }

    // http_request: one Info node per response.
    let hr_data = json!({
        "url": "http://10.0.0.1/login",
        "method": "GET",
        "status": 200,
        "ok": true,
        "headers": {"server": "nginx"},
        "body": "hi",
        "body_bytes": 2,
        "body_truncated": false
    });
    let hr_prov = Provenance::new(
        "http_request",
        "0.6",
        ProbeCommand::from_exact("curl -sS -k -X GET http://10.0.0.1/login"),
        "hi",
    );
    for node in evidence_from_http_request(&hr_data, hr_prov) {
        node_ids.push(node.id.clone());
        push_evidence(node).expect("tool buffer should accept the http_request node");
    }

    assert_eq!(
        node_ids.len(),
        4,
        "2 web_vuln + 1 default_creds + 1 http_request"
    );

    // Drain into the graph and confirm the gate sees every node as pending.
    let forwarded = session::drain_tool_evidence_into_graph();
    assert_eq!(forwarded, 4, "all four nodes should reach the graph");

    let snapshot = session::evidence_snapshot();
    match gate_for_report(&snapshot, engagement()) {
        Err(GateError::PendingNodes { pending_ids }) => {
            for id in &node_ids {
                assert!(
                    pending_ids.contains(id),
                    "node {id} must block the gate before validation"
                );
            }
        }
        other => panic!("expected PendingNodes before validation, got {other:?}"),
    }

    // Validator confirms all; the gate then accepts and every finding lands.
    let verdicts =
        parse_validator_verdicts(&confirm_all(&node_ids)).expect("verdict reply should parse");
    let apply = session::apply_validator_verdicts(&verdicts);
    assert_eq!(apply.applied, 4);
    assert!(apply.is_fully_adjudicated());

    let snapshot = session::evidence_snapshot();
    let manifest = gate_for_report(&snapshot, engagement())
        .expect("gate should accept a fully-adjudicated graph");
    assert_eq!(
        manifest.findings.len(),
        4,
        "every web-wrapper finding must reach the report manifest"
    );

    session::clear_evidence();
}

/// pick#52 PR2: extends the same production-path guard to `port_scan` and
/// `execute_command`. `port_scan` (a native scanner) promotes each open port via
/// a synthesized nmap-equivalent provenance; the `execute_command` primitive
/// promotes one Info node per run. Both must travel tool-buffer -> graph -> gate
/// -> manifest exactly like the nmap and web-wrapper cases above.
#[test]
fn port_scan_and_execute_command_findings_reach_the_report_after_validation() {
    let _guard = serial();
    session::clear_evidence();

    let mut node_ids = Vec::new();

    // port_scan (single-host shape): only the two open ports become nodes; the
    // closed 3306 is not a finding.
    let ps_data = json!({
        "host": "10.0.0.1",
        "ports": [
            {"port": 22, "service": "ssh", "open": true},
            {"port": 445, "service": "microsoft-ds", "open": true},
            {"port": 3306, "service": "mysql", "open": false}
        ],
        "open_count": 2
    });
    let ps_prov = Provenance::new(
        "port_scan",
        "0.6",
        ProbeCommand::from_exact("nmap -Pn -sT -p 22,445,3306 --open 10.0.0.1"),
        "{\"open_count\":2}",
    );
    for node in evidence_from_port_scan(&ps_data, ps_prov) {
        node_ids.push(node.id.clone());
        push_evidence(node).expect("tool buffer should accept the port_scan finding");
    }

    // execute_command: one Info node per run.
    let ec_data = json!({
        "stdout": "uid=0(root)",
        "stderr": "",
        "exit_code": 0,
        "timed_out": false,
        "duration_ms": 12
    });
    let ec_prov = Provenance::new(
        "shell",
        "0.6",
        ProbeCommand::from_exact("id"),
        "uid=0(root)",
    );
    for node in evidence_from_execute_command(&ec_data, ec_prov) {
        node_ids.push(node.id.clone());
        push_evidence(node).expect("tool buffer should accept the execute_command node");
    }

    assert_eq!(node_ids.len(), 3, "2 open ports + 1 command_execution");

    // Drain into the graph and confirm the gate sees every node as pending.
    let forwarded = session::drain_tool_evidence_into_graph();
    assert_eq!(forwarded, 3, "all three nodes should reach the graph");

    let snapshot = session::evidence_snapshot();
    match gate_for_report(&snapshot, engagement()) {
        Err(GateError::PendingNodes { pending_ids }) => {
            for id in &node_ids {
                assert!(
                    pending_ids.contains(id),
                    "node {id} must block the gate before validation"
                );
            }
        }
        other => panic!("expected PendingNodes before validation, got {other:?}"),
    }

    // Validator confirms all; the gate then accepts and every finding lands.
    let verdicts =
        parse_validator_verdicts(&confirm_all(&node_ids)).expect("verdict reply should parse");
    let apply = session::apply_validator_verdicts(&verdicts);
    assert_eq!(apply.applied, 3);
    assert!(apply.is_fully_adjudicated());

    let snapshot = session::evidence_snapshot();
    let manifest = gate_for_report(&snapshot, engagement())
        .expect("gate should accept a fully-adjudicated graph");
    assert_eq!(
        manifest.findings.len(),
        3,
        "every port_scan + execute_command finding must reach the report manifest"
    );

    session::clear_evidence();
}
