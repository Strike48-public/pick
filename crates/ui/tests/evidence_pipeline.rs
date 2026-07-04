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

use pentest_core::orchestrator::{
    build_pending_evidence_manifest, gate_for_report, parse_validator_verdicts, EngagementInfo,
    GateError,
};
use pentest_core::provenance::{ProbeCommand, Provenance};
use pentest_tools::evidence_producer::{evidence_from_nmap, push_evidence};
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
