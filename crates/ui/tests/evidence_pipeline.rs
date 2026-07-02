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
use serde_json::json;

fn engagement() -> EngagementInfo {
    EngagementInfo::new("10.0.0.0/24", chrono::Utc::now())
}

#[test]
fn tool_finding_reaches_the_report_after_validation() {
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
