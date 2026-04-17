//! Orchestrator gate between evidence collection and report rendering.
//!
//! The gate sits between three agents:
//!
//! * the **Red Team Agent** pushes [`EvidenceNode`]s into the graph in
//!   [`ValidationStatus::Pending`],
//! * the **Validator Agent** transitions each node to [`ValidationStatus::Confirmed`],
//!   [`ValidationStatus::Revised`], [`ValidationStatus::FalsePositive`], or
//!   [`ValidationStatus::InfoOnly`],
//! * the **Report Agent** consumes a [`ValidatedFindingsManifest`] and renders
//!   the final report.
//!
//! The Report Agent must never see an unvalidated node. [`gate_for_report`]
//! enforces that invariant by refusing to build a manifest while any node is
//! still `Pending`, and strips `FalsePositive` nodes entirely (they stay in
//! the graph for audit but never appear in the report).
//!
//! This module is pure — no I/O, no agent calls. UI plumbing reads the graph
//! from its own session store and hands `&[EvidenceNode]` in.

use crate::evidence::{EvidenceNode, ValidationStatus};
use crate::export::Severity;
use crate::provenance::Provenance;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Engagement-level metadata rendered at the top of every report.
///
/// Mirrors the `engagement` block in the Report Agent's input contract
/// (see `REPORT_AGENT_SYSTEM_PROMPT`). Keep field names in lockstep with
/// that prompt — they are parsed as-is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngagementInfo {
    pub target: String,
    pub started_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,
}

impl EngagementInfo {
    pub fn new(target: impl Into<String>, started_at: DateTime<Utc>) -> Self {
        Self {
            target: target.into(),
            started_at,
            completed_at: None,
        }
    }

    pub fn with_completed_at(mut self, completed_at: DateTime<Utc>) -> Self {
        self.completed_at = Some(completed_at);
        self
    }
}

/// Single entry in the manifest's `findings` array.
///
/// This is an intentionally flattened view of [`EvidenceNode`]: it exposes
/// `current_severity` and `validation_status` as top-level fields so the
/// Report Agent does not have to walk `severity_history` to find them. The
/// original history is still included for audit rendering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ManifestFinding {
    pub id: String,
    pub node_type: String,
    pub title: String,
    pub description: String,
    pub affected_target: String,
    pub validation_status: ValidationStatus,
    pub current_severity: Severity,
    pub severity_history: Vec<crate::evidence::SeverityHistoryEntry>,
    pub confidence: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
}

impl ManifestFinding {
    fn from_node(node: &EvidenceNode) -> Self {
        Self {
            id: node.id.clone(),
            node_type: node.node_type.clone(),
            title: node.title.clone(),
            description: node.description.clone(),
            affected_target: node.affected_target.clone(),
            validation_status: node.validation_status,
            current_severity: node.current_severity(),
            severity_history: node.severity_history.clone(),
            confidence: node.confidence,
            provenance: node.provenance.clone(),
            metadata: node.metadata.clone(),
            created_at: node.created_at,
        }
    }
}

/// The complete payload the Report Agent expects.
///
/// Shape is pinned by `REPORT_AGENT_SYSTEM_PROMPT` — changing field names
/// here without updating the prompt will break report rendering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ValidatedFindingsManifest {
    pub engagement: EngagementInfo,
    /// Publishable findings: `validation_status` is `Confirmed` or `Revised`.
    pub findings: Vec<ManifestFinding>,
    /// Informational context (`validation_status == InfoOnly`) — renders in
    /// the report appendix, not the findings table.
    pub context_nodes: Vec<ManifestFinding>,
    pub counts: ManifestCounts,
}

/// Summary counts the Report Agent uses for the executive summary bullets.
///
/// Derived — never set by hand. Update [`ValidatedFindingsManifest::counts`]
/// through the gate so the totals always match the arrays.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestCounts {
    pub reviewed: usize,
    pub publishable: usize,
    pub info_only: usize,
    pub false_positives: usize,
    pub by_severity: SeverityCounts,
}

/// Per-severity tallies across publishable findings only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

/// Reasons the gate can refuse to build a manifest.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
pub enum GateError {
    /// At least one node is still awaiting validation. The Report Agent must
    /// never see an un-adjudicated node. The IDs are included so the UI can
    /// highlight the offenders.
    #[error("{} evidence node(s) are still pending validation: {}", .pending_ids.len(), .pending_ids.join(", "))]
    PendingNodes { pending_ids: Vec<String> },
}

/// Build a [`ValidatedFindingsManifest`] from the current evidence graph.
///
/// The gate refuses to produce a manifest while any node is
/// [`ValidationStatus::Pending`]. This is the single enforcement point that
/// keeps un-adjudicated findings from leaking into the report.
///
/// `FalsePositive` nodes are silently dropped — they remain in the graph for
/// audit but carry no report presence.
///
/// An empty graph is a valid input: the manifest will have empty `findings`
/// and `context_nodes`, and the Report Agent's prompt tells it to produce a
/// one-page "no findings" report in that case.
pub fn gate_for_report(
    nodes: &[EvidenceNode],
    engagement: EngagementInfo,
) -> Result<ValidatedFindingsManifest, GateError> {
    let pending_ids: Vec<String> = nodes
        .iter()
        .filter(|n| n.validation_status == ValidationStatus::Pending)
        .map(|n| n.id.clone())
        .collect();
    if !pending_ids.is_empty() {
        return Err(GateError::PendingNodes { pending_ids });
    }

    let findings: Vec<ManifestFinding> = nodes
        .iter()
        .filter(|n| n.is_publishable_finding())
        .map(ManifestFinding::from_node)
        .collect();

    let context_nodes: Vec<ManifestFinding> = nodes
        .iter()
        .filter(|n| n.validation_status == ValidationStatus::InfoOnly)
        .map(ManifestFinding::from_node)
        .collect();

    let false_positive_count = nodes
        .iter()
        .filter(|n| n.validation_status == ValidationStatus::FalsePositive)
        .count();

    let mut by_severity = SeverityCounts::default();
    for f in &findings {
        match f.current_severity {
            Severity::Critical => by_severity.critical += 1,
            Severity::High => by_severity.high += 1,
            Severity::Medium => by_severity.medium += 1,
            Severity::Low => by_severity.low += 1,
            Severity::Info => by_severity.info += 1,
        }
    }

    let counts = ManifestCounts {
        reviewed: nodes.len(),
        publishable: findings.len(),
        info_only: context_nodes.len(),
        false_positives: false_positive_count,
        by_severity,
    };

    Ok(ValidatedFindingsManifest {
        engagement,
        findings,
        context_nodes,
        counts,
    })
}

/// Render a manifest as the seed message the UI sends to the Report Agent.
///
/// The Report Agent's system prompt pins the JSON shape, so we hand the
/// manifest over verbatim inside a fenced block and prefix a short
/// instruction. Keeping this as a helper means the UI and tests agree on
/// exactly what the Report Agent receives.
pub fn build_report_agent_seed_message(manifest: &ValidatedFindingsManifest) -> String {
    let json = serde_json::to_string_pretty(manifest)
        .expect("manifest serialization is infallible: all fields serialize to JSON");
    format!(
        "The orchestrator has closed the engagement. Below is the \
         `validated_findings_manifest`. Render the final penetration test \
         report per your system prompt.\n\n```json\n{json}\n```"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::EvidenceNode;
    use crate::provenance::{ProbeCommand, Provenance};

    fn ts() -> DateTime<Utc> {
        // Fixed timestamp keeps manifest snapshots stable across runs.
        DateTime::parse_from_rfc3339("2026-04-17T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn engagement() -> EngagementInfo {
        EngagementInfo::new("10.0.0.0/24", ts()).with_completed_at(ts())
    }

    fn confirmed_finding(id: &str, sev: Severity) -> EvidenceNode {
        let mut n = EvidenceNode::new(
            id,
            "finding",
            format!("Finding {id}"),
            "desc",
            "10.0.0.1",
            sev,
            "initial rationale",
        );
        n.apply_validator_decision(sev, "validator confirmed");
        n
    }

    fn revised_finding(id: &str, from: Severity, to: Severity) -> EvidenceNode {
        let mut n = EvidenceNode::new(
            id,
            "finding",
            format!("Finding {id}"),
            "desc",
            "10.0.0.1",
            from,
            "initial rationale",
        );
        n.apply_validator_decision(to, "severity adjusted after reproducing");
        n
    }

    fn info_only(id: &str) -> EvidenceNode {
        let mut n = EvidenceNode::new(
            id,
            "host",
            format!("Host {id}"),
            "Nginx 1.24 on Debian",
            "10.0.0.5",
            Severity::Info,
            "tech stack fingerprint",
        );
        n.mark_info_only("context only");
        n
    }

    fn false_positive(id: &str) -> EvidenceNode {
        let mut n = EvidenceNode::new(
            id,
            "finding",
            format!("Finding {id}"),
            "desc",
            "10.0.0.1",
            Severity::High,
            "suspicious banner",
        );
        n.reject_as_false_positive("static 404 page, not a real admin panel");
        n
    }

    fn pending(id: &str) -> EvidenceNode {
        EvidenceNode::new(
            id,
            "finding",
            format!("Finding {id}"),
            "desc",
            "10.0.0.1",
            Severity::Medium,
            "initial",
        )
    }

    #[test]
    fn gate_blocks_when_any_node_is_pending() {
        let nodes = [
            confirmed_finding("n1", Severity::High),
            pending("p1"),
            pending("p2"),
        ];
        let err = gate_for_report(&nodes, engagement()).unwrap_err();
        match err {
            GateError::PendingNodes { pending_ids } => {
                assert_eq!(pending_ids, vec!["p1", "p2"]);
            }
        }
    }

    #[test]
    fn gate_accepts_empty_graph_and_emits_empty_manifest() {
        let manifest = gate_for_report(&[], engagement()).expect("empty graph is valid");
        assert!(manifest.findings.is_empty());
        assert!(manifest.context_nodes.is_empty());
        assert_eq!(manifest.counts.reviewed, 0);
        assert_eq!(manifest.counts.publishable, 0);
    }

    #[test]
    fn gate_includes_confirmed_and_revised_findings_only() {
        let nodes = [
            confirmed_finding("c1", Severity::Critical),
            revised_finding("r1", Severity::High, Severity::Medium),
            false_positive("fp1"),
            info_only("i1"),
        ];
        let manifest = gate_for_report(&nodes, engagement()).unwrap();
        assert_eq!(manifest.findings.len(), 2);
        assert!(manifest.findings.iter().any(|f| f.id == "c1"));
        assert!(manifest.findings.iter().any(|f| f.id == "r1"));
        assert_eq!(manifest.context_nodes.len(), 1);
        assert_eq!(manifest.context_nodes[0].id, "i1");
    }

    #[test]
    fn gate_drops_false_positives_from_manifest_but_counts_them() {
        let nodes = [
            confirmed_finding("c1", Severity::Low),
            false_positive("fp1"),
            false_positive("fp2"),
        ];
        let manifest = gate_for_report(&nodes, engagement()).unwrap();
        assert!(manifest.findings.iter().all(|f| f.id != "fp1"));
        assert!(manifest.findings.iter().all(|f| f.id != "fp2"));
        assert_eq!(manifest.counts.false_positives, 2);
        assert_eq!(manifest.counts.reviewed, 3);
        assert_eq!(manifest.counts.publishable, 1);
    }

    #[test]
    fn revised_findings_use_the_validators_severity_not_the_red_teams() {
        let nodes = [revised_finding("r1", Severity::Critical, Severity::Low)];
        let manifest = gate_for_report(&nodes, engagement()).unwrap();
        // current_severity must equal the Validator's final call, not the
        // Red Team's initial claim. Getting this wrong would inflate severity
        // in the report.
        assert_eq!(manifest.findings[0].current_severity, Severity::Low);
        assert_eq!(manifest.counts.by_severity.low, 1);
        assert_eq!(manifest.counts.by_severity.critical, 0);
    }

    #[test]
    fn severity_counts_tally_only_publishable_findings() {
        let nodes = [
            confirmed_finding("c1", Severity::Critical),
            confirmed_finding("c2", Severity::High),
            confirmed_finding("c3", Severity::High),
            confirmed_finding("c4", Severity::Medium),
            info_only("i1"), // Info-only: must NOT tally against severity counts.
            false_positive("fp1"),
        ];
        let manifest = gate_for_report(&nodes, engagement()).unwrap();
        assert_eq!(manifest.counts.by_severity.critical, 1);
        assert_eq!(manifest.counts.by_severity.high, 2);
        assert_eq!(manifest.counts.by_severity.medium, 1);
        assert_eq!(manifest.counts.by_severity.low, 0);
        assert_eq!(manifest.counts.by_severity.info, 0);
    }

    #[test]
    fn manifest_preserves_provenance_for_publishable_findings() {
        let mut n = confirmed_finding("c1", Severity::High);
        n.provenance = Some(Provenance::new(
            "nmap",
            "7.95",
            ProbeCommand::from_exact("nmap -sV 10.0.0.1"),
            "Nmap scan report",
        ));
        let manifest = gate_for_report(&[n], engagement()).unwrap();
        let prov = manifest.findings[0]
            .provenance
            .as_ref()
            .expect("provenance preserved in manifest");
        assert_eq!(prov.underlying_tool, "nmap");
    }

    #[test]
    fn seed_message_embeds_manifest_as_fenced_json() {
        let manifest =
            gate_for_report(&[confirmed_finding("c1", Severity::High)], engagement()).unwrap();
        let msg = build_report_agent_seed_message(&manifest);
        assert!(msg.contains("validated_findings_manifest"));
        assert!(msg.contains("```json"));
        assert!(msg.contains("\"c1\""));
        assert!(msg.trim_end().ends_with("```"));
    }

    #[test]
    fn seed_message_round_trips_through_json() {
        // The Report Agent parses the fenced JSON back into a manifest. Make
        // sure our seed message always yields a block that deserializes.
        let manifest = gate_for_report(
            &[
                confirmed_finding("c1", Severity::High),
                revised_finding("r1", Severity::High, Severity::Medium),
                info_only("i1"),
            ],
            engagement(),
        )
        .unwrap();
        let msg = build_report_agent_seed_message(&manifest);
        let start = msg.find("```json\n").unwrap() + "```json\n".len();
        let end = msg.rfind("\n```").unwrap();
        let json = &msg[start..end];
        let back: ValidatedFindingsManifest = serde_json::from_str(json).unwrap();
        assert_eq!(back, manifest);
    }
}
