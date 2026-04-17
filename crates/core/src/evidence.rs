//! Evidence graph nodes for the multi-agent pipeline.
//!
//! `EvidenceNode` is the contract between Pick (which executes tools and
//! builds the graph), the Validator Agent (which confirms or rejects nodes),
//! and the Report Agent (which renders the published report).
//!
//! The graph is additive: once a node exists it is never mutated by the
//! Red Team Agent. The Validator transitions its `validation_status` and
//! may append a `SeverityHistoryEntry` explaining any severity revision.
//! Every published finding carries a [`Provenance`] produced at tool
//! execution time — this is how a senior reviewer reproduces it.

use crate::export::Severity;
use crate::provenance::Provenance;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Lifecycle state of an evidence node as seen by the Validator Agent.
///
/// The order below matches the happy-path transition the orchestrator
/// enforces: nodes enter as `Pending`, the Validator moves them to
/// `Confirmed`, `Revised`, `FalsePositive`, or `InfoOnly`, and only
/// non-false-positive nodes appear in the Report Agent's validated
/// findings manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationStatus {
    /// The Red Team Agent produced this node; the Validator has not
    /// inspected it yet. Nodes in this state MUST NOT be published.
    Pending,
    /// Validator confirmed the underlying claim at the original severity.
    Confirmed,
    /// Validator confirmed a real issue but at a different severity than
    /// the Red Team Agent originally claimed. See `severity_history` for
    /// the prior value and the revision reason.
    Revised,
    /// Validator concluded the node does not represent a real issue.
    /// Kept in the graph for audit trail, excluded from the report.
    FalsePositive,
    /// Node carries context (host fingerprint, tech stack, banner) that
    /// is useful for the report narrative but is not itself a finding.
    InfoOnly,
}

impl ValidationStatus {
    /// Whether a node in this state is eligible for the validated
    /// findings manifest consumed by the Report Agent.
    pub fn is_publishable_finding(self) -> bool {
        matches!(self, Self::Confirmed | Self::Revised)
    }
}

/// A single entry in a node's severity history.
///
/// Every time the Validator changes severity — or declares the original
/// assessment correct — an entry is appended. The first entry is always
/// the Red Team Agent's initial assessment; the last entry is the
/// Validator's final call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeverityHistoryEntry {
    /// Severity at this point in the node's lifecycle.
    pub severity: Severity,
    /// Free-form rationale — cited CVE, missing auth on a non-sensitive
    /// endpoint, etc. Rendered verbatim in the published report so the
    /// reader can follow the Validator's reasoning.
    pub rationale: String,
    /// Who emitted this entry. Conventionally `"red_team"`, `"validator"`,
    /// or a specific tool name. Kept as a string so the schema does not
    /// need to enumerate every future agent.
    pub set_by: String,
    /// When this entry was recorded.
    pub timestamp: DateTime<Utc>,
}

impl SeverityHistoryEntry {
    /// Record a new severity assessment.
    pub fn new(
        severity: Severity,
        rationale: impl Into<String>,
        set_by: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            rationale: rationale.into(),
            set_by: set_by.into(),
            timestamp: Utc::now(),
        }
    }
}

/// A node in the evidence graph.
///
/// Fields fall into three groups:
///
/// 1. **Identity / content** (`id`, `title`, `description`, `affected_target`,
///    `node_type`, `metadata`) — populated by the Red Team Agent and the
///    executing tool.
/// 2. **Reproducibility** (`provenance`) — attached by the tool wrapper
///    via [`Provenance`]. Optional because some nodes (hardware findings,
///    manual observations) have no tool output to reproduce.
/// 3. **Validation lifecycle** (`validation_status`, `severity_history`,
///    `confidence`) — mutated only by the Validator Agent / orchestrator.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceNode {
    /// Stable, globally unique identifier for cross-referencing from the
    /// Report Agent's `validated_findings_manifest`. Conventionally a UUID.
    pub id: String,

    /// Node category — e.g. `"finding"`, `"host"`, `"service"`, `"credential"`.
    /// Kept as a string so new graph shapes (web surfaces, pivoted hosts)
    /// do not require schema changes.
    pub node_type: String,

    /// One-line human-readable title.
    pub title: String,

    /// Multi-paragraph description suitable for the published report body.
    pub description: String,

    /// Target this node applies to — IP, CIDR, hostname, URL, etc.
    pub affected_target: String,

    /// Ordered severity history. The first entry is the initial claim;
    /// the last entry is the current authoritative severity. Never empty
    /// after construction.
    pub severity_history: Vec<SeverityHistoryEntry>,

    /// Current validation lifecycle state.
    pub validation_status: ValidationStatus,

    /// Subjective confidence in the underlying claim, `0.0..=1.0`. The
    /// Red Team Agent sets an initial value; the Validator may revise it.
    pub confidence: f32,

    /// Reproducibility metadata from the tool that produced this node.
    /// See [`crate::provenance`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Provenance>,

    /// Tool-specific structured detail (open ports, request headers,
    /// service banners) that did not fit the generic fields above.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,

    /// When this node entered the graph.
    pub created_at: DateTime<Utc>,
}

impl EvidenceNode {
    /// Create a new node with an initial `Pending` validation state and
    /// a single severity history entry attributed to the Red Team Agent.
    pub fn new(
        id: impl Into<String>,
        node_type: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        affected_target: impl Into<String>,
        initial_severity: Severity,
        initial_rationale: impl Into<String>,
    ) -> Self {
        let entry = SeverityHistoryEntry::new(initial_severity, initial_rationale, "red_team");
        Self {
            id: id.into(),
            node_type: node_type.into(),
            title: title.into(),
            description: description.into(),
            affected_target: affected_target.into(),
            severity_history: vec![entry],
            validation_status: ValidationStatus::Pending,
            confidence: 0.5,
            provenance: None,
            metadata: HashMap::new(),
            created_at: Utc::now(),
        }
    }

    /// Attach reproducibility metadata — called once by the tool wrapper
    /// before the node is inserted into the graph.
    pub fn with_provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = Some(provenance);
        self
    }

    /// Attach tool-specific structured metadata.
    pub fn with_metadata(mut self, metadata: HashMap<String, serde_json::Value>) -> Self {
        self.metadata = metadata;
        self
    }

    /// Set the initial confidence score.
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }

    /// Current authoritative severity — the last entry in `severity_history`.
    /// Never panics because the constructor always pushes an initial entry.
    pub fn current_severity(&self) -> Severity {
        self.severity_history
            .last()
            .expect("severity_history is never empty after construction")
            .severity
    }

    /// Record a validation decision from the Validator Agent.
    ///
    /// If `new_severity` differs from the current severity, appends a
    /// history entry and sets status to [`ValidationStatus::Revised`].
    /// If it matches, appends a confirmation entry and sets status to
    /// [`ValidationStatus::Confirmed`].
    ///
    /// Returns `&mut Self` so the caller cannot silently drop the
    /// transition — the chained call form is a visual marker in reviews.
    pub fn apply_validator_decision(
        &mut self,
        new_severity: Severity,
        rationale: impl Into<String>,
    ) -> &mut Self {
        let rationale = rationale.into();
        let changed = new_severity != self.current_severity();
        self.severity_history.push(SeverityHistoryEntry::new(
            new_severity,
            rationale,
            "validator",
        ));
        self.validation_status = if changed {
            ValidationStatus::Revised
        } else {
            ValidationStatus::Confirmed
        };
        self
    }

    /// Mark this node as a false positive. Rationale is appended to the
    /// severity history at the current severity so the audit trail shows
    /// *why* the Validator rejected it.
    pub fn reject_as_false_positive(&mut self, rationale: impl Into<String>) -> &mut Self {
        let current = self.current_severity();
        self.severity_history
            .push(SeverityHistoryEntry::new(current, rationale, "validator"));
        self.validation_status = ValidationStatus::FalsePositive;
        self
    }

    /// Mark this node as informational context (host fingerprint, tech
    /// stack) rather than a finding.
    pub fn mark_info_only(&mut self, rationale: impl Into<String>) -> &mut Self {
        let current = self.current_severity();
        self.severity_history
            .push(SeverityHistoryEntry::new(current, rationale, "validator"));
        self.validation_status = ValidationStatus::InfoOnly;
        self
    }

    /// Whether this node belongs in the Report Agent's
    /// `validated_findings_manifest`.
    pub fn is_publishable_finding(&self) -> bool {
        self.validation_status.is_publishable_finding()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> EvidenceNode {
        EvidenceNode::new(
            "node-1",
            "finding",
            "Exposed admin panel",
            "Admin login page reachable without auth at /admin.",
            "https://target.example/admin",
            Severity::High,
            "Login page returns 200 to unauthenticated requests.",
        )
    }

    #[test]
    fn new_node_starts_pending_with_one_history_entry() {
        let n = fixture();
        assert_eq!(n.validation_status, ValidationStatus::Pending);
        assert_eq!(n.severity_history.len(), 1);
        assert_eq!(n.severity_history[0].set_by, "red_team");
        assert!(matches!(n.current_severity(), Severity::High));
        assert!(!n.is_publishable_finding());
    }

    #[test]
    fn validator_confirmation_at_same_severity_yields_confirmed() {
        let mut n = fixture();
        n.apply_validator_decision(Severity::High, "Reproduced the 200 response.");
        assert_eq!(n.validation_status, ValidationStatus::Confirmed);
        assert_eq!(n.severity_history.len(), 2);
        assert_eq!(n.severity_history[1].set_by, "validator");
        assert!(n.is_publishable_finding());
    }

    #[test]
    fn validator_severity_change_yields_revised() {
        let mut n = fixture();
        n.apply_validator_decision(
            Severity::Medium,
            "Admin panel requires VPN; reachable only from jump host.",
        );
        assert_eq!(n.validation_status, ValidationStatus::Revised);
        assert!(matches!(n.current_severity(), Severity::Medium));
        assert!(n.is_publishable_finding());
    }

    #[test]
    fn false_positive_is_not_publishable() {
        let mut n = fixture();
        n.reject_as_false_positive("/admin returns a static 404 with an admin-styled template.");
        assert_eq!(n.validation_status, ValidationStatus::FalsePositive);
        assert!(!n.is_publishable_finding());
    }

    #[test]
    fn info_only_is_not_publishable() {
        let mut n = fixture();
        n.mark_info_only("Context only — Nginx 1.24 on Debian.");
        assert_eq!(n.validation_status, ValidationStatus::InfoOnly);
        assert!(!n.is_publishable_finding());
    }

    #[test]
    fn provenance_attaches_cleanly_and_round_trips() {
        use crate::provenance::{ProbeCommand, Provenance};
        let prov = Provenance::new(
            "nmap",
            "7.95",
            ProbeCommand::from_exact("nmap -sV 192.168.1.1"),
            "Nmap scan report",
        );
        let node = fixture().with_provenance(prov.clone());
        let wire = serde_json::to_value(&node).unwrap();
        let back: EvidenceNode = serde_json::from_value(wire).unwrap();
        assert_eq!(back.provenance, Some(prov));
    }

    #[test]
    fn confidence_is_clamped_to_zero_one() {
        let n = fixture().with_confidence(1.7);
        assert_eq!(n.confidence, 1.0);
        let n = fixture().with_confidence(-0.5);
        assert_eq!(n.confidence, 0.0);
    }

    #[test]
    fn pending_node_is_omitted_from_publishable_set() {
        let nodes = [
            {
                let mut n = fixture();
                n.apply_validator_decision(Severity::High, "ok");
                n
            },
            fixture(), // still Pending
            {
                let mut n = fixture();
                n.reject_as_false_positive("dup");
                n
            },
            {
                let mut n = fixture();
                n.mark_info_only("ctx");
                n
            },
        ];
        let publishable: Vec<&EvidenceNode> = nodes
            .iter()
            .filter(|n| n.is_publishable_finding())
            .collect();
        assert_eq!(publishable.len(), 1);
    }
}
