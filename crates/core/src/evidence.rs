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

/// Metadata keys that cross the tools → UI crate boundary. Declared once
/// here so the producer that writes a key and the view that reads it cannot
/// drift apart — bare duplicated strings fail silently as an empty panel.
pub mod metadata_keys {
    /// Post-exploit sub-category tag; the UI post-exploit view filters on it.
    pub const POSTEXPLOIT_CATEGORY: &str = "postexploit_category";
    /// Harvested account name (credential-access builders).
    pub const USERNAME: &str = "username";
    /// Tool that produced the node.
    pub const ORIGIN_TOOL: &str = "origin_tool";
    /// Lateral-movement technique label.
    pub const TECHNIQUE: &str = "technique";
}

/// Which engagement an evidence node belongs to (pick#513).
///
/// One Pick can serve several StrikeKit engagements at once, so the pending
/// buffer and the evidence graph are kept per scope: a scan start or a drain
/// for one engagement never touches another's nodes. A call that carries no
/// engagement id (standalone Pick use outside StrikeKit) uses `Default`, which
/// is separate from every engagement.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub enum EvidenceScope {
    /// No engagement id on the call.
    #[default]
    Default,
    /// The StrikeKit engagement id from the call context.
    Engagement(String),
}

impl EvidenceScope {
    /// The scope for an optional engagement id. A missing or blank id is
    /// `Default`, so a call cannot address an engagement named "".
    pub fn from_engagement_id(engagement_id: Option<&str>) -> Self {
        match engagement_id {
            Some(id) if !id.trim().is_empty() => Self::Engagement(id.to_string()),
            _ => Self::Default,
        }
    }

    /// The workspace directory a call in this scope uses under the Pick's
    /// workspace `base` (pick#513): `base` itself for `Default`, and
    /// `base/engagements/<id>` for an engagement, so one engagement's tools
    /// never read, list or upload another's files. The sandboxes mount only
    /// this directory as `/workspace`.
    ///
    /// The id becomes a path segment, so it must be 1 to 128 lowercase ASCII
    /// letters, digits, `-` or `_`. Anything else (a `/`, `..`, a NUL, an
    /// uppercase letter) is refused rather than rewritten, because two
    /// different ids must never map to one directory. Uppercase is refused
    /// because macOS and Windows filesystems ignore case, so `Eng-A` and
    /// `eng-a` would share a directory there. Matrix engagement ids are
    /// lowercase UUIDs, so a real id always passes.
    pub fn workspace_dir(
        &self,
        base: &std::path::Path,
    ) -> crate::error::Result<std::path::PathBuf> {
        match self {
            Self::Default => Ok(base.to_path_buf()),
            Self::Engagement(id) if is_safe_path_segment(id) => {
                Ok(base.join(ENGAGEMENTS_DIR).join(id))
            }
            Self::Engagement(_) => Err(crate::error::Error::InvalidParams(
                "engagement id is not a safe workspace directory name (1-128 of a-z 0-9 - _)"
                    .to_string(),
            )),
        }
    }
}

/// Directory under the Pick workspace that holds one subdirectory per
/// engagement (pick#513).
pub const ENGAGEMENTS_DIR: &str = "engagements";

fn is_safe_path_segment(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

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
    #[must_use = "with_provenance consumes self; assign the returned node or the provenance is lost"]
    pub fn with_provenance(mut self, provenance: Provenance) -> Self {
        self.provenance = Some(provenance);
        self
    }

    /// Attach tool-specific structured metadata.
    #[must_use = "with_metadata consumes self; assign the returned node or the metadata is lost"]
    pub fn with_metadata(mut self, metadata: HashMap<String, serde_json::Value>) -> Self {
        self.metadata = metadata;
        self
    }

    /// Set the initial confidence score.
    #[must_use = "with_confidence consumes self; assign the returned node or the score is lost"]
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

    #[test]
    fn evidence_scope_from_engagement_id() {
        assert_eq!(
            EvidenceScope::from_engagement_id(Some("eng-1")),
            EvidenceScope::Engagement("eng-1".to_string())
        );
        assert_eq!(
            EvidenceScope::from_engagement_id(None),
            EvidenceScope::Default
        );
        assert_eq!(
            EvidenceScope::from_engagement_id(Some("  ")),
            EvidenceScope::Default,
            "a blank id must not name an engagement"
        );
    }

    #[test]
    fn workspace_dir_is_per_engagement_and_default_keeps_the_base() {
        let base = std::path::Path::new("/ws");
        let scope = |id: &str| EvidenceScope::Engagement(id.to_string());
        assert_eq!(EvidenceScope::Default.workspace_dir(base).unwrap(), base);
        assert_eq!(
            scope("0b9c-4e2f_a1").workspace_dir(base).unwrap(),
            base.join("engagements").join("0b9c-4e2f_a1")
        );
        assert_ne!(
            scope("eng-a").workspace_dir(base).unwrap(),
            scope("eng-b").workspace_dir(base).unwrap()
        );
    }

    #[test]
    fn workspace_dir_refuses_ids_that_are_not_a_safe_segment() {
        let base = std::path::Path::new("/ws");
        let long = "a".repeat(129);
        for bad in [
            "..",
            "../eng-b",
            "eng/b",
            "eng.b",
            "a\0b",
            "eng b",
            long.as_str(),
        ] {
            assert!(
                EvidenceScope::Engagement(bad.to_string())
                    .workspace_dir(base)
                    .is_err(),
                "{bad:?} must be refused"
            );
        }
        assert!(EvidenceScope::Engagement("a".repeat(128))
            .workspace_dir(base)
            .is_ok());
    }

    /// On a case-insensitive filesystem (macOS, Windows) `Eng-A` and `eng-a`
    /// name one directory, so two engagements would share files. Uppercase is
    /// refused; a lowercase UUID, which is what Matrix sends, is accepted.
    /// Allowing ASCII uppercase in `is_safe_path_segment` turns this red.
    #[test]
    fn workspace_dir_refuses_uppercase_so_ids_cannot_collide_by_case() {
        let base = std::path::Path::new("/ws");
        for bad in ["Eng-A", "ENG", "0193a1B2-7c3d"] {
            assert!(
                EvidenceScope::Engagement(bad.to_string())
                    .workspace_dir(base)
                    .is_err(),
                "{bad:?} must be refused"
            );
        }
        let uuid = "0193a1b2-7c3d-7e4f-8a9b-0c1d2e3f4a5b";
        assert_eq!(
            EvidenceScope::Engagement(uuid.to_string())
                .workspace_dir(base)
                .unwrap(),
            base.join(ENGAGEMENTS_DIR).join(uuid)
        );
    }

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
        let node = fixture().with_provenance(prov);
        let wire = serde_json::to_value(&node).unwrap();
        let back: EvidenceNode = serde_json::from_value(wire).unwrap();
        // The wire-facing provenance fields survive the round-trip. The raw
        // `command` is intentionally not serialized (#317 review) — it can carry
        // an injected credential — so it comes back empty while the redacted
        // `effective_command` is intact.
        let back_prov = back.provenance.expect("provenance present");
        assert_eq!(back_prov.underlying_tool, "nmap");
        assert_eq!(back_prov.tool_version, "7.95");
        assert_eq!(back_prov.probe_commands[0].command, "");
        assert_eq!(
            back_prov.probe_commands[0].effective_command,
            "nmap -sV 192.168.1.1"
        );
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
