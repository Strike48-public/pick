//! Map Webwright artifacts to EvidenceNodes.

use pentest_core::evidence::EvidenceNode;
use pentest_core::export::Severity;
use pentest_core::provenance::Provenance;
use serde_json::Value;
use uuid::Uuid;

use crate::evidence_producer::push_evidence;

/// Ingest all artifacts from a Webwright run into the evidence buffer.
///
/// Generated artifacts are evidence *context*, not confirmed findings, so
/// severity hygiene keeps them out of the top of the report (agent hardening
/// C2): screenshots/DOM snapshots/logs are Info, and generated exploit scripts
/// are Low rather than Medium — a script's existence demonstrates an
/// exploration path, not a confirmed vulnerability.
pub fn ingest_webwright_evidence(
    artifacts: &Value,
    target: &str,
    task_id: &str,
    provenance: &Provenance,
) {
    // Ingest generated scripts as exploit evidence
    if let Some(scripts) = artifacts["scripts"].as_array() {
        for script_path in scripts {
            if let Some(path) = script_path.as_str() {
                let filename = path.rsplit('/').next().unwrap_or(path);
                let mut node = EvidenceNode::new(
                    Uuid::new_v4().to_string(),
                    "browser_exploit_script",
                    format!("Generated exploit script: {}", filename),
                    format!(
                        "Webwright generated a Playwright script during exploration of {}. \
                         This script can be replayed to reproduce the finding. This node is \
                         context, not a confirmed finding; the Validator adjudicates whether \
                         the script demonstrates a real issue.",
                        target
                    ),
                    target,
                    Severity::Low,
                    "AI-generated browser automation script demonstrating a vulnerability or technique.".to_string(),
                )
                .with_provenance(provenance.clone());

                node.metadata
                    .insert("artifact_type".to_string(), "script".into());
                node.metadata.insert("file_path".to_string(), path.into());
                node.metadata.insert("task_id".to_string(), task_id.into());

                let _ = push_evidence(node);
            }
        }
    }

    // Ingest screenshots as observations
    if let Some(screenshots) = artifacts["screenshots"].as_array() {
        for screenshot_path in screenshots {
            if let Some(path) = screenshot_path.as_str() {
                let filename = path.rsplit('/').next().unwrap_or(path);
                let mut node = EvidenceNode::new(
                    Uuid::new_v4().to_string(),
                    "browser_screenshot",
                    format!("Browser screenshot: {}", filename),
                    format!(
                        "Screenshot captured during browser automation of {}.",
                        target
                    ),
                    target,
                    Severity::Info,
                    "Visual evidence of application state during testing.".to_string(),
                )
                .with_provenance(provenance.clone());

                node.metadata
                    .insert("artifact_type".to_string(), "screenshot".into());
                node.metadata.insert("file_path".to_string(), path.into());
                node.metadata.insert("task_id".to_string(), task_id.into());

                let _ = push_evidence(node);
            }
        }
    }

    // Ingest DOM snapshots as observations
    if let Some(snapshots) = artifacts["dom_snapshots"].as_array() {
        for snapshot_path in snapshots {
            if let Some(path) = snapshot_path.as_str() {
                let filename = path.rsplit('/').next().unwrap_or(path);
                let mut node = EvidenceNode::new(
                    Uuid::new_v4().to_string(),
                    "dom_snapshot",
                    format!("DOM snapshot: {}", filename),
                    format!("DOM state captured from {} during browser testing.", target),
                    target,
                    Severity::Info,
                    "DOM snapshot preserving page state at time of finding.".to_string(),
                )
                .with_provenance(provenance.clone());

                node.metadata
                    .insert("artifact_type".to_string(), "dom_snapshot".into());
                node.metadata.insert("file_path".to_string(), path.into());
                node.metadata.insert("task_id".to_string(), task_id.into());

                let _ = push_evidence(node);
            }
        }
    }

    // Ingest logs (network, console, agent reasoning)
    if let Some(logs) = artifacts["logs"].as_array() {
        for log_path in logs {
            if let Some(path) = log_path.as_str() {
                let filename = path.rsplit('/').next().unwrap_or(path);
                let log_type = if filename.contains("network") {
                    "network_log"
                } else if filename.contains("console") {
                    "console_log"
                } else if filename.contains("reasoning") || filename.contains("agent") {
                    "agent_reasoning"
                } else {
                    "execution_log"
                };

                let mut node = EvidenceNode::new(
                    Uuid::new_v4().to_string(),
                    log_type,
                    format!("Browser {}: {}", log_type.replace('_', " "), filename),
                    format!("Log captured during browser automation of {}.", target),
                    target,
                    Severity::Info,
                    "Execution log providing context for browser testing session.".to_string(),
                )
                .with_provenance(provenance.clone());

                node.metadata
                    .insert("artifact_type".to_string(), log_type.into());
                node.metadata.insert("file_path".to_string(), path.into());
                node.metadata.insert("task_id".to_string(), task_id.into());

                let _ = push_evidence(node);
            }
        }
    }
}

/// Parse a Webwright findings.json and push structured findings.
///
/// Severity hygiene (agent hardening C2): a finding is only as strong as its
/// evidence. Findings default to [`Severity::Low`] unless the browser agent
/// explicitly labeled them `critical` or `high` — an unlabeled/placeholder
/// finding is a lead, not a confirmed vulnerability, and must not inflate the
/// report's severity profile. Identical titles across a single run are
/// deduplicated so a noisy target cannot flood the evidence graph with
/// look-alike nodes.
pub fn ingest_webwright_findings(
    findings_json: &Value,
    target: &str,
    task_id: &str,
    provenance: &Provenance,
) {
    if let Some(findings) = findings_json.as_array() {
        let mut seen_titles = std::collections::HashSet::new();
        for finding in findings {
            let title = finding["title"]
                .as_str()
                .unwrap_or("Browser finding")
                .to_string();
            // Dedupe: identical titles within one run collapse to a single
            // node with a count note. Keeps the graph lean and the Validator's
            // attention on distinct claims.
            if !seen_titles.insert(title.clone()) {
                continue;
            }
            let description = finding["description"].as_str().unwrap_or("").to_string();
            let severity = match finding["severity"].as_str().unwrap_or("").to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                // Anything unlabeled / placeholder / unknown descends to Low:
                // the browser agent's default "medium" and unrecognized labels
                // are leads, not confirmed severities.
                _ => Severity::Low,
            };

            let mut node = EvidenceNode::new(
                Uuid::new_v4().to_string(),
                "browser_finding",
                title,
                description,
                target,
                severity,
                "Vulnerability discovered through AI-driven browser automation.".to_string(),
            )
            .with_provenance(provenance.clone());

            node.metadata.insert("task_id".to_string(), task_id.into());
            if let Some(url) = finding.get("url") {
                node.metadata.insert("finding_url".to_string(), url.clone());
            }
            if let Some(vuln_type) = finding["type"].as_str() {
                node.metadata
                    .insert("vuln_type".to_string(), vuln_type.into());
            }

            let _ = push_evidence(node);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::provenance::ProbeCommand;
    use serde_json::json;

    fn test_provenance() -> Provenance {
        Provenance::new(
            "webwright",
            "0.1.0",
            ProbeCommand::from_exact("webwright explore --start-url https://test.com"),
            "test output",
        )
    }

    #[test]
    fn ingest_creates_evidence_for_scripts() {
        let artifacts = json!({
            "scripts": ["/tmp/webwright/test/exploit_xss.py"],
            "screenshots": [],
            "logs": [],
            "dom_snapshots": [],
        });
        // Just verify it doesn't panic
        ingest_webwright_evidence(
            &artifacts,
            "https://target.com",
            "task-123",
            &test_provenance(),
        );
    }

    #[test]
    fn ingest_findings_parses_severity() {
        let findings = json!([
            {
                "title": "Reflected XSS in search",
                "description": "Search parameter reflects unescaped input",
                "severity": "high",
                "type": "xss",
                "url": "https://target.com/search?q=<script>"
            }
        ]);
        ingest_webwright_findings(
            &findings,
            "https://target.com",
            "task-456",
            &test_provenance(),
        );
    }

    /// Severity hygiene (agent hardening C2): an explicit `critical` or `high`
    /// label survives; an unlabeled or placeholder severity descends to Low —
    /// the browser agent's default "medium" is a lead, not a confirmed
    /// severity. The dedup also collapses identical titles within a run.
    #[test]
    fn findings_flood_control_honors_explicit_severity_and_dedupes() {
        use pentest_core::evidence::ValidationStatus;
        use crate::evidence_producer::drain_pending_evidence;

        let _ = drain_pending_evidence(); // isolate this run's nodes
        let findings = json!([
            {
                "title": "Reflected XSS in search",
                "description": "Search reflects unescaped input",
                "severity": "high",
                "url": "https://target.com/search?q=<script>"
            },
            {
                "title": "Open redirect",
                "description": "Redirect without validation",
                "severity": "medium",
                "url": "https://target.com/r?u=//evil"
            },
            // Duplicate of the first title — must be deduped.
            {
                "title": "Reflected XSS in search",
                "description": "Duplicate",
                "severity": "critical",
                "url": "https://target.com/search?q=again"
            }
        ]);
        ingest_webwright_findings(
            &findings,
            "https://target.com",
            "task-456",
            &test_provenance(),
        );
        let nodes = drain_pending_evidence();
        let ours: Vec<_> = nodes
            .iter()
            .filter(|n| n.node_type == "browser_finding")
            .collect();
        assert_eq!(ours.len(), 2, "duplicate title must dedupe to one node");

        let xss = ours
            .iter()
            .find(|n| n.title.contains("Reflected XSS"))
            .expect("xss finding present");
        // Explicit high survives.
        assert_eq!(xss.current_severity(), Severity::High);
        // Unlabeled default medium descends to Low.
        let redirect = ours
            .iter()
            .find(|n| n.title.contains("Open redirect"))
            .expect("redirect finding present");
        assert_eq!(redirect.current_severity(), Severity::Low);
        // Every ingested screen/path node is Info; scripts are Low; findings
        // are pending for the Validator.
        assert_eq!(xss.validation_status, ValidationStatus::Pending);
    }

    #[test]
    fn generated_scripts_are_low_not_medium() {
        use crate::evidence_producer::drain_pending_evidence;
        let _ = drain_pending_evidence();
        let artifacts = json!({
            "scripts": ["/tmp/webwright/test/exploit_xss.py"],
            "screenshots": [],
            "logs": [],
            "dom_snapshots": [],
        });
        ingest_webwright_evidence(
            &artifacts,
            "https://target.com",
            "task-123",
            &test_provenance(),
        );
        let nodes = drain_pending_evidence();
        let scripts: Vec<_> = nodes
            .iter()
            .filter(|n| n.node_type == "browser_exploit_script")
            .collect();
        assert_eq!(scripts.len(), 1);
        assert_eq!(
            scripts[0].current_severity(),
            Severity::Low,
            "generated script is context, not a confirmed Medium finding"
        );
    }
}
