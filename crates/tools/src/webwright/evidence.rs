//! Map Webwright artifacts to EvidenceNodes.

use pentest_core::evidence::{EvidenceNode, SeverityHistoryEntry};
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
/// report's severity profile (an explicit `info` label stays `Info` —
/// context, not a Low finding). Identical titles across a single run are
/// merged into the retained node (max severity wins; descriptions and URLs
/// accumulate) so a noisy target cannot flood the evidence graph with
/// look-alike nodes, and a distinct same-headline variant is not erased.
pub fn ingest_webwright_findings(
    findings_json: &Value,
    target: &str,
    task_id: &str,
    provenance: &Provenance,
) {
    // Severity rank for merge decisions (Severity deliberately does not
    // derive Ord — ordering severity levels numerically is a policy choice,
    // and this is the only place we need it).
    fn severity_rank(s: Severity) -> u8 {
        match s {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::Info => 0,
        }
    }

    if let Some(findings) = findings_json.as_array() {
        // Dedupe: identical titles within one run merge into the retained
        // node — max severity wins, descriptions and URLs accumulate — so a
        // noisy target cannot flood the graph with look-alike nodes AND a
        // genuinely distinct same-headline variant (different payload, URL,
        // or severity) is not silently erased.
        let mut merged: Vec<EvidenceNode> = Vec::new();
        let mut by_title: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for finding in findings {
            let title = finding["title"]
                .as_str()
                .unwrap_or("Browser finding")
                .to_string();
            let description = finding["description"].as_str().unwrap_or("").to_string();
            let severity = match finding["severity"].as_str().unwrap_or("").to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                // An explicit informational label stays context, not a Low
                // finding — only UNLABELED / placeholder / unknown labels
                // descend to Low (leads, not confirmed severities).
                "info" | "informational" => Severity::Info,
                _ => Severity::Low,
            };
            let url = finding.get("url").cloned();

            if let Some(&idx) = by_title.get(&title) {
                let kept = &mut merged[idx];
                if severity_rank(severity) > severity_rank(kept.current_severity()) {
                    // Append a history entry rather than using the validator
                    // transition: the node stays Pending for the Validator;
                    // this only records that a same-title duplicate carried a
                    // stronger claim.
                    kept.severity_history.push(SeverityHistoryEntry::new(
                        severity,
                        "same-title duplicate carried a stronger severity",
                        "ingest_merge",
                    ));
                }
                if !description.is_empty() && !kept.description.contains(&description) {
                    if !kept.description.is_empty() {
                        kept.description.push_str("\n\n");
                    }
                    kept.description.push_str(&description);
                }
                if let Some(url) = &url {
                    let urls = kept
                        .metadata
                        .entry("finding_urls".to_string())
                        .or_insert_with(|| Value::Array(Vec::new()));
                    if let Some(arr) = urls.as_array_mut() {
                        if !arr.contains(url) {
                            arr.push(url.clone());
                        }
                    }
                }
                tracing::warn!(
                    title = %title,
                    url = url.as_ref().and_then(|v| v.as_str()).unwrap_or(""),
                    "duplicate webwright finding title merged into retained node"
                );
                continue;
            }

            let mut node = EvidenceNode::new(
                Uuid::new_v4().to_string(),
                "browser_finding",
                title.clone(),
                description,
                target,
                severity,
                "Vulnerability discovered through AI-driven browser automation.".to_string(),
            )
            .with_provenance(provenance.clone());

            node.metadata.insert("task_id".to_string(), task_id.into());
            if let Some(url) = &url {
                node.metadata.insert("finding_url".to_string(), url.clone());
                node.metadata.insert(
                    "finding_urls".to_string(),
                    Value::Array(vec![url.clone()]),
                );
            }
            if let Some(vuln_type) = finding["type"].as_str() {
                node.metadata
                    .insert("vuln_type".to_string(), vuln_type.into());
            }

            by_title.insert(title, merged.len());
            merged.push(node);
        }
        for node in merged {
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
    /// severity; an explicit `info` label stays Info. Same-title findings
    /// merge into the retained node: max severity wins, descriptions and
    /// URLs accumulate — a duplicate carrying a stronger severity or a
    /// different URL must not be silently erased.
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
            // Duplicate of the first title — must merge into the retained
            // node, not vanish: it carries a stronger severity and a
            // different URL.
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
        assert_eq!(ours.len(), 2, "duplicate title must merge to one node");

        let xss = ours
            .iter()
            .find(|n| n.title.contains("Reflected XSS"))
            .expect("xss finding present");
        // Max severity wins across the merged duplicates (high + critical).
        assert_eq!(xss.current_severity(), Severity::Critical);
        // Both variants' URLs survive on the retained node.
        let urls = xss
            .metadata
            .get("finding_urls")
            .and_then(|u| u.as_array())
            .expect("merged URLs array present");
        assert_eq!(urls.len(), 2, "both duplicates' URLs must survive");
        // Both variants' descriptions survive.
        assert!(xss.description.contains("Search reflects unescaped input"));
        assert!(xss.description.contains("Duplicate"));
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

    /// An explicitly informational finding stays Info — context for the
    /// report, not severity-inflated to Low by the hygiene fallback.
    #[test]
    fn explicit_info_stays_info() {
        use crate::evidence_producer::drain_pending_evidence;

        let _ = drain_pending_evidence();
        let findings = json!([
            {
                "title": "Cookie without SameSite",
                "description": "Informational observation",
                "severity": "info",
                "url": "https://target.com/"
            }
        ]);
        ingest_webwright_findings(
            &findings,
            "https://target.com",
            "task-457",
            &test_provenance(),
        );
        let nodes = drain_pending_evidence();
        let info = nodes
            .iter()
            .find(|n| n.title.contains("Cookie without SameSite"))
            .expect("info finding present");
        assert_eq!(info.current_severity(), Severity::Info);
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
