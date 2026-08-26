//! Evidence producer that converts tool results into evidence nodes.
//!
//! This module bridges the gap between tool execution (which produces
//! `ToolResult` with `Provenance`) and the evidence graph (which stores
//! `EvidenceNode`s for the Validator and Report agents).

use pentest_core::evidence::EvidenceNode;
use pentest_core::export::Severity;
use pentest_core::provenance::Provenance;
use serde_json::Value;
use std::sync::LazyLock;
use std::sync::RwLock;
use uuid::Uuid;

/// Error returned when evidence buffer is full.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BufferFullError;

impl std::fmt::Display for BufferFullError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "evidence buffer full")
    }
}

impl std::error::Error for BufferFullError {}

/// Maximum evidence nodes buffered before rejecting new evidence.
///
/// This prevents memory exhaustion from runaway scans or malicious agents.
/// The limit is high enough for legitimate large scans (10K findings) but
/// low enough to prevent DOS attacks.
const MAX_EVIDENCE_NODES: usize = 10_000;

/// Global pending evidence buffer.
///
/// Tools push evidence here via [`push_evidence`]. The connector drains it after
/// every tool run via [`drain_pending_evidence`] and forwards each node into the
/// report evidence graph (`pentest_ui::session::drain_tool_evidence_into_graph`),
/// where the Validator round-trip adjudicates it before the report gate can
/// publish it. This buffer-to-graph bridge is the fix for pick#172.
///
/// # Thread Safety
/// Protected by `RwLock` for concurrent access. Multiple tools can
/// push evidence simultaneously, and a drain can run without blocking
/// tool execution (briefly blocks during the write lock acquisition).
#[cfg(not(target_arch = "wasm32"))]
static PENDING_EVIDENCE: LazyLock<RwLock<Vec<EvidenceNode>>> =
    LazyLock::new(|| RwLock::new(Vec::new()));

/// Push an evidence node to the global evidence buffer.
///
/// This function is called by tools after producing findings. The evidence is
/// stored in [`PENDING_EVIDENCE`], which the connector drains into the report
/// graph after each tool run (see that static's docs and pick#172).
///
/// # Capacity
/// The buffer has a maximum capacity of [`MAX_EVIDENCE_NODES`]. If the
/// buffer is full, this function logs a warning and drops the new evidence.
/// A consumer should drain evidence periodically to prevent overflow.
///
/// # Thread Safety
/// This function is thread-safe and can be called from multiple tools
/// concurrently. Evidence order is deterministic within a single tool
/// but non-deterministic across concurrent tools.
///
/// # Returns
/// - `Ok(())` if evidence was pushed successfully
/// - `Err(BufferFullError)` if buffer is full (evidence was dropped)
///
/// # Examples
/// ```ignore
/// use pentest_core::evidence::EvidenceNode;
/// use pentest_core::export::Severity;
///
/// let node = EvidenceNode::new(
///     "finding-1".to_string(),
///     "open_port",
///     "Port 22/tcp open".to_string(),
///     "SSH service detected".to_string(),
///     "192.168.1.1",
///     Severity::Medium,
///     "Open SSH port requires validation".to_string(),
/// );
///
/// if let Err(e) = push_evidence(node) {
///     eprintln!("Failed to push evidence: {}", e);
/// }
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub fn push_evidence(node: EvidenceNode) -> Result<(), BufferFullError> {
    let mut buffer = PENDING_EVIDENCE.write().unwrap();

    if buffer.len() >= MAX_EVIDENCE_NODES {
        eprintln!(
            "⚠️  Evidence buffer full ({} nodes). Dropping new evidence: {}",
            MAX_EVIDENCE_NODES, node.title
        );
        return Err(BufferFullError);
    }

    buffer.push(node);
    Ok(())
}

/// Drain all pending evidence nodes.
///
/// Called by the UI layer to retrieve accumulated evidence. This function
/// returns all evidence and clears the buffer atomically.
///
/// # Thread Safety
/// This function is thread-safe. If called concurrently from multiple threads,
/// each call will receive a portion of the evidence (non-deterministic split).
/// The UI should call this from a single thread for predictable behavior.
///
/// # Lock Ordering Safety
/// **CRITICAL:** This function MUST NOT hold the `PENDING_EVIDENCE` lock after
/// returning. The UI layer's `drain_tool_evidence_into_graph` depends on this
/// property to avoid deadlock - it acquires `EVIDENCE_GRAPH` after calling this
/// function. See `pentest_ui::session::EVIDENCE_GRAPH` documentation for the
/// complete lock ordering contract (PENDING_EVIDENCE first, EVIDENCE_GRAPH second).
///
/// The current implementation correctly releases the lock before returning via
/// `std::mem::take`, which only holds the write lock for the duration of the swap.
///
/// # Returns
/// All accumulated evidence nodes since the last drain. Empty vector if
/// no evidence has been produced.
///
/// # Examples
/// ```ignore
/// let evidence = drain_pending_evidence();
///
/// for node in evidence {
///     // Add to evidence graph
///     evidence_graph.add_node(node);
/// }
/// ```
#[cfg(not(target_arch = "wasm32"))]
pub fn drain_pending_evidence() -> Vec<EvidenceNode> {
    std::mem::take(&mut *PENDING_EVIDENCE.write().unwrap())
}

/// Get current evidence buffer size.
///
/// Useful for monitoring and debugging. The UI can use this to detect
/// when the buffer is approaching capacity.
#[cfg(not(target_arch = "wasm32"))]
pub fn evidence_buffer_size() -> usize {
    PENDING_EVIDENCE.read().unwrap().len()
}

/// Check if evidence buffer is approaching capacity.
///
/// Returns `true` if buffer is > 80% full, indicating the UI should
/// drain more frequently.
#[cfg(not(target_arch = "wasm32"))]
pub fn evidence_buffer_near_full() -> bool {
    let size = evidence_buffer_size();
    size > (MAX_EVIDENCE_NODES * 80 / 100)
}

#[cfg(target_arch = "wasm32")]
pub fn push_evidence(_node: EvidenceNode) -> Result<(), BufferFullError> {
    // WASM cannot push evidence - no-op
    Ok(())
}

#[cfg(target_arch = "wasm32")]
pub fn drain_pending_evidence() -> Vec<EvidenceNode> {
    Vec::new()
}

#[cfg(target_arch = "wasm32")]
pub fn evidence_buffer_size() -> usize {
    0
}

#[cfg(target_arch = "wasm32")]
pub fn evidence_buffer_near_full() -> bool {
    false
}

/// Create evidence nodes from nmap scan results.
///
/// Produces one evidence node per discovered open port with service info.
pub fn evidence_from_nmap(
    nmap_data: &Value,
    target: &str,
    provenance: Provenance,
) -> Vec<EvidenceNode> {
    let mut nodes = Vec::new();

    if let Some(hosts) = nmap_data["hosts"].as_array() {
        for host in hosts {
            let host_ip = host["ip"].as_str().unwrap_or(target);

            if let Some(ports) = host["ports"].as_array() {
                for port in ports {
                    let port_num = port["port"].as_u64().unwrap_or(0);
                    let protocol = port["protocol"].as_str().unwrap_or("tcp");
                    let state = port["state"].as_str().unwrap_or("unknown");
                    let service = port["service"].as_str().unwrap_or("unknown");
                    let version = port["version"].as_str().unwrap_or("");

                    if state != "open" {
                        continue; // Only report open ports
                    }

                    // Determine severity based on port and service
                    let severity = assess_port_severity(port_num, service);

                    let title = if version.is_empty() {
                        format!("Port {}/{} open on {}", port_num, protocol, host_ip)
                    } else {
                        format!(
                            "Port {}/{} open on {} - {} {}",
                            port_num, protocol, host_ip, service, version
                        )
                    };

                    let description = if version.is_empty() {
                        format!(
                            "Network scan discovered port {}/{} in state '{}' with service '{}'.",
                            port_num, protocol, state, service
                        )
                    } else {
                        format!(
                            "Network scan discovered port {}/{} in state '{}' with service '{}' version '{}'.",
                            port_num, protocol, state, service, version
                        )
                    };

                    let sensitive = if is_sensitive_port(port_num) {
                        "sensitive"
                    } else {
                        "network"
                    };
                    let rationale = format!(
                        "Port {} is commonly associated with {} service. Open {} ports should be validated for necessity.",
                        port_num, service, sensitive
                    );

                    let mut node = EvidenceNode::new(
                        Uuid::new_v4().to_string(),
                        "open_port",
                        title,
                        description,
                        host_ip,
                        severity,
                        rationale,
                    )
                    .with_provenance(provenance.clone());

                    // Add structured metadata
                    node.metadata.insert("port".to_string(), port_num.into());
                    node.metadata
                        .insert("protocol".to_string(), protocol.into());
                    node.metadata.insert("service".to_string(), service.into());
                    if !version.is_empty() {
                        node.metadata.insert("version".to_string(), version.into());
                    }

                    nodes.push(node);
                }
            }
        }
    }

    nodes
}

/// Create evidence nodes from service banner grab results.
pub fn evidence_from_service_banner(
    banner_data: &Value,
    host: &str,
    port: u16,
    provenance: Provenance,
) -> Vec<EvidenceNode> {
    let mut nodes = Vec::new();

    if let Some(banner) = banner_data["banner"].as_str() {
        if banner.is_empty() {
            return nodes;
        }

        // Check for potentially vulnerable version strings
        let severity = if contains_vulnerable_version(banner) {
            Severity::High
        } else if contains_interesting_info(banner) {
            Severity::Medium
        } else {
            Severity::Info
        };

        let title = format!("Service banner on {}:{}", host, port);
        let description = format!(
            "Service banner grab revealed: {}",
            banner.chars().take(200).collect::<String>()
        );

        let rationale = if severity == Severity::High {
            "Banner contains version information that may indicate known vulnerabilities."
        } else if severity == Severity::Medium {
            "Banner reveals service details that assist in vulnerability assessment."
        } else {
            "Banner provides service fingerprinting information."
        };

        let mut node = EvidenceNode::new(
            Uuid::new_v4().to_string(),
            "service_banner",
            title,
            description,
            format!("{}:{}", host, port),
            severity,
            rationale.to_string(),
        )
        .with_provenance(provenance);

        node.metadata.insert("banner".to_string(), banner.into());
        node.metadata.insert("port".to_string(), port.into());

        nodes.push(node);
    }

    nodes
}

/// Create evidence nodes from whatweb scan results.
pub fn evidence_from_whatweb(
    whatweb_data: &Value,
    target: &str,
    provenance: Provenance,
) -> Vec<EvidenceNode> {
    let mut nodes = Vec::new();

    if let Some(plugins) = whatweb_data["plugins"].as_array() {
        // Collect interesting technologies
        let mut technologies = Vec::new();
        let mut versions = Vec::new();

        for plugin in plugins {
            if let Some(name) = plugin["name"].as_str() {
                technologies.push(name.to_string());

                if let Some(version) = plugin["version"].as_str() {
                    if !version.is_empty() {
                        versions.push(format!("{} {}", name, version));
                    }
                }
            }
        }

        if !technologies.is_empty() {
            let severity = if versions.iter().any(|v| contains_vulnerable_version(v)) {
                Severity::High
            } else if !versions.is_empty() {
                Severity::Medium
            } else {
                Severity::Info
            };

            let title = format!("Web technologies identified on {}", target);
            let description = if !versions.is_empty() {
                format!(
                    "Web application scan identified {} with versions: {}",
                    target,
                    versions.join(", ")
                )
            } else {
                format!(
                    "Web application scan identified {} technologies: {}",
                    target,
                    technologies.join(", ")
                )
            };

            let rationale = "Technology fingerprinting assists in vulnerability assessment and attack surface analysis.";

            let mut node = EvidenceNode::new(
                Uuid::new_v4().to_string(),
                "web_tech",
                title,
                description,
                target,
                severity,
                rationale.to_string(),
            )
            .with_provenance(provenance);

            node.metadata
                .insert("technologies".to_string(), technologies.into());
            if !versions.is_empty() {
                node.metadata
                    .insert("versions".to_string(), versions.into());
            }

            nodes.push(node);
        }
    }

    nodes
}

/// A tool-agnostic finding, normalized into the shape an [`EvidenceNode`]
/// needs. Wrappers map their own result JSON into these and hand them to
/// [`evidence_from_generic`], which owns the node construction the
/// tool-specific builders would otherwise each duplicate.
pub struct GenericFinding {
    /// Node type tag, e.g. `"web_vuln"`, `"default_credentials"`.
    pub node_type: String,
    /// Short human-readable finding title.
    pub title: String,
    /// Fuller description of what was observed.
    pub description: String,
    /// The affected target (host, `host:port`, or URL).
    pub target: String,
    /// Severity assessed by the producing tool.
    pub severity: Severity,
    /// Why this warrants validation / attention.
    pub rationale: String,
    /// Structured extras copied into the node's metadata map. Callers MUST
    /// NOT place secrets here — node metadata can reach a published report.
    pub metadata: Vec<(String, Value)>,
}

/// Build evidence nodes from normalized findings, attaching the same
/// `provenance` to each.
///
/// This is the shared core behind the per-tool `evidence_from_*` builders: it
/// owns the `EvidenceNode::new` + `with_provenance` + metadata boilerplate so
/// each tool builder only has to map its own result shape into
/// [`GenericFinding`]s (pick#52 coverage promotion).
pub fn evidence_from_generic(
    findings: Vec<GenericFinding>,
    provenance: Provenance,
) -> Vec<EvidenceNode> {
    findings
        .into_iter()
        .map(|f| {
            let mut node = EvidenceNode::new(
                Uuid::new_v4().to_string(),
                f.node_type,
                f.title,
                f.description,
                f.target,
                f.severity,
                f.rationale,
            )
            .with_provenance(provenance.clone());
            for (k, v) in f.metadata {
                node.metadata.insert(k, v);
            }
            node
        })
        .collect()
}

/// Map a tool's uppercase severity label (`CRITICAL`/`HIGH`/`MEDIUM`/`LOW`)
/// to a [`Severity`]. Anything unrecognized (including `INFO`) becomes
/// [`Severity::Info`], the safe low-signal default.
fn severity_from_label(label: &str) -> Severity {
    match label.to_ascii_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Create evidence nodes from `web_vuln_scan` results.
///
/// Emits one node per entry in `data["findings"]`, carrying the finding's
/// `type` in the title and its `details` as the description. The tool's
/// per-finding `severity` label drives the node severity.
pub fn evidence_from_web_vuln_scan(
    data: &Value,
    target: &str,
    provenance: Provenance,
) -> Vec<EvidenceNode> {
    let Some(findings) = data["findings"].as_array() else {
        return Vec::new();
    };

    let generic = findings
        .iter()
        .map(|f| {
            let finding_type = f["type"].as_str().unwrap_or("WEB_FINDING");
            let details = f["details"].as_str().unwrap_or("");
            let severity = severity_from_label(f["severity"].as_str().unwrap_or("INFO"));

            let title = format!("{} on {}", finding_type, target);
            let description = if details.is_empty() {
                format!(
                    "Web vulnerability scan flagged {} on {}.",
                    finding_type, target
                )
            } else {
                details.to_string()
            };

            let mut metadata = vec![("finding_type".to_string(), finding_type.into())];
            if let Some(path) = f["path"].as_str() {
                metadata.push(("path".to_string(), path.into()));
            }
            if let Some(code) = f["status_code"].as_u64() {
                metadata.push(("status_code".to_string(), code.into()));
            }

            GenericFinding {
                node_type: "web_vuln".to_string(),
                title,
                description,
                target: target.to_string(),
                severity,
                rationale:
                    "Web-application finding surfaced by an automated scan; validate exploitability and impact before reporting."
                        .to_string(),
                metadata,
            }
        })
        .collect();

    evidence_from_generic(generic, provenance)
}

/// Create evidence nodes from `default_creds` results.
///
/// Emits one node per **successful** login (`status == "SUCCESS"`); failed and
/// errored attempts are not findings. The affected target is `host:port`.
///
/// # Security
/// The attempted password is never copied into the node (title, description, or
/// metadata). A successful default credential is a High-severity finding that
/// reaches the customer report; the working secret must stay out of the
/// published bytes (pick#52 / pick#317). The reproducible probe lives in the
/// already-redacted `provenance.probe_commands`.
pub fn evidence_from_default_creds(data: &Value, provenance: Provenance) -> Vec<EvidenceNode> {
    let host = data["host"].as_str().unwrap_or("unknown");
    let port = data["port"].as_u64().unwrap_or(0);
    let service = data["service"].as_str().unwrap_or("unknown");
    let target = format!("{host}:{port}");

    let Some(attempts) = data["attempts"].as_array() else {
        return Vec::new();
    };

    let generic = attempts
        .iter()
        .filter(|a| a["status"].as_str() == Some("SUCCESS"))
        .map(|a| {
            let username = a["username"].as_str().unwrap_or("unknown");
            GenericFinding {
                node_type: "default_credentials".to_string(),
                title: format!("Default credentials accepted: {username} on {target} ({service})"),
                description: format!(
                    "A default/weak credential for user '{username}' was accepted by the \
                     {service} service on {target}. The password value is withheld from this \
                     report; see the redacted probe command for the reproduction structure."
                ),
                target: target.clone(),
                severity: Severity::High,
                rationale:
                    "Accepting default credentials grants unauthorized access; rotate the credential and disable defaults."
                        .to_string(),
                metadata: vec![
                    ("username".to_string(), username.into()),
                    ("service".to_string(), service.into()),
                    ("port".to_string(), port.into()),
                ],
            }
        })
        .collect();

    evidence_from_generic(generic, provenance)
}

/// Create an evidence node from a single `http_request` response.
///
/// http_request is a primitive the agent calls frequently, not a
/// finding-producer, so this emits exactly one Info-severity node capturing the
/// response line (method, status, final URL). Info lets the Validator downgrade
/// or drop it while keeping the reproducible curl (in `provenance`) available to
/// ground any finding the agent builds on top of this request.
pub fn evidence_from_http_request(data: &Value, provenance: Provenance) -> Vec<EvidenceNode> {
    // Redact secrets in the URL (query-string tokens like `?api_key=...`, HTTP
    // userinfo `user:pass@`) BEFORE it lands in the node's title/description/
    // target. These fields reach the published report, and the sibling
    // provenance curl for this same URL is already redacted — without this the
    // node fields would be strictly less protected than their own provenance
    // (pick#52 / pick#317).
    let url = pentest_core::provenance::redact(data["url"].as_str().unwrap_or("unknown"));
    let method = data["method"].as_str().unwrap_or("GET");
    let status = data["status"].as_u64().unwrap_or(0);

    let finding = GenericFinding {
        node_type: "http_response".to_string(),
        title: format!("HTTP {method} {status} {url}"),
        description: format!("HTTP {method} request to {url} returned status {status}."),
        target: url.clone(),
        severity: Severity::Info,
        rationale:
            "Raw HTTP response captured for grounding; the Validator adjudicates whether it supports a finding."
                .to_string(),
        metadata: vec![
            ("method".to_string(), method.into()),
            ("status_code".to_string(), status.into()),
        ],
    };

    evidence_from_generic(vec![finding], provenance)
}

/// Assess severity of an open port based on port number and service.
fn assess_port_severity(port: u64, service: &str) -> Severity {
    // Sensitive/high-risk ports
    if is_sensitive_port(port) {
        return Severity::High;
    }

    // Common administrative/management ports
    if matches!(port, 22 | 3389 | 5900 | 5985 | 5986) {
        return Severity::Medium;
    }

    // Database ports
    if matches!(port, 3306 | 5432 | 1433 | 27017 | 6379 | 9200) {
        return Severity::Medium;
    }

    // Common web/application ports
    if matches!(port, 80 | 443 | 8080 | 8443) {
        return Severity::Low;
    }

    // Check service name for keywords
    let service_lower = service.to_lowercase();
    if service_lower.contains("telnet")
        || service_lower.contains("ftp")
        || service_lower.contains("smb")
        || service_lower.contains("rpc")
    {
        return Severity::High;
    }

    Severity::Info
}

/// Check if a port is considered sensitive/high-risk.
fn is_sensitive_port(port: u64) -> bool {
    matches!(
        port,
        21 | 23 | 445 | 135 | 139 | 111 | 512..=514 | 2049 | 873
    )
}

/// Check if banner contains version strings that might indicate vulnerabilities.
fn contains_vulnerable_version(text: &str) -> bool {
    let text_lower = text.to_lowercase();

    // Check for old/vulnerable version patterns
    text_lower.contains("apache/2.2")
        || text_lower.contains("apache/2.0")
        || text_lower.contains("apache/1.")
        || text_lower.contains("nginx/1.0")
        || text_lower.contains("nginx/0.")
        || text_lower.contains("openssh_5")
        || text_lower.contains("openssh_4")
        || text_lower.contains("iis/6")
        || text_lower.contains("iis/5")
        || text_lower.contains("php/5.2")
        || text_lower.contains("php/5.3")
}

/// Check if banner contains interesting information worth noting.
fn contains_interesting_info(text: &str) -> bool {
    let text_lower = text.to_lowercase();

    text_lower.contains("version")
        || text_lower.contains("server:")
        || text_lower.contains("apache")
        || text_lower.contains("nginx")
        || text_lower.contains("openssh")
        || text_lower.contains("microsoft")
        || text_lower.contains("php")
        || text_lower.contains("python")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // NOTE: Tests that interact with the global PENDING_EVIDENCE static may
    // experience race conditions when run in parallel. Run with --test-threads=1
    // if you need deterministic behavior. The production code is thread-safe;
    // this is only a testing artifact.
    //
    // Run: cargo test --package pentest-tools --lib evidence_producer::tests -- --test-threads=1

    /// Test that evidence survives the push → drain cycle on a single shared
    /// static (the tools-side buffer). This covers only the `pentest-tools`
    /// half: that a pushed node is retrievable by a later drain.
    ///
    /// It does NOT prove the node reaches the report — that end-to-end flow
    /// (tool -> buffer -> report graph -> validator -> gate) is covered by the
    /// `evidence_pipeline` integration test in `crates/ui/tests/`. See pick#172.
    #[test]
    fn evidence_flows_through_buffer() {
        // Create test evidence nodes with unique IDs
        let node1 = EvidenceNode::new(
            "test-flow-unique-1".to_string(),
            "test_type",
            "Test Finding 1".to_string(),
            "Description for finding 1".to_string(),
            "192.168.1.1",
            Severity::Medium,
            "Test rationale".to_string(),
        );

        let node2 = EvidenceNode::new(
            "test-flow-unique-2".to_string(),
            "test_type",
            "Test Finding 2".to_string(),
            "Description for finding 2".to_string(),
            "192.168.1.2",
            Severity::High,
            "Test rationale".to_string(),
        );

        // Act: Push evidence
        let push1_ok = push_evidence(node1.clone()).is_ok();
        let push2_ok = push_evidence(node2.clone()).is_ok();

        // Assert: Drain should contain our nodes (may contain others from parallel tests)
        let drained = drain_pending_evidence();

        // Find our nodes in the drained evidence
        let our_nodes: Vec<_> = drained
            .iter()
            .filter(|n| n.id.starts_with("test-flow-unique-"))
            .collect();

        let expected_count = if push1_ok && push2_ok {
            2
        } else if push1_ok || push2_ok {
            1
        } else {
            0
        };
        assert_eq!(
            our_nodes.len(),
            expected_count,
            "Should find {} nodes (push1: {}, push2: {})",
            expected_count,
            push1_ok,
            push2_ok
        );

        // Skip remaining assertions if buffer was full
        if expected_count == 0 {
            // Re-push nodes from other tests
            for node in drained {
                if !node.id.starts_with("test-flow-unique-") {
                    let _ = push_evidence(node);
                }
            }
            return;
        }

        // Verify our specific nodes made it through
        if push1_ok {
            assert!(drained.iter().any(|n| n.id == "test-flow-unique-1"));
            let node1_found = drained
                .iter()
                .find(|n| n.id == "test-flow-unique-1")
                .unwrap();
            assert_eq!(node1_found.affected_target, "192.168.1.1");
        }

        if push2_ok {
            assert!(drained.iter().any(|n| n.id == "test-flow-unique-2"));
            let node2_found = drained
                .iter()
                .find(|n| n.id == "test-flow-unique-2")
                .unwrap();
            assert_eq!(node2_found.affected_target, "192.168.1.2");
        }

        // Re-push nodes from other tests
        for node in drained {
            if !node.id.starts_with("test-flow-unique-") {
                let _ = push_evidence(node);
            }
        }
    }

    /// Test multiple pushes followed by single drain.
    ///
    /// Note: Uses unique IDs to avoid interference from parallel tests.
    #[test]
    #[ignore = "Requires exclusive access to global buffer - run with --test-threads=1"]
    fn multiple_push_single_drain() {
        // Act: Push 10 nodes with unique IDs
        for i in 0..10 {
            let node = EvidenceNode::new(
                format!("test-multi-unique-{}", i),
                "test_type",
                format!("Finding {}", i),
                format!("Description {}", i),
                "192.168.1.1",
                Severity::Info,
                "Test".to_string(),
            );
            let _ = push_evidence(node);
        }

        // Assert: Drain and verify our 10 nodes are present
        let drained = drain_pending_evidence();

        // Filter to only our nodes
        let our_nodes: Vec<_> = drained
            .iter()
            .filter(|n| n.id.starts_with("test-multi-unique-"))
            .collect();

        assert_eq!(our_nodes.len(), 10, "Should find our 10 nodes");

        // Verify IDs are present
        for i in 0..10 {
            let expected_id = format!("test-multi-unique-{}", i);
            assert!(
                drained.iter().any(|n| n.id == expected_id),
                "Should find node with ID {}",
                expected_id
            );
        }
    }

    /// Test that push is non-blocking (returns immediately).
    ///
    /// Note: Uses unique IDs and only verifies our nodes arrived.
    #[test]
    #[ignore = "Requires exclusive access to global buffer - run with --test-threads=1"]
    fn push_is_non_blocking() {
        // Act & Assert: Push many nodes rapidly
        let start = std::time::Instant::now();
        let mut succeeded = 0;
        for i in 0..1000 {
            let node = EvidenceNode::new(
                format!("perf-unique-{}", i),
                "test",
                format!("F{}", i),
                "D".to_string(),
                "192.168.1.1",
                Severity::Info,
                "R".to_string(),
            );
            if push_evidence(node).is_ok() {
                succeeded += 1;
            }
        }
        let elapsed = start.elapsed();

        // Should complete in < 100ms (generous threshold)
        assert!(
            elapsed.as_millis() < 100,
            "Pushing 1000 nodes took {}ms, expected < 100ms",
            elapsed.as_millis()
        );

        // Verify our nodes arrived (drain and filter)
        let drained = drain_pending_evidence();
        let our_nodes: Vec<_> = drained
            .iter()
            .filter(|n| n.id.starts_with("perf-unique-"))
            .collect();
        assert_eq!(
            our_nodes.len(),
            succeeded,
            "Should find all {} of our nodes that succeeded",
            succeeded
        );

        // Re-push nodes from other tests
        for node in drained {
            if !node.id.starts_with("perf-unique-") {
                let _ = push_evidence(node);
            }
        }
    }

    #[test]
    #[ignore = "Requires exclusive access to global buffer - run with --test-threads=1"]
    fn evidence_buffer_enforces_capacity_limit() {
        // Arrange: Record initial buffer size (other tests may be running in parallel)
        let initial_size = evidence_buffer_size();

        // Act: Try to push until buffer is full + 100 more
        let mut success_count = 0;
        let mut rejected_count = 0;
        let to_push = MAX_EVIDENCE_NODES - initial_size + 100;

        for i in 0..to_push {
            let node = EvidenceNode::new(
                format!("capacity-test-{}", i),
                "test",
                "Finding".to_string(),
                "Desc".to_string(),
                "192.168.1.1",
                Severity::Info,
                "R".to_string(),
            );

            match push_evidence(node) {
                Ok(()) => success_count += 1,
                Err(BufferFullError) => rejected_count += 1,
            }
        }

        // Assert: Should have succeeded until full, then rejected remaining
        let expected_success = MAX_EVIDENCE_NODES - initial_size;
        assert_eq!(
            success_count, expected_success,
            "Expected {} successes with initial_size={}, got {}",
            expected_success, initial_size, success_count
        );
        assert_eq!(rejected_count, 100);

        // Assert: Buffer is now at capacity
        assert_eq!(evidence_buffer_size(), MAX_EVIDENCE_NODES);

        // Cleanup: drain our test nodes
        let drained = drain_pending_evidence();
        // Re-push nodes from other tests
        for node in drained {
            if !node.id.starts_with("capacity-test-") {
                let _ = push_evidence(node);
            }
        }
    }

    #[test]
    #[ignore = "Requires exclusive access to global buffer - run with --test-threads=1"]
    fn evidence_buffer_near_full_detection() {
        // Arrange: Clear and fill to 85%
        let _ = drain_pending_evidence();

        let threshold = (MAX_EVIDENCE_NODES * 85) / 100;
        for i in 0..threshold {
            let node = EvidenceNode::new(
                format!("near-full-{}", i),
                "test",
                "F".to_string(),
                "D".to_string(),
                "192.168.1.1",
                Severity::Info,
                "R".to_string(),
            );
            let _ = push_evidence(node);
        }

        // Assert: Should detect near-full
        assert!(evidence_buffer_near_full());

        // Drain completely
        let _ = drain_pending_evidence();

        // Fill to 70%
        let target = (MAX_EVIDENCE_NODES * 70) / 100;
        for i in 0..target {
            let node = EvidenceNode::new(
                format!("not-full-{}", i),
                "test",
                "F".to_string(),
                "D".to_string(),
                "192.168.1.1",
                Severity::Info,
                "R".to_string(),
            );
            let _ = push_evidence(node);
        }

        // Assert: Should NOT detect near-full
        assert!(!evidence_buffer_near_full());

        // Cleanup
        let _ = drain_pending_evidence();
    }

    #[test]
    fn test_evidence_from_nmap_open_ports() {
        let nmap_data = json!({
            "hosts": [
                {
                    "ip": "192.168.1.100",
                    "ports": [
                        {
                            "port": 22,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "ssh",
                            "version": "OpenSSH 8.2"
                        },
                        {
                            "port": 80,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "http",
                            "version": ""
                        }
                    ]
                }
            ]
        });

        let provenance = Provenance::new(
            "nmap",
            "7.94".to_string(),
            pentest_core::provenance::ProbeCommand::from_exact("nmap -sV 192.168.1.100"),
            "test output",
        );

        let nodes = evidence_from_nmap(&nmap_data, "192.168.1.100", provenance);

        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].node_type, "open_port");
        assert!(nodes[0].title.contains("Port 22"));
        assert!(nodes[0].title.contains("192.168.1.100"));
    }

    #[test]
    fn test_assess_port_severity() {
        assert_eq!(assess_port_severity(21, "ftp"), Severity::High);
        assert_eq!(assess_port_severity(22, "ssh"), Severity::Medium);
        assert_eq!(assess_port_severity(80, "http"), Severity::Low);
        assert_eq!(assess_port_severity(12345, "unknown"), Severity::Info);
    }

    #[test]
    fn test_vulnerable_version_detection() {
        assert!(contains_vulnerable_version("Apache/2.2.15"));
        assert!(contains_vulnerable_version("nginx/1.0.15"));
        assert!(contains_vulnerable_version("OpenSSH_5.3"));
        assert!(!contains_vulnerable_version("Apache/2.4.52"));
        assert!(!contains_vulnerable_version("nginx/1.21.1"));
    }

    fn test_provenance(tool: &str) -> Provenance {
        Provenance::new(
            tool.to_string(),
            "1.0".to_string(),
            pentest_core::provenance::ProbeCommand::from_exact("echo test"),
            "test output",
        )
    }

    #[test]
    fn test_evidence_from_web_vuln_scan_one_node_per_finding() {
        let data = json!({
            "url": "http://target.example",
            "findings": [
                {
                    "type": "ADMIN_PANEL_EXPOSED",
                    "severity": "MEDIUM",
                    "path": "/admin",
                    "status_code": 200,
                    "details": "Admin panel accessible at http://target.example/admin"
                },
                {
                    "type": "INFORMATION_DISCLOSURE",
                    "severity": "HIGH",
                    "path": "/.env",
                    "status_code": 200,
                    "details": "Sensitive file exposed"
                }
            ]
        });

        let nodes = evidence_from_web_vuln_scan(
            &data,
            "http://target.example",
            test_provenance("web_vuln_scan"),
        );

        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].node_type, "web_vuln");
        assert_eq!(nodes[0].current_severity(), Severity::Medium);
        assert!(nodes[0].title.contains("ADMIN_PANEL_EXPOSED"));
        assert_eq!(nodes[0].affected_target, "http://target.example");
        assert!(nodes[0].provenance.is_some());
        assert_eq!(nodes[1].current_severity(), Severity::High);
    }

    #[test]
    fn test_evidence_from_default_creds_only_successful_and_no_password() {
        let data = json!({
            "host": "10.0.0.5",
            "port": 22,
            "service": "ssh",
            "attempts": [
                {"username": "root", "password": "hunter2", "status": "FAILED"},
                {"username": "admin", "password": "s3cr3t", "status": "SUCCESS"}
            ],
            "successful": 1,
            "total_tested": 2
        });

        // Build the provenance the way default_creds's execute() does for a
        // successful ssh login: one probe per attempt embedding the real
        // password, scrubbed by exact value. Using a dummy `test_provenance`
        // here (the old version of this test did) never exercises the real
        // `sshpass -p '<pw>'` path, so it could not catch a password leaking
        // through `effective_command`. Reverting the builder to plain
        // `from_exact` turns this test red.
        let probe = pentest_core::provenance::ProbeCommand::from_exact_redacting_secret(
            "sshpass -p 's3cr3t' ssh -o StrictHostKeyChecking=no -p 22 admin@10.0.0.5 exit",
            "s3cr3t",
        );
        let provenance = Provenance::multi_step("sshpass+openssh", "1.0", vec![probe], "");
        let nodes = evidence_from_default_creds(&data, provenance);

        // Only the successful login is a finding; failed attempts are not.
        assert_eq!(nodes.len(), 1);
        let node = &nodes[0];
        assert_eq!(node.node_type, "default_credentials");
        assert_eq!(node.current_severity(), Severity::High);
        assert!(node.title.contains("admin"));
        assert_eq!(node.affected_target, "10.0.0.5:22");
        assert!(node.provenance.is_some());

        // The plaintext password must never appear in ANY published byte of the
        // node — including the attached provenance's `effective_command`.
        let serialized = serde_json::to_string(node).unwrap();
        assert!(
            !serialized.contains("s3cr3t"),
            "plaintext password leaked into evidence node: {serialized}"
        );
    }

    #[test]
    fn test_evidence_from_http_request_redacts_url_secret() {
        // A query-string secret in the request URL must not survive into the
        // node's published fields (title/description/target). The sibling
        // provenance curl for the same URL is already redacted; this guards the
        // node fields against being the weaker path (pick#52 / pick#317).
        let data = json!({
            "url": "http://target.example/api?api_key=SECRET123&x=1",
            "method": "GET",
            "status": 200
        });

        let nodes = evidence_from_http_request(&data, test_provenance("http_request"));
        assert_eq!(nodes.len(), 1);
        let node = &nodes[0];

        for field in [&node.title, &node.description, &node.affected_target] {
            assert!(
                !field.contains("SECRET123"),
                "url secret leaked into a published node field: {field}"
            );
        }
        assert!(
            node.title.contains("<REDACTED>"),
            "url should be redacted in the node title: {}",
            node.title
        );
    }

    #[test]
    fn test_evidence_from_http_request_one_info_node() {
        let data = json!({
            "url": "http://target.example/login",
            "method": "GET",
            "status": 200,
            "ok": true,
            "headers": {"server": "nginx"},
            "body": "hello",
            "body_bytes": 5,
            "body_truncated": false
        });

        let nodes = evidence_from_http_request(&data, test_provenance("http_request"));

        assert_eq!(nodes.len(), 1);
        let node = &nodes[0];
        assert_eq!(node.node_type, "http_response");
        assert_eq!(node.current_severity(), Severity::Info);
        assert!(node.title.contains("200"));
        assert!(node.title.contains("GET"));
        assert_eq!(node.affected_target, "http://target.example/login");
        assert!(node.provenance.is_some());
    }
}
