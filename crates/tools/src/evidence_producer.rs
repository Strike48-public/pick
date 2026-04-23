//! Evidence producer that converts tool results into evidence nodes.
//!
//! This module bridges the gap between tool execution (which produces
//! `ToolResult` with `Provenance`) and the evidence graph (which stores
//! `EvidenceNode`s for the Validator and Report agents).

use pentest_core::evidence::EvidenceNode;
use pentest_core::export::Severity;
use pentest_core::provenance::Provenance;
use serde_json::Value;
use uuid::Uuid;

/// Push an evidence node to the global evidence graph.
///
/// This function is called by `pentest_ui::session::push_evidence` after tools
/// produce evidence. The tools crate itself just provides the conversion logic;
/// the actual graph management happens in the UI layer to avoid circular dependencies.
///
/// This re-export exists so tool code can call `crate::evidence_producer::push_evidence(node)`
/// without needing to know about the UI layer.
#[cfg(not(target_arch = "wasm32"))]
pub fn push_evidence(node: EvidenceNode) {
    // Store in a thread-local or global that the UI layer reads, or
    // use an injected callback. For now, we'll use a simple approach:
    // store in a static and let the UI poll it.
    use std::sync::LazyLock;
    use std::sync::RwLock;

    static PENDING_EVIDENCE: LazyLock<RwLock<Vec<EvidenceNode>>> =
        LazyLock::new(|| RwLock::new(Vec::new()));

    PENDING_EVIDENCE.write().unwrap().push(node);
}

/// Drain pending evidence nodes. Called by the UI layer.
#[cfg(not(target_arch = "wasm32"))]
pub fn drain_pending_evidence() -> Vec<EvidenceNode> {
    use std::sync::LazyLock;
    use std::sync::RwLock;

    static PENDING_EVIDENCE: LazyLock<RwLock<Vec<EvidenceNode>>> =
        LazyLock::new(|| RwLock::new(Vec::new()));

    std::mem::take(&mut *PENDING_EVIDENCE.write().unwrap())
}

#[cfg(target_arch = "wasm32")]
pub fn push_evidence(_node: EvidenceNode) {
    // WASM cannot push evidence - no-op
}

#[cfg(target_arch = "wasm32")]
pub fn drain_pending_evidence() -> Vec<EvidenceNode> {
    Vec::new()
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
}
