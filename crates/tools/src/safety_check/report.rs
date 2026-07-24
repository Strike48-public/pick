//! Report generation and recommendation engine for safety checks.

use super::types::{CheckResult, CheckStatus, NetworkMap, Priority, Recommendation, Severity};

/// Generate actionable recommendations based on safety check findings.
///
/// Recommendations are context-aware and prioritized by severity.
pub fn generate_recommendations(
    checks: &[CheckResult],
    network_map: &Option<NetworkMap>,
) -> Vec<Recommendation> {
    let mut recommendations = Vec::new();

    // Check for DNS issues
    let dns_check = checks.iter().find(|c| c.name == "DNS Integrity");
    if let Some(check) = dns_check {
        match check.status {
            CheckStatus::Failed => {
                if check.details.contains("Captive portal") {
                    recommendations.push(Recommendation {
                        priority: Priority::High,
                        title: "Captive Portal Detected".to_string(),
                        description: "All domains are resolving to the same IP, indicating a captive portal. You may need to authenticate through a web browser before gaining full network access.".to_string(),
                        action: Some("Open a web browser and complete the captive portal authentication.".to_string()),
                    });
                } else {
                    recommendations.push(Recommendation {
                        priority: Priority::Critical,
                        title: "DNS Hijacking Detected".to_string(),
                        description: "DNS responses do not match expected values. This could indicate a malicious hotspot or DNS poisoning attack.".to_string(),
                        action: Some("Disconnect immediately and use a trusted network or mobile hotspot.".to_string()),
                    });
                }
            }
            CheckStatus::Warning => {
                recommendations.push(Recommendation {
                    priority: Priority::Medium,
                    title: "DNS Integrity Concerns".to_string(),
                    description:
                        "Some DNS validation checks could not be completed. Proceed with caution."
                            .to_string(),
                    action: Some(
                        "Manually verify DNS server settings: Settings -> Network -> DNS"
                            .to_string(),
                    ),
                });
            }
            CheckStatus::Unknown => {
                recommendations.push(Recommendation {
                    priority: Priority::Low,
                    title: "DNS Check Incomplete".to_string(),
                    description: "Unable to validate DNS integrity due to connectivity issues."
                        .to_string(),
                    action: None,
                });
            }
            // DNS integrity has no remote-enrichment step; nothing to advise on
            // a pass or a (not-produced) pending state.
            CheckStatus::Passed | CheckStatus::NeedsEnrichment => {}
        }
    }

    // Check for threat intelligence issues
    let threat_check = checks
        .iter()
        .find(|c| c.name == "Router Threat Intelligence");
    if let Some(check) = threat_check {
        match check.status {
            CheckStatus::Failed => {
                if check.severity == Severity::Critical {
                    recommendations.push(Recommendation {
                        priority: Priority::Critical,
                        title: "Malicious Router Detected".to_string(),
                        description: "The network gateway has been flagged in threat intelligence databases as malicious. Your traffic may be intercepted.".to_string(),
                        action: Some("Disconnect immediately. Use a mobile hotspot or trusted network instead.".to_string()),
                    });
                } else {
                    recommendations.push(Recommendation {
                        priority: Priority::High,
                        title: "Router Has Suspicious Activity".to_string(),
                        description: "The network gateway has some reports in threat databases. This could be a shared IP or compromised router.".to_string(),
                        action: Some("Enable VPN before accessing sensitive resources.".to_string()),
                    });
                }
            }
            CheckStatus::Warning => {
                recommendations.push(Recommendation {
                    priority: Priority::Medium,
                    title: "Router Threat Score Elevated".to_string(),
                    description: "The network gateway has a medium threat score. May be a public hotspot with previous abuse reports.".to_string(),
                    action: Some("Use VPN for sensitive operations.".to_string()),
                });
            }
            CheckStatus::NeedsEnrichment => {
                recommendations.push(Recommendation {
                    priority: Priority::Low,
                    title: "Gateway/DNS Reputation Pending".to_string(),
                    description: "The public gateway and/or DNS resolver IPs have not yet been checked against threat-intelligence feeds. Nothing bad was found locally, but reputation is unconfirmed.".to_string(),
                    action: Some("Reputation lookup (abuseipdb_check, virustotal) will complete this verification.".to_string()),
                });
            }
            CheckStatus::Unknown => {
                // No specific recommendation for unknown status
            }
            CheckStatus::Passed => {
                // No recommendation needed
            }
        }
    }

    // General public WiFi recommendations
    if let Some(map) = network_map {
        if map.other_devices.len() > 20 {
            recommendations.push(Recommendation {
                priority: Priority::Medium,
                title: "High-Traffic Network Detected".to_string(),
                description: format!(
                    "Found {} devices on this network. This appears to be a public WiFi hotspot with many users.",
                    map.other_devices.len()
                ),
                action: Some(
                    "Use VPN, disable file sharing, and avoid entering passwords or sensitive data."
                        .to_string(),
                ),
            });
        }
    }

    // If multiple critical issues, recommend disconnecting
    let critical_count = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Failed && c.severity == Severity::Critical)
        .count();

    if critical_count >= 2 {
        recommendations.insert(
            0,
            Recommendation {
                priority: Priority::Critical,
                title: "Multiple Critical Issues Detected".to_string(),
                description: "Multiple checks failed for this network environment, so it is likely unsafe to operate from. (This is about the network you are connected to, not your own device.)".to_string(),
                action: Some("Disconnect immediately and use a mobile hotspot or trusted network.".to_string()),
            },
        );
    }

    // If everything passed, still provide basic security advice
    if recommendations.is_empty() {
        recommendations.push(Recommendation {
            priority: Priority::Low,
            title: "Network Appears Safe".to_string(),
            description: "All security checks passed. However, always follow best practices on any network.".to_string(),
            action: Some("Use HTTPS-only mode in browsers and avoid entering sensitive credentials when possible.".to_string()),
        });
    }

    // Sort by priority (Critical first, Low last)
    recommendations.sort_by_key(|r| match r.priority {
        Priority::Critical => 0,
        Priority::High => 1,
        Priority::Medium => 2,
        Priority::Low => 3,
    });

    recommendations
}

/// Format a safety check result as a Markdown report for the chat panel.
///
/// Output is GitHub-flavored Markdown: a headline verdict with a plain-language
/// gloss, a status table of every check, an embedded Mermaid network diagram,
/// and prioritized recommendations. The verdict is always backed by its
/// reasons - the status word is the headline, never the whole story.
pub fn format_report(result: &super::types::SafetyCheckResult) -> String {
    let mut output = String::new();

    // Headline verdict with a one-line, non-technical gloss. The verdict is
    // explicitly scoped to the *network environment* - never the user's own
    // device - so an "UNSAFE" headline is not misread as "you have been
    // compromised". Pick assesses the network it operates from, not the host.
    output.push_str("## Network Safety Check\n\n");
    output.push_str(&format!(
        "### Network environment: {} {}\n\n",
        status_indicator(result.status),
        result.status
    ));
    output.push_str(status_gloss(result.status));
    output.push_str("\n\n");

    // Check results as a scannable table.
    output.push_str("### What we checked\n\n");
    output.push_str("| Check | Result | Details |\n");
    output.push_str("|-------|--------|--------|\n");
    for check in &result.checks {
        output.push_str(&format!(
            "| {} | {} | {} |\n",
            check.name,
            check.status,
            // Keep details single-line so the table cell stays intact.
            check.details.replace('\n', " ")
        ));
    }
    output.push('\n');

    // Network map: a Mermaid diagram plus a quick textual summary.
    if let Some(map) = &result.network_map {
        output.push_str("### Network map\n\n");
        output.push_str(&render_network_mermaid(map));
        output.push('\n');
        output.push_str(&format!(
            "*Your device `{}` connects through gateway `{}`. {} other device(s) seen on this network.*\n\n",
            map.your_device.ip,
            map.gateway.ip,
            map.other_devices.len()
        ));

        // Device inventory table - shown when at least one device carries any
        // identifying detail (MAC, hostname, or vendor). MAC is frequently the
        // only available signal since modern phones randomize their address,
        // so it alone is enough to justify the table. Capped so a busy network
        // does not produce a wall of rows.
        const MAX_TABLE_ROWS: usize = 15;
        let any_enriched = map
            .other_devices
            .iter()
            .any(|d| d.mac.is_some() || d.hostname.is_some() || d.vendor.is_some());
        if any_enriched {
            output.push_str("| Device | IP | Vendor | MAC |\n");
            output.push_str("|--------|----|--------|----|\n");
            for dev in map.other_devices.iter().take(MAX_TABLE_ROWS) {
                output.push_str(&format!(
                    "| {} | `{}` | {} | {} |\n",
                    dev.hostname.as_deref().unwrap_or("-"),
                    dev.ip,
                    dev.vendor.as_deref().unwrap_or("-"),
                    dev.mac.as_deref().unwrap_or("-"),
                ));
            }
            output.push('\n');
            let total = map.other_devices.len();
            if total > MAX_TABLE_ROWS {
                output.push_str(&format!(
                    "*Showing {} of {} devices.*\n\n",
                    MAX_TABLE_ROWS, total
                ));
            }
        }
    }

    // Recommendations, already priority-sorted by the generator.
    if !result.recommendations.is_empty() {
        output.push_str("### Recommendations\n\n");
        for rec in &result.recommendations {
            output.push_str(&format!(
                "- **{} ({:?})** - {}",
                rec.title, rec.priority, rec.description
            ));
            if let Some(action) = &rec.action {
                output.push_str(&format!(" _{}_", action));
            }
            output.push('\n');
        }
        output.push('\n');
    }

    output.push_str(&format!(
        "<sub>Checked {}</sub>\n",
        result.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    ));

    output
}

/// Short textual status indicator (no emoji per project output rules).
fn status_indicator(status: super::types::SafetyStatus) -> &'static str {
    use super::types::SafetyStatus::*;
    match status {
        Safe => "[OK]",
        MostlySafe => "[OK~]",
        Caution => "[!]",
        Unsafe => "[X]",
    }
}

/// Plain-language explanation of what the verdict means for the user.
fn status_gloss(status: super::types::SafetyStatus) -> &'static str {
    use super::types::SafetyStatus::*;
    match status {
        Safe => "Everything we checked looked good and was verified. This network appears safe to use.",
        // Cause-neutral on purpose: MostlySafe can come from pending reputation
        // enrichment OR from a large/shared network. The specific reason is
        // surfaced in the recommendations below, so this stays general.
        MostlySafe => "Nothing harmful was found, but this network could not be fully verified - likely a busy or shared network. Probably fine; see the notes below before doing anything sensitive.",
        Caution => "This network has the normal unknowns of a public network. Take basic precautions like using a VPN and avoiding sensitive logins.",
        // Scoped to the network, not the device: this verdict means the network
        // you are connected to looks risky to operate from - it does NOT mean
        // your own machine has been compromised.
        Unsafe => "We found an active problem with the network you are connected to (not your own device). Avoid sensitive activity (banking, passwords) and consider disconnecting or switching to a mobile hotspot.",
    }
}

/// Render the discovered network as a Mermaid diagram.
///
/// Devices are colored by threat level so a malicious or suspicious host is
/// visually obvious in the chat panel. Emitted inside a ```mermaid fence so it
/// renders rather than showing as raw text.
fn render_network_mermaid(map: &super::types::NetworkMap) -> String {
    use super::types::ThreatLevel;

    let mut m = String::from("```mermaid\ngraph TD\n");

    // (helper `device_label` defined below)

    // Core nodes.
    m.push_str(&format!(
        "    YOU[\"Your device<br/>{}\"]\n",
        map.your_device.ip
    ));
    m.push_str(&format!(
        "    GW[\"Gateway / Router<br/>{}\"]\n",
        map.gateway.ip
    ));
    m.push_str("    YOU --> GW\n");

    // Cap rendered devices so a busy coffee-shop network does not produce an
    // unreadable diagram; summarize the remainder in a single node.
    const MAX_RENDERED: usize = 12;
    let total = map.other_devices.len();
    for (i, dev) in map.other_devices.iter().take(MAX_RENDERED).enumerate() {
        m.push_str(&format!("    D{i}[\"{}\"]\n", device_label(dev)));
        m.push_str(&format!("    GW --- D{i}\n"));
        let cls = match dev.threat_level {
            ThreatLevel::Malicious => Some("malicious"),
            ThreatLevel::Suspicious => Some("suspicious"),
            ThreatLevel::Safe => None,
        };
        if let Some(cls) = cls {
            m.push_str(&format!("    class D{i} {cls}\n"));
        }
    }
    if total > MAX_RENDERED {
        m.push_str(&format!(
            "    MORE[\"+{} more device(s)\"]\n    GW --- MORE\n",
            total - MAX_RENDERED
        ));
    }

    // Style: highlight your device and the gateway; threat classes for hosts.
    m.push_str("    classDef you fill:#1e40af,stroke:#1e3a8a,color:#fff\n");
    m.push_str("    classDef gw fill:#92400e,stroke:#78350f,color:#fff\n");
    m.push_str("    classDef suspicious fill:#a16207,stroke:#854d0e,color:#fff\n");
    m.push_str("    classDef malicious fill:#991b1b,stroke:#7f1d1d,color:#fff\n");
    m.push_str("    class YOU you\n    class GW gw\n");
    m.push_str("```\n");

    m
}

/// Build a Mermaid node label for a discovered device.
///
/// Prefers the most human-friendly identifier available: hostname if known,
/// otherwise the vendor name, always with the IP on a second line. A bare IP
/// is the fallback when nothing was enriched. The `<br/>` keeps the IP on its
/// own line inside the node. Any double-quotes are stripped to avoid breaking
/// the Mermaid label syntax.
fn device_label(dev: &super::types::Device) -> String {
    // Prefer the most human-friendly identifier: hostname, then vendor, then
    // MAC, then nothing (bare IP). MAC is included because randomized phone
    // MACs often defeat vendor lookup, leaving the MAC as the only label.
    let primary = dev
        .hostname
        .clone()
        .or_else(|| dev.vendor.clone())
        .or_else(|| dev.mac.clone());

    let label = match primary {
        Some(name) => format!("{}<br/>{}", name, dev.ip),
        None => dev.ip.to_string(),
    };

    label.replace('"', "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::safety_check::types::*;

    #[test]
    fn test_generate_recommendations_dns_failed() {
        let checks = vec![CheckResult {
            name: "DNS Integrity".to_string(),
            status: CheckStatus::Failed,
            details: "DNS hijacking detected".to_string(),
            severity: Severity::Critical,
        }];

        let recs = generate_recommendations(&checks, &None);
        assert!(!recs.is_empty());
        assert_eq!(recs[0].priority, Priority::Critical);
        assert!(recs[0].title.contains("DNS Hijacking"));
    }

    #[test]
    fn test_generate_recommendations_all_passed() {
        let checks = vec![
            CheckResult {
                name: "DNS Integrity".to_string(),
                status: CheckStatus::Passed,
                details: "OK".to_string(),
                severity: Severity::Info,
            },
            CheckResult {
                name: "Router Threat Intelligence".to_string(),
                status: CheckStatus::Passed,
                details: "Clean".to_string(),
                severity: Severity::Info,
            },
        ];

        let recs = generate_recommendations(&checks, &None);
        assert!(!recs.is_empty());
        assert_eq!(recs[0].priority, Priority::Low);
    }

    #[test]
    fn multi_critical_recommendation_does_not_imply_host_compromise() {
        // Two Critical failures trigger the "Multiple Critical Issues" advice.
        // Its wording must stay scoped to the NETWORK and must not tell the user
        // their machine is "compromised" - that phrasing is the exact false
        // "you've been hacked" misread this fix removes.
        let checks = vec![
            CheckResult {
                name: "DNS Integrity".to_string(),
                status: CheckStatus::Failed,
                details: "no connectivity".to_string(),
                severity: Severity::Critical,
            },
            CheckResult {
                name: "Router Threat Intelligence".to_string(),
                status: CheckStatus::Failed,
                details: "flagged".to_string(),
                severity: Severity::Critical,
            },
        ];

        let recs = generate_recommendations(&checks, &None);
        let multi = recs
            .iter()
            .find(|r| r.title == "Multiple Critical Issues Detected")
            .expect("multi-critical recommendation should be present");

        assert!(
            !multi.description.contains("compromised"),
            "verdict copy must not imply the host is compromised: {:?}",
            multi.description
        );
        // It should make the network-vs-device distinction explicit.
        assert!(multi.description.contains("not your own device"));
    }

    #[test]
    fn test_recommendations_sorted_by_priority() {
        let checks = vec![
            CheckResult {
                name: "DNS Integrity".to_string(),
                status: CheckStatus::Warning,
                details: "Medium issue".to_string(),
                severity: Severity::Medium,
            },
            CheckResult {
                name: "DNS Integrity".to_string(),
                status: CheckStatus::Failed,
                details: "DNS hijacking detected".to_string(),
                severity: Severity::Critical,
            },
        ];

        let recs = generate_recommendations(&checks, &None);
        // Should have at least one recommendation
        assert!(!recs.is_empty());
        // Critical should come first
        if recs.len() >= 2 {
            assert!(recs[0].priority as u8 <= recs[1].priority as u8);
        }
    }

    fn sample_device(ip: &str, threat: ThreatLevel) -> Device {
        Device {
            ip: ip.parse().unwrap(),
            mac: None,
            hostname: None,
            vendor: None,
            open_ports: Vec::new(),
            threat_level: threat,
        }
    }

    fn sample_result(status: SafetyStatus, map: Option<NetworkMap>) -> SafetyCheckResult {
        SafetyCheckResult {
            status,
            checks: vec![CheckResult {
                name: "DNS Integrity".to_string(),
                status: CheckStatus::Passed,
                details: "Validated 5 domains".to_string(),
                severity: Severity::Info,
            }],
            network_map: map,
            recommendations: generate_recommendations(&[], &None),
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        }
    }

    #[test]
    fn test_format_report_is_markdown_with_verdict() {
        let report = format_report(&sample_result(SafetyStatus::MostlySafe, None));
        assert!(report.contains("## Network Safety Check"));
        // Verdict is scoped to the network environment (not the user's device),
        // so an UNSAFE headline is not misread as "you have been compromised".
        assert!(report.contains("### Network environment:"));
        assert!(report.contains("MOSTLY SAFE"));
        // Status table headers present.
        assert!(report.contains("| Check | Result | Details |"));
        // No legacy ASCII separator bars.
        assert!(!report.contains("===================="));
    }

    #[test]
    fn test_format_report_renders_mermaid_map() {
        let map = NetworkMap {
            gateway: sample_device("192.168.1.1", ThreatLevel::Safe),
            your_device: sample_device("192.168.1.100", ThreatLevel::Safe),
            other_devices: vec![
                sample_device("192.168.1.50", ThreatLevel::Safe),
                sample_device("192.168.1.66", ThreatLevel::Malicious),
            ],
        };
        let report = format_report(&sample_result(SafetyStatus::Caution, Some(map)));
        assert!(report.contains("```mermaid"));
        assert!(report.contains("graph TD"));
        // Your device and gateway nodes labeled with their IPs.
        assert!(report.contains("192.168.1.100"));
        assert!(report.contains("192.168.1.1"));
        // The malicious host gets the malicious class.
        assert!(report.contains("class D1 malicious"));
    }

    #[test]
    fn test_mermaid_caps_large_networks() {
        let mut others = Vec::new();
        for i in 0..30 {
            others.push(sample_device(
                &format!("192.168.1.{}", 10 + i),
                ThreatLevel::Safe,
            ));
        }
        let map = NetworkMap {
            gateway: sample_device("192.168.1.1", ThreatLevel::Safe),
            your_device: sample_device("192.168.1.2", ThreatLevel::Safe),
            other_devices: others,
        };
        let report = format_report(&sample_result(SafetyStatus::Caution, Some(map)));
        // 30 devices, capped at 12 rendered -> a "+18 more" summary node.
        assert!(report.contains("+18 more device(s)"));
    }
}
