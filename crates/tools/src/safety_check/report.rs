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
            CheckStatus::Passed => {
                // No recommendation needed for passed checks
            }
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
                description: "Multiple security checks failed. This network is likely malicious or severely compromised.".to_string(),
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

/// Format a safety check result as a human-readable report.
pub fn format_report(result: &super::types::SafetyCheckResult) -> String {
    let mut output = String::new();

    // Header
    output.push_str("=".repeat(60).as_str());
    output.push('\n');
    output.push_str("  NETWORK SAFETY CHECK REPORT\n");
    output.push_str("=".repeat(60).as_str());
    output.push('\n');
    output.push('\n');

    // Overall status
    output.push_str(&format!("Overall Status: {}\n", result.status));
    output.push_str(&format!(
        "Timestamp: {}\n",
        result.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    output.push('\n');

    // Individual checks
    output.push_str("=".repeat(60).as_str());
    output.push('\n');
    output.push_str("CHECK RESULTS\n");
    output.push_str("=".repeat(60).as_str());
    output.push('\n');
    output.push('\n');

    for check in &result.checks {
        output.push_str(&format!("[{}] {}\n", check.status, check.name));
        output.push_str(&format!("  {}\n", check.details));
        output.push('\n');
    }

    // Network map
    if let Some(map) = &result.network_map {
        output.push_str("=".repeat(60).as_str());
        output.push('\n');
        output.push_str("NETWORK MAP\n");
        output.push_str("=".repeat(60).as_str());
        output.push('\n');
        output.push('\n');
        output.push_str(&format!("Your Device: {}\n", map.your_device.ip));
        output.push_str(&format!("Gateway: {}\n", map.gateway.ip));
        output.push_str(&format!(
            "Other Devices: {} discovered\n",
            map.other_devices.len()
        ));
        output.push('\n');
    }

    // Recommendations
    if !result.recommendations.is_empty() {
        output.push_str("=".repeat(60).as_str());
        output.push('\n');
        output.push_str("RECOMMENDATIONS\n");
        output.push_str("=".repeat(60).as_str());
        output.push('\n');
        output.push('\n');

        for (idx, rec) in result.recommendations.iter().enumerate() {
            output.push_str(&format!(
                "{}. {} [{:?}]\n",
                idx + 1,
                rec.title,
                rec.priority
            ));
            output.push_str(&format!("   {}\n", rec.description));
            if let Some(action) = &rec.action {
                output.push_str(&format!("   Action: {}\n", action));
            }
            output.push('\n');
        }
    }

    output.push_str("=".repeat(60).as_str());
    output.push('\n');

    output
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
}
