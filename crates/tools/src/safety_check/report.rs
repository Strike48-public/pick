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
/// The layout follows the refined summary report (project-management#490): a
/// non-expert reads five sections top to bottom -
///
/// 1. the verdict heading,
/// 2. a network diagram that highlights the issues,
/// 3. "is anything malicious?" - attacker signs vs. plain weaknesses,
/// 4. "how this could impact you" - a scenario -> risk-to-you table,
/// 5. one recommendation.
///
/// The full per-check table, device inventory and every recommendation follow
/// under "Details", so nothing the old report carried is lost. Every sentence
/// in the first five sections is derived from a check result; nothing here is
/// a claim the tool did not measure.
pub fn format_report(result: &super::types::SafetyCheckResult) -> String {
    let mut output = String::new();
    let impacts = impacts(result);

    // 1. Verdict heading. Scoped to the *network environment* - never the
    // user's own device - so a "Not safe" headline is not misread as "you have
    // been compromised". Pick assesses the network it operates from.
    output.push_str(&format!(
        "## {} {}\n\n",
        status_indicator(result.status),
        verdict_label(result.status)
    ));
    output.push_str(status_gloss(result.status));
    output.push_str("\n\n");

    // 2. Network at a glance.
    if let Some(map) = &result.network_map {
        output.push_str("### Your network at a glance\n\n");
        output.push_str(&render_network_mermaid(map, &result.checks));
        output.push('\n');
    }

    // 3. Is anything malicious?
    output.push_str("### The verdict: is anything malicious?\n\n");
    output.push_str(&malicious_verdict(result, &impacts));
    output.push_str("\n\n");

    // 4. How this could impact you.
    output.push_str("### How this could impact you\n\n");
    if impacts.is_empty() {
        output.push_str(
            "Nothing we checked gives someone an obvious way to reach you or your traffic on this network.\n\n",
        );
    } else {
        output.push_str("| Scenario | Risk to you |\n");
        output.push_str("|----------|-------------|\n");
        for impact in impacts.iter().take(MAX_IMPACT_ROWS) {
            output.push_str(&format!(
                "| {} | **{}** — {} |\n",
                table_cell(&impact.scenario),
                impact.risk.label(),
                table_cell(&impact.why)
            ));
        }
        output.push('\n');
        if impacts.iter().any(|i| i.risk != Risk::Low) {
            output.push_str(
                "**The network's weaknesses are the attack surface. You are one of the targets on that surface.** \
                 A problem in a device your traffic passes through is a problem in your connection.\n\n",
            );
        }
    }

    // 5. One recommendation: the highest-priority one, already sorted by the
    // generator. The rest stay in Details.
    output.push_str("### What we recommend\n\n");
    output.push_str(&one_recommendation(result));
    output.push_str("\n\n");

    // Details: everything the report carried before, below the summary.
    output.push_str("### Details\n\n");
    output.push_str("| Check | Result | Details |\n");
    output.push_str("|-------|--------|--------|\n");
    for check in &result.checks {
        output.push_str(&format!(
            "| {} | {} | {} |\n",
            check.name,
            check.status,
            // Keep details single-line so the table cell stays intact.
            table_cell(&check.details)
        ));
    }
    output.push('\n');

    if let Some(map) = &result.network_map {
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
                    dev.hostname
                        .as_deref()
                        .map(table_cell)
                        .unwrap_or_else(|| "-".into()),
                    dev.ip,
                    dev.vendor
                        .as_deref()
                        .map(table_cell)
                        .unwrap_or_else(|| "-".into()),
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

    if !result.recommendations.is_empty() {
        output.push_str("**All recommendations**\n\n");
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

/// The five summary sections as structured data, for the agent to repeat
/// verbatim in its write-up instead of paraphrasing them.
pub fn summary_json(result: &super::types::SafetyCheckResult) -> serde_json::Value {
    let impacts = impacts(result);
    serde_json::json!({
        "verdict": verdict_label(result.status),
        "is_anything_malicious": malicious_verdict(result, &impacts),
        "impact": impacts.iter().take(MAX_IMPACT_ROWS).map(|i| serde_json::json!({
            "scenario": i.scenario,
            "risk_to_you": format!("{} — {}", i.risk.label(), i.why),
        })).collect::<Vec<_>>(),
        "recommendation": one_recommendation(result),
    })
}

/// Most rows the impact table shows; the rest are covered by Details.
const MAX_IMPACT_ROWS: usize = 6;

/// How directly a finding touches the person on this network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Risk {
    High,
    Medium,
    Low,
}

impl Risk {
    fn label(self) -> &'static str {
        match self {
            Risk::High => "High direct risk",
            Risk::Medium => "Medium risk",
            Risk::Low => "Low direct risk",
        }
    }
}

/// Whether a finding is a sign of an attacker, a suspicion, or a weakness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Signal {
    /// Evidence of hostile activity (hijacked DNS, a gateway or device on a
    /// threat list).
    Malicious,
    /// Reputation hits that may be an attacker or may be a shared/abused IP.
    Suspicious,
    /// A weakness or an unverified area - not evidence of an attacker.
    Weakness,
}

/// One row of "How this could impact you", plus what it says about malice.
#[derive(Debug, Clone)]
pub(crate) struct Impact {
    pub scenario: String,
    pub risk: Risk,
    pub why: String,
    pub signal: Signal,
    /// Short phrase for the malicious-verdict sentence.
    pub evidence: String,
}

fn impact(scenario: &str, risk: Risk, why: &str, signal: Signal, evidence: &str) -> Impact {
    Impact {
        scenario: scenario.to_string(),
        risk,
        why: why.to_string(),
        signal,
        evidence: evidence.to_string(),
    }
}

/// Derive the impact rows from the check results, most direct risk first.
pub(crate) fn impacts(result: &super::types::SafetyCheckResult) -> Vec<Impact> {
    use super::types::ThreatLevel;

    let mut out = Vec::new();

    if let Some(check) = result.checks.iter().find(|c| c.name == "DNS Integrity") {
        match check.status {
            CheckStatus::Failed if check.details.contains("Captive portal") => out.push(impact(
                "A captive portal is intercepting your web traffic until you sign in",
                Risk::Low,
                "normal on hotel and airport Wi-Fi; only sign in on the portal you expect to see",
                Signal::Weakness,
                "a captive portal is intercepting lookups",
            )),
            CheckStatus::Failed => out.push(impact(
                "Someone answers your DNS lookups with addresses of their choosing",
                Risk::High,
                "websites you type can be swapped for look-alikes that collect your passwords",
                Signal::Malicious,
                "DNS answers on this network are being changed",
            )),
            CheckStatus::Warning => out.push(impact(
                "Some DNS answers could not be verified",
                Risk::Medium,
                "a redirected lookup would not be noticed",
                Signal::Weakness,
                "some DNS answers could not be verified",
            )),
            CheckStatus::Unknown => out.push(impact(
                "DNS integrity could not be checked",
                Risk::Low,
                "we cannot rule out redirected lookups on this network",
                Signal::Weakness,
                "DNS could not be checked",
            )),
            CheckStatus::Passed | CheckStatus::NeedsEnrichment => {}
        }
    }

    if let Some(check) = result
        .checks
        .iter()
        .find(|c| c.name == "Router Threat Intelligence")
    {
        match check.status {
            CheckStatus::Failed if check.severity == Severity::Critical => out.push(impact(
                "Your traffic passes through a gateway flagged as malicious",
                Risk::High,
                "anything you send that is not encrypted can be read or changed on the way",
                Signal::Malicious,
                "the gateway is flagged as malicious in threat intelligence",
            )),
            CheckStatus::Failed => out.push(impact(
                "The gateway has abuse reports in threat databases",
                Risk::High,
                "every connection you make goes through it; it may be compromised or shared with abusers",
                Signal::Suspicious,
                "the gateway has abuse reports",
            )),
            CheckStatus::Warning => out.push(impact(
                "The gateway has an elevated threat score",
                Risk::Medium,
                "often a public hotspot with past abuse; your traffic still passes through it",
                Signal::Suspicious,
                "the gateway has an elevated threat score",
            )),
            CheckStatus::NeedsEnrichment => out.push(impact(
                "The gateway's reputation has not been checked yet",
                Risk::Low,
                "nothing bad was found locally, but the gateway is not confirmed clean",
                Signal::Weakness,
                "the gateway's reputation is still unchecked",
            )),
            CheckStatus::Unknown => out.push(impact(
                "The gateway's reputation could not be checked",
                Risk::Low,
                "we cannot rule out a known-bad gateway",
                Signal::Weakness,
                "the gateway's reputation could not be checked",
            )),
            CheckStatus::Passed => {}
        }
    }

    if let Some(map) = &result.network_map {
        for dev in &map.other_devices {
            let name = device_name(dev);
            match dev.threat_level {
                ThreatLevel::Malicious => out.push(impact(
                    &format!("A device on this network ({name}) is flagged as malicious"),
                    Risk::High,
                    "it shares the network with you and can try to reach your device directly",
                    Signal::Malicious,
                    &format!("{name} is flagged as malicious"),
                )),
                ThreatLevel::Suspicious => out.push(impact(
                    &format!("A device on this network ({name}) looks suspicious"),
                    Risk::Medium,
                    "it can reach your device directly; keep file sharing and remote access off",
                    Signal::Suspicious,
                    &format!("{name} looks suspicious"),
                )),
                ThreatLevel::Safe => {}
            }
        }
        if map.other_devices.len() > 20 {
            out.push(impact(
                &format!(
                    "{} other devices share this network with you",
                    map.other_devices.len()
                ),
                Risk::Medium,
                "any of them can try to reach your device directly, as on any public Wi-Fi",
                Signal::Weakness,
                "it is a busy shared network",
            ));
        }
        if map.sweep_truncated.is_some() {
            out.push(impact(
                "Not every device on this network was checked",
                Risk::Low,
                "something risky could be among the devices we did not reach",
                Signal::Weakness,
                "not every device was checked",
            ));
        }
    }

    // Stable sort: most direct risk first, check order within a level.
    out.sort_by_key(|i| i.risk);
    out
}

/// The "is anything malicious?" answer: attacker signs vs. weaknesses, and
/// never more certain than the checks allow.
fn malicious_verdict(result: &super::types::SafetyCheckResult, impacts: &[Impact]) -> String {
    let join = |signal: Signal| {
        impacts
            .iter()
            .filter(|i| i.signal == signal)
            .map(|i| i.evidence.as_str())
            .collect::<Vec<_>>()
    };
    let malicious = join(Signal::Malicious);
    let suspicious = join(Signal::Suspicious);
    let weaknesses = join(Signal::Weakness);

    if !malicious.is_empty() {
        return format!(
            "**Possibly - treat this network as hostile:** {}.",
            sentence_list(&malicious)
        );
    }
    if !suspicious.is_empty() {
        return format!(
            "**Nothing confirmed malicious, but** {} - that can be a shared or previously abused address rather than an attacker on this network.",
            sentence_list(&suspicious)
        );
    }

    // No attacker signs. Say what was actually seen, and what was not checked.
    let dns_ok = result
        .checks
        .iter()
        .any(|c| c.name == "DNS Integrity" && c.status == CheckStatus::Passed);
    let gw_ok = result
        .checks
        .iter()
        .any(|c| c.name == "Router Threat Intelligence" && c.status == CheckStatus::Passed);
    let mut seen = Vec::new();
    if dns_ok {
        seen.push("DNS answers matched what we expected");
    }
    if gw_ok {
        seen.push("the gateway is not on a threat list");
    }
    let mut sentence = if seen.is_empty() {
        "**We saw no signs of an attacker**, but we could not confirm it either.".to_string()
    } else {
        format!(
            "**We saw no signs of an attacker:** {}.",
            sentence_list(&seen)
        )
    };
    if !weaknesses.is_empty() {
        sentence.push_str(&format!(
            " Not fully confirmed: {}.",
            sentence_list(&weaknesses)
        ));
    }
    sentence
}

/// The single recommendation: the top-priority action, or its description
/// when it has no action.
fn one_recommendation(result: &super::types::SafetyCheckResult) -> String {
    match result.recommendations.first() {
        Some(rec) => rec.action.clone().unwrap_or_else(|| rec.description.clone()),
        None => "Keep using HTTPS-only browsing and avoid entering sensitive credentials on shared networks.".to_string(),
    }
}

/// Plain-language verdict label for the heading.
fn verdict_label(status: super::types::SafetyStatus) -> &'static str {
    use super::types::SafetyStatus::*;
    match status {
        Safe => "Looks safe",
        MostlySafe => "Probably safe",
        Caution => "Use with caution",
        Unsafe => "Not safe",
    }
}

/// "a", "a and b", "a, b and c".
fn sentence_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {}", rest.join(", "), last),
    }
}

/// Keep a value safe inside a Markdown table cell: one line, no pipe, and the
/// angle brackets escaped (the MDX renderer breaks on raw `<`/`>` in cells).
fn table_cell(s: &str) -> String {
    s.replace('\n', " ")
        .replace('|', "/")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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

/// Render the discovered network as a Mermaid diagram that highlights issues.
///
/// Devices are colored by threat level, and the gateway by its reputation
/// check, so a malicious or suspicious hop is visually obvious. Hijacked DNS
/// gets its own red node off the gateway. Emitted inside a ```mermaid fence so
/// it renders rather than showing as raw text.
fn render_network_mermaid(map: &super::types::NetworkMap, checks: &[CheckResult]) -> String {
    use super::types::ThreatLevel;

    let mut m = String::from("```mermaid\ngraph TD\n");

    // Gateway issue, from the reputation check.
    let gw_class = match checks
        .iter()
        .find(|c| c.name == "Router Threat Intelligence")
    {
        Some(c) if c.status == CheckStatus::Failed && c.severity == Severity::Critical => {
            Some(("malicious", "FLAGGED MALICIOUS"))
        }
        Some(c) if c.status == CheckStatus::Failed => Some(("suspicious", "ABUSE REPORTS")),
        Some(c) if c.status == CheckStatus::Warning => {
            Some(("suspicious", "ELEVATED THREAT SCORE"))
        }
        _ => None,
    };
    let dns_hijacked = checks.iter().any(|c| {
        c.name == "DNS Integrity"
            && c.status == CheckStatus::Failed
            && !c.details.contains("Captive portal")
    });

    // Core nodes.
    m.push_str(&format!(
        "    YOU[\"Your device<br/>{}\"]\n",
        map.your_device.ip
    ));
    let gw_issue = gw_class
        .map(|(_, issue)| format!("<br/>{issue}"))
        .unwrap_or_default();
    m.push_str(&format!(
        "    GW[\"Gateway / Router<br/>{}{}\"]\n",
        map.gateway.ip, gw_issue
    ));
    m.push_str("    YOU --> GW\n");
    if dns_hijacked {
        m.push_str("    DNS[\"DNS answers<br/>CHANGED IN TRANSIT\"]\n    GW --> DNS\n");
    }

    // Cap rendered devices so a busy coffee-shop network does not produce an
    // unreadable diagram; summarize the remainder in a single node. Flagged
    // devices are drawn first so the cap never hides them.
    const MAX_RENDERED: usize = 12;
    let mut ordered: Vec<&super::types::Device> = map.other_devices.iter().collect();
    ordered.sort_by_key(|d| match d.threat_level {
        ThreatLevel::Malicious => 0,
        ThreatLevel::Suspicious => 1,
        ThreatLevel::Safe => 2,
    });
    let total = ordered.len();
    for (i, dev) in ordered.iter().take(MAX_RENDERED).enumerate() {
        let (cls, issue) = match dev.threat_level {
            ThreatLevel::Malicious => (Some("malicious"), "<br/>FLAGGED MALICIOUS"),
            ThreatLevel::Suspicious => (Some("suspicious"), "<br/>SUSPICIOUS"),
            ThreatLevel::Safe => (None, ""),
        };
        m.push_str(&format!("    D{i}[\"{}{issue}\"]\n", device_label(dev)));
        m.push_str(&format!("    GW --- D{i}\n"));
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

    // Style: highlight your device; threat classes for the gateway and hosts.
    m.push_str("    classDef you fill:#1e40af,stroke:#1e3a8a,color:#fff\n");
    m.push_str("    classDef gw fill:#374151,stroke:#1f2937,color:#fff\n");
    m.push_str("    classDef suspicious fill:#e8710a,stroke:#b45309,color:#fff\n");
    m.push_str("    classDef malicious fill:#d93025,stroke:#7f1d1d,color:#fff\n");
    m.push_str("    class YOU you\n");
    m.push_str(&format!(
        "    class GW {}\n",
        gw_class.map(|(c, _)| c).unwrap_or("gw")
    ));
    if dns_hijacked {
        m.push_str("    class DNS malicious\n");
    }
    m.push_str("```\n");

    m
}

/// Short human name for a device in prose: hostname, vendor, else IP.
fn device_name(dev: &super::types::Device) -> String {
    match dev.hostname.as_deref().or(dev.vendor.as_deref()) {
        Some(name) => format!("{} at {}", name, dev.ip),
        None => dev.ip.to_string(),
    }
}

/// Build a Mermaid node label for a discovered device.
///
/// Prefers the most human-friendly identifier available: hostname if known,
/// otherwise the vendor name, always with the IP on a second line. A bare IP
/// is the fallback when nothing was enriched. The `<br/>` keeps the IP on its
/// own line inside the node. Quotes and angle brackets are stripped to avoid breaking
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

    // Hostnames come off the network (mDNS/NetBIOS), so strip what would
    // break the label or inject markup before adding our own `<br/>`.
    match primary {
        Some(name) => format!("{}<br/>{}", name.replace(['"', '<', '>'], ""), dev.ip),
        None => dev.ip.to_string(),
    }
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
            active_subnets: Vec::new(),
            recommendations: generate_recommendations(&[], &None),
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        }
    }

    #[test]
    fn test_format_report_is_markdown_with_verdict() {
        let report = format_report(&sample_result(SafetyStatus::MostlySafe, None));
        // The verdict heading leads, with the network-scoped gloss under it so
        // a bad verdict is not misread as "you have been compromised".
        assert!(report.starts_with("## [OK~] Probably safe\n"));
        assert!(report.contains("could not be fully verified"));
        // The per-check table moved under Details, not dropped.
        assert!(report.contains("### Details"));
        assert!(report.contains("| Check | Result | Details |"));
        // No legacy ASCII separator bars.
        assert!(!report.contains("===================="));
    }

    fn map_with(others: Vec<Device>) -> NetworkMap {
        NetworkMap {
            gateway: sample_device("192.168.1.1", ThreatLevel::Safe),
            your_device: sample_device("192.168.1.100", ThreatLevel::Safe),
            other_devices: others,
            sweep_truncated: None,
        }
    }

    fn result_with(
        status: SafetyStatus,
        checks: Vec<CheckResult>,
        map: Option<NetworkMap>,
    ) -> SafetyCheckResult {
        let recommendations = generate_recommendations(&checks, &map);
        SafetyCheckResult {
            status,
            checks,
            network_map: map,
            active_subnets: Vec::new(),
            recommendations,
            timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        }
    }

    fn check(name: &str, status: CheckStatus, details: &str, severity: Severity) -> CheckResult {
        CheckResult {
            name: name.to_string(),
            status,
            details: details.to_string(),
            severity,
        }
    }

    #[test]
    fn report_has_the_five_summary_sections_in_order() {
        // project-management#490: verdict -> diagram -> malicious? -> impact ->
        // one recommendation, then Details.
        let report = format_report(&result_with(
            SafetyStatus::Caution,
            vec![check(
                "DNS Integrity",
                CheckStatus::Warning,
                "2 of 5 domains unverified",
                Severity::Medium,
            )],
            Some(map_with(vec![sample_device(
                "192.168.1.50",
                ThreatLevel::Safe,
            )])),
        ));
        let mut last = 0;
        for section in [
            "## [!] Use with caution",
            "### Your network at a glance",
            "```mermaid",
            "### The verdict: is anything malicious?",
            "### How this could impact you",
            "### What we recommend",
            "### Details",
        ] {
            let at = report[last..]
                .find(section)
                .unwrap_or_else(|| panic!("'{section}' missing or out of order in:\n{report}"));
            last += at + section.len();
        }
    }

    #[test]
    fn dns_hijack_reads_as_possibly_malicious_with_high_direct_risk() {
        let report = format_report(&result_with(
            SafetyStatus::Unsafe,
            vec![check(
                "DNS Integrity",
                CheckStatus::Failed,
                "DNS hijacking detected",
                Severity::Critical,
            )],
            Some(map_with(vec![])),
        ));
        assert!(report.starts_with("## [X] Not safe\n"));
        assert!(report.contains("**Possibly - treat this network as hostile:** DNS answers on this network are being changed."));
        assert!(report.contains("| Scenario | Risk to you |"));
        assert!(report.contains(
            "| Someone answers your DNS lookups with addresses of their choosing | **High direct risk** —"
        ));
        assert!(report.contains("You are one of the targets on that surface."));
        // The diagram calls the hijack out on its own red node.
        assert!(report.contains("DNS[\"DNS answers<br/>CHANGED IN TRANSIT\"]"));
        assert!(report.contains("class DNS malicious"));
        // One recommendation: the critical action, not the whole list.
        let rec = section(&report, "### What we recommend");
        assert_eq!(
            rec.trim(),
            "Disconnect immediately and use a trusted network or mobile hotspot."
        );
        // The heading copy never says the user's machine is compromised.
        assert!(!report.contains("compromised"));
    }

    #[test]
    fn captive_portal_is_a_weakness_not_an_attacker() {
        let report = format_report(&result_with(
            SafetyStatus::Caution,
            vec![check(
                "DNS Integrity",
                CheckStatus::Failed,
                "Captive portal detected: all domains resolve to 10.0.0.1",
                Severity::High,
            )],
            Some(map_with(vec![])),
        ));
        assert!(!report.contains("Possibly"));
        assert!(!report.contains("class DNS malicious"));
        assert!(report.contains("**Low direct risk** — normal on hotel and airport Wi-Fi"));
        // Only low risks: no attack-surface line.
        assert!(!report.contains("You are one of the targets"));
    }

    #[test]
    fn clean_network_says_what_was_seen_and_skips_the_table() {
        let report = format_report(&result_with(
            SafetyStatus::Safe,
            vec![
                check("DNS Integrity", CheckStatus::Passed, "OK", Severity::Info),
                check(
                    "Router Threat Intelligence",
                    CheckStatus::Passed,
                    "Clean",
                    Severity::Info,
                ),
            ],
            Some(map_with(vec![sample_device(
                "192.168.1.50",
                ThreatLevel::Safe,
            )])),
        ));
        assert!(report.starts_with("## [OK] Looks safe\n"));
        assert!(report.contains(
            "**We saw no signs of an attacker:** DNS answers matched what we expected and the gateway is not on a threat list."
        ));
        assert!(!report.contains("| Scenario | Risk to you |"));
        assert!(report.contains("Nothing we checked gives someone an obvious way"));
    }

    #[test]
    fn pending_reputation_is_not_claimed_clean() {
        let report = format_report(&result_with(
            SafetyStatus::MostlySafe,
            vec![
                check("DNS Integrity", CheckStatus::Passed, "OK", Severity::Info),
                check(
                    "Router Threat Intelligence",
                    CheckStatus::NeedsEnrichment,
                    "public gateway 203.0.113.9 pending reputation",
                    Severity::Low,
                ),
            ],
            Some(map_with(vec![])),
        ));
        let verdict = section(&report, "### The verdict: is anything malicious?");
        assert!(verdict.contains("DNS answers matched what we expected."));
        assert!(!verdict.contains("not on a threat list"));
        assert!(
            verdict.contains("Not fully confirmed: the gateway's reputation is still unchecked.")
        );
    }

    #[test]
    fn flagged_gateway_and_device_are_highlighted_in_the_diagram() {
        let mut bad = sample_device("192.168.1.66", ThreatLevel::Malicious);
        bad.vendor = Some("Acme".into());
        let report = format_report(&result_with(
            SafetyStatus::Unsafe,
            vec![check(
                "Router Threat Intelligence",
                CheckStatus::Failed,
                "flagged",
                Severity::Critical,
            )],
            Some(map_with(vec![
                sample_device("192.168.1.50", ThreatLevel::Safe),
                bad,
            ])),
        ));
        assert!(report.contains("GW[\"Gateway / Router<br/>192.168.1.1<br/>FLAGGED MALICIOUS\"]"));
        assert!(report.contains("class GW malicious"));
        // Flagged devices are drawn first so the node cap never hides them.
        assert!(report.contains("D0[\"Acme<br/>192.168.1.66<br/>FLAGGED MALICIOUS\"]"));
        assert!(report.contains("class D0 malicious"));
        assert!(report.contains("Acme at 192.168.1.66 is flagged as malicious"));
    }

    #[test]
    fn impact_table_escapes_cells() {
        let mut odd = sample_device("192.168.1.70", ThreatLevel::Suspicious);
        odd.hostname = Some("<pwn>|box".into());
        let report = format_report(&result_with(
            SafetyStatus::Caution,
            vec![],
            Some(map_with(vec![odd])),
        ));
        assert!(report.contains("&lt;pwn&gt;/box at 192.168.1.70"));
        assert!(!report.contains("<pwn>"));
    }

    /// The text between `heading` and the next `###` heading.
    fn section<'a>(report: &'a str, heading: &str) -> &'a str {
        let start = report.find(heading).expect("heading present") + heading.len();
        let rest = &report[start..];
        let end = rest.find("\n###").unwrap_or(rest.len());
        &rest[..end]
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
            sweep_truncated: None,
        };
        let report = format_report(&sample_result(SafetyStatus::Caution, Some(map)));
        assert!(report.contains("```mermaid"));
        assert!(report.contains("graph TD"));
        // Your device and gateway nodes labeled with their IPs.
        assert!(report.contains("192.168.1.100"));
        assert!(report.contains("192.168.1.1"));
        // The malicious host is drawn first and gets the malicious class.
        assert!(report.contains("class D0 malicious"));
        assert!(report.contains("class GW gw"));
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
            sweep_truncated: None,
        };
        let report = format_report(&sample_result(SafetyStatus::Caution, Some(map)));
        // 30 devices, capped at 12 rendered -> a "+18 more" summary node.
        assert!(report.contains("+18 more device(s)"));
    }
}
