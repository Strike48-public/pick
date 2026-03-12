//! Parser for cve_lookup tool output

use chrono::Utc;
use pentest_core::output_parser::{
    Evidence, FindingReported, FindingStatus, OutputParser, ParserContext, Severity,
    StructuredMessage,
};
use pentest_core::tools::ToolResult;

/// Parser for CVE lookup results
pub struct CveLookupParser;

impl CveLookupParser {
    /// Map CVE severity string to core Severity enum
    fn map_severity(severity_str: &str) -> Severity {
        match severity_str.to_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Informational,
        }
    }

    /// Map CVSS score to severity if severity string is missing
    fn cvss_to_severity(score: f64) -> Severity {
        if score >= 9.0 {
            Severity::Critical
        } else if score >= 7.0 {
            Severity::High
        } else if score >= 4.0 {
            Severity::Medium
        } else if score > 0.0 {
            Severity::Low
        } else {
            Severity::Informational
        }
    }
}

impl OutputParser for CveLookupParser {
    fn parser_name(&self) -> &str {
        "cve_lookup"
    }

    fn parse(
        &self,
        _tool_name: &str,
        result: &ToolResult,
        _context: &ParserContext,
    ) -> Vec<StructuredMessage> {
        // Only parse successful results
        if !result.success {
            return vec![];
        }

        let mut messages = vec![];

        // Extract product and version
        let product = match result.data.get("product").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => {
                tracing::warn!("cve_lookup result missing 'product' field");
                return vec![];
            }
        };

        let version = result
            .data
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Extract CVEs array
        let cves = match result.data.get("cves").and_then(|v| v.as_array()) {
            Some(c) => c,
            None => {
                tracing::warn!("cve_lookup result missing 'cves' array");
                return vec![];
            }
        };

        // Parse each CVE into a finding
        for cve in cves {
            if let Some(cve_obj) = cve.as_object() {
                let cve_id = cve_obj
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN");

                let description = cve_obj
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("No description available");

                let cvss_score = cve_obj
                    .get("cvss")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);

                let severity_str = cve_obj
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN");

                let published = cve_obj
                    .get("published")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Determine severity
                let severity = if severity_str == "UNKNOWN" {
                    Self::cvss_to_severity(cvss_score)
                } else {
                    Self::map_severity(severity_str)
                };

                // Build title and details
                let version_str = if !version.is_empty() {
                    format!(" {}", version)
                } else {
                    String::new()
                };

                let finding = FindingReported {
                    title: format!("{}: {}{}", cve_id, product, version_str),
                    description: format!(
                        "CVE {} affects {}{} (CVSS: {:.1}). {}",
                        cve_id, product, version_str, cvss_score, description
                    ),
                    severity,
                    status: FindingStatus::Confirmed,
                    evidence: vec![Evidence {
                        evidence_type: "cve_lookup".to_string(),
                        description: format!("CVE found via NVD database lookup"),
                        data: format!(
                            "CVE: {}, Product: {}{}, CVSS: {:.1}, Severity: {}{}",
                            cve_id,
                            product,
                            version_str,
                            cvss_score,
                            severity_str,
                            if !published.is_empty() {
                                format!(", Published: {}", published)
                            } else {
                                String::new()
                            }
                        ),
                        timestamp: Utc::now(),
                    }],
                    mitre_techniques: vec![
                        "T1190".to_string(), // Exploit Public-Facing Application
                    ],
                    remediation: Some(format!(
                        "Update {} to a patched version that addresses {}. \
                        Consult vendor security advisories for specific version recommendations. \
                        If no patch is available, implement compensating controls or consider \
                        disabling affected functionality until a fix is released.",
                        product, cve_id
                    )),
                    cve_ids: vec![cve_id.to_string()],
                    target_ids: vec![],
                    credential_ids: vec![],
                };

                messages.push(StructuredMessage::FindingReported(finding));
            }
        }

        messages
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::output_parser::ParserContext;
    use pentest_core::tools::ToolResult;
    use serde_json::json;

    #[test]
    fn test_parse_cve_lookup_with_results() {
        let parser = CveLookupParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "product": "nginx",
                "version": "1.18.0",
                "cves": [
                    {
                        "id": "CVE-2021-23017",
                        "description": "A security issue in nginx resolver was identified, which might allow an attacker to cause 1-byte memory overwrite by using a specially crafted DNS response.",
                        "cvss": 8.1,
                        "severity": "HIGH",
                        "published": "2021-05-27T00:00:00"
                    },
                    {
                        "id": "CVE-2020-5902",
                        "description": "Remote code execution vulnerability in TMUI.",
                        "cvss": 9.8,
                        "severity": "CRITICAL",
                        "published": "2020-07-01T00:00:00"
                    }
                ],
                "count": 2
            }),
            error: None,
            duration_ms: 1500,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("cve_lookup", &result, &context);

        assert_eq!(messages.len(), 2);

        // Check first CVE (HIGH severity)
        match &messages[0] {
            StructuredMessage::FindingReported(finding) => {
                assert!(finding.title.contains("CVE-2021-23017"));
                assert!(finding.title.contains("nginx 1.18.0"));
                assert_eq!(finding.severity, Severity::High);
                assert!(finding.description.contains("CVSS: 8.1"));
                assert!(finding.cve_ids.contains(&"CVE-2021-23017".to_string()));
                assert!(finding.mitre_techniques.contains(&"T1190".to_string()));
                assert!(finding.remediation.is_some());
            }
            _ => panic!("Expected FindingReported message"),
        }

        // Check second CVE (CRITICAL severity)
        match &messages[1] {
            StructuredMessage::FindingReported(finding) => {
                assert!(finding.title.contains("CVE-2020-5902"));
                assert_eq!(finding.severity, Severity::Critical);
                assert!(finding.description.contains("CVSS: 9.8"));
            }
            _ => panic!("Expected FindingReported message"),
        }
    }

    #[test]
    fn test_parse_cve_lookup_no_version() {
        let parser = CveLookupParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "product": "openssh",
                "version": null,
                "cves": [
                    {
                        "id": "CVE-2021-41617",
                        "description": "OpenSSH vulnerability",
                        "cvss": 7.0,
                        "severity": "HIGH",
                        "published": "2021-09-26T00:00:00"
                    }
                ],
                "count": 1
            }),
            error: None,
            duration_ms: 1200,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("cve_lookup", &result, &context);

        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::FindingReported(finding) => {
                assert!(finding.title.contains("openssh"));
                assert!(!finding.title.contains(" null"));
            }
            _ => panic!("Expected FindingReported message"),
        }
    }

    #[test]
    fn test_parse_cve_lookup_no_cves() {
        let parser = CveLookupParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "product": "custom-app",
                "version": "1.0.0",
                "cves": [],
                "count": 0
            }),
            error: None,
            duration_ms: 800,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("cve_lookup", &result, &context);
        assert_eq!(messages.len(), 0);
    }

    #[test]
    fn test_parse_failed_cve_lookup() {
        let parser = CveLookupParser;
        let result = ToolResult {
            success: false,
            data: json!({}),
            error: Some("NVD API timeout".to_string()),
            duration_ms: 10000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("cve_lookup", &result, &context);
        assert_eq!(messages.len(), 0);
    }

    #[test]
    fn test_cvss_to_severity_mapping() {
        assert_eq!(CveLookupParser::cvss_to_severity(10.0), Severity::Critical);
        assert_eq!(CveLookupParser::cvss_to_severity(9.5), Severity::Critical);
        assert_eq!(CveLookupParser::cvss_to_severity(8.0), Severity::High);
        assert_eq!(CveLookupParser::cvss_to_severity(7.0), Severity::High);
        assert_eq!(CveLookupParser::cvss_to_severity(5.0), Severity::Medium);
        assert_eq!(CveLookupParser::cvss_to_severity(4.0), Severity::Medium);
        assert_eq!(CveLookupParser::cvss_to_severity(2.0), Severity::Low);
        assert_eq!(
            CveLookupParser::cvss_to_severity(0.0),
            Severity::Informational
        );
    }
}
