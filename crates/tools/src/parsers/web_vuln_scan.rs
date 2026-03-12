//! Parser for web_vuln_scan tool output

use chrono::Utc;
use pentest_core::output_parser::{
    Evidence, FindingReported, FindingStatus, OutputParser, ParserContext, Severity,
    StructuredMessage, TargetDiscovered, TargetType,
};
use pentest_core::tools::ToolResult;

/// Parser for web vulnerability scan results
pub struct WebVulnScanParser;

impl WebVulnScanParser {
    /// Map tool severity strings to core Severity enum
    fn map_severity(severity_str: &str) -> Severity {
        match severity_str.to_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Informational,
        }
    }

    /// Map vulnerability type to MITRE ATT&CK techniques
    fn get_mitre_techniques(vuln_type: &str) -> Vec<String> {
        match vuln_type {
            "ADMIN_PANEL_EXPOSED" => vec!["T1190".to_string()], // Exploit Public-Facing Application
            "INFORMATION_DISCLOSURE" => vec![
                "T1592".to_string(), // Gather Victim Host Information
                "T1595".to_string(), // Active Scanning
            ],
            "DIRECTORY_LISTING" => vec![
                "T1083".to_string(), // File and Directory Discovery
                "T1592".to_string(), // Gather Victim Host Information
            ],
            "MISSING_SECURITY_HEADERS" => vec!["T1071.001".to_string()], // Application Layer Protocol: Web Protocols
            "SERVER_VERSION_DISCLOSURE" | "TECHNOLOGY_DISCLOSURE" => {
                vec!["T1592.002".to_string()] // Gather Victim Host Information: Software
            }
            "NO_HTTPS_REDIRECT" => vec!["T1557".to_string()], // Man-in-the-Middle
            _ => vec![],
        }
    }

    /// Get remediation advice for vulnerability type
    fn get_remediation(vuln_type: &str, details: &str) -> String {
        match vuln_type {
            "ADMIN_PANEL_EXPOSED" => {
                "Restrict access to admin panels using IP allowlisting, VPN, or additional authentication layers. \
                Ensure admin interfaces use strong authentication and are not publicly accessible."
                    .to_string()
            }
            "INFORMATION_DISCLOSURE" => {
                if details.contains(".git") {
                    "Remove .git directory from production web servers. Add .git to robots.txt and configure web server to deny access to hidden files."
                        .to_string()
                } else if details.contains(".env") {
                    "Remove .env files from web-accessible directories. Store configuration in environment variables or secure vaults. \
                    Configure web server to deny access to .env files."
                        .to_string()
                } else {
                    "Remove or restrict access to sensitive files. Configure web server to deny access to configuration files, \
                    backups, and development artifacts."
                        .to_string()
                }
            }
            "DIRECTORY_LISTING" => {
                "Disable directory listing in web server configuration. For Apache, set 'Options -Indexes'. \
                For nginx, ensure 'autoindex off' is set."
                    .to_string()
            }
            "MISSING_SECURITY_HEADERS" => {
                format!(
                    "Implement missing security headers: {}. Configure web server or application to include these headers in all responses.",
                    details
                )
            }
            "SERVER_VERSION_DISCLOSURE" => {
                "Configure web server to suppress version information in Server header. \
                For Apache, set 'ServerTokens Prod'. For nginx, set 'server_tokens off'."
                    .to_string()
            }
            "TECHNOLOGY_DISCLOSURE" => {
                "Remove X-Powered-By header from responses. For PHP, set 'expose_php = Off' in php.ini. \
                Configure application framework to suppress technology disclosure headers."
                    .to_string()
            }
            "NO_HTTPS_REDIRECT" => {
                "Configure automatic redirect from HTTP to HTTPS. Implement HSTS (Strict-Transport-Security) header \
                to enforce HTTPS connections. Consider disabling HTTP entirely if not needed for compatibility."
                    .to_string()
            }
            _ => "Review and remediate this security issue according to best practices.".to_string(),
        }
    }

    /// Get finding title based on vulnerability type
    fn get_title(vuln_type: &str, url: &str) -> String {
        match vuln_type {
            "ADMIN_PANEL_EXPOSED" => format!("Exposed Admin Panel: {}", url),
            "INFORMATION_DISCLOSURE" => format!("Sensitive File Disclosure: {}", url),
            "DIRECTORY_LISTING" => format!("Directory Listing Enabled: {}", url),
            "MISSING_SECURITY_HEADERS" => format!("Missing Security Headers: {}", url),
            "SERVER_VERSION_DISCLOSURE" => format!("Server Version Disclosure: {}", url),
            "TECHNOLOGY_DISCLOSURE" => format!("Technology Stack Disclosure: {}", url),
            "NO_HTTPS_REDIRECT" => format!("HTTP Does Not Redirect to HTTPS: {}", url),
            _ => format!("Web Vulnerability: {}", url),
        }
    }
}

impl OutputParser for WebVulnScanParser {
    fn parser_name(&self) -> &str {
        "web_vuln_scan"
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

        // Extract URL
        let url = match result.data.get("url").and_then(|v| v.as_str()) {
            Some(u) => u,
            None => {
                tracing::warn!("web_vuln_scan result missing 'url' field");
                return vec![];
            }
        };

        // Create TargetDiscovered for the web application
        let target = TargetDiscovered {
            target_type: TargetType::Application,
            name: format!("Web Application: {}", url),
            ip_address: None,
            hostname: url
                .split("://")
                .nth(1)
                .and_then(|s| s.split('/').next())
                .and_then(|s| s.split(':').next())
                .map(|s| s.to_string()),
            domain: None,
            os: None,
            ports: vec![],
            tags: vec!["web".to_string(), "http".to_string()],
            detection_source: "pick:web_vuln_scan".to_string(),
            confidence: Some(90),
            notes: None,
        };

        messages.push(StructuredMessage::TargetDiscovered(target));

        // Extract findings array
        let findings = match result.data.get("findings").and_then(|v| v.as_array()) {
            Some(f) => f,
            None => {
                tracing::warn!("web_vuln_scan result missing 'findings' array");
                return messages;
            }
        };

        // Parse each vulnerability finding
        for finding in findings {
            if let Some(finding_obj) = finding.as_object() {
                let vuln_type = finding_obj
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("UNKNOWN");

                let severity_str = finding_obj
                    .get("severity")
                    .and_then(|v| v.as_str())
                    .unwrap_or("INFORMATIONAL");

                let details = finding_obj
                    .get("details")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                let path = finding_obj
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                // Build evidence data
                let mut evidence_data = format!("URL: {}", url);
                if !path.is_empty() {
                    evidence_data.push_str(&format!(", Path: {}", path));
                }
                if let Some(status_code) = finding_obj.get("status_code").and_then(|v| v.as_u64())
                {
                    evidence_data.push_str(&format!(", Status Code: {}", status_code));
                }

                // Create FindingReported
                let finding_reported = FindingReported {
                    title: Self::get_title(vuln_type, url),
                    description: format!(
                        "{}. {}",
                        details,
                        match vuln_type {
                            "ADMIN_PANEL_EXPOSED" =>
                                "Admin panels should not be publicly accessible as they are high-value targets for attackers.",
                            "INFORMATION_DISCLOSURE" =>
                                "Sensitive files exposed to the internet can reveal configuration details, credentials, or source code.",
                            "DIRECTORY_LISTING" =>
                                "Directory listing allows attackers to browse files and discover sensitive resources.",
                            "MISSING_SECURITY_HEADERS" =>
                                "Security headers help protect against common web attacks like XSS, clickjacking, and MIME sniffing.",
                            "SERVER_VERSION_DISCLOSURE" | "TECHNOLOGY_DISCLOSURE" =>
                                "Version disclosure helps attackers identify known vulnerabilities in the software stack.",
                            "NO_HTTPS_REDIRECT" =>
                                "Unencrypted HTTP traffic can be intercepted, allowing man-in-the-middle attacks.",
                            _ => "This vulnerability may be exploited to compromise the application or leak sensitive information.",
                        }
                    ),
                    severity: Self::map_severity(severity_str),
                    status: FindingStatus::Confirmed,
                    evidence: vec![Evidence {
                        evidence_type: "web_scan".to_string(),
                        description: details.to_string(),
                        data: evidence_data,
                        timestamp: Utc::now(),
                    }],
                    mitre_techniques: Self::get_mitre_techniques(vuln_type),
                    remediation: Some(Self::get_remediation(vuln_type, details)),
                    cve_ids: vec![],
                    target_ids: vec![],
                    credential_ids: vec![],
                };

                messages.push(StructuredMessage::FindingReported(finding_reported));
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
    fn test_parse_web_vuln_scan_with_findings() {
        let parser = WebVulnScanParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "url": "http://example.com",
                "findings": [
                    {
                        "type": "ADMIN_PANEL_EXPOSED",
                        "severity": "MEDIUM",
                        "path": "/admin",
                        "status_code": 200,
                        "details": "Admin panel accessible at http://example.com/admin"
                    },
                    {
                        "type": "INFORMATION_DISCLOSURE",
                        "severity": "HIGH",
                        "path": "/.env",
                        "details": "Sensitive file accessible at http://example.com/.env"
                    },
                    {
                        "type": "MISSING_SECURITY_HEADERS",
                        "severity": "LOW",
                        "details": "Missing: X-Frame-Options, Content-Security-Policy",
                        "missing_headers": ["X-Frame-Options", "Content-Security-Policy"]
                    }
                ],
                "summary": {
                    "total": 3,
                    "critical": 0,
                    "high": 1,
                    "medium": 1,
                    "low": 1
                }
            }),
            error: None,
            duration_ms: 5000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("web_vuln_scan", &result, &context);

        // Should create 1 target + 3 findings
        assert_eq!(messages.len(), 4);

        // Check target
        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert!(target.name.contains("Web Application"));
                assert_eq!(target.target_type, TargetType::Application);
                assert!(target.tags.contains(&"web".to_string()));
            }
            _ => panic!("Expected TargetDiscovered message"),
        }

        // Check admin panel finding
        match &messages[1] {
            StructuredMessage::FindingReported(finding) => {
                assert!(finding.title.contains("Exposed Admin Panel"));
                assert_eq!(finding.severity, Severity::Medium);
                assert!(finding.mitre_techniques.contains(&"T1190".to_string()));
                assert!(finding.remediation.is_some());
            }
            _ => panic!("Expected FindingReported message"),
        }

        // Check info disclosure finding
        match &messages[2] {
            StructuredMessage::FindingReported(finding) => {
                assert!(finding.title.contains("Sensitive File Disclosure"));
                assert_eq!(finding.severity, Severity::High);
                assert!(finding.description.contains(".env"));
            }
            _ => panic!("Expected FindingReported message"),
        }

        // Check missing headers finding
        match &messages[3] {
            StructuredMessage::FindingReported(finding) => {
                assert!(finding.title.contains("Missing Security Headers"));
                assert_eq!(finding.severity, Severity::Low);
                assert!(finding.description.contains("X-Frame-Options"));
            }
            _ => panic!("Expected FindingReported message"),
        }
    }

    #[test]
    fn test_parse_web_vuln_scan_no_findings() {
        let parser = WebVulnScanParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "url": "https://secure.example.com",
                "findings": [],
                "summary": {
                    "total": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                }
            }),
            error: None,
            duration_ms: 3000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("web_vuln_scan", &result, &context);

        // Should only create target, no findings
        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::TargetDiscovered(_) => {}
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_directory_listing_finding() {
        let parser = WebVulnScanParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "url": "http://example.com",
                "findings": [
                    {
                        "type": "DIRECTORY_LISTING",
                        "severity": "MEDIUM",
                        "path": "/backup",
                        "details": "Directory listing enabled at http://example.com/backup/"
                    }
                ],
                "summary": {
                    "total": 1,
                    "medium": 1
                }
            }),
            error: None,
            duration_ms: 2000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("web_vuln_scan", &result, &context);

        assert_eq!(messages.len(), 2);

        match &messages[1] {
            StructuredMessage::FindingReported(finding) => {
                assert!(finding.title.contains("Directory Listing"));
                assert_eq!(finding.severity, Severity::Medium);
                assert!(finding.mitre_techniques.contains(&"T1083".to_string()));
                assert!(finding.remediation.as_ref().unwrap().contains("Options -Indexes"));
            }
            _ => panic!("Expected FindingReported message"),
        }
    }

    #[test]
    fn test_parse_failed_web_vuln_scan() {
        let parser = WebVulnScanParser;
        let result = ToolResult {
            success: false,
            data: json!({}),
            error: Some("Connection timeout".to_string()),
            duration_ms: 5000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("web_vuln_scan", &result, &context);
        assert_eq!(messages.len(), 0);
    }

    #[test]
    fn test_severity_mapping() {
        assert_eq!(
            WebVulnScanParser::map_severity("CRITICAL"),
            Severity::Critical
        );
        assert_eq!(WebVulnScanParser::map_severity("HIGH"), Severity::High);
        assert_eq!(WebVulnScanParser::map_severity("MEDIUM"), Severity::Medium);
        assert_eq!(WebVulnScanParser::map_severity("LOW"), Severity::Low);
        assert_eq!(
            WebVulnScanParser::map_severity("UNKNOWN"),
            Severity::Informational
        );
    }
}
