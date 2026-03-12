//! Parser for default_creds_test tool output

use pentest_core::output_parser::{
    CredentialFound, CredentialInfo, CredentialStatus, CredentialType, Evidence, FindingReported,
    FindingStatus, OutputParser, ParserContext, PrivilegeTier, Severity, StructuredMessage,
};
use pentest_core::tools::ToolResult;
use chrono::Utc;

/// Parser for default credentials testing results
pub struct DefaultCredsParser;

impl OutputParser for DefaultCredsParser {
    fn parser_name(&self) -> &str {
        "default_creds_test"
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

        // Extract host and service info
        let host = match result.data.get("host").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => {
                tracing::warn!("default_creds_test result missing 'host' field");
                return vec![];
            }
        };

        let port = result
            .data
            .get("port")
            .and_then(|v| v.as_u64())
            .unwrap_or(80) as u16;

        let service = result
            .data
            .get("service")
            .and_then(|v| v.as_str())
            .unwrap_or("http");

        // Extract attempts array
        let attempts = match result.data.get("attempts").and_then(|v| v.as_array()) {
            Some(a) => a,
            None => {
                tracing::warn!("default_creds_test result missing 'attempts' array");
                return vec![];
            }
        };

        let mut successful_creds = Vec::new();

        // Parse each attempt
        for attempt in attempts {
            if let Some(attempt_obj) = attempt.as_object() {
                let status = attempt_obj
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("FAILED");

                if status == "SUCCESS" {
                    let username = attempt_obj
                        .get("username")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    let password = attempt_obj
                        .get("password")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");

                    // Handle <empty> placeholder
                    let password = if password == "<empty>" {
                        ""
                    } else {
                        password
                    };

                    successful_creds.push((username.to_string(), password.to_string()));

                    // Create CredentialFound message
                    let credential = CredentialFound {
                        credential: CredentialInfo {
                            credential_type: CredentialType::Plaintext,
                            username: Some(username.to_string()),
                            secret: password.to_string(),
                            domain: None,
                            source: format!("pick:default_creds_test:{}", service),
                            status: CredentialStatus::Valid,
                            notes: Some(format!(
                                "Default credentials accepted on {}:{} ({})",
                                host, port, service
                            )),
                        },
                        target_id: None, // Will be linked by StrikeKit
                        privilege_tier: infer_privilege_tier(username, service),
                        test_result: Some("passed".to_string()),
                    };

                    messages.push(StructuredMessage::CredentialFound(credential));
                }
            }
        }

        // If any credentials were successful, create a finding
        if !successful_creds.is_empty() {
            let cred_list: Vec<String> = successful_creds
                .iter()
                .map(|(u, p)| {
                    if p.is_empty() {
                        format!("{}:<empty>", u)
                    } else {
                        format!("{}:{}", u, p)
                    }
                })
                .collect();

            let finding = FindingReported {
                title: format!("Default Credentials Accepted: {}:{} ({})", host, port, service),
                description: format!(
                    "The {} service on {}:{} accepts default credentials. {} credential(s) were successfully validated: {}. \
                    Default credentials are a critical security risk as they are publicly known and documented.",
                    service, host, port,
                    successful_creds.len(),
                    cred_list.join(", ")
                ),
                severity: Severity::Critical,
                status: FindingStatus::Confirmed,
                evidence: successful_creds
                    .iter()
                    .map(|(username, password)| Evidence {
                        evidence_type: "credential_test".to_string(),
                        description: format!("Successful authentication with username: {}", username),
                        data: format!(
                            "Host: {}, Port: {}, Service: {}, Username: {}, Password: {}",
                            host,
                            port,
                            service,
                            username,
                            if password.is_empty() { "<empty>" } else { "***" }
                        ),
                        timestamp: Utc::now(),
                    })
                    .collect(),
                mitre_techniques: vec![
                    "T1078".to_string(), // Valid Accounts
                    "T1078.001".to_string(), // Default Accounts
                ],
                remediation: Some(format!(
                    "Immediately change the default credentials on {}:{}. \
                    Implement a strong password policy and ensure all default accounts are either \
                    disabled or configured with unique, complex passwords. \
                    Consider implementing multi-factor authentication where possible.",
                    host, port
                )),
                cve_ids: vec![],
                target_ids: vec![],
                credential_ids: vec![],
            };

            messages.push(StructuredMessage::FindingReported(finding));
        }

        messages
    }
}

/// Infer privilege tier based on username and service
fn infer_privilege_tier(username: &str, service: &str) -> PrivilegeTier {
    let username_lower = username.to_lowercase();

    // Admin-level usernames
    if username_lower == "root"
        || username_lower == "admin"
        || username_lower == "administrator"
        || username_lower == "sa" // SQL Server admin
        || username_lower == "postgres" // PostgreSQL admin
    {
        return PrivilegeTier::LocalAdmin;
    }

    // Service accounts
    if service.contains("sql")
        || service.contains("mysql")
        || service.contains("postgres")
        || service.contains("mongodb")
    {
        if username_lower.contains("service") || username_lower == "mysql" {
            return PrivilegeTier::Service;
        }
    }

    // Default to user-level
    PrivilegeTier::User
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::output_parser::ParserContext;
    use pentest_core::tools::ToolResult;
    use serde_json::json;

    #[test]
    fn test_parse_successful_default_creds() {
        let parser = DefaultCredsParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "host": "192.168.1.100",
                "port": 80,
                "service": "http",
                "attempts": [
                    {"username": "admin", "password": "admin", "status": "SUCCESS"},
                    {"username": "root", "password": "password", "status": "FAILED"},
                    {"username": "admin", "password": "<empty>", "status": "FAILED"}
                ],
                "successful": 1,
                "total_tested": 3
            }),
            error: None,
            duration_ms: 5000,
        };

        let context = ParserContext::new(
            "test-engagement".to_string(),
            "test-connector".to_string(),
        );

        let messages = parser.parse("default_creds_test", &result, &context);

        // Should create 1 credential + 1 finding
        assert_eq!(messages.len(), 2);

        // Check credential
        match &messages[0] {
            StructuredMessage::CredentialFound(cred) => {
                assert_eq!(cred.credential.credential_type, CredentialType::Plaintext);
                assert_eq!(cred.credential.username, Some("admin".to_string()));
                assert_eq!(cred.credential.secret, "admin");
                assert_eq!(cred.credential.status, CredentialStatus::Valid);
                assert_eq!(cred.privilege_tier, PrivilegeTier::LocalAdmin);
                assert_eq!(cred.test_result, Some("passed".to_string()));
            }
            _ => panic!("Expected CredentialFound message"),
        }

        // Check finding
        match &messages[1] {
            StructuredMessage::FindingReported(finding) => {
                assert!(finding.title.contains("Default Credentials"));
                assert_eq!(finding.severity, Severity::Critical);
                assert!(finding.mitre_techniques.contains(&"T1078.001".to_string()));
                assert_eq!(finding.evidence.len(), 1);
            }
            _ => panic!("Expected FindingReported message"),
        }
    }

    #[test]
    fn test_parse_multiple_successful_creds() {
        let parser = DefaultCredsParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "host": "192.168.1.50",
                "port": 22,
                "service": "ssh",
                "attempts": [
                    {"username": "root", "password": "root", "status": "SUCCESS"},
                    {"username": "admin", "password": "admin", "status": "SUCCESS"},
                    {"username": "user", "password": "user", "status": "FAILED"}
                ],
                "successful": 2,
                "total_tested": 3
            }),
            error: None,
            duration_ms: 8000,
        };

        let context = ParserContext::new(
            "test-engagement".to_string(),
            "test-connector".to_string(),
        );

        let messages = parser.parse("default_creds_test", &result, &context);

        // Should create 2 credentials + 1 finding
        assert_eq!(messages.len(), 3);

        // Verify both credentials
        match &messages[0] {
            StructuredMessage::CredentialFound(cred) => {
                assert_eq!(cred.credential.username, Some("root".to_string()));
            }
            _ => panic!("Expected CredentialFound message"),
        }

        match &messages[1] {
            StructuredMessage::CredentialFound(cred) => {
                assert_eq!(cred.credential.username, Some("admin".to_string()));
            }
            _ => panic!("Expected CredentialFound message"),
        }

        // Verify finding mentions both credentials
        match &messages[2] {
            StructuredMessage::FindingReported(finding) => {
                assert!(finding.description.contains("2 credential(s)"));
                assert_eq!(finding.evidence.len(), 2);
            }
            _ => panic!("Expected FindingReported message"),
        }
    }

    #[test]
    fn test_parse_no_successful_creds() {
        let parser = DefaultCredsParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "host": "192.168.1.200",
                "port": 80,
                "service": "http",
                "attempts": [
                    {"username": "admin", "password": "admin", "status": "FAILED"},
                    {"username": "root", "password": "root", "status": "FAILED"}
                ],
                "successful": 0,
                "total_tested": 2
            }),
            error: None,
            duration_ms: 3000,
        };

        let context = ParserContext::new(
            "test-engagement".to_string(),
            "test-connector".to_string(),
        );

        let messages = parser.parse("default_creds_test", &result, &context);

        // Should create no messages (no successful credentials)
        assert_eq!(messages.len(), 0);
    }

    #[test]
    fn test_infer_privilege_tier() {
        assert_eq!(infer_privilege_tier("root", "ssh"), PrivilegeTier::LocalAdmin);
        assert_eq!(infer_privilege_tier("admin", "http"), PrivilegeTier::LocalAdmin);
        assert_eq!(
            infer_privilege_tier("administrator", "smb"),
            PrivilegeTier::LocalAdmin
        );
        assert_eq!(infer_privilege_tier("postgres", "postgresql"), PrivilegeTier::LocalAdmin);
        assert_eq!(infer_privilege_tier("user", "ssh"), PrivilegeTier::User);
        assert_eq!(infer_privilege_tier("guest", "http"), PrivilegeTier::User);
    }
}
