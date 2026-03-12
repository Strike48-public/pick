//! Parser for autopwn_crack tool output

use chrono::Utc;
use pentest_core::output_parser::{
    CredentialFound, CredentialInfo, CredentialStatus, CredentialType, Evidence, FindingReported,
    FindingStatus, OutputParser, ParserContext, PrivilegeTier, Severity, StructuredMessage,
};
use pentest_core::tools::ToolResult;

/// Parser for AutoPwn crack results
pub struct AutoPwnCrackParser;

impl OutputParser for AutoPwnCrackParser {
    fn parser_name(&self) -> &str {
        "autopwn_crack"
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

        // Check if cracking was successful
        let success = result
            .data
            .get("success")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !success {
            // No password found - no messages to create
            return messages;
        }

        // Extract password
        let password = match result.data.get("password").and_then(|v| v.as_str()) {
            Some(p) => p,
            None => return messages, // Success but no password field
        };

        let method = result
            .data
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown");

        let duration_sec = result
            .data
            .get("duration_sec")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        // Create CredentialFound for the WiFi password
        let credential = CredentialFound {
            credential: CredentialInfo {
                credential_type: CredentialType::Plaintext,
                username: None, // WiFi passwords don't have usernames
                secret: password.to_string(),
                domain: None,
                source: format!("pick:autopwn_crack:{}", method),
                status: CredentialStatus::Valid,
                notes: Some(format!(
                    "WiFi password cracked using {} in {}s",
                    method, duration_sec
                )),
            },
            target_id: None,                     // Will be linked by StrikeKit
            privilege_tier: PrivilegeTier::User, // WiFi access = user-level
            test_result: Some("cracked".to_string()),
        };

        messages.push(StructuredMessage::CredentialFound(credential));

        // Create a finding for successful password crack
        let finding = FindingReported {
            title: "WiFi Password Cracked".to_string(),
            description: format!(
                "The WiFi network password was successfully cracked using {} in {} seconds. \
                This demonstrates that the network password is weak and vulnerable to \
                offline dictionary or brute-force attacks. An attacker with a captured handshake \
                can crack weak passwords without needing to be in physical range of the network.",
                method, duration_sec
            ),
            severity: if duration_sec < 60 {
                Severity::Critical // Cracked in under 1 minute = very weak
            } else if duration_sec < 300 {
                Severity::High // Cracked in under 5 minutes = weak
            } else {
                Severity::Medium // Took longer but still crackable
            },
            status: FindingStatus::Exploited, // We successfully exploited it
            evidence: vec![Evidence {
                evidence_type: "password_crack".to_string(),
                description: format!("Password cracked in {} seconds", duration_sec),
                data: format!(
                    "Method: {}, Duration: {}s, Password Length: {} characters",
                    method,
                    duration_sec,
                    password.len()
                ),
                timestamp: Utc::now(),
            }],
            mitre_techniques: vec![
                "T1110".to_string(),     // Brute Force
                "T1110.002".to_string(), // Password Cracking
            ],
            remediation: Some(
                "Immediately change the WiFi password to a strong passphrase with at least 20 characters \
                including uppercase, lowercase, numbers, and special characters. Use WPA3 if supported. \
                Consider using a password manager to generate and store a random 32+ character passphrase. \
                Avoid dictionary words, names, dates, and predictable patterns."
                    .to_string(),
            ),
            cve_ids: vec![],
            target_ids: vec![],
            credential_ids: vec![],
        };

        messages.push(StructuredMessage::FindingReported(finding));

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
    fn test_parse_successful_crack_fast() {
        let parser = AutoPwnCrackParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "success": true,
                "password": "password123",
                "attempts": 1000,
                "duration_sec": 45,
                "method": "Dictionary Attack (aircrack-ng)"
            }),
            error: None,
            duration_ms: 45000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("autopwn_crack", &result, &context);

        // Should create 1 credential + 1 finding
        assert_eq!(messages.len(), 2);

        // Check credential
        match &messages[0] {
            StructuredMessage::CredentialFound(cred) => {
                assert_eq!(cred.credential.credential_type, CredentialType::Plaintext);
                assert_eq!(cred.credential.secret, "password123");
                assert_eq!(cred.credential.status, CredentialStatus::Valid);
                assert_eq!(cred.privilege_tier, PrivilegeTier::User);
                assert!(cred.credential.notes.as_ref().unwrap().contains("45s"));
            }
            _ => panic!("Expected CredentialFound message"),
        }

        // Check finding
        match &messages[1] {
            StructuredMessage::FindingReported(finding) => {
                assert_eq!(finding.title, "WiFi Password Cracked");
                assert_eq!(finding.severity, Severity::Critical); // < 60 seconds
                assert_eq!(finding.status, FindingStatus::Exploited);
                assert!(finding.mitre_techniques.contains(&"T1110.002".to_string()));
                assert!(finding.description.contains("45 seconds"));
            }
            _ => panic!("Expected FindingReported message"),
        }
    }

    #[test]
    fn test_parse_successful_crack_medium() {
        let parser = AutoPwnCrackParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "success": true,
                "password": "MyC0mpl3xP@ssw0rd",
                "attempts": 1000000,
                "duration_sec": 180,
                "method": "Dictionary Attack (aircrack-ng)"
            }),
            error: None,
            duration_ms: 180000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("autopwn_crack", &result, &context);

        assert_eq!(messages.len(), 2);

        match &messages[1] {
            StructuredMessage::FindingReported(finding) => {
                assert_eq!(finding.severity, Severity::High); // 60-300 seconds
            }
            _ => panic!("Expected FindingReported message"),
        }
    }

    #[test]
    fn test_parse_successful_crack_slow() {
        let parser = AutoPwnCrackParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "success": true,
                "password": "VeryLongComplexPassword12345",
                "attempts": 10000000,
                "duration_sec": 600,
                "method": "Dictionary Attack (aircrack-ng)"
            }),
            error: None,
            duration_ms: 600000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("autopwn_crack", &result, &context);

        assert_eq!(messages.len(), 2);

        match &messages[1] {
            StructuredMessage::FindingReported(finding) => {
                assert_eq!(finding.severity, Severity::Medium); // > 300 seconds
            }
            _ => panic!("Expected FindingReported message"),
        }
    }

    #[test]
    fn test_parse_failed_crack() {
        let parser = AutoPwnCrackParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "success": false,
                "password": null,
                "attempts": 0,
                "duration_sec": 300,
                "method": "Dictionary Attack (aircrack-ng)"
            }),
            error: None,
            duration_ms: 300000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("autopwn_crack", &result, &context);

        // No messages if crack failed
        assert_eq!(messages.len(), 0);
    }

    #[test]
    fn test_parse_tool_failure() {
        let parser = AutoPwnCrackParser;
        let result = ToolResult {
            success: false,
            data: json!({}),
            error: Some("aircrack-ng not found".to_string()),
            duration_ms: 0,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("autopwn_crack", &result, &context);
        assert_eq!(messages.len(), 0);
    }
}
