//! Parser for smb_enum tool output

use chrono::Utc;
use pentest_core::output_parser::{
    Evidence, FindingReported, FindingStatus, OutputParser, ParserContext, PortInfo, PortState,
    Severity, StructuredMessage, TargetDiscovered, TargetType,
};
use pentest_core::tools::ToolResult;

/// Parser for SMB enumeration results
pub struct SmbEnumParser;

impl OutputParser for SmbEnumParser {
    fn parser_name(&self) -> &str {
        "smb_enum"
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

        // Extract host
        let host = match result.data.get("host").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => {
                tracing::warn!("smb_enum result missing 'host' field");
                return vec![];
            }
        };

        // Extract shares array
        let shares = match result.data.get("shares").and_then(|v| v.as_array()) {
            Some(s) => s,
            None => {
                tracing::warn!("smb_enum result missing 'shares' array");
                return vec![];
            }
        };

        // Create TargetDiscovered for SMB service
        let target = TargetDiscovered {
            target_type: TargetType::Service,
            name: format!("SMB Service ({})", host),
            ip_address: Some(host.to_string()),
            hostname: None,
            domain: None,
            os: None,
            ports: vec![
                PortInfo {
                    number: 445,
                    protocol: "tcp".to_string(),
                    service: Some("smb".to_string()),
                    version: None,
                    state: PortState::Open,
                },
                PortInfo {
                    number: 139,
                    protocol: "tcp".to_string(),
                    service: Some("netbios-ssn".to_string()),
                    version: None,
                    state: PortState::Open,
                },
            ],
            tags: vec!["smb".to_string(), "file-sharing".to_string()],
            detection_source: "pick:smb_enum".to_string(),
            confidence: Some(90),
            notes: Some(format!("Discovered {} SMB share(s)", shares.len())),
        };

        messages.push(StructuredMessage::TargetDiscovered(target));

        // Check for anonymous access vulnerabilities
        let mut anonymous_shares = Vec::new();

        for share in shares {
            if let Some(share_obj) = share.as_object() {
                let share_name = share_obj
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");

                let share_type = share_obj
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Unknown");

                let anonymous_access = share_obj
                    .get("anonymous_access")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                // Skip administrative shares (ending with $)
                let is_admin_share = share_name.ends_with('$');

                if anonymous_access && !is_admin_share && share_type != "IPC" {
                    anonymous_shares.push((share_name.to_string(), share_type.to_string()));
                }
            }
        }

        // Create finding if anonymous access is enabled on non-admin shares
        if !anonymous_shares.is_empty() {
            let share_list: Vec<String> = anonymous_shares
                .iter()
                .map(|(name, stype)| format!("{} ({})", name, stype))
                .collect();

            let finding = FindingReported {
                title: format!("SMB Shares with Anonymous Access: {}", host),
                description: format!(
                    "The SMB service on {} allows anonymous (unauthenticated) access to {} share(s): {}. \
                    Anonymous access to SMB shares can lead to unauthorized data disclosure, data tampering, \
                    or provide attackers with information about the network and systems.",
                    host,
                    anonymous_shares.len(),
                    share_list.join(", ")
                ),
                severity: Severity::High,
                status: FindingStatus::Confirmed,
                evidence: anonymous_shares
                    .iter()
                    .map(|(name, stype)| Evidence {
                        evidence_type: "smb_enumeration".to_string(),
                        description: format!("Anonymous access confirmed on share: {}", name),
                        data: format!(
                            "Host: {}, Share: {}, Type: {}, Access: Anonymous",
                            host, name, stype
                        ),
                        timestamp: Utc::now(),
                    })
                    .collect(),
                mitre_techniques: vec![
                    "T1021.002".to_string(), // Remote Services: SMB/Windows Admin Shares
                    "T1135".to_string(),     // Network Share Discovery
                ],
                remediation: Some(format!(
                    "Disable anonymous access to SMB shares on {}. \
                    Configure proper authentication and access controls. \
                    Use the principle of least privilege for share permissions. \
                    Consider disabling SMBv1 if not required.",
                    host
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

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::output_parser::ParserContext;
    use pentest_core::tools::ToolResult;
    use serde_json::json;

    #[test]
    fn test_parse_smb_enum_with_anonymous_access() {
        let parser = SmbEnumParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "host": "192.168.1.100",
                "shares": [
                    {
                        "name": "Public",
                        "type": "Disk",
                        "comment": "Public share",
                        "anonymous_access": true
                    },
                    {
                        "name": "Documents",
                        "type": "Disk",
                        "comment": "Document storage",
                        "anonymous_access": true
                    },
                    {
                        "name": "IPC$",
                        "type": "IPC",
                        "comment": "IPC Service",
                        "anonymous_access": true
                    }
                ],
                "count": 3
            }),
            error: None,
            duration_ms: 2500,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("smb_enum", &result, &context);

        // Should create 1 target + 1 finding (2 non-IPC shares with anonymous access)
        assert_eq!(messages.len(), 2);

        // Check target
        match &messages[0] {
            StructuredMessage::TargetDiscovered(target) => {
                assert!(target.name.contains("SMB Service"));
                assert_eq!(target.target_type, TargetType::Service);
                assert!(target.tags.contains(&"smb".to_string()));
                assert_eq!(target.ports.len(), 2); // 445 and 139
                assert!(target.notes.as_ref().unwrap().contains("3 SMB share"));
            }
            _ => panic!("Expected TargetDiscovered message"),
        }

        // Check finding
        match &messages[1] {
            StructuredMessage::FindingReported(finding) => {
                assert!(finding.title.contains("Anonymous Access"));
                assert_eq!(finding.severity, Severity::High);
                assert!(finding.description.contains("2 share(s)"));
                assert!(finding.description.contains("Public"));
                assert!(finding.description.contains("Documents"));
                assert!(!finding.description.contains("IPC$")); // Should exclude IPC shares
                assert_eq!(finding.evidence.len(), 2);
                assert!(finding.mitre_techniques.contains(&"T1021.002".to_string()));
                assert!(finding.mitre_techniques.contains(&"T1135".to_string()));
            }
            _ => panic!("Expected FindingReported message"),
        }
    }

    #[test]
    fn test_parse_smb_enum_no_anonymous_access() {
        let parser = SmbEnumParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "host": "192.168.1.200",
                "shares": [
                    {
                        "name": "Private",
                        "type": "Disk",
                        "comment": "Private share",
                        "anonymous_access": false
                    },
                    {
                        "name": "C$",
                        "type": "Disk",
                        "comment": "Default share",
                        "anonymous_access": false
                    }
                ],
                "count": 2
            }),
            error: None,
            duration_ms: 2000,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("smb_enum", &result, &context);

        // Should only create target, no finding (no anonymous access)
        assert_eq!(messages.len(), 1);

        match &messages[0] {
            StructuredMessage::TargetDiscovered(_) => {}
            _ => panic!("Expected TargetDiscovered message"),
        }
    }

    #[test]
    fn test_parse_smb_enum_admin_shares() {
        let parser = SmbEnumParser;
        let result = ToolResult {
            success: true,
            data: json!({
                "host": "192.168.1.50",
                "shares": [
                    {
                        "name": "C$",
                        "type": "Disk",
                        "comment": "Default share",
                        "anonymous_access": true
                    },
                    {
                        "name": "ADMIN$",
                        "type": "Disk",
                        "comment": "Remote Admin",
                        "anonymous_access": true
                    }
                ],
                "count": 2
            }),
            error: None,
            duration_ms: 1800,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("smb_enum", &result, &context);

        // Should only create target, no finding (admin shares are excluded)
        assert_eq!(messages.len(), 1);
    }

    #[test]
    fn test_parse_failed_smb_enum() {
        let parser = SmbEnumParser;
        let result = ToolResult {
            success: false,
            data: json!({}),
            error: Some("Connection refused".to_string()),
            duration_ms: 100,
        };

        let context =
            ParserContext::new("test-engagement".to_string(), "test-connector".to_string());

        let messages = parser.parse("smb_enum", &result, &context);
        assert_eq!(messages.len(), 0);
    }
}
