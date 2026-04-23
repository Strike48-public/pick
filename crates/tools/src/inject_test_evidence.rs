//! Test tool to manually inject evidence nodes for testing the three-agent pipeline.
//!
//! This tool allows manual testing of the Validator → Report pipeline
//! by creating sample evidence nodes with various severities and types.

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::evidence::{EvidenceNode, ValidationStatus};
use pentest_core::export::Severity;
use pentest_core::provenance::{ProbeCommand, Provenance};
use pentest_core::tools::{
    execute_timed, ParamType, PentestTool, Platform, ToolContext, ToolParam, ToolResult,
    ToolSchema,
};
use serde_json::{json, Value};
use uuid::Uuid;

pub struct InjectTestEvidenceTool;

#[async_trait]
impl PentestTool for InjectTestEvidenceTool {
    fn name(&self) -> &str {
        "inject_test_evidence"
    }

    fn description(&self) -> &str {
        "Inject test evidence nodes for testing the three-agent pipeline"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::optional(
                "count",
                ParamType::Integer,
                "Number of test evidence nodes to create (default: 3)",
                json!(3),
            ))
            .param(ToolParam::optional(
                "severity",
                ParamType::String,
                "Severity: 'critical', 'high', 'medium', 'low', 'info', or 'mixed' (default)",
                json!("mixed"),
            ))
            .param(ToolParam::optional(
                "target",
                ParamType::String,
                "Target IP or hostname for evidence (default: 192.168.1.100)",
                json!("192.168.1.100"),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![
            Platform::Desktop,
            Platform::Tui,
            Platform::Web,
            Platform::Android,
            Platform::Ios,
        ]
    }

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async move {
            let count = params["count"].as_u64().unwrap_or(3) as usize;
            let severity_type = params["severity"].as_str().unwrap_or("mixed");
            let target = params["target"].as_str().unwrap_or("192.168.1.100");

            let mut created = Vec::new();

            for i in 0..count {
                let severity = if severity_type == "mixed" {
                    match i % 5 {
                        0 => Severity::Critical,
                        1 => Severity::High,
                        2 => Severity::Medium,
                        3 => Severity::Low,
                        _ => Severity::Info,
                    }
                } else {
                    match severity_type {
                        "critical" => Severity::Critical,
                        "high" => Severity::High,
                        "medium" => Severity::Medium,
                        "low" => Severity::Low,
                        "info" => Severity::Info,
                        _ => Severity::Medium,
                    }
                };

                let (node_type, title, description, port) = match i % 4 {
                    0 => (
                        "open_port",
                        format!("Port 22/tcp open on {}", target),
                        "SSH service detected with version information".to_string(),
                        Some(22),
                    ),
                    1 => (
                        "service_banner",
                        format!("Service banner on {}:80", target),
                        "HTTP server banner reveals Apache/2.4.52".to_string(),
                        Some(80),
                    ),
                    2 => (
                        "web_tech",
                        format!("Web technologies identified on http://{}", target),
                        "WordPress 6.0, PHP 8.1, MySQL detected".to_string(),
                        None,
                    ),
                    _ => (
                        "default_cred",
                        format!("Default credentials on {}", target),
                        "Admin panel accessible with default credentials admin:admin".to_string(),
                        Some(443),
                    ),
                };

                // Create provenance
                let command = match node_type {
                    "open_port" => "nmap -sV -p22 192.168.1.100",
                    "service_banner" => "nc 192.168.1.100 80",
                    "web_tech" => "whatweb http://192.168.1.100",
                    "default_cred" => "hydra -l admin -p admin https://192.168.1.100",
                    _ => "test_tool",
                };

                let provenance = Provenance::new(
                    "test_tool",
                    "1.0.0".to_string(),
                    ProbeCommand::from_exact(command).with_description("Test evidence generation"),
                    format!("Test output for {} finding", node_type),
                );

                let severity_name = match severity {
                    Severity::Critical => "Critical",
                    Severity::High => "High",
                    Severity::Medium => "Medium",
                    Severity::Low => "Low",
                    Severity::Info => "Info",
                };

                let mut node = EvidenceNode::new(
                    Uuid::new_v4().to_string(),
                    node_type,
                    title.clone(),
                    description.clone(),
                    target,
                    severity,
                    format!("Test evidence for demonstrating {}-severity {}", severity_name, node_type),
                )
                .with_provenance(provenance);

                // Add metadata
                if let Some(port_num) = port {
                    node.metadata.insert("port".to_string(), port_num.into());
                }
                node.metadata
                    .insert("test_evidence".to_string(), true.into());

                // Push to evidence graph
                crate::evidence_producer::push_evidence(node.clone());

                let severity_str = match severity {
                    Severity::Critical => "Critical",
                    Severity::High => "High",
                    Severity::Medium => "Medium",
                    Severity::Low => "Low",
                    Severity::Info => "Info",
                };

                created.push(json!({
                    "id": node.id,
                    "type": node.node_type,
                    "title": node.title,
                    "severity": severity_str,
                }));
            }

            Ok(json!({
                "success": true,
                "evidence_created": count,
                "nodes": created,
                "message": format!("Created {} test evidence nodes. Use Validator Agent to adjudicate, then Generate Report.", count)
            }))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_inject_evidence() {
        let tool = InjectTestEvidenceTool;
        let params = json!({
            "count": 2,
            "severity": "high",
            "target": "10.0.0.1"
        });

        let result = tool
            .execute(params, &ToolContext::default())
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.data["evidence_created"], 2);
    }
}
