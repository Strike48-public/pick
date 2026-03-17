//! Web Application Toolchain
//!
//! Automated web application security assessment

use super::engine::ToolchainEngine;
use super::playbook::PlaybookManager;
use super::session::{AttackProfile, ExecutionMode, PentestSession};
use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::*;
use serde_json::{json, Value};
use std::sync::Arc;

/// Web Application Automated Toolchain
pub struct WebAppToolchain;

impl WebAppToolchain {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl PentestTool for WebAppToolchain {
    fn name(&self) -> &str {
        "autopwn_webapp"
    }

    fn description(&self) -> &str {
        "Automated web application security assessment using intelligent toolchain execution"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .param(ToolParam::required(
                "target",
                ParamType::String,
                "Target URL (e.g., http://10.10.2.169)",
            ))
            .param(ToolParam::optional(
                "execution_mode",
                ParamType::String,
                "Execution mode: manual (user approves each step), guided (AI assists), autonomous (fully automated)",
                json!("guided"),
            ))
            .param(ToolParam::optional(
                "attack_profile",
                ParamType::String,
                "Attack profile: silent (stealthy), normal (balanced), aggressive (fast/noisy)",
                json!("normal"),
            ))
            .param(ToolParam::optional(
                "session_id",
                ParamType::String,
                "Session ID for tracking (auto-generated if not provided)",
                json!(""),
            ))
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop]
    }

    async fn execute(&self, params: Value, ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed(|| async {
            // Parse parameters
            let target = params["target"]
                .as_str()
                .ok_or_else(|| {
                    pentest_core::error::Error::InvalidParams("target is required".into())
                })?
                .to_string();

            let execution_mode = params["execution_mode"].as_str().unwrap_or("guided");

            let attack_profile = params["attack_profile"].as_str().unwrap_or("normal");

            let session_id = params["session_id"]
                .as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "webapp")
                .to_string();

            // Parse execution mode
            let mode = match execution_mode {
                "manual" => ExecutionMode::Manual,
                "guided" => ExecutionMode::Guided,
                "autonomous" => ExecutionMode::Autonomous,
                _ => ExecutionMode::Guided,
            };

            // Parse attack profile
            let profile = match attack_profile {
                "silent" => AttackProfile::Silent,
                "normal" => AttackProfile::Normal,
                "aggressive" => AttackProfile::Aggressive,
                _ => AttackProfile::Normal,
            };

            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("🎯 AutoPwn Web Application Assessment");
            tracing::info!("═══════════════════════════════════════════════════");
            tracing::info!("  Target:         {}", target);
            tracing::info!("  Execution Mode: {:?}", mode);
            tracing::info!("  Attack Profile: {:?}", profile);
            tracing::info!("  Session ID:     {}", session_id);
            tracing::info!("═══════════════════════════════════════════════════");

            // Create session
            let session = PentestSession::new(session_id, vec![target.clone()], mode, profile);

            // Load web app playbook
            let playbook = PlaybookManager::builtin_webapp();

            tracing::info!("");
            tracing::info!("📋 Playbook: {}", playbook.name);
            tracing::info!("   {}", playbook.description);
            tracing::info!("   Phases: {}", playbook.phases.len());

            // Display phase overview
            for (i, phase) in playbook.phases.iter().enumerate() {
                tracing::info!("   {}. {} ({} steps)", i + 1, phase.name, phase.steps.len());
            }

            // Create a fresh registry with all tools for the engine
            let registry = Arc::new(crate::create_tool_registry());

            tracing::info!("");
            tracing::info!("🔧 Registry contains {} tools", registry.names().len());
            eprintln!("\n🔧 Registry contains {} tools", registry.names().len());

            // Create engine
            let engine = ToolchainEngine::new(session, registry, ctx.clone());

            tracing::info!("🚀 Executing playbook...");
            eprintln!(
                "🚀 Executing playbook with {} phases...",
                playbook.phases.len()
            );

            // Execute playbook
            let report = engine.execute_playbook(&playbook, &target).await?;

            tracing::info!("📝 Report generated");
            eprintln!(
                "📝 Report generated: {} tools executed\n",
                report
                    .get("tools_executed")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0)
            );

            // Display summary
            if let Some(findings) = report.get("findings") {
                tracing::info!("");
                tracing::info!("🔍 Findings Summary:");
                if let Some(total) = findings.get("total") {
                    tracing::info!("   Total findings: {}", total);
                }
                if let Some(by_severity) = findings.get("by_severity").and_then(|v| v.as_object()) {
                    for (severity, count) in by_severity {
                        tracing::info!("   {}: {}", severity, count);
                    }
                }
            }

            if let Some(progress) = report.get("progress") {
                if let Some(elapsed) = progress.get("elapsed_time_sec") {
                    tracing::info!("");
                    tracing::info!("⏱ Execution time: {} seconds", elapsed);
                }
            }

            Ok(json!({
                "success": true,
                "playbook": playbook.name,
                "target": target,
                "execution_mode": format!("{:?}", mode),
                "attack_profile": format!("{:?}", profile),
                "report": report,
            }))
        })
        .await
    }
}
