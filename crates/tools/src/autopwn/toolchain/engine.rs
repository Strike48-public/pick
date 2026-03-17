//! Toolchain execution engine

use super::playbook::{Phase, Playbook, RiskLevel, Step, StepCondition};
use super::session::{ExecutionMode, FailedStep, Finding, PentestSession, ToolExecution};
use crate::external::install::ensure_tool_installed;
use pentest_core::error::{Error, Result};
use pentest_core::tools::{ToolContext, ToolRegistry};
use pentest_platform;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

/// Toolchain execution engine
pub struct ToolchainEngine {
    session: Arc<Mutex<PentestSession>>,
    registry: Arc<ToolRegistry>,
    context: ToolContext,
}

impl ToolchainEngine {
    /// Create a new toolchain engine
    pub fn new(session: PentestSession, registry: Arc<ToolRegistry>, context: ToolContext) -> Self {
        Self {
            session: Arc::new(Mutex::new(session)),
            registry,
            context,
        }
    }

    /// Execute a complete playbook
    pub async fn execute_playbook(&self, playbook: &Playbook, target: &str) -> Result<Value> {
        tracing::info!("═══════════════════════════════════════════════════");
        tracing::info!("🚀 Starting Toolchain Execution");
        tracing::info!("═══════════════════════════════════════════════════");
        tracing::info!("  Playbook:  {}", playbook.name);
        tracing::info!("  Target:    {}", target);
        tracing::info!("  Phases:    {}", playbook.phases.len());
        tracing::info!("  Steps:     {}", playbook.total_steps());

        // Update session with total steps
        {
            let mut session = self.session.lock().await;
            session.total_steps = playbook.total_steps();
            tracing::info!("  Mode:      {:?}", session.execution_mode);
            tracing::info!("  Profile:   {:?}", session.attack_profile);
        }

        tracing::info!("───────────────────────────────────────────────────");

        // Pre-install all required tools
        self.preinstall_tools(playbook).await?;

        // Execute each phase
        for phase in &playbook.phases {
            self.execute_phase(phase, target).await?;
        }

        // Generate final report
        let report = self.generate_report().await;

        tracing::info!("═══════════════════════════════════════════════════");
        tracing::info!("✅ Toolchain Execution Complete");
        tracing::info!("═══════════════════════════════════════════════════");

        Ok(report)
    }

    /// Pre-install all tools needed by the playbook
    async fn preinstall_tools(&self, playbook: &Playbook) -> Result<()> {
        tracing::info!("");
        tracing::info!("📦 Pre-installing required tools...");

        let mut tools_to_install = Vec::new();

        // Collect all unique tool names from playbook
        for phase in &playbook.phases {
            for step in &phase.steps {
                if !tools_to_install.contains(&step.tool) {
                    tools_to_install.push(step.tool.clone());
                }
                // Also collect alternatives
                for alt in &step.alternatives {
                    if !tools_to_install.contains(alt) {
                        tools_to_install.push(alt.clone());
                    }
                }
            }
        }

        tracing::info!("  Tools to check: {}", tools_to_install.len());

        // Get platform for tool installation
        let platform = pentest_platform::get_platform();

        // Check and install each tool
        for tool_name in &tools_to_install {
            // Get tool schema to find external dependencies
            if let Some(tool) = self.registry.get(tool_name) {
                let schema = tool.schema();
                if schema.has_external_dependencies() {
                    for dep in &schema.external_dependencies {
                        if let Err(e) =
                            ensure_tool_installed(&platform, &dep.binary_name, &dep.package_name)
                                .await
                        {
                            tracing::warn!("    ⚠ Failed to install {}: {}", dep.binary_name, e);
                        } else {
                            tracing::debug!("    ✓ {} is available", dep.binary_name);
                        }
                    }
                }
            }
        }

        tracing::info!("  ✓ Tool installation check complete");
        tracing::info!("");

        Ok(())
    }

    /// Execute a single phase
    async fn execute_phase(&self, phase: &Phase, target: &str) -> Result<()> {
        let mut session = self.session.lock().await;
        session.current_phase = phase.name.clone();
        drop(session);

        tracing::info!("📍 Phase: {}", phase.name);
        tracing::info!("   {}", phase.description);
        tracing::info!("");

        if phase.parallel {
            // Execute steps in parallel
            let mut handles = Vec::new();

            for step in &phase.steps {
                let step = step.clone();
                let target = target.to_string();
                let engine = Self {
                    session: Arc::clone(&self.session),
                    registry: Arc::clone(&self.registry),
                    context: self.context.clone(),
                };

                let handle = tokio::spawn(async move { engine.execute_step(&step, &target).await });

                handles.push(handle);
            }

            // Wait for all parallel steps to complete
            for handle in handles {
                if let Err(e) = handle.await {
                    tracing::error!("    ✗ Parallel step failed: {}", e);
                }
            }
        } else {
            // Execute steps sequentially
            for step in &phase.steps {
                self.execute_step(step, target).await?;
            }
        }

        let mut session = self.session.lock().await;
        session.completed_phases.push(phase.name.clone());

        tracing::info!("");

        Ok(())
    }

    /// Execute a single step
    async fn execute_step(&self, step: &Step, target: &str) -> Result<()> {
        eprintln!("  [execute_step] Tool: {}, Target: {}", step.tool, target);

        // Check condition
        if !self.should_execute_step(step).await {
            tracing::info!("    ⊘ Skipping {}: condition not met", step.tool);
            eprintln!("    ⊘ Skipped: condition not met");
            let mut execution = ToolExecution::new(
                step.tool.clone(),
                target.to_string(),
                self.session.lock().await.current_phase.clone(),
            );
            execution.skip("Condition not met".to_string());
            self.session.lock().await.record_execution(execution);
            return Ok(());
        }

        // Check if already executed (deduplication)
        {
            let session = self.session.lock().await;
            if session.has_executed(&step.tool, target) {
                tracing::info!("    ⊘ Skipping {}: already executed", step.tool);
                return Ok(());
            }
        }

        // Check for approval if needed
        if self.requires_approval(step).await {
            tracing::warn!("    ⏸ Step requires user approval: {}", step.tool);
            tracing::warn!("      Risk: {:?}", step.risk_level);
            tracing::warn!("      Description: {}", step.description);
            // In a real implementation, this would wait for user input
            // For now, we'll skip high-risk steps in autonomous mode
            let session = self.session.lock().await;
            if matches!(session.execution_mode, ExecutionMode::Autonomous)
                && matches!(step.risk_level, RiskLevel::High | RiskLevel::Critical)
            {
                tracing::warn!("    ⊘ Skipping high-risk step in autonomous mode");
                let mut execution = ToolExecution::new(
                    step.tool.clone(),
                    target.to_string(),
                    session.current_phase.clone(),
                );
                execution.skip("High-risk step skipped in autonomous mode".to_string());
                drop(session);
                self.session.lock().await.record_execution(execution);
                return Ok(());
            }
        }

        tracing::info!("    ▶ Executing: {}", step.tool);
        eprintln!("    ▶ Executing: {}", step.tool);

        // Create execution record
        let phase = self.session.lock().await.current_phase.clone();
        let mut execution = ToolExecution::new(step.tool.clone(), target.to_string(), phase);
        execution.start();

        // Resolve parameters (replace ${target} etc.)
        let params = self.resolve_params(&step.params, target).await;

        // Execute the tool
        let start = Instant::now();

        match self.registry.get(&step.tool) {
            Some(tool) => {
                match tool.execute(params, &self.context).await {
                    Ok(result) => {
                        let duration_ms = start.elapsed().as_millis() as u64;
                        execution.complete(result.data.clone(), duration_ms);

                        tracing::info!("      ✓ {} completed in {}ms", step.tool, duration_ms);
                        eprintln!("      ✓ {} completed in {}ms", step.tool, duration_ms);
                        eprintln!(
                            "         Result: {}",
                            serde_json::to_string(&result.data)
                                .unwrap_or_default()
                                .chars()
                                .take(200)
                                .collect::<String>()
                        );

                        // Extract findings if available
                        self.extract_findings(&step.tool, target, &result.data)
                            .await;

                        self.session.lock().await.record_execution(execution);
                        Ok(())
                    }
                    Err(e) => {
                        let duration_ms = start.elapsed().as_millis() as u64;
                        let error_msg = format!("{}", e);
                        execution.fail(error_msg.clone(), duration_ms);

                        tracing::error!("      ✗ {} failed: {}", step.tool, error_msg);
                        eprintln!("      ✗ {} failed: {}", step.tool, error_msg);

                        self.session.lock().await.record_execution(execution);

                        // Try alternatives if available
                        if !step.alternatives.is_empty() {
                            tracing::info!("      ↻ Trying alternatives...");
                            for alt in &step.alternatives {
                                tracing::info!("        Trying: {}", alt);
                                // Create alternative step
                                let alt_step = Step {
                                    tool: alt.clone(),
                                    alternatives: vec![], // Don't recurse alternatives
                                    ..step.clone()
                                };
                                // Box the recursive call to avoid infinite size
                                if Box::pin(self.execute_step(&alt_step, target)).await.is_ok() {
                                    return Ok(());
                                }
                            }
                        }

                        // Record failure
                        let failed_step = FailedStep {
                            step_id: step.id.clone(),
                            tool_name: step.tool.clone(),
                            target: target.to_string(),
                            error: error_msg,
                            alternatives_tried: step.alternatives.clone(),
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap()
                                .as_secs(),
                        };
                        self.session.lock().await.record_failure(failed_step);

                        if step.required {
                            return Err(Error::InvalidParams(format!(
                                "Required step {} failed",
                                step.tool
                            )));
                        }

                        Ok(())
                    }
                }
            }
            None => {
                let error_msg = format!("Tool not found: {}", step.tool);
                execution.fail(error_msg.clone(), 0);
                self.session.lock().await.record_execution(execution);
                Err(Error::ToolNotFound(step.tool.clone()))
            }
        }
    }

    /// Check if a step should be executed based on its condition
    async fn should_execute_step(&self, step: &Step) -> bool {
        match &step.condition {
            StepCondition::Always => true,
            StepCondition::Expression(expr) => {
                // Simple expression evaluation
                // For now, just check if it's "true"
                // In a full implementation, this would evaluate against session state
                expr == "true"
            }
        }
    }

    /// Check if step requires user approval
    async fn requires_approval(&self, step: &Step) -> bool {
        let session = self.session.lock().await;

        // Manual mode requires approval for everything
        if matches!(session.execution_mode, ExecutionMode::Manual) {
            return true;
        }

        // Guided mode requires approval for high-risk steps
        if matches!(session.execution_mode, ExecutionMode::Guided)
            && matches!(step.risk_level, RiskLevel::High | RiskLevel::Critical)
        {
            return true;
        }

        // Check if step explicitly requires approval
        step.require_approval
    }

    /// Resolve parameter values (replace variables)
    async fn resolve_params(&self, params: &HashMap<String, Value>, target: &str) -> Value {
        let mut resolved = serde_json::Map::new();

        for (key, value) in params {
            let resolved_value = match value {
                Value::String(s) => {
                    let replaced = s.replace("${target}", target);
                    Value::String(replaced)
                }
                other => other.clone(),
            };
            resolved.insert(key.clone(), resolved_value);
        }

        Value::Object(resolved)
    }

    /// Extract findings from tool result
    async fn extract_findings(&self, tool: &str, target: &str, result: &Value) {
        // Simple finding extraction - in a full implementation, this would be tool-specific
        if let Some(vulnerabilities) = result.get("vulnerabilities").and_then(|v| v.as_array()) {
            for vuln in vulnerabilities {
                if let (Some(severity), Some(title)) = (
                    vuln.get("severity").and_then(|s| s.as_str()),
                    vuln.get("title").and_then(|t| t.as_str()),
                ) {
                    let finding = Finding::new(
                        severity,
                        title,
                        vuln.get("description")
                            .and_then(|d| d.as_str())
                            .unwrap_or(""),
                        tool,
                        target,
                        vuln.clone(),
                    );
                    self.session.lock().await.add_finding(finding);
                }
            }
        }
    }

    /// Generate final report
    async fn generate_report(&self) -> Value {
        let session = self.session.lock().await;
        session.summary()
    }

    /// Get current progress
    pub async fn get_progress(&self) -> Value {
        let session = self.session.lock().await;
        serde_json::json!({
            "current_phase": session.current_phase,
            "completed_steps": session.completed_steps,
            "total_steps": session.total_steps,
            "progress_percentage": session.progress(),
            "elapsed_time_sec": session.elapsed_time(),
        })
    }
}
