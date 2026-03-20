//! Pentest session state management

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Execution mode for the toolchain
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionMode {
    /// User approves each tool execution
    Manual,
    /// AI recommends and semi-executes with oversight
    Guided,
    /// AI executes full toolchains, user approves critical events
    Autonomous,
}

/// Attack profile determining noise level and speed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AttackProfile {
    /// Stealthy, slow, avoid detection
    Silent,
    /// Balanced approach
    Normal,
    /// Fast, comprehensive, noisy
    Aggressive,
}

impl AttackProfile {
    /// Get rate limit in requests per second for this profile
    pub fn rate_limit(&self) -> u32 {
        match self {
            AttackProfile::Silent => 10,
            AttackProfile::Normal => 50,
            AttackProfile::Aggressive => 200,
        }
    }

    /// Get concurrent thread count for this profile
    pub fn concurrency(&self) -> usize {
        match self {
            AttackProfile::Silent => 5,
            AttackProfile::Normal => 20,
            AttackProfile::Aggressive => 50,
        }
    }

    /// Get scan delay in milliseconds
    pub fn delay_ms(&self) -> u64 {
        match self {
            AttackProfile::Silent => 500,
            AttackProfile::Normal => 100,
            AttackProfile::Aggressive => 10,
        }
    }
}

/// Status of a tool execution
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionStatus {
    Pending,
    Running,
    Success,
    Failed,
    Skipped,
}

/// Record of a tool execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolExecution {
    pub tool_name: String,
    pub target: String,
    pub timestamp: u64,
    pub status: ExecutionStatus,
    pub result: Option<Value>,
    pub error: Option<String>,
    pub duration_ms: u64,
    pub phase: String,
}

impl ToolExecution {
    pub fn new(tool_name: String, target: String, phase: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            tool_name,
            target,
            timestamp,
            status: ExecutionStatus::Pending,
            result: None,
            error: None,
            duration_ms: 0,
            phase,
        }
    }

    pub fn start(&mut self) {
        self.status = ExecutionStatus::Running;
    }

    pub fn complete(&mut self, result: Value, duration_ms: u64) {
        self.status = ExecutionStatus::Success;
        self.result = Some(result);
        self.duration_ms = duration_ms;
    }

    pub fn fail(&mut self, error: String, duration_ms: u64) {
        self.status = ExecutionStatus::Failed;
        self.error = Some(error);
        self.duration_ms = duration_ms;
    }

    pub fn skip(&mut self, reason: String) {
        self.status = ExecutionStatus::Skipped;
        self.error = Some(reason);
    }
}

/// Finding from reconnaissance or vulnerability scanning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: String, // critical, high, medium, low, info
    pub title: String,
    pub description: String,
    pub tool: String,
    pub target: String,
    pub evidence: Value,
    pub timestamp: u64,
}

impl Finding {
    pub fn new(
        severity: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
        tool: impl Into<String>,
        target: impl Into<String>,
        evidence: Value,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            severity: severity.into(),
            title: title.into(),
            description: description.into(),
            tool: tool.into(),
            target: target.into(),
            evidence,
            timestamp,
        }
    }
}

/// Credential harvested during the pentest
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub username: String,
    pub password: Option<String>,
    pub hash: Option<String>,
    pub service: String,
    pub host: String,
    pub source_tool: String,
}

/// Compromised host information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Host {
    pub ip: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub access_method: String, // ssh, smb, rdp, shell, etc.
    pub credentials_used: Option<String>,
}

/// Failed step with recovery information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedStep {
    pub step_id: String,
    pub tool_name: String,
    pub target: String,
    pub error: String,
    pub alternatives_tried: Vec<String>,
    pub timestamp: u64,
}

/// Pentest session state
pub struct PentestSession {
    pub session_id: String,
    pub target_scope: Vec<String>,
    pub execution_mode: ExecutionMode,
    pub attack_profile: AttackProfile,

    // State tracking
    pub tools_executed: HashMap<String, ToolExecution>,
    pub findings: Vec<Finding>,
    pub credentials: Vec<Credential>,
    pub compromised_hosts: Vec<Host>,

    // Workflow tracking
    pub current_phase: String,
    pub completed_phases: Vec<String>,
    pub failed_steps: Vec<FailedStep>,

    // Progress tracking
    pub total_steps: usize,
    pub completed_steps: usize,
    pub start_time: u64,
}

impl PentestSession {
    pub fn new(
        session_id: String,
        target_scope: Vec<String>,
        execution_mode: ExecutionMode,
        attack_profile: AttackProfile,
    ) -> Self {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            session_id,
            target_scope,
            execution_mode,
            attack_profile,
            tools_executed: HashMap::new(),
            findings: Vec::new(),
            credentials: Vec::new(),
            compromised_hosts: Vec::new(),
            current_phase: String::new(),
            completed_phases: Vec::new(),
            failed_steps: Vec::new(),
            total_steps: 0,
            completed_steps: 0,
            start_time,
        }
    }

    /// Check if a tool has been executed against a target
    pub fn has_executed(&self, tool: &str, target: &str) -> bool {
        let key = format!("{}::{}", tool, target);
        self.tools_executed.contains_key(&key)
    }

    /// Get cached result from previous execution
    pub fn get_cached_result(&self, tool: &str, target: &str) -> Option<&Value> {
        let key = format!("{}::{}", tool, target);
        self.tools_executed
            .get(&key)
            .and_then(|e| e.result.as_ref())
    }

    /// Record tool execution
    pub fn record_execution(&mut self, execution: ToolExecution) {
        let key = format!("{}::{}", execution.tool_name, execution.target);
        let status = execution.status.clone();
        self.tools_executed.insert(key, execution);

        if status == ExecutionStatus::Success
            || status == ExecutionStatus::Failed
            || status == ExecutionStatus::Skipped
        {
            self.completed_steps += 1;
        }
    }

    /// Add a finding
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Add a credential
    pub fn add_credential(&mut self, credential: Credential) {
        self.credentials.push(credential);
    }

    /// Add a compromised host
    pub fn add_compromised_host(&mut self, host: Host) {
        self.compromised_hosts.push(host);
    }

    /// Record a failed step
    pub fn record_failure(&mut self, failed_step: FailedStep) {
        self.failed_steps.push(failed_step);
    }

    /// Get progress percentage
    pub fn progress(&self) -> f32 {
        if self.total_steps == 0 {
            0.0
        } else {
            (self.completed_steps as f32 / self.total_steps as f32) * 100.0
        }
    }

    /// Get elapsed time in seconds
    pub fn elapsed_time(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now - self.start_time
    }

    /// Generate summary report
    pub fn summary(&self) -> Value {
        serde_json::json!({
            "session_id": self.session_id,
            "target_scope": self.target_scope,
            "execution_mode": self.execution_mode,
            "attack_profile": self.attack_profile,
            "progress": {
                "completed_steps": self.completed_steps,
                "total_steps": self.total_steps,
                "percentage": self.progress(),
                "elapsed_time_sec": self.elapsed_time(),
            },
            "findings": {
                "total": self.findings.len(),
                "by_severity": self.findings_by_severity(),
            },
            "credentials_found": self.credentials.len(),
            "hosts_compromised": self.compromised_hosts.len(),
            "tools_executed": self.tools_executed.len(),
            "failed_steps": self.failed_steps.len(),
        })
    }

    fn findings_by_severity(&self) -> HashMap<String, usize> {
        let mut by_severity = HashMap::new();
        for finding in &self.findings {
            *by_severity.entry(finding.severity.clone()).or_insert(0) += 1;
        }
        by_severity
    }
}
