# Webwright Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate Microsoft's Webwright as a sandboxed browser automation tool in Pick, enabling AI-driven web application testing with full evidence capture routed through Strike48 conversations.

**Architecture:** Webwright runs as an external tool in proot/bwrap sandbox. LLM calls route through a local OpenAI-compatible proxy that translates to Strike48 conversation messages via the connector SDK. Two modes: autonomous exploration and scripted replay. All artifacts (scripts, screenshots, logs) become EvidenceNodes.

**Tech Stack:** Rust (Pick), Python 3.10+ (Webwright), Playwright/Chromium, axum (proxy route), Strike48 Connector SDK (gRPC), serde_json

---

## File Structure

| File | Responsibility |
|------|---------------|
| `crates/tools/src/webwright/mod.rs` | WebwrightTool struct, PentestTool impl, mode dispatch |
| `crates/tools/src/webwright/workspace.rs` | Workspace creation, config YAML generation, artifact sweep |
| `crates/tools/src/webwright/evidence.rs` | Map Webwright artifacts to EvidenceNodes |
| `crates/tools/src/webwright/config.rs` | Webwright YAML config types and serialization |
| `crates/ui/src/liveview_connector/llm_proxy.rs` | OpenAI-compatible /v1/chat/completions route |
| `crates/tools/src/lib.rs` | Registration (modify) |
| `crates/tools/src/external/web/mod.rs` | Re-export (modify) |

---

### Task 1: WebwrightTool Scaffold and Schema

**Files:**
- Create: `crates/tools/src/webwright/mod.rs`
- Create: `crates/tools/src/webwright/config.rs`
- Modify: `crates/tools/src/lib.rs`

- [ ] **Step 1: Create the webwright module directory**

```bash
mkdir -p crates/tools/src/webwright
```

- [ ] **Step 2: Write the config types**

Create `crates/tools/src/webwright/config.rs`:

```rust
//! Webwright YAML configuration generation.

use serde::Serialize;

/// Webwright model configuration (OpenAI-compatible endpoint).
#[derive(Debug, Clone, Serialize)]
pub struct WebwrightModelConfig {
    pub provider: String,
    pub base_url: String,
    pub api_key: String,
    pub model: String,
}

/// Top-level Webwright config written to workspace as YAML.
#[derive(Debug, Clone, Serialize)]
pub struct WebwrightConfig {
    pub model: WebwrightModelConfig,
}

impl WebwrightConfig {
    /// Create config pointing at Pick's local LLM proxy.
    pub fn new(proxy_port: u16, model_name: &str) -> Self {
        Self {
            model: WebwrightModelConfig {
                provider: "openai".to_string(),
                base_url: format!("http://127.0.0.1:{}/v1", proxy_port),
                api_key: "pick-internal".to_string(),
                model: model_name.to_string(),
            },
        }
    }

    /// Serialize to YAML string for writing to workspace.
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_serializes_to_yaml() {
        let config = WebwrightConfig::new(9100, "strike48-default");
        let yaml = config.to_yaml().unwrap();
        assert!(yaml.contains("provider: openai"));
        assert!(yaml.contains("base_url: http://127.0.0.1:9100/v1"));
        assert!(yaml.contains("model: strike48-default"));
    }
}
```

- [ ] **Step 3: Write the WebwrightTool struct with schema**

Create `crates/tools/src/webwright/mod.rs`:

```rust
//! Webwright browser automation tool.
//!
//! Provides AI-driven browser testing via Microsoft's Webwright framework.
//! Supports two modes:
//! - `explore`: Autonomous LLM-driven browser exploration and testing
//! - `execute`: Replay a Playwright script for validation/evidence capture

pub mod config;
pub mod evidence;
pub mod workspace;

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::tools::{
    execute_timed_with_provenance, ExternalDependency, ParamType, PentestTool, Platform,
    ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_core::provenance::{ProbeCommand, Provenance};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use crate::external::runner::{param_str_opt, param_str_or};
use crate::util::param_u64;

use self::workspace::WebwrightWorkspace;

/// Webwright browser automation tool.
pub struct WebwrightTool;

#[async_trait]
impl PentestTool for WebwrightTool {
    fn name(&self) -> &str {
        "webwright"
    }

    fn description(&self) -> &str {
        "AI-driven browser automation for testing JavaScript-heavy web apps, OAuth flows, and client-side vulnerabilities"
    }

    fn schema(&self) -> ToolSchema {
        ToolSchema::new(self.name(), self.description())
            .external_dependency(ExternalDependency::new(
                "python3",
                "python3",
                "Python 3.10+ runtime (available in sandbox)",
            ))
            .external_dependency(ExternalDependency::new(
                "playwright",
                "playwright",
                "Browser automation framework (pip install playwright)",
            ))
            .param(ToolParam::required(
                "mode",
                ParamType::String,
                "Execution mode: 'explore' (autonomous AI-driven) or 'execute' (replay script)",
            ))
            .param(ToolParam::required(
                "start_url",
                ParamType::String,
                "Target URL to start browsing from (e.g., 'https://target.com')",
            ))
            .param(ToolParam::optional(
                "task",
                ParamType::String,
                "Natural language objective for explore mode (e.g., 'test all forms for XSS')",
                json!(""),
            ))
            .param(ToolParam::optional(
                "script",
                ParamType::String,
                "Python/Playwright script content for execute mode",
                json!(""),
            ))
            .param(ToolParam::optional(
                "max_steps",
                ParamType::Integer,
                "Maximum agent loop iterations for explore mode (default: 50)",
                json!(50),
            ))
            .param(ToolParam::optional(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds (default: 600)",
                json!(600),
            ))
            .platforms(vec![Platform::Desktop, Platform::Android, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Android, Platform::Tui]
    }

    async fn execute(&self, params: Value, ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed_with_provenance(|| async move {
            let platform = get_platform();

            let mode = param_str_or(&params, "mode", "explore");
            let start_url = param_str_or(&params, "start_url", "");
            let task = param_str_opt(&params, "task");
            let script = param_str_opt(&params, "script");
            let max_steps = param_u64(&params, "max_steps", 50);
            let timeout_secs = param_u64(&params, "timeout", 600);

            if start_url.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "start_url parameter is required".into(),
                ));
            }

            // Create workspace
            let workspace = WebwrightWorkspace::create(&platform).await?;

            // Build command based on mode
            let (args, probe_desc) = match mode.as_str() {
                "explore" => {
                    let task_str = task.unwrap_or_default();
                    if task_str.is_empty() {
                        return Err(pentest_core::error::Error::InvalidParams(
                            "task parameter is required for explore mode".into(),
                        ));
                    }
                    workspace.write_config(9100, "strike48-default").await?;
                    let args = vec![
                        "-m".to_string(),
                        "webwright.run.cli".to_string(),
                        "-c".to_string(),
                        workspace.config_path(),
                        "-t".to_string(),
                        task_str.clone(),
                        "--start-url".to_string(),
                        start_url.clone(),
                        "--workspace".to_string(),
                        workspace.path(),
                    ];
                    let desc = format!(
                        "webwright explore --start-url {} --task \"{}\"",
                        start_url, task_str
                    );
                    (args, desc)
                }
                "execute" => {
                    let script_content = script.unwrap_or_default();
                    if script_content.is_empty() {
                        return Err(pentest_core::error::Error::InvalidParams(
                            "script parameter is required for execute mode".into(),
                        ));
                    }
                    workspace.write_script(&script_content).await?;
                    let args = vec![
                        workspace.script_path(),
                    ];
                    let desc = format!("webwright execute script on {}", start_url);
                    (args, desc)
                }
                _ => {
                    return Err(pentest_core::error::Error::InvalidParams(
                        "mode must be 'explore' or 'execute'".into(),
                    ));
                }
            };

            let args_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

            // Execute in sandbox
            let result = platform
                .execute_command("python3", &args_refs, Duration::from_secs(timeout_secs))
                .await?;

            // Collect artifacts from workspace
            let artifacts = workspace.collect_artifacts(&platform).await?;

            // Build provenance
            let provenance = Provenance::new(
                "webwright",
                "0.1.0",
                ProbeCommand::from_exact(&probe_desc),
                &result.stdout,
            );

            // Build result data
            let data = json!({
                "mode": mode,
                "start_url": start_url,
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "artifacts": artifacts,
            });

            Ok((data, provenance))
        })
        .await
    }
}
```

- [ ] **Step 4: Add webwright module to lib.rs**

In `crates/tools/src/lib.rs`, add:

```rust
pub mod webwright;
pub use webwright::WebwrightTool;
```

And in `create_tool_registry()`, add at the end of the "Web application testing" section:

```rust
    // Browser automation (AI-driven)
    registry.register(webwright::WebwrightTool);
```

- [ ] **Step 5: Run cargo check**

```bash
cargo check -p pentest-tools --all-targets
```

Expected: Compilation errors for missing `workspace` and `evidence` modules (not yet created). The struct and schema themselves should be valid.

- [ ] **Step 6: Commit scaffold**

```bash
git add crates/tools/src/webwright/
git commit -m "feat: scaffold WebwrightTool struct and schema"
```

---

### Task 2: Workspace Management

**Files:**
- Create: `crates/tools/src/webwright/workspace.rs`

- [ ] **Step 1: Write workspace module**

Create `crates/tools/src/webwright/workspace.rs`:

```rust
//! Webwright workspace management.
//!
//! Handles creation of temp directories, config YAML writing,
//! script file writing, and post-execution artifact collection.

use pentest_core::error::{Error, Result};
use pentest_platform::CommandExec;
use serde_json::Value;
use uuid::Uuid;

use super::config::WebwrightConfig;

/// Manages a Webwright execution workspace.
pub struct WebwrightWorkspace {
    /// Unique task ID for this execution.
    pub task_id: String,
    /// Base directory path inside the sandbox.
    base_dir: String,
}

impl WebwrightWorkspace {
    /// Create a new workspace directory in the sandbox.
    pub async fn create(platform: &impl CommandExec) -> Result<Self> {
        let task_id = Uuid::new_v4().to_string();
        let base_dir = format!("/tmp/webwright/{}", task_id);

        let result = platform
            .execute_command(
                "mkdir",
                &["-p", &base_dir],
                std::time::Duration::from_secs(5),
            )
            .await?;

        if result.exit_code != 0 {
            return Err(Error::ToolExecution(format!(
                "Failed to create workspace: {}",
                result.stderr
            )));
        }

        Ok(Self { task_id, base_dir })
    }

    /// Write Webwright YAML config to workspace.
    pub async fn write_config(
        &self,
        proxy_port: u16,
        model_name: &str,
    ) -> Result<()> {
        let config = WebwrightConfig::new(proxy_port, model_name);
        let yaml = config.to_yaml().map_err(|e| {
            Error::ToolExecution(format!("Failed to serialize config: {}", e))
        })?;

        // Write via echo to avoid needing file write access from Rust
        std::fs::write(
            format!("{}/config.yaml", self.base_dir),
            yaml.as_bytes(),
        )
        .map_err(|e| Error::ToolExecution(format!("Failed to write config: {}", e)))?;

        Ok(())
    }

    /// Write a Python script to workspace for execute mode.
    pub async fn write_script(&self, content: &str) -> Result<()> {
        std::fs::write(
            format!("{}/script.py", self.base_dir),
            content.as_bytes(),
        )
        .map_err(|e| Error::ToolExecution(format!("Failed to write script: {}", e)))?;

        Ok(())
    }

    /// Config file path inside the workspace.
    pub fn config_path(&self) -> String {
        format!("{}/config.yaml", self.base_dir)
    }

    /// Script file path inside the workspace.
    pub fn script_path(&self) -> String {
        format!("{}/script.py", self.base_dir)
    }

    /// Base workspace path.
    pub fn path(&self) -> String {
        self.base_dir.clone()
    }

    /// Collect all artifacts produced by Webwright in the workspace.
    ///
    /// Scans for: *.py scripts, screenshot_*.png, *.json logs,
    /// *.html DOM snapshots, console_output.log, and the agent reasoning log.
    pub async fn collect_artifacts(&self, platform: &impl CommandExec) -> Result<Value> {
        // List all files in workspace
        let result = platform
            .execute_command(
                "find",
                &[&self.base_dir, "-type", "f", "-name", "*"],
                std::time::Duration::from_secs(10),
            )
            .await?;

        let files: Vec<&str> = result
            .stdout
            .lines()
            .filter(|l| !l.is_empty())
            .collect();

        let mut scripts = Vec::new();
        let mut screenshots = Vec::new();
        let mut logs = Vec::new();
        let mut snapshots = Vec::new();
        let mut other = Vec::new();

        for file in &files {
            let filename = file.rsplit('/').next().unwrap_or(file);
            if filename.ends_with(".py") && filename != "script.py" {
                scripts.push(*file);
            } else if filename.contains("screenshot") && filename.ends_with(".png") {
                screenshots.push(*file);
            } else if filename.ends_with(".json") || filename.ends_with(".log") {
                logs.push(*file);
            } else if filename.ends_with(".html") {
                snapshots.push(*file);
            } else if filename != "config.yaml" && filename != "script.py" {
                other.push(*file);
            }
        }

        Ok(serde_json::json!({
            "workspace": self.base_dir,
            "task_id": self.task_id,
            "scripts": scripts,
            "screenshots": screenshots,
            "logs": logs,
            "dom_snapshots": snapshots,
            "other": other,
            "total_files": files.len(),
        }))
    }

    /// Clean up workspace directory.
    pub async fn cleanup(&self, platform: &impl CommandExec) -> Result<()> {
        let _ = platform
            .execute_command(
                "rm",
                &["-rf", &self.base_dir],
                std::time::Duration::from_secs(10),
            )
            .await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_paths_are_consistent() {
        let ws = WebwrightWorkspace {
            task_id: "test-123".to_string(),
            base_dir: "/tmp/webwright/test-123".to_string(),
        };
        assert_eq!(ws.config_path(), "/tmp/webwright/test-123/config.yaml");
        assert_eq!(ws.script_path(), "/tmp/webwright/test-123/script.py");
        assert_eq!(ws.path(), "/tmp/webwright/test-123");
    }
}
```

- [ ] **Step 2: Run cargo check**

```bash
cargo check -p pentest-tools --all-targets
```

Expected: Should pass (or only fail on missing `evidence` module).

- [ ] **Step 3: Commit**

```bash
git add crates/tools/src/webwright/workspace.rs
git commit -m "feat: add webwright workspace management"
```

---

### Task 3: Evidence Collection

**Files:**
- Create: `crates/tools/src/webwright/evidence.rs`

- [ ] **Step 1: Write evidence mapping module**

Create `crates/tools/src/webwright/evidence.rs`:

```rust
//! Map Webwright artifacts to EvidenceNodes.
//!
//! Sweeps the workspace after execution and creates typed evidence
//! nodes for each artifact category.

use pentest_core::evidence::EvidenceNode;
use pentest_core::export::Severity;
use pentest_core::provenance::Provenance;
use serde_json::Value;
use uuid::Uuid;

use crate::evidence_producer::push_evidence;

/// Ingest all artifacts from a Webwright run into the evidence buffer.
///
/// Maps each artifact type to the appropriate EvidenceNode type:
/// - Scripts -> Exploit/Technique
/// - Screenshots -> Observation
/// - Network logs -> Observation
/// - DOM snapshots -> Observation
/// - Findings JSON -> Finding (parsed)
pub fn ingest_webwright_evidence(
    artifacts: &Value,
    target: &str,
    task_id: &str,
    provenance: &Provenance,
) {
    // Ingest generated scripts as exploit evidence
    if let Some(scripts) = artifacts["scripts"].as_array() {
        for script_path in scripts {
            if let Some(path) = script_path.as_str() {
                let filename = path.rsplit('/').next().unwrap_or(path);
                let mut node = EvidenceNode::new(
                    Uuid::new_v4().to_string(),
                    "browser_exploit_script",
                    format!("Generated exploit script: {}", filename),
                    format!(
                        "Webwright generated a Playwright script during exploration of {}. \
                         This script can be replayed to reproduce the finding.",
                        target
                    ),
                    target,
                    Severity::Medium,
                    "AI-generated browser automation script demonstrating a vulnerability or technique.".to_string(),
                )
                .with_provenance(provenance.clone());

                node.metadata.insert("artifact_type".to_string(), "script".into());
                node.metadata.insert("file_path".to_string(), path.into());
                node.metadata.insert("task_id".to_string(), task_id.into());

                let _ = push_evidence(node);
            }
        }
    }

    // Ingest screenshots as observations
    if let Some(screenshots) = artifacts["screenshots"].as_array() {
        for screenshot_path in screenshots {
            if let Some(path) = screenshot_path.as_str() {
                let filename = path.rsplit('/').next().unwrap_or(path);
                let mut node = EvidenceNode::new(
                    Uuid::new_v4().to_string(),
                    "browser_screenshot",
                    format!("Browser screenshot: {}", filename),
                    format!(
                        "Screenshot captured during browser automation of {}.",
                        target
                    ),
                    target,
                    Severity::Info,
                    "Visual evidence of application state during testing.".to_string(),
                )
                .with_provenance(provenance.clone());

                node.metadata.insert("artifact_type".to_string(), "screenshot".into());
                node.metadata.insert("file_path".to_string(), path.into());
                node.metadata.insert("task_id".to_string(), task_id.into());

                let _ = push_evidence(node);
            }
        }
    }

    // Ingest DOM snapshots as observations
    if let Some(snapshots) = artifacts["dom_snapshots"].as_array() {
        for snapshot_path in snapshots {
            if let Some(path) = snapshot_path.as_str() {
                let filename = path.rsplit('/').next().unwrap_or(path);
                let mut node = EvidenceNode::new(
                    Uuid::new_v4().to_string(),
                    "dom_snapshot",
                    format!("DOM snapshot: {}", filename),
                    format!(
                        "DOM state captured from {} during browser testing.",
                        target
                    ),
                    target,
                    Severity::Info,
                    "DOM snapshot preserving page state at time of finding.".to_string(),
                )
                .with_provenance(provenance.clone());

                node.metadata.insert("artifact_type".to_string(), "dom_snapshot".into());
                node.metadata.insert("file_path".to_string(), path.into());
                node.metadata.insert("task_id".to_string(), task_id.into());

                let _ = push_evidence(node);
            }
        }
    }

    // Ingest logs (network, console, agent reasoning) as observations
    if let Some(logs) = artifacts["logs"].as_array() {
        for log_path in logs {
            if let Some(path) = log_path.as_str() {
                let filename = path.rsplit('/').next().unwrap_or(path);
                let log_type = if filename.contains("network") {
                    "network_log"
                } else if filename.contains("console") {
                    "console_log"
                } else if filename.contains("reasoning") || filename.contains("agent") {
                    "agent_reasoning"
                } else {
                    "execution_log"
                };

                let mut node = EvidenceNode::new(
                    Uuid::new_v4().to_string(),
                    log_type,
                    format!("Browser {} : {}", log_type.replace('_', " "), filename),
                    format!(
                        "Log captured during browser automation of {}.",
                        target
                    ),
                    target,
                    Severity::Info,
                    "Execution log providing context for browser testing session.".to_string(),
                )
                .with_provenance(provenance.clone());

                node.metadata.insert("artifact_type".to_string(), log_type.into());
                node.metadata.insert("file_path".to_string(), path.into());
                node.metadata.insert("task_id".to_string(), task_id.into());

                let _ = push_evidence(node);
            }
        }
    }
}

/// Parse a Webwright findings.json and push structured findings.
///
/// Called separately when findings.json is detected in the workspace logs.
pub fn ingest_webwright_findings(
    findings_json: &Value,
    target: &str,
    task_id: &str,
    provenance: &Provenance,
) {
    if let Some(findings) = findings_json.as_array() {
        for finding in findings {
            let title = finding["title"]
                .as_str()
                .unwrap_or("Browser finding")
                .to_string();
            let description = finding["description"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let severity_str = finding["severity"]
                .as_str()
                .unwrap_or("medium");
            let severity = match severity_str.to_lowercase().as_str() {
                "critical" => Severity::Critical,
                "high" => Severity::High,
                "medium" => Severity::Medium,
                "low" => Severity::Low,
                _ => Severity::Info,
            };

            let mut node = EvidenceNode::new(
                Uuid::new_v4().to_string(),
                "browser_finding",
                title,
                description,
                target,
                severity,
                "Vulnerability discovered through AI-driven browser automation.".to_string(),
            )
            .with_provenance(provenance.clone());

            node.metadata.insert("task_id".to_string(), task_id.into());
            if let Some(url) = finding.get("url") {
                node.metadata.insert("finding_url".to_string(), url.clone());
            }
            if let Some(vuln_type) = finding["type"].as_str() {
                node.metadata.insert("vuln_type".to_string(), vuln_type.into());
            }

            let _ = push_evidence(node);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pentest_core::provenance::ProbeCommand;
    use serde_json::json;

    fn test_provenance() -> Provenance {
        Provenance::new(
            "webwright",
            "0.1.0",
            ProbeCommand::from_exact("webwright explore --start-url https://test.com"),
            "test output",
        )
    }

    #[test]
    fn ingest_creates_evidence_for_scripts() {
        let artifacts = json!({
            "scripts": ["/tmp/webwright/test/exploit_xss.py"],
            "screenshots": [],
            "logs": [],
            "dom_snapshots": [],
        });

        // This will push to the global buffer - just verify it doesn't panic
        ingest_webwright_evidence(
            &artifacts,
            "https://target.com",
            "task-123",
            &test_provenance(),
        );
    }

    #[test]
    fn ingest_findings_parses_severity() {
        let findings = json!([
            {
                "title": "Reflected XSS in search",
                "description": "Search parameter reflects unescaped input",
                "severity": "high",
                "type": "xss",
                "url": "https://target.com/search?q=<script>"
            }
        ]);

        ingest_webwright_findings(
            &findings,
            "https://target.com",
            "task-456",
            &test_provenance(),
        );
    }
}
```

- [ ] **Step 2: Run tests**

```bash
cargo test -p pentest-tools webwright -- --nocapture
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add crates/tools/src/webwright/evidence.rs
git commit -m "feat: add webwright evidence collection and ingestion"
```

---

### Task 4: LLM Proxy Route (Conversation-Backed)

**Files:**
- Create: `crates/ui/src/liveview_connector/llm_proxy.rs`
- Modify: `crates/ui/src/liveview_connector/mod.rs` (add route)

- [ ] **Step 1: Write the OpenAI-compatible proxy route**

Create `crates/ui/src/liveview_connector/llm_proxy.rs`:

```rust
//! OpenAI-compatible LLM proxy that routes through Strike48 conversations.
//!
//! Webwright sends standard OpenAI chat completion requests to this endpoint.
//! The proxy translates them into conversation messages via the connector SDK,
//! waits for the response, and formats it back as an OpenAI response.
//!
//! All LLM interactions are tracked as conversation messages in Strike48,
//! providing full auditability and operator visibility.

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use pentest_core::matrix::MatrixChatClient;

/// Shared state for the LLM proxy.
#[derive(Clone)]
pub struct LlmProxyState {
    pub matrix_client: Arc<RwLock<Option<MatrixChatClient>>>,
    /// Conversation ID for the browser automation agent.
    /// Created on first request if not already set.
    pub conversation_id: Arc<RwLock<Option<String>>>,
    /// Agent ID for the browser automation persona.
    pub agent_id: Arc<RwLock<Option<String>>>,
}

/// OpenAI ChatCompletion request format (subset Webwright uses).
#[derive(Debug, Deserialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default)]
    pub temperature: Option<f64>,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub stream: Option<bool>,
}

/// OpenAI message format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

/// OpenAI ChatCompletion response format.
#[derive(Debug, Serialize)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub object: String,
    pub created: u64,
    pub model: String,
    pub choices: Vec<Choice>,
    pub usage: Usage,
}

#[derive(Debug, Serialize)]
pub struct Choice {
    pub index: u32,
    pub message: ChatMessage,
    pub finish_reason: String,
}

#[derive(Debug, Serialize)]
pub struct Usage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// POST /v1/chat/completions
///
/// Receives OpenAI-format request from Webwright, forwards the last user
/// message to the Strike48 conversation, and returns the agent response.
async fn chat_completions(
    State(state): State<LlmProxyState>,
    Json(request): Json<ChatCompletionRequest>,
) -> Result<Json<ChatCompletionResponse>, StatusCode> {
    // Extract the last user message
    let user_message = request
        .messages
        .iter()
        .rev()
        .find(|m| m.role == "user")
        .map(|m| m.content.clone())
        .unwrap_or_default();

    if user_message.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // Get Matrix client
    let client_guard = state.matrix_client.read().await;
    let client = match client_guard.as_ref() {
        Some(c) => c,
        None => {
            tracing::error!("LLM proxy: Matrix client not available");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    // Get or create conversation
    let conv_id = {
        let conv_guard = state.conversation_id.read().await;
        conv_guard.clone()
    };

    let conversation_id = match conv_id {
        Some(id) => id,
        None => {
            // TODO: Create conversation via connector SDK invoke_request
            // For now, return error until conversation creation is wired up
            tracing::error!("LLM proxy: No conversation ID configured");
            return Err(StatusCode::SERVICE_UNAVAILABLE);
        }
    };

    let agent_id = {
        let agent_guard = state.agent_id.read().await;
        agent_guard.clone().unwrap_or_default()
    };

    // Send message to conversation and get response
    // The full message history from Webwright's context is maintained
    // server-side in the Strike48 conversation.
    let response_text = match client
        .send_and_receive_message(&conversation_id, &agent_id, &user_message)
        .await
    {
        Ok(response) => response,
        Err(e) => {
            tracing::error!("LLM proxy: Failed to get response from Strike48: {}", e);
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    // Format as OpenAI response
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let response = ChatCompletionResponse {
        id: format!("chatcmpl-{}", uuid::Uuid::new_v4()),
        object: "chat.completion".to_string(),
        created: now,
        model: request.model,
        choices: vec![Choice {
            index: 0,
            message: ChatMessage {
                role: "assistant".to_string(),
                content: response_text,
            },
            finish_reason: "stop".to_string(),
        }],
        usage: Usage {
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
        },
    };

    Ok(Json(response))
}

/// Create the LLM proxy router.
///
/// Binds to localhost only. No auth required since it's only reachable
/// from the local sandbox.
pub fn create_llm_proxy_routes(state: LlmProxyState) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_request_deserializes() {
        let json = serde_json::json!({
            "model": "strike48-default",
            "messages": [
                {"role": "system", "content": "You are a browser agent."},
                {"role": "user", "content": "Navigate to the login page."}
            ],
            "temperature": 0.7
        });

        let request: ChatCompletionRequest = serde_json::from_value(json).unwrap();
        assert_eq!(request.model, "strike48-default");
        assert_eq!(request.messages.len(), 2);
        assert_eq!(request.messages[1].role, "user");
    }

    #[test]
    fn chat_response_serializes() {
        let response = ChatCompletionResponse {
            id: "chatcmpl-test".to_string(),
            object: "chat.completion".to_string(),
            created: 1234567890,
            model: "strike48-default".to_string(),
            choices: vec![Choice {
                index: 0,
                message: ChatMessage {
                    role: "assistant".to_string(),
                    content: "I'll navigate to the login page.".to_string(),
                },
                finish_reason: "stop".to_string(),
            }],
            usage: Usage {
                prompt_tokens: 50,
                completion_tokens: 20,
                total_tokens: 70,
            },
        };

        let json = serde_json::to_value(&response).unwrap();
        assert_eq!(json["object"], "chat.completion");
        assert_eq!(json["choices"][0]["message"]["role"], "assistant");
    }
}
```

- [ ] **Step 2: Wire the route into the LiveView connector**

In `crates/ui/src/liveview_connector/mod.rs`, add:

```rust
pub mod llm_proxy;
```

And in the server startup where routes are merged, add the LLM proxy router on a separate port (9100) or merge it into the existing axum app. The exact wiring depends on how `create_api_routes` is composed — merge the LLM proxy router alongside the existing API routes.

- [ ] **Step 3: Run cargo check**

```bash
cargo check -p pentest-ui --all-targets
```

Expected: May have type errors around `send_and_receive_message` if that method doesn't exist on `MatrixChatClient` yet. This is expected — that method will need to be added to the Matrix client as part of the connector SDK integration. For now, stub it or add a TODO.

- [ ] **Step 4: Run tests**

```bash
cargo test -p pentest-ui llm_proxy -- --nocapture
```

Expected: PASS for serialization tests.

- [ ] **Step 5: Commit**

```bash
git add crates/ui/src/liveview_connector/llm_proxy.rs
git commit -m "feat: add OpenAI-compatible LLM proxy route for Webwright"
```

---

### Task 5: Matrix Client Extension (send_and_receive_message)

**Files:**
- Modify: `crates/core/src/matrix/client.rs`

- [ ] **Step 1: Write failing test for the new method**

Add to the test module in `crates/core/src/matrix/client.rs`:

```rust
#[test]
fn send_and_receive_message_signature_exists() {
    // Verify the method signature compiles.
    // Integration testing requires a live Matrix server.
    fn _assert_method_exists(client: &MatrixChatClient) {
        let _fut = client.send_and_receive_message("conv-id", "agent-id", "hello");
        // Just needs to compile - async method returns impl Future
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cargo test -p pentest-core send_and_receive -- --nocapture
```

Expected: FAIL - method does not exist.

- [ ] **Step 3: Implement send_and_receive_message**

Add to `MatrixChatClient` impl block in `crates/core/src/matrix/client.rs`:

```rust
    /// Send a message to a conversation and wait for the agent's response.
    ///
    /// Used by the LLM proxy to route Webwright's requests through
    /// Strike48 conversations. Sends the user message via GraphQL mutation,
    /// then polls/subscribes for the agent's reply.
    pub async fn send_and_receive_message(
        &self,
        conversation_id: &str,
        agent_id: &str,
        message: &str,
    ) -> crate::error::Result<String> {
        // Send user message to conversation
        self.send_user_message(conversation_id, message).await?;

        // Wait for agent response (poll with timeout)
        // The agent processes the message and responds asynchronously.
        // We poll the conversation for the latest agent message.
        let timeout = std::time::Duration::from_secs(120);
        let poll_interval = std::time::Duration::from_millis(500);
        let start = std::time::Instant::now();

        loop {
            if start.elapsed() > timeout {
                return Err(crate::error::Error::Timeout(
                    "Timed out waiting for agent response".to_string(),
                ));
            }

            // Check for new agent message
            if let Some(response) = self
                .get_latest_agent_message(conversation_id, agent_id)
                .await?
            {
                return Ok(response);
            }

            tokio::time::sleep(poll_interval).await;
        }
    }
```

Note: The exact GraphQL mutations/queries (`send_user_message`, `get_latest_agent_message`) depend on the Strike48 Matrix API. These may already exist or need to be added. Check `crates/core/src/matrix/client.rs` for existing query patterns and mirror them.

- [ ] **Step 4: Run test to verify it passes**

```bash
cargo test -p pentest-core send_and_receive -- --nocapture
```

Expected: PASS (compilation test)

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/matrix/client.rs
git commit -m "feat: add send_and_receive_message for LLM proxy conversations"
```

---

### Task 6: Wire Evidence Into WebwrightTool Execute

**Files:**
- Modify: `crates/tools/src/webwright/mod.rs`

- [ ] **Step 1: Add evidence ingestion after artifact collection**

In `WebwrightTool::execute()`, after the `collect_artifacts` call and before building the result, add:

```rust
            // Ingest artifacts into evidence buffer
            evidence::ingest_webwright_evidence(
                &artifacts,
                &start_url,
                &workspace.task_id,
                &provenance,
            );

            // Check for findings.json specifically
            if let Some(logs) = artifacts["logs"].as_array() {
                for log_path in logs {
                    if let Some(path) = log_path.as_str() {
                        if path.contains("findings.json") {
                            if let Ok(content) = std::fs::read_to_string(path) {
                                if let Ok(findings) = serde_json::from_str::<Value>(&content) {
                                    evidence::ingest_webwright_findings(
                                        &findings,
                                        &start_url,
                                        &workspace.task_id,
                                        &provenance,
                                    );
                                }
                            }
                        }
                    }
                }
            }
```

- [ ] **Step 2: Run cargo check**

```bash
cargo check -p pentest-tools --all-targets
```

Expected: PASS

- [ ] **Step 3: Run full test suite**

```bash
cargo test -p pentest-tools webwright -- --nocapture
```

Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/tools/src/webwright/mod.rs
git commit -m "feat: wire evidence ingestion into webwright tool execution"
```

---

### Task 7: Tool Registration and Integration Test

**Files:**
- Modify: `crates/tools/src/lib.rs`
- Create: `crates/tools/tests/webwright_integration.rs` (optional)

- [ ] **Step 1: Verify tool appears in registry**

Write a test at the bottom of `crates/tools/src/lib.rs` tests or in a new integration test:

```rust
#[cfg(test)]
mod webwright_tests {
    use super::*;

    #[test]
    fn webwright_registered_in_tool_registry() {
        let registry = create_tool_registry();
        assert!(registry.get("webwright").is_some());
    }

    #[test]
    fn webwright_schema_has_required_params() {
        let registry = create_tool_registry();
        let tool = registry.get("webwright").unwrap();
        let schema = tool.schema();
        let param_names: Vec<&str> = schema.params.iter().map(|p| p.name.as_str()).collect();
        assert!(param_names.contains(&"mode"));
        assert!(param_names.contains(&"start_url"));
        assert!(param_names.contains(&"task"));
        assert!(param_names.contains(&"script"));
    }

    #[test]
    fn webwright_schema_exports_to_json() {
        let registry = create_tool_registry();
        let tool = registry.get("webwright").unwrap();
        let json_schema = tool.schema().to_json_schema();
        assert_eq!(json_schema["name"], "webwright");
        assert!(json_schema["parameters"]["properties"]["mode"].is_object());
    }
}
```

- [ ] **Step 2: Run the test**

```bash
cargo test -p pentest-tools webwright_registered -- --nocapture
```

Expected: PASS

- [ ] **Step 3: Run clippy**

```bash
cargo clippy -p pentest-tools -- -D warnings
```

Expected: PASS (fix any warnings)

- [ ] **Step 4: Run format**

```bash
cargo fmt --all
```

- [ ] **Step 5: Commit**

```bash
git add crates/tools/src/lib.rs
git commit -m "feat: register webwright in tool registry with integration tests"
```

---

### Task 8: Add serde_yaml Dependency

**Files:**
- Modify: `crates/tools/Cargo.toml`

- [ ] **Step 1: Add serde_yaml to pentest-tools dependencies**

Check if `serde_yaml` is already in the workspace. If not, add to `crates/tools/Cargo.toml`:

```toml
[dependencies]
serde_yaml = "0.9"
```

- [ ] **Step 2: Run cargo check to verify dependency resolves**

```bash
cargo check -p pentest-tools
```

Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add crates/tools/Cargo.toml Cargo.lock
git commit -m "chore: add serde_yaml dependency for webwright config"
```

---

### Task 9: Full Compilation and Test Verification

**Files:** None (verification only)

- [ ] **Step 1: Full workspace check**

```bash
cargo check --all-targets
```

Expected: PASS

- [ ] **Step 2: Full test suite**

```bash
cargo test --lib --bins
```

Expected: PASS

- [ ] **Step 3: Clippy clean**

```bash
cargo clippy --all-targets -- -D warnings
```

Expected: PASS

- [ ] **Step 4: Format check**

```bash
cargo fmt --all -- --check
```

Expected: PASS

- [ ] **Step 5: Final commit (if any fixes needed)**

```bash
git add -A
git commit -m "fix: resolve any compilation or lint issues from webwright integration"
```

---

### Task 10 (Stretch): Sidecar Protocol Wrapper

**Files:**
- Create: `crates/tools/src/webwright/sidecar.rs`

This task implements the persistent sidecar process with JSON-over-stdin/stdout for real-time updates. Only start this after Tasks 1-9 are complete and the basic subprocess approach is working.

- [ ] **Step 1: Define the sidecar protocol types**

Create `crates/tools/src/webwright/sidecar.rs`:

```rust
//! Webwright sidecar protocol for real-time updates.
//!
//! Communicates with a long-lived Webwright process via JSON lines
//! over stdin/stdout. Enables live progress streaming, warm browser
//! reuse, and future interactive steering.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Messages sent from Pick to the Webwright sidecar.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SidecarCommand {
    /// Start an autonomous exploration task.
    StartTask {
        mode: String,
        task: String,
        url: String,
        max_steps: u32,
    },
    /// Execute a pre-written script.
    ExecuteScript {
        script: String,
        url: String,
    },
    /// Cancel the current task.
    Cancel,
}

/// Messages sent from the Webwright sidecar to Pick.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SidecarEvent {
    /// Agent completed one step.
    Step {
        n: u32,
        action: String,
        screenshot: Option<String>,
    },
    /// A vulnerability or finding was discovered.
    Finding {
        severity: String,
        title: String,
        detail: String,
    },
    /// A replayable script was generated.
    ScriptGenerated {
        path: String,
    },
    /// A network request/response was captured.
    NetworkEvent {
        request: Value,
        response: Value,
    },
    /// Task completed.
    Complete {
        summary: String,
        artifacts: Value,
    },
    /// Task failed.
    Error {
        message: String,
    },
}

impl SidecarCommand {
    /// Serialize to JSON line (newline-terminated).
    pub fn to_json_line(&self) -> String {
        let mut s = serde_json::to_string(self).unwrap_or_default();
        s.push('\n');
        s
    }
}

impl SidecarEvent {
    /// Parse from a JSON line.
    pub fn from_json_line(line: &str) -> Option<Self> {
        serde_json::from_str(line.trim()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_serializes_to_json_line() {
        let cmd = SidecarCommand::StartTask {
            mode: "explore".to_string(),
            task: "test XSS".to_string(),
            url: "https://target.com".to_string(),
            max_steps: 50,
        };
        let line = cmd.to_json_line();
        assert!(line.ends_with('\n'));
        assert!(line.contains("start_task"));
        assert!(line.contains("test XSS"));
    }

    #[test]
    fn event_deserializes_from_json_line() {
        let line = r#"{"type":"step","n":3,"action":"clicking login button","screenshot":null}"#;
        let event = SidecarEvent::from_json_line(line).unwrap();
        match event {
            SidecarEvent::Step { n, action, .. } => {
                assert_eq!(n, 3);
                assert_eq!(action, "clicking login button");
            }
            _ => panic!("Expected Step event"),
        }
    }

    #[test]
    fn finding_event_deserializes() {
        let line = r#"{"type":"finding","severity":"high","title":"XSS in search","detail":"Reflected XSS via q param"}"#;
        let event = SidecarEvent::from_json_line(line).unwrap();
        match event {
            SidecarEvent::Finding { severity, title, .. } => {
                assert_eq!(severity, "high");
                assert_eq!(title, "XSS in search");
            }
            _ => panic!("Expected Finding event"),
        }
    }

    #[test]
    fn complete_event_deserializes() {
        let line = r#"{"type":"complete","summary":"Found 3 vulns","artifacts":{"scripts":["a.py"]}}"#;
        let event = SidecarEvent::from_json_line(line).unwrap();
        match event {
            SidecarEvent::Complete { summary, .. } => {
                assert_eq!(summary, "Found 3 vulns");
            }
            _ => panic!("Expected Complete event"),
        }
    }
}
```

- [ ] **Step 2: Add module to webwright/mod.rs**

```rust
pub mod sidecar;
```

- [ ] **Step 3: Run tests**

```bash
cargo test -p pentest-tools sidecar -- --nocapture
```

Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/tools/src/webwright/sidecar.rs
git commit -m "feat: add webwright sidecar protocol types (stretch goal)"
```

---

## Dependency Order

```
Task 8 (serde_yaml dep)
    ↓
Task 1 (scaffold) → Task 2 (workspace) → Task 3 (evidence)
                                                ↓
Task 5 (matrix client) → Task 4 (LLM proxy)   Task 6 (wire evidence)
                                                ↓
                                          Task 7 (registration + tests)
                                                ↓
                                          Task 9 (full verification)
                                                ↓
                                          Task 10 (stretch: sidecar)
```

Tasks 8, 1, 2, 3 can be done first. Task 4 depends on Task 5. Task 6 depends on Tasks 1-3. Task 7 depends on all prior. Task 10 is independent stretch goal.
