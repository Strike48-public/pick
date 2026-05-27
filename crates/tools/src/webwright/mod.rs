//! Webwright browser automation tool.
//!
//! Provides AI-driven browser testing via Microsoft's Webwright framework.
//! Supports two modes:
//! - `explore`: Autonomous LLM-driven browser exploration and testing
//! - `execute`: Replay a Playwright script for validation/evidence capture

pub mod config;
pub mod evidence;
pub mod install;
pub mod sidecar;
pub mod workspace;

use async_trait::async_trait;
use pentest_core::error::Result;
use pentest_core::provenance::{ProbeCommand, Provenance};
use pentest_core::tools::{
    execute_timed_with_provenance, ExternalDependency, ParamType, PentestTool, Platform,
    ToolContext, ToolParam, ToolResult, ToolSchema,
};
use pentest_platform::{get_platform, CommandExec};
use serde_json::{json, Value};
use std::time::Duration;

use self::workspace::WebwrightWorkspace;
use crate::external::runner::{param_str_opt, param_str_or};
use crate::util::param_u64;

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

    async fn execute(&self, params: Value, _ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed_with_provenance(|| async move {
            let platform = get_platform();

            let mode = param_str_or(&params, "mode", "explore");
            let start_url = param_str_or(&params, "start_url", "");
            let task = param_str_opt(&params, "task");
            let script = param_str_opt(&params, "script");
            let _max_steps = param_u64(&params, "max_steps", 50); // reserved for future sidecar use
            let timeout_secs = param_u64(&params, "timeout", 600);

            if start_url.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "start_url parameter is required".into(),
                ));
            }

            // Ensure webwright is installed (auto-installs in sandbox)
            install::ensure_webwright_installed(&platform).await?;

            // Create workspace
            let workspace = WebwrightWorkspace::create(&platform).await?;

            // Build env vars for webwright (forward API keys from Pick's environment)
            let env_exports = build_env_exports();

            // Build command based on mode
            let (args, probe_desc) = match mode.as_str() {
                "explore" => {
                    let task_str = task.unwrap_or_default();
                    if task_str.is_empty() {
                        return Err(pentest_core::error::Error::InvalidParams(
                            "task parameter is required for explore mode".into(),
                        ));
                    }
                    // Override model endpoint to use Pick's local LLM proxy.
                    // Must include base.yaml + model_openai.yaml explicitly since
                    // adding any -c flag replaces the defaults.
                    let proxy_port = std::env::var("PICK_LLM_PROXY_PORT").unwrap_or_else(|_| "9100".to_string());
                    let endpoint = std::env::var("OPENAI_BASE_URL")
                        .unwrap_or_else(|_| format!("http://127.0.0.1:{}/v1/chat/completions", proxy_port));
                    let cmd = format!(
                        "{} python3 -m webwright.run.cli -c base.yaml -c model_openai.yaml -c model.openai_endpoint={} -t {} --start-url {} --output-dir {} --task-id {}",
                        env_exports,
                        shell_escape(&endpoint),
                        shell_escape(&task_str),
                        shell_escape(&start_url),
                        shell_escape(&workspace.path()),
                        shell_escape(&workspace.task_id),
                    );
                    let args = vec!["-c".to_string(), cmd];
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
                    let cmd = format!(
                        "{} python3 {}",
                        env_exports,
                        shell_escape(&workspace.script_path()),
                    );
                    let args = vec!["-c".to_string(), cmd];
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

            // Execute in sandbox via bash (to inject env vars)
            let result = platform
                .execute_command("bash", &args_refs, Duration::from_secs(timeout_secs))
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

            // Ingest evidence
            evidence::ingest_webwright_evidence(
                &artifacts,
                &start_url,
                &workspace.task_id,
                &provenance,
            );

            // Check for findings.json in logs
            if let Some(logs) = artifacts["logs"].as_array() {
                for log_path in logs {
                    if let Some(path) = log_path.as_str() {
                        if path.contains("findings.json") || path.ends_with("findings.json") {
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

            let data = json!({
                "mode": mode,
                "start_url": start_url,
                "exit_code": result.exit_code,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "artifacts": artifacts,
                "task_id": workspace.task_id,
                "workspace_path": workspace.path(),
            });

            Ok((data, provenance))
        })
        .await
    }
}

/// Build shell export statements for webwright's LLM configuration.
///
/// Priority:
/// 1. If OPENAI_API_KEY is set in Pick's env, forward it (user-provided key)
/// 2. Otherwise, point at Pick's local LLM proxy (port 3030) with a dummy key
///
/// The local proxy translates OpenAI requests → Strike48 conversation messages.
fn build_env_exports() -> String {
    let mut exports = Vec::new();

    // Check if user provided their own API key
    let has_user_key = std::env::var("OPENAI_API_KEY")
        .map(|v| !v.is_empty())
        .unwrap_or(false);

    if has_user_key {
        // Forward user-provided keys
        for var in [
            "OPENAI_API_KEY",
            "OPENAI_BASE_URL",
            "ANTHROPIC_API_KEY",
            "OPENAI_MODEL",
        ] {
            if let Ok(val) = std::env::var(var) {
                if !val.is_empty() {
                    exports.push(format!("export {}={}", var, shell_escape(&val)));
                }
            }
        }
    } else {
        // Point at Pick's local LLM proxy (dynamic port stored in env)
        let proxy_port = std::env::var("PICK_LLM_PROXY_PORT").unwrap_or_else(|_| "9100".to_string());
        exports.push(format!(
            "export OPENAI_BASE_URL={}",
            shell_escape(&format!("http://127.0.0.1:{}/v1", proxy_port))
        ));
        exports.push(format!(
            "export OPENAI_API_KEY={}",
            shell_escape("pick-internal")
        ));
    }

    // Sanitize host env vars that leak into proot and cause issues:
    // - SSL_CERT_FILE/SSL_CERT_DIR: NixOS paths don't exist in proot
    // - TMPDIR: NixOS nix-shell paths don't exist in proot
    // - DISPLAY/WAYLAND_DISPLAY: headless, no display needed
    exports.push("unset SSL_CERT_FILE SSL_CERT_DIR TMPDIR DISPLAY WAYLAND_DISPLAY XDG_RUNTIME_DIR".to_string());
    exports.push("export TMPDIR=/tmp".to_string());
    exports.push("export HOME=/root".to_string());
    // Chromium needs --no-sandbox in proot (no real namespaces available).
    // PLAYWRIGHT_CHROMIUM_SANDBOX=0 tells Playwright to add --no-sandbox automatically.
    exports.push("export PLAYWRIGHT_CHROMIUM_SANDBOX=0".to_string());

    format!("{};", exports.join("; "))
}

/// Simple shell escaping — wraps in single quotes, escaping any internal single quotes.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}
