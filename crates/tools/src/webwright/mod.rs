//! Webwright browser automation tool.
//!
//! Provides AI-driven browser testing via Microsoft's Webwright framework.
//! Supports two modes:
//! - `explore`: Autonomous LLM-driven browser exploration and testing
//! - `execute`: Replay a Playwright script for validation/evidence capture

pub mod config;
pub mod evidence;
pub mod install;
pub mod live_state;
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

use self::sidecar::{SidecarCommand, SidecarEvent, SidecarProcess};
use self::workspace::WebwrightWorkspace;
use crate::external::runner::{param_str_opt, param_str_or};
use crate::util::param_u64;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Global sidecar instance — shared across tool invocations for warm browser reuse.
static SIDECAR: std::sync::LazyLock<Arc<Mutex<Option<SidecarProcess>>>> =
    std::sync::LazyLock::new(|| Arc::new(Mutex::new(None)));

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
            .param(ToolParam::required(
                "timeout",
                ParamType::Integer,
                "Timeout in seconds. MUST be set explicitly. Use 300 for most tasks, 600 for complex multi-page explorations.",
            ))
            .platforms(vec![Platform::Desktop, Platform::Android, Platform::Tui])
    }

    fn supported_platforms(&self) -> Vec<Platform> {
        vec![Platform::Desktop, Platform::Android, Platform::Tui]
    }

    async fn execute(&self, params: Value, ctx: &ToolContext) -> Result<ToolResult> {
        execute_timed_with_provenance(|| async move {
            let platform = get_platform();
            let t0 = std::time::Instant::now();

            let mode = param_str_or(&params, "mode", "explore");
            let start_url = param_str_or(&params, "start_url", "");
            let task = param_str_opt(&params, "task");
            let script = param_str_opt(&params, "script");
            let _max_steps = param_u64(&params, "max_steps", 50); // reserved for future sidecar use
            let timeout_secs = param_u64(&params, "timeout", 60);

            tracing::info!("[webwright] execute start: mode={} url={} timeout={}s", mode, start_url, timeout_secs);

            if start_url.is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "start_url parameter is required".into(),
                ));
            }

            // Validate mode + mode-specific params before triggering auto-install,
            // so misuse surfaces a clear error instead of being masked by an
            // environment-dependent install failure (e.g. bwrap unavailable in CI).
            if mode != "explore" && mode != "execute" {
                return Err(pentest_core::error::Error::InvalidParams(
                    "mode must be 'explore' or 'execute'".into(),
                ));
            }
            if mode == "explore" && task.as_deref().unwrap_or("").is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "task parameter is required for explore mode".into(),
                ));
            }
            if mode == "execute" && script.as_deref().unwrap_or("").is_empty() {
                return Err(pentest_core::error::Error::InvalidParams(
                    "script parameter is required for execute mode".into(),
                ));
            }

            // Ensure webwright is installed (auto-installs in sandbox)
            tracing::info!("[webwright] checking installation...");
            install::ensure_webwright_installed(&platform).await?;
            tracing::info!("[webwright] installed OK ({:.1}s elapsed)", t0.elapsed().as_secs_f32());

            // Create workspace inside the connector's instance workspace
            tracing::info!("[webwright] ctx.workspace_path={:?}", ctx.workspace_path);
            let workspace = WebwrightWorkspace::create(&platform, ctx.workspace_path.as_deref()).await?;
            tracing::info!("[webwright] workspace created: sandbox={} host={}", workspace.path(), workspace.host_path());

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

            // Sidecar mode is default (warm browser, live updates). Disable with WEBWRIGHT_SIDECAR=0.
            let use_sidecar = std::env::var("WEBWRIGHT_SIDECAR").unwrap_or_else(|_| "1".to_string()) != "0";
            let task_str_for_sidecar = param_str_opt(&params, "task").unwrap_or_default();
            let sidecar_result = if use_sidecar {
                try_sidecar_execution(&mode, &start_url, &task_str_for_sidecar, &workspace, &env_exports, timeout_secs).await
            } else {
                None
            };

            let result = if let Some(r) = sidecar_result {
                tracing::info!("[webwright] sidecar execution complete ({:.1}s elapsed)", t0.elapsed().as_secs_f32());
                r
            } else {
                // Subprocess fallback
                tracing::info!("[webwright] launching subprocess (timeout={}s, {:.1}s elapsed)", timeout_secs, t0.elapsed().as_secs_f32());
                let r = platform
                    .execute_command("bash", &args_refs, Duration::from_secs(timeout_secs))
                    .await?;
                tracing::info!(
                    "[webwright] subprocess exited: code={} stdout_len={} stderr_len={} ({:.1}s elapsed)",
                    r.exit_code, r.stdout.len(), r.stderr.len(), t0.elapsed().as_secs_f32()
                );
                r
            };

            // Copy artifacts to connector workspace (for Files panel)
            workspace.copy_to_connector_workspace();

            // Collect artifacts from workspace
            tracing::info!("[webwright] collecting artifacts from {}", workspace.host_path());
            let artifacts = workspace.collect_artifacts(&platform).await?;
            tracing::info!("[webwright] artifacts: {} files ({:.1}s elapsed)", artifacts["total_files"], t0.elapsed().as_secs_f32());

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

            // Truncate stdout to avoid blowing up WebSocket frame limits.
            // Webwright can produce very large output (>100MB with debug info).
            let stdout_truncated = if result.stdout.len() > 4000 {
                format!("{}... (truncated, {} bytes total)", &result.stdout[..4000], result.stdout.len())
            } else {
                result.stdout.clone()
            };

            let data = json!({
                "mode": mode,
                "start_url": start_url,
                "exit_code": result.exit_code,
                "stdout": stdout_truncated,
                "stderr": result.stderr,
                "artifacts": artifacts,
                "task_id": workspace.task_id,
                "workspace_path": workspace.path(),
                "note": "Screenshots are displayed inline to the user automatically. Do NOT use read_file on them unless you need to analyze their content.",
            });

            tracing::info!("[webwright] execute complete ({:.1}s total)", t0.elapsed().as_secs_f32());
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
        let proxy_port =
            std::env::var("PICK_LLM_PROXY_PORT").unwrap_or_else(|_| "9100".to_string());
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
    exports.push(
        "unset SSL_CERT_FILE SSL_CERT_DIR TMPDIR DISPLAY WAYLAND_DISPLAY XDG_RUNTIME_DIR"
            .to_string(),
    );
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

/// Try to execute via the sidecar process. Returns None if sidecar unavailable.
async fn try_sidecar_execution(
    mode: &str,
    start_url: &str,
    task: &str,
    workspace: &WebwrightWorkspace,
    env_exports: &str,
    timeout_secs: u64,
) -> Option<pentest_platform::CommandResult> {
    let mut guard = SIDECAR.lock().await;

    // Spawn sidecar if not running
    if guard.is_none() || !guard.as_ref().unwrap().is_alive().await {
        let proxy_port: u16 = std::env::var("PICK_LLM_PROXY_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(9100);

        match SidecarProcess::spawn(env_exports, proxy_port).await {
            Ok(proc) => {
                *guard = Some(proc);
            }
            Err(e) => {
                tracing::warn!(
                    "[webwright-sidecar] failed to spawn: {}, falling back to subprocess",
                    e
                );
                return None;
            }
        }
    }

    let sidecar = guard.as_ref().unwrap();

    // Send command
    let cmd = match mode {
        "explore" => SidecarCommand::StartTask {
            mode: "explore".to_string(),
            task: task.to_string(),
            url: start_url.to_string(),
            max_steps: 50,
            output_dir: workspace.path(),
            task_id: workspace.task_id.clone(),
        },
        _ => return None, // Only explore mode supported via sidecar for now
    };

    if let Err(e) = sidecar.send(cmd).await {
        tracing::warn!("[webwright-sidecar] send failed: {}, falling back", e);
        return None;
    }

    // Signal start for live UI (per-task)
    live_state::start(&workspace.task_id);

    // Subscribe and wait for completion — timeout matches what the user requested
    let mut rx = sidecar.subscribe();
    let timeout = tokio::time::Duration::from_secs(timeout_secs);
    let deadline = tokio::time::Instant::now() + timeout;
    let mut findings: Vec<live_state::WebwrightFinding> = Vec::new();
    let mut log: Vec<live_state::LogEntry> = Vec::new();
    let mut screenshots: Vec<String> = Vec::new();

    loop {
        let event = tokio::select! {
            ev = rx.recv() => match ev {
                Ok(e) => e,
                Err(_) => break,
            },
            _ = tokio::time::sleep_until(deadline) => {
                tracing::warn!("[webwright-sidecar] timed out waiting for completion");
                let _ = sidecar.send(SidecarCommand::Cancel).await;
                break;
            }
        };

        match &event {
            SidecarEvent::Step {
                n,
                action,
                screenshot,
            } => {
                tracing::info!("[webwright-sidecar] step {}: {}", n, action);
                // Skip useless lines (UUIDs, blank lines, directory paths)
                let useful = !action.is_empty() && !action.contains("_2026") && action.len() > 5;
                if useful {
                    log.push(live_state::LogEntry {
                        step: *n,
                        action: action.clone(),
                    });
                    // Keep last 20 entries
                    if log.len() > 20 {
                        log.remove(0);
                    }
                }
                // Accumulate screenshots into the gallery
                if let Some(ref shot) = screenshot {
                    screenshots.push(shot.clone());
                }
                live_state::update(
                    &workspace.task_id,
                    live_state::WebwrightProgress {
                        step: *n,
                        action: if useful {
                            action.clone()
                        } else {
                            "working...".to_string()
                        },
                        screenshot: screenshot.clone(),
                        screenshots: screenshots.clone(),
                        findings: findings.clone(),
                        log: log.clone(),
                        running: true,
                        task_id: workspace.task_id.clone(),
                    },
                );
            }
            SidecarEvent::Finding {
                severity, title, ..
            } => {
                tracing::info!("[webwright-sidecar] finding: [{}] {}", severity, title);
                findings.push(live_state::WebwrightFinding {
                    severity: severity.clone(),
                    title: title.clone(),
                });
                live_state::update(
                    &workspace.task_id,
                    live_state::WebwrightProgress {
                        step: 0,
                        action: format!("Found: {}", title),
                        screenshot: None,
                        screenshots: Vec::new(),
                        findings: findings.clone(),
                        log: log.clone(),
                        running: true,
                        task_id: workspace.task_id.clone(),
                    },
                );
            }
            SidecarEvent::Complete { summary, .. } => {
                tracing::info!("[webwright-sidecar] complete: {}", summary);
                live_state::complete(&workspace.task_id);
                return Some(pentest_platform::CommandResult {
                    stdout: summary.clone(),
                    stderr: String::new(),
                    exit_code: 0,
                    timed_out: false,
                    duration_ms: 0,
                });
            }
            SidecarEvent::Error { message } => {
                tracing::error!("[webwright-sidecar] error: {}", message);
                live_state::complete(&workspace.task_id);
                return Some(pentest_platform::CommandResult {
                    stdout: String::new(),
                    stderr: message.clone(),
                    exit_code: 1,
                    timed_out: false,
                    duration_ms: 0,
                });
            }
            _ => {}
        }
    }

    live_state::complete(&workspace.task_id);

    // If we get here, something went wrong
    None
}
