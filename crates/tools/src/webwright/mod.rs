//! Webwright browser automation tool.
//!
//! Provides AI-driven browser testing via Microsoft's Webwright framework.
//! Supports two modes:
//! - `explore`: Autonomous LLM-driven browser exploration and testing
//! - `execute`: Replay a Playwright script for validation/evidence capture

pub mod config;
pub mod constants;
pub mod evidence;
pub mod install;
pub mod live_state;
pub mod sidecar;
pub mod workspace;

// Re-export UI-facing API so external crates (pentest-ui) depend on a stable
// boundary rather than reaching into live_state internals.
pub use live_state::{
    peek as live_peek, signature_for_call, subscribe as live_subscribe, task_for_request,
    WebwrightProgress,
};

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use pentest_core::error::{Error, Result};
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

// Sidecars are spawned fresh per task — no global singleton, so parallel webwright
// invocations each get their own browser process.

/// Which webwright mode is being executed. Mirrors the `mode` tool parameter, but
/// parsed once at the top of `execute` so the rest of the pipeline stops re-checking
/// strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebwrightMode {
    /// Autonomous LLM-driven exploration of `start_url` toward `task`.
    Explore,
    /// Replay a user-supplied Playwright script.
    Execute,
}

impl WebwrightMode {
    fn parse(s: &str) -> Result<Self> {
        match s {
            "explore" => Ok(Self::Explore),
            "execute" => Ok(Self::Execute),
            _ => Err(Error::InvalidParams(
                "mode must be 'explore' or 'execute'".into(),
            )),
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Explore => "explore",
            Self::Execute => "execute",
        }
    }
}

/// Everything both execution paths need to run a webwright task.
///
/// Built once by [`build_execution_plan`] from the parsed tool parameters and the
/// workspace, then handed to either [`try_sidecar_execution`] (warm browser, live
/// progress) or [`run_subprocess`] (fallback). Keeping the build separate from the
/// dispatch means schema changes happen in one place and the two paths cannot drift.
struct ExecutionPlan {
    mode: WebwrightMode,
    start_url: String,
    /// For [`WebwrightMode::Execute`] this is the Python source; the orchestrator
    /// writes it to `workspace.script_path()` before dispatch.
    script_content: Option<String>,
    /// `bash -c <line>` command line used by the subprocess fallback. Already
    /// includes env exports.
    shell_command_line: String,
    /// Sidecar message describing the same work.
    sidecar_command: SidecarCommand,
    /// Human-readable provenance description.
    probe_desc: String,
    /// Effective timeout (after the connector-deadline subtraction).
    timeout_secs: u64,
    /// Hard cap on sidecar steps. Enforced by Pick even if the sidecar ignores it.
    max_steps: u32,
}

/// Parsed-and-validated inputs to [`build_execution_plan`]. Bundled into a
/// struct to keep the helper signature short and to give the test suite a
/// natural place to assemble inputs without 8-argument call sites.
struct PlanInputs<'a> {
    mode: WebwrightMode,
    start_url: &'a str,
    task: &'a str,
    script: &'a str,
    workspace: &'a WebwrightWorkspace,
    env_exports: &'a str,
    timeout_secs: u64,
    max_steps: u32,
}

/// Build the single source-of-truth execution plan for one webwright invocation.
///
/// Pure: does no I/O, touches no globals. Callers are expected to have already
/// validated `start_url` (non-empty), the mode-specific params (task/script),
/// and constructed the workspace.
fn build_execution_plan(inputs: PlanInputs<'_>) -> ExecutionPlan {
    let PlanInputs {
        mode,
        start_url,
        task,
        script,
        workspace,
        env_exports,
        timeout_secs,
        max_steps,
    } = inputs;
    let proxy_port = std::env::var("PICK_LLM_PROXY_PORT")
        .unwrap_or_else(|_| constants::DEFAULT_LLM_PROXY_PORT_STR.to_string());

    match mode {
        WebwrightMode::Explore => {
            // Override model endpoint to use Pick's local LLM proxy. Must include
            // base.yaml + model_openai.yaml explicitly since adding any -c flag
            // replaces the defaults.
            let endpoint = std::env::var("OPENAI_BASE_URL")
                .unwrap_or_else(|_| format!("http://127.0.0.1:{}/v1/chat/completions", proxy_port));
            let shell_command_line = format!(
                "{} python3 -m webwright.run.cli -c base.yaml -c model_openai.yaml -c model.openai_endpoint={} -t {} --start-url {} --output-dir {} --task-id {}",
                env_exports,
                shell_escape(&endpoint),
                shell_escape(task),
                shell_escape(start_url),
                shell_escape(&workspace.path()),
                shell_escape(&workspace.task_id),
            );
            let probe_desc = format!(
                "webwright explore --start-url {} --task \"{}\"",
                start_url, task
            );
            let sidecar_command = SidecarCommand::StartTask {
                mode: "explore".to_string(),
                task: task.to_string(),
                url: start_url.to_string(),
                max_steps,
                output_dir: workspace.path(),
                task_id: workspace.task_id.clone(),
            };
            ExecutionPlan {
                mode,
                start_url: start_url.to_string(),
                script_content: None,
                shell_command_line,
                sidecar_command,
                probe_desc,
                timeout_secs,
                max_steps,
            }
        }
        WebwrightMode::Execute => {
            let shell_command_line = format!(
                "{} python3 {}",
                env_exports,
                shell_escape(&workspace.script_path()),
            );
            let probe_desc = format!("webwright execute script on {}", start_url);
            let sidecar_command = SidecarCommand::ExecuteScript {
                script: script.to_string(),
                url: start_url.to_string(),
                output_dir: workspace.path(),
                task_id: workspace.task_id.clone(),
            };
            ExecutionPlan {
                mode,
                start_url: start_url.to_string(),
                script_content: Some(script.to_string()),
                shell_command_line,
                sidecar_command,
                probe_desc,
                timeout_secs,
                max_steps,
            }
        }
    }
}

/// Reserve some headroom before the connector framework's deadline so we can
/// return cleanly instead of being killed mid-execution (which trips the circuit
/// breaker). `raw_timeout - 10`, clamped at a 30s floor so a user-supplied tiny
/// timeout still leaves us *some* runway.
fn effective_timeout_secs(raw_timeout: u64) -> u64 {
    raw_timeout
        .saturating_sub(10)
        .max(constants::MIN_EFFECTIVE_TIMEOUT_SECS)
}

/// Webwright browser automation tool.
pub struct WebwrightTool;

#[async_trait]
impl PentestTool for WebwrightTool {
    fn name(&self) -> &str {
        "webwright"
    }

    fn description(&self) -> &str {
        "Headless browser (Playwright) for screenshots and web app testing. Only two modes: 'explore' and 'execute'. For screenshots, use mode=explore with a task like 'capture a screenshot of the page'. Always set timeout=600."
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
                "Timeout in seconds. MUST be 600 or higher. Browser startup + LLM reasoning + navigation all take time. Default 600.",
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

            let mode_str = param_str_or(&params, "mode", "explore");
            let start_url = param_str_or(&params, "start_url", "");
            let task = param_str_opt(&params, "task").unwrap_or_default();
            let script = param_str_opt(&params, "script").unwrap_or_default();
            let max_steps = param_u64(&params, "max_steps", 50) as u32;
            let raw_timeout = param_u64(&params, "timeout", 600);
            let timeout_secs = effective_timeout_secs(raw_timeout);

            tracing::info!("[webwright] execute start: mode={} url={} timeout={}s", mode_str, start_url, timeout_secs);

            // Parse and validate everything before any I/O so misuse surfaces a clear
            // error instead of being masked by an environment-dependent install failure
            // (e.g. bwrap unavailable in CI).
            if start_url.is_empty() {
                return Err(Error::InvalidParams(
                    "start_url parameter is required".into(),
                ));
            }
            let mode = WebwrightMode::parse(&mode_str)?;
            if mode == WebwrightMode::Explore && task.is_empty() {
                return Err(Error::InvalidParams(
                    "task parameter is required for explore mode".into(),
                ));
            }
            if mode == WebwrightMode::Execute && script.is_empty() {
                return Err(Error::InvalidParams(
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

            // Register bindings so the chat-panel widget can find this task's live stream.
            // Widgets look up by tc.id (= toolCall.id from the platform conversation). The
            // platform forwards a tool_call_id in ExecuteRequest.context, but that may not
            // match what ends up in the conversation (different ID namespaces). To make the
            // binding robust we register under THREE keys:
            //   1. tool_call_id from context (the platform's claimed identifier)
            //   2. request_id (the gRPC stream request id, fallback for older platforms)
            //   3. a content signature hash(tool_name + arguments) — the widget computes
            //      the same hash from its own (tc.name, tc.arguments) and can find the
            //      task even when no platform ID matches.
            let signature = live_state::signature_for_call("webwright", &params.to_string());
            let mut binding_keys: Vec<String> = Vec::new();
            if let Some(v) = ctx.metadata.get("tool_call_id") {
                binding_keys.push(v.clone());
            }
            if let Some(v) = ctx.metadata.get("request_id") {
                binding_keys.push(v.clone());
            }
            binding_keys.push(signature);
            for key in &binding_keys {
                live_state::register_request(key, &workspace.task_id);
            }
            tracing::info!(
                "[webwright] registered live-state bindings: {:?} -> task_id={}",
                binding_keys,
                workspace.task_id
            );

            // Pass session token so each sidecar authenticates as the correct user
            let session_token = ctx.metadata.get("session_token").map(|s| s.as_str());
            let env_exports = build_env_exports(session_token);

            // Single source of truth for "what to run". Both dispatch paths
            // (sidecar + subprocess) read from this plan.
            let plan = build_execution_plan(PlanInputs {
                mode,
                start_url: &start_url,
                task: &task,
                script: &script,
                workspace: &workspace,
                env_exports: &env_exports,
                timeout_secs,
                max_steps,
            });

            // Execute-mode plans carry the script content; write it to the workspace
            // so the subprocess fallback can find it on disk. The sidecar path reads
            // the content straight from the plan and writes it inside the sandbox.
            if let Some(ref content) = plan.script_content {
                workspace.write_script(content).await?;
            }

            // Sidecar is default (warm browser, live updates). Disable with WEBWRIGHT_SIDECAR=0.
            let use_sidecar = std::env::var("WEBWRIGHT_SIDECAR").unwrap_or_else(|_| "1".to_string()) != "0";
            let sidecar_result = if use_sidecar {
                try_sidecar_execution(&plan, &workspace, &env_exports).await
            } else {
                None
            };

            let (result, completion) = if let Some((r, reason)) = sidecar_result {
                tracing::info!(
                    "[webwright] sidecar execution complete (reason={}, {:.1}s elapsed)",
                    reason,
                    t0.elapsed().as_secs_f32()
                );
                (r, reason)
            } else {
                tracing::info!(
                    "[webwright] launching subprocess (timeout={}s, {:.1}s elapsed)",
                    timeout_secs,
                    t0.elapsed().as_secs_f32()
                );
                let r = run_subprocess(&plan, &platform).await?;
                tracing::info!(
                    "[webwright] subprocess exited: code={} stdout_len={} stderr_len={} ({:.1}s elapsed)",
                    r.exit_code,
                    r.stdout.len(),
                    r.stderr.len(),
                    t0.elapsed().as_secs_f32()
                );
                // The subprocess path runs the CLI to completion under its own
                // timeout; map its exit status onto the same completion vocabulary.
                let reason = subprocess_completion(r.timed_out, r.exit_code);
                (r, reason)
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
                ProbeCommand::from_exact(&plan.probe_desc),
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
            let stdout_truncated = if result.stdout.len() > constants::STDOUT_TRUNCATION_THRESHOLD_BYTES {
                format!(
                    "{}... (truncated, {} bytes total)",
                    &result.stdout[..constants::STDOUT_TRUNCATION_THRESHOLD_BYTES],
                    result.stdout.len()
                )
            } else {
                result.stdout.clone()
            };

            let data = json!({
                "mode": plan.mode.as_str(),
                "start_url": plan.start_url,
                "exit_code": result.exit_code,
                // Machine-readable outcome: "complete" | "timeout" | "step_limit"
                // | "error". Distinguishes a fully-explored task from one that
                // stopped early, all of which carry exit_code 0 on purpose so a
                // graceful early stop doesn't trip the connector circuit breaker.
                "completion": completion,
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
fn build_env_exports(session_token: Option<&str>) -> String {
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
        let proxy_port = std::env::var("PICK_LLM_PROXY_PORT")
            .unwrap_or_else(|_| constants::DEFAULT_LLM_PROXY_PORT_STR.to_string());
        exports.push(format!(
            "export OPENAI_BASE_URL={}",
            shell_escape(&format!("http://127.0.0.1:{}/v1", proxy_port))
        ));
        // Use the session token as the API key if available (the LLM proxy
        // will use it as a Matrix auth token). Otherwise use dummy key.
        let api_key = session_token.unwrap_or("pick-internal");
        exports.push(format!("export OPENAI_API_KEY={}", shell_escape(api_key)));
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

/// Shell-escape a string for safe embedding inside a `bash -c` command line.
///
/// Wraps in single quotes; any internal single quote is closed (`'`), backslash-escaped
/// (`\'`), and reopened (`'`) — the canonical POSIX pattern. The output is always safe
/// against shell-metacharacter injection from the input, including session tokens, URLs,
/// and user-supplied task descriptions.
///
/// Tested in `shell_escape_*` below; do not "simplify" without re-running those tests.
fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Heuristic: action text that is just a UUID, a timestamp, or looks like a
/// generated ID isn't useful for the live log widget.
fn looks_like_uuid_or_timestamp(s: &str) -> bool {
    let s = s.trim();
    // UUID pattern: 8-4-4-4-12 hex chars
    if s.len() == 36 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return true;
    }
    // Timestamp-like: starts with 4 digits (year) followed by - or _
    if s.len() > 10 {
        let prefix: String = s.chars().take(5).collect();
        if prefix.chars().take(4).all(|c| c.is_ascii_digit())
            && matches!(prefix.chars().nth(4), Some('-' | '_' | 'T'))
        {
            return true;
        }
    }
    false
}

/// Run the plan as a one-shot subprocess (`bash -c <plan.shell_command_line>`).
///
/// This is the fallback path when the sidecar can't be spawned or is disabled
/// via `WEBWRIGHT_SIDECAR=0`. No live progress, no warm browser — just exec and
/// collect the final stdout/stderr.
async fn run_subprocess(
    plan: &ExecutionPlan,
    platform: &impl CommandExec,
) -> Result<pentest_platform::CommandResult> {
    let args = ["-c", plan.shell_command_line.as_str()];
    platform
        .execute_command("bash", &args, Duration::from_secs(plan.timeout_secs))
        .await
}

/// Map a subprocess-path exit status onto the machine-readable completion
/// vocabulary used in the tool result JSON. A hard timeout wins over the exit
/// code; otherwise `0` is a clean finish and anything else is an error.
fn subprocess_completion(timed_out: bool, exit_code: i32) -> &'static str {
    if timed_out {
        constants::WEBWRIGHT_COMPLETION_TIMEOUT
    } else if exit_code == 0 {
        constants::WEBWRIGHT_COMPLETION_COMPLETE
    } else {
        constants::WEBWRIGHT_COMPLETION_ERROR
    }
}

/// Try to execute the plan via the sidecar process. Returns `None` if the
/// sidecar couldn't be spawned or the command couldn't be sent, so the
/// orchestrator can fall back to [`run_subprocess`].
///
/// On success returns the [`pentest_platform::CommandResult`] alongside a
/// machine-readable completion reason (see the `WEBWRIGHT_COMPLETION_*`
/// constants). The reason lets callers distinguish a fully-explored task from
/// one that stopped early on a timeout or step limit; all three otherwise
/// carry `exit_code: 0` on purpose, so the connector framework doesn't treat a
/// graceful early stop as a hard failure and trip the circuit breaker.
///
/// Both [`WebwrightMode::Explore`] and [`WebwrightMode::Execute`] are supported
/// — the plan's [`SidecarCommand`] already encodes which one. Live progress is
/// pumped into [`live_state`] keyed by `workspace.task_id`.
async fn try_sidecar_execution(
    plan: &ExecutionPlan,
    workspace: &WebwrightWorkspace,
    env_exports: &str,
) -> Option<(pentest_platform::CommandResult, &'static str)> {
    // Spawn a fresh sidecar for this task (enables parallel execution).
    // env_exports already encodes OPENAI_BASE_URL with the proxy port.
    let sidecar = match SidecarProcess::spawn(env_exports).await {
        Ok(proc) => proc,
        Err(e) => {
            tracing::warn!(
                "[webwright-sidecar] failed to spawn: {}, falling back to subprocess",
                e
            );
            return None;
        }
    };

    tracing::info!(
        "[webwright-sidecar] sending command: {}",
        plan.sidecar_command.to_json_line().trim()
    );

    if let Err(e) = sidecar.send(plan.sidecar_command.clone()).await {
        tracing::warn!("[webwright-sidecar] send failed: {}, falling back", e);
        return None;
    }

    let timeout_secs = plan.timeout_secs;
    let max_steps = plan.max_steps;

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
                Err(e) => {
                    tracing::warn!(
                        "[webwright-sidecar] event channel closed before completion ({}); \
                         will fall back to subprocess",
                        e
                    );
                    break;
                }
            },
            _ = tokio::time::sleep_until(deadline) => {
                tracing::warn!("[webwright-sidecar] timed out waiting for completion ({}s)", timeout_secs);
                let _ = sidecar.send(SidecarCommand::Cancel).await;
                live_state::complete(&workspace.task_id);
                return Some((
                    pentest_platform::CommandResult {
                        stdout: format!("Webwright timed out after {}s (task still had work to do)", timeout_secs),
                        stderr: String::new(),
                        exit_code: 0,
                        timed_out: false, // we handled it gracefully, not a hard timeout
                        duration_ms: timeout_secs * 1000,
                    },
                    constants::WEBWRIGHT_COMPLETION_TIMEOUT,
                ));
            }
        };

        match &event {
            SidecarEvent::Step {
                n,
                action,
                screenshot,
            } => {
                tracing::info!("[webwright-sidecar] step {}: {}", n, action);
                // Skip useless lines (UUIDs, timestamps, directory paths)
                let useful = !action.is_empty()
                    && action.len() > 5
                    && !action.starts_with('/')
                    && !looks_like_uuid_or_timestamp(action);
                if useful {
                    log.push(live_state::LogEntry {
                        step: *n,
                        action: action.clone(),
                    });
                    // Cap the rolling log so live UI frames stay small.
                    if log.len() > constants::MAX_LIVE_LOG_ENTRIES {
                        log.remove(0);
                    }
                }
                // Write screenshots to disk and store only the file path.
                // Keeps memory usage constant regardless of task length.
                if let Some(ref shot) = screenshot {
                    let shot_dir = format!("{}/live_screenshots", workspace.host_path());
                    let _ = std::fs::create_dir_all(&shot_dir);
                    let shot_path = format!("{}/step_{:04}.png", shot_dir, n);
                    if let Ok(bytes) = BASE64.decode(shot) {
                        if std::fs::write(&shot_path, &bytes).is_ok() {
                            screenshots.push(shot_path.clone());
                            if screenshots.len() > constants::MAX_LIVE_SCREENSHOTS {
                                let drop_count =
                                    screenshots.len() - constants::MAX_LIVE_SCREENSHOTS;
                                screenshots.drain(0..drop_count);
                            }
                        }
                    }
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
                        screenshot: screenshots.last().cloned(),
                        screenshots: screenshots.clone(),
                        findings: findings.clone(),
                        log: log.clone(),
                        running: true,
                        task_id: workspace.task_id.clone(),
                    },
                );

                if *n >= max_steps {
                    tracing::warn!(
                        "[webwright-sidecar] step limit reached ({}/{}), cancelling",
                        n,
                        max_steps
                    );
                    let _ = sidecar.send(SidecarCommand::Cancel).await;
                    live_state::complete(&workspace.task_id);
                    return Some((
                        pentest_platform::CommandResult {
                            stdout: format!(
                                "Webwright reached step limit ({} steps). Partial results collected.",
                                max_steps
                            ),
                            stderr: String::new(),
                            exit_code: 0,
                            timed_out: false,
                            duration_ms: 0,
                        },
                        constants::WEBWRIGHT_COMPLETION_STEP_LIMIT,
                    ));
                }
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
                return Some((
                    pentest_platform::CommandResult {
                        stdout: summary.clone(),
                        stderr: String::new(),
                        exit_code: 0,
                        timed_out: false,
                        duration_ms: 0,
                    },
                    constants::WEBWRIGHT_COMPLETION_COMPLETE,
                ));
            }
            SidecarEvent::Error { message } => {
                tracing::error!("[webwright-sidecar] error: {}", message);
                live_state::complete(&workspace.task_id);
                return Some((
                    pentest_platform::CommandResult {
                        stdout: String::new(),
                        stderr: message.clone(),
                        exit_code: 1,
                        timed_out: false,
                        duration_ms: 0,
                    },
                    constants::WEBWRIGHT_COMPLETION_ERROR,
                ));
            }
            _ => {}
        }
    }

    live_state::complete(&workspace.task_id);

    // Reached only when the event loop broke out (channel closed) without a
    // terminal event. The break arm already logged why; return None so the
    // orchestrator falls back to the subprocess path.
    tracing::warn!(
        "[webwright-sidecar] no terminal event received for task {}; returning None",
        workspace.task_id
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a synthetic plan via the public helper. Uses a workspace produced by
    /// `WebwrightWorkspace::create` with no connector dir, so we don't touch the
    /// filesystem beyond the constructor's random task_id.
    async fn make_workspace() -> WebwrightWorkspace {
        let platform = pentest_platform::get_platform();
        WebwrightWorkspace::create(&platform, None)
            .await
            .expect("workspace create with no connector dir is infallible")
    }

    fn unescape_through_bash(escaped: &str) -> String {
        // Use bash to evaluate the escaped string; if our escaper is correct,
        // the round-trip should be lossless.
        let output = std::process::Command::new("bash")
            .args(["-c", &format!("printf %s {}", escaped)])
            .output()
            .expect("bash exists");
        assert!(
            output.status.success(),
            "bash failed for input: {}",
            escaped
        );
        String::from_utf8(output.stdout).expect("utf8")
    }

    #[test]
    fn subprocess_completion_maps_exit_status() {
        // Hard timeout wins regardless of exit code.
        assert_eq!(
            subprocess_completion(true, 0),
            constants::WEBWRIGHT_COMPLETION_TIMEOUT
        );
        assert_eq!(
            subprocess_completion(true, 1),
            constants::WEBWRIGHT_COMPLETION_TIMEOUT
        );
        // Clean exit is a complete run.
        assert_eq!(
            subprocess_completion(false, 0),
            constants::WEBWRIGHT_COMPLETION_COMPLETE
        );
        // Any non-zero exit without a timeout is an error.
        assert_eq!(
            subprocess_completion(false, 1),
            constants::WEBWRIGHT_COMPLETION_ERROR
        );
        assert_eq!(
            subprocess_completion(false, -1),
            constants::WEBWRIGHT_COMPLETION_ERROR
        );
    }

    #[test]
    fn shell_escape_roundtrip_plain() {
        let s = "hello world";
        assert_eq!(unescape_through_bash(&shell_escape(s)), s);
    }

    #[test]
    fn shell_escape_roundtrip_single_quote() {
        let s = "it's a test";
        assert_eq!(unescape_through_bash(&shell_escape(s)), s);
    }

    #[test]
    fn shell_escape_roundtrip_double_quote_and_dollar() {
        let s = r#"$(rm -rf /) "evil" `nope`"#;
        assert_eq!(unescape_through_bash(&shell_escape(s)), s);
    }

    #[test]
    fn shell_escape_roundtrip_backslash() {
        let s = r"a\b\c";
        assert_eq!(unescape_through_bash(&shell_escape(s)), s);
    }

    #[test]
    fn shell_escape_roundtrip_session_token_like() {
        // JWTs use dots and dashes; throw in dangerous characters too
        let s = "eyJhbGc.iOiJSUzI.signa-ture'+`whoami`+";
        assert_eq!(unescape_through_bash(&shell_escape(s)), s);
    }

    #[test]
    fn shell_escape_roundtrip_newline_and_tab() {
        let s = "line1\nline2\ttab";
        assert_eq!(unescape_through_bash(&shell_escape(s)), s);
    }

    #[test]
    fn shell_escape_roundtrip_empty() {
        assert_eq!(unescape_through_bash(&shell_escape("")), "");
    }

    // ---------------------------------------------------------------------
    // ExecutionPlan
    // ---------------------------------------------------------------------

    #[test]
    fn webwright_mode_parses_known_values_and_rejects_others() {
        assert_eq!(
            WebwrightMode::parse("explore").unwrap(),
            WebwrightMode::Explore
        );
        assert_eq!(
            WebwrightMode::parse("execute").unwrap(),
            WebwrightMode::Execute
        );
        let err = WebwrightMode::parse("bogus").unwrap_err();
        assert!(
            err.to_string().contains("mode must be"),
            "unexpected error message: {}",
            err
        );
    }

    #[test]
    fn effective_timeout_subtracts_ten_seconds() {
        assert_eq!(effective_timeout_secs(600), 590);
        assert_eq!(effective_timeout_secs(300), 290);
    }

    #[test]
    fn effective_timeout_clamps_at_floor_for_tiny_inputs() {
        // The floor matches the constant; verifying the constraint, not the literal.
        let floor = constants::MIN_EFFECTIVE_TIMEOUT_SECS;
        assert_eq!(effective_timeout_secs(0), floor);
        assert_eq!(effective_timeout_secs(5), floor);
        assert_eq!(effective_timeout_secs(35), floor.max(25));
        // Above the floor: subtraction wins.
        assert!(effective_timeout_secs(120) >= floor);
        assert_eq!(effective_timeout_secs(120), 110);
    }

    #[tokio::test]
    async fn build_plan_explore_emits_explore_shell_and_start_task_sidecar() {
        let workspace = make_workspace().await;
        let plan = build_execution_plan(PlanInputs {
            mode: WebwrightMode::Explore,
            start_url: "https://target.example",
            task: "test all forms for XSS",
            script: "",
            workspace: &workspace,
            env_exports: "export FOO=bar;",
            timeout_secs: 120,
            max_steps: 42,
        });

        assert_eq!(plan.mode, WebwrightMode::Explore);
        assert_eq!(plan.start_url, "https://target.example");
        assert!(plan.script_content.is_none());
        assert_eq!(plan.timeout_secs, 120);

        // probe_desc must name the mode + URL + task so we can read it in audit logs.
        assert!(plan.probe_desc.starts_with("webwright explore"));
        assert!(plan.probe_desc.contains("https://target.example"));
        assert!(plan.probe_desc.contains("test all forms for XSS"));

        // shell line carries the env exports verbatim and points at the CLI.
        assert!(plan.shell_command_line.contains("export FOO=bar;"));
        assert!(plan
            .shell_command_line
            .contains("python3 -m webwright.run.cli"));
        assert!(plan
            .shell_command_line
            .contains("--start-url 'https://target.example'"));
        assert!(plan
            .shell_command_line
            .contains("--output-dir '/tmp/webwright/"));

        // Sidecar command is StartTask with mode="explore" and the same max_steps
        // the orchestrator parsed from params.
        match &plan.sidecar_command {
            SidecarCommand::StartTask {
                mode,
                task,
                url,
                max_steps,
                output_dir,
                task_id,
            } => {
                assert_eq!(mode, "explore");
                assert_eq!(task, "test all forms for XSS");
                assert_eq!(url, "https://target.example");
                assert_eq!(*max_steps, 42);
                assert_eq!(output_dir, &workspace.path());
                assert_eq!(task_id, &workspace.task_id);
            }
            other => panic!("explore plan should emit StartTask, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn build_plan_execute_writes_script_path_and_execute_script_sidecar() {
        let workspace = make_workspace().await;
        let script_body = "print('hi')";
        let plan = build_execution_plan(PlanInputs {
            mode: WebwrightMode::Execute,
            start_url: "https://target.example",
            task: "",
            script: script_body,
            workspace: &workspace,
            env_exports: "export FOO=bar;",
            timeout_secs: 90,
            max_steps: 10,
        });

        assert_eq!(plan.mode, WebwrightMode::Execute);
        assert_eq!(plan.start_url, "https://target.example");
        assert_eq!(plan.script_content.as_deref(), Some(script_body));
        assert_eq!(plan.timeout_secs, 90);

        // probe_desc must indicate we're in execute mode + which target.
        assert!(plan.probe_desc.contains("execute script"));
        assert!(plan.probe_desc.contains("https://target.example"));

        // shell line runs `python3 <workspace>/script.py`.
        assert!(plan.shell_command_line.contains("export FOO=bar;"));
        assert!(plan.shell_command_line.contains("python3 "));
        let expected_script = format!("'{}'", workspace.script_path());
        assert!(
            plan.shell_command_line.contains(&expected_script),
            "shell line missing quoted script path {}: {}",
            expected_script,
            plan.shell_command_line
        );

        // Sidecar carries the raw script body + output dir + task id.
        match &plan.sidecar_command {
            SidecarCommand::ExecuteScript {
                script,
                url,
                output_dir,
                task_id,
            } => {
                assert_eq!(script, script_body);
                assert_eq!(url, "https://target.example");
                assert_eq!(output_dir, &workspace.path());
                assert_eq!(task_id, &workspace.task_id);
            }
            other => panic!("execute plan should emit ExecuteScript, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn build_plan_explore_shell_contains_required_cli_flags() {
        // Regression: when this string drifts (someone renames a flag), the
        // subprocess fallback silently breaks. Pin the flag names here.
        let workspace = make_workspace().await;
        let plan = build_execution_plan(PlanInputs {
            mode: WebwrightMode::Explore,
            start_url: "https://target.example",
            task: "task",
            script: "",
            workspace: &workspace,
            env_exports: "",
            timeout_secs: 60,
            max_steps: 50,
        });
        for flag in [
            "-c base.yaml",
            "-c model_openai.yaml",
            "-c model.openai_endpoint=",
            "-t 'task'",
            "--start-url",
            "--output-dir",
            "--task-id",
        ] {
            assert!(
                plan.shell_command_line.contains(flag),
                "shell command line is missing required flag {:?}: {}",
                flag,
                plan.shell_command_line
            );
        }
    }

    // ---------------------------------------------------------------------
    // build_env_exports
    // ---------------------------------------------------------------------

    #[test]
    fn env_exports_uses_proxy_when_no_user_key() {
        // Clear any user-provided key so we hit the proxy path.
        std::env::remove_var("OPENAI_API_KEY");
        let exports = build_env_exports(Some("my-session-token"));
        assert!(
            exports.contains("OPENAI_BASE_URL='http://127.0.0.1:"),
            "should set OPENAI_BASE_URL to local proxy: {}",
            exports
        );
        assert!(
            exports.contains("OPENAI_API_KEY='my-session-token'"),
            "should use session_token as API key: {}",
            exports
        );
    }

    #[test]
    fn env_exports_falls_back_to_pick_internal_without_token() {
        std::env::remove_var("OPENAI_API_KEY");
        let exports = build_env_exports(None);
        assert!(
            exports.contains("OPENAI_API_KEY='pick-internal'"),
            "should use 'pick-internal' when no session_token: {}",
            exports
        );
    }

    #[test]
    fn env_exports_sanitizes_nix_vars() {
        std::env::remove_var("OPENAI_API_KEY");
        let exports = build_env_exports(None);
        assert!(
            exports.contains("unset SSL_CERT_FILE"),
            "should unset SSL_CERT_FILE: {}",
            exports
        );
        assert!(
            exports.contains("export TMPDIR=/tmp"),
            "should reset TMPDIR: {}",
            exports
        );
        assert!(
            exports.contains("PLAYWRIGHT_CHROMIUM_SANDBOX=0"),
            "should disable chromium sandbox: {}",
            exports
        );
    }

    // ---------------------------------------------------------------------
    // WebwrightWorkspace::collect_artifacts
    // ---------------------------------------------------------------------

    #[tokio::test]
    async fn collect_artifacts_classifies_by_extension() {
        let platform = pentest_platform::get_platform();
        let ws = WebwrightWorkspace::create(&platform, None).await.unwrap();

        // Write test files to the host_dir
        std::fs::create_dir_all(ws.host_path()).unwrap();
        std::fs::write(format!("{}/exploit.py", ws.host_path()), b"# code").unwrap();
        std::fs::write(format!("{}/page.png", ws.host_path()), b"PNG").unwrap();
        std::fs::write(format!("{}/trace.json", ws.host_path()), b"{}").unwrap();
        std::fs::write(format!("{}/snap.html", ws.host_path()), b"<html>").unwrap();
        std::fs::write(format!("{}/readme.txt", ws.host_path()), b"hi").unwrap();
        // config.yaml and script.py should be excluded
        std::fs::write(format!("{}/config.yaml", ws.host_path()), b"x").unwrap();
        std::fs::write(format!("{}/script.py", ws.host_path()), b"x").unwrap();

        let artifacts = ws.collect_artifacts(&platform).await.unwrap();

        assert_eq!(artifacts["scripts"].as_array().unwrap().len(), 1);
        assert_eq!(artifacts["screenshots"].as_array().unwrap().len(), 1);
        assert_eq!(artifacts["logs"].as_array().unwrap().len(), 1);
        assert_eq!(artifacts["dom_snapshots"].as_array().unwrap().len(), 1);
        assert_eq!(artifacts["other"].as_array().unwrap().len(), 1);
        assert_eq!(artifacts["total_files"], 7); // 5 classified + config + script in total count

        // Cleanup
        ws.cleanup(&platform).await.unwrap();
    }

    #[tokio::test]
    async fn collect_artifacts_empty_workspace_returns_zero() {
        let platform = pentest_platform::get_platform();
        let ws = WebwrightWorkspace::create(&platform, None).await.unwrap();

        let artifacts = ws.collect_artifacts(&platform).await.unwrap();
        assert_eq!(artifacts["total_files"], 0);
        assert!(artifacts["scripts"].as_array().unwrap().is_empty());
    }
}
