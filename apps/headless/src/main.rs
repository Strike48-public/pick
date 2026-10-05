//! Headless Pentest Connector Agent
//!
//! Droppable payload binary — no host UI, no windowing system.
//! Connects to Strike48 via gRPC, registers tools, and serves the full
//! workspace app (Dashboard, Tools, Files, Shell, Logs, Chat) through
//! the internal Dioxus LiveView server proxied via Strike48.
//!
//! Configuration via environment variables:
//!   STRIKE48_HOST        - Server host:port (e.g. "connectors-studio.example.com:50061")
//!   STRIKE48_URL         - Alias for STRIKE48_HOST (used by StrikeHub)
//!   STRIKE48_API_URL     - Alias for STRIKE48_HOST
//!   STRIKE48_TOKEN       - JWT auth token (optional — uses OTT approval flow if absent)
//!   STRIKE48_TENANT      - Tenant ID (default: "default")
//!   TENANT_ID            - Alias for STRIKE48_TENANT (used by StrikeHub)
//!   STRIKE48_INSTANCE_ID - Instance ID (default: auto-generated UUID)
//!   INSTANCE_ID          - Alias for STRIKE48_INSTANCE_ID (used by StrikeHub)
//!   STRIKE48_TLS         - "true" or "false" (default: true)
//!   STRIKEHUB_SOCKET     - Unix socket path (set by StrikeHub for IPC mode)
//!
//! Or pass as CLI arguments:
//!   pentest-agent <host:port> [--token <jwt>] [--tenant <id>] [--no-tls]

use pentest_core::config::{load_connector_config, ConfigLoadResult, ShellMode};
use pentest_core::settings::{load_settings, save_settings};
use pentest_tools::create_tool_registry;
use pentest_ui::LiveViewConnector;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Windows leaves HOME unset; resolve it before anything reads ~/.strike48.
    pentest_core::config::ensure_home_env();

    // Initialize logging: console plus the rolling JSON file under the local
    // data dir, so a failure in a customer install leaves a trail after the
    // process is gone (pick#476). A read-only filesystem degrades to console
    // only with a warning rather than refusing to start.
    if let Some(log_dir) = pentest_core::logging::init_logging_with_file("info") {
        tracing::info!("Log directory: {}", log_dir.display());
    }

    // Usage telemetry (#278): initialize before anything can emit activity.
    // This binary previously called telemetry::flush() on exit without ever
    // calling telemetry::init, so no headless/server deployment could report
    // sessions or activity and the flush was always a no-op (#527). Runs
    // before config load so the persisted device id below is the one
    // load_connector_config reuses as the instance id on a fresh install.
    init_telemetry();

    let is_strikehub = std::env::var("STRIKEHUB_SOCKET").is_ok();

    let mut args: Vec<String> = std::env::args().collect();

    // `pentest-agent connect <studio-url>` — one-command onboarding: browser
    // sign-in, tenant discovery, and self-registration against any Prospector
    // Studio. The discovered settings are pushed into the environment (and
    // persisted) so the standard startup path below connects with them.
    if args.get(1).map(String::as_str) == Some("connect") {
        let Some(url) = args.get(2).cloned() else {
            eprintln!("Usage: pentest-agent connect <studio-url>");
            std::process::exit(1);
        };
        match pentest_core::onboarding::connect_to_studio(&url).await {
            Ok(conn) => {
                // SAFETY: mutating the environment is sound here because we are
                // still in single-threaded startup — no tokio tasks have been
                // spawned yet, so nothing reads the environment concurrently.
                // (edition 2021 also does not require `unsafe` for set_var.)
                std::env::set_var("STRIKE48_HOST", &conn.config.host);
                std::env::set_var("STRIKE48_API_URL", &conn.api_url);
                // The in-app LLM chat and connector read the MATRIX_* aliases
                // exclusively (llm_proxy.rs, liveview_connector/mod.rs,
                // connector_app.rs); without MATRIX_API_URL a first-run operator
                // registers fine but chat is silently dead.
                std::env::set_var("MATRIX_API_URL", &conn.api_url);
                std::env::set_var("STRIKE48_TENANT", &conn.config.tenant_id);
                // MATRIX_TENANT_ID leads TENANT_ENV_VARS (config.rs): without it,
                // a stale value already in the environment out-ranks the tenant we
                // just resolved — the credential-replay class this feature fixes.
                std::env::set_var("MATRIX_TENANT_ID", &conn.config.tenant_id);
                std::env::set_var("STRIKE48_INSTANCE_ID", &conn.config.instance_id);
                std::env::set_var(
                    "STRIKE48_TLS",
                    if conn.config.use_tls { "true" } else { "false" },
                );
                match &conn.mode {
                    pentest_core::onboarding::RegistrationMode::PreApproved { ott } => {
                        std::env::set_var("STRIKE48_REGISTRATION_TOKEN", ott);
                        tracing::info!(
                            "connect: onboarded to {} (pre-approved) as {}",
                            conn.api_url,
                            conn.config.instance_id
                        );
                    }
                    pentest_core::onboarding::RegistrationMode::PendingApproval => tracing::info!(
                        "connect: onboarded to {} — approve connector '{}' in Studio to finish",
                        conn.api_url,
                        conn.config.instance_id
                    ),
                }
                // Fall through to the normal startup path using the env just set.
                args.truncate(1);
            }
            Err(e) => {
                eprintln!("connect failed: {e:#}");
                std::process::exit(1);
            }
        }
    }

    let config = match load_connector_config(&args) {
        ConfigLoadResult::Ok(c) => c,
        ConfigLoadResult::Help => {
            print_usage();
            std::process::exit(0);
        }
        ConfigLoadResult::Error(e) => {
            eprintln!("Error: {}", e);
            eprintln!();
            print_usage();
            std::process::exit(1);
        }
        ConfigLoadResult::ValidationFailed(e) => {
            eprintln!("Configuration validation failed: {}", e);
            eprintln!();
            print_usage();
            std::process::exit(1);
        }
    };

    // In StrikeHub mode the host is optional (liveview-only).
    // In standalone mode the host is required for gRPC registration.
    let has_host = !config.host.is_empty();
    if !is_strikehub {
        if let Err(e) = config.validate() {
            eprintln!("Error: {}", e);
            eprintln!();
            print_usage();
            std::process::exit(1);
        }
    }

    tracing::info!("pentest-agent starting");
    if is_strikehub {
        tracing::info!(
            "  mode:      StrikeHub IPC (socket={})",
            std::env::var("STRIKEHUB_SOCKET").unwrap_or_default()
        );
    }
    if has_host {
        tracing::info!("  host:      {}", config.host);
    }
    tracing::info!("  tenant:    {}", config.tenant_id);
    tracing::info!("  instance:  {}", config.instance_id);
    tracing::info!("  tls:       {}", config.use_tls);
    tracing::info!(
        "  auth:      {}",
        if config.has_auth() {
            "jwt"
        } else {
            "ott (pending approval)"
        }
    );
    tracing::info!(
        "  aggression: {} ({}x cost)",
        config.aggression_level.display_name(),
        config.aggression_level.cost_multiplier()
    );

    // Create tool registry
    let tools = create_tool_registry();
    tracing::info!("Registered {} tools", tools.tools().len());

    // Create connector
    let mut connector = LiveViewConnector::new(config, tools);

    // Start the internal LiveView server (Dioxus WorkspaceApp on :3030 or Unix socket)
    // with shell WebSocket routes merged in
    let shell_routes = pentest_ui::shell_ws::shell_routes(ShellMode::Native);
    if let Err(e) = connector.start_liveview_server(shell_routes).await {
        tracing::error!("LiveView server failed to start: {}", e);
        // Continue anyway — tools still work, just no app UI
    }

    // Spawn log consumer (just prints events to stderr since there's no UI)
    let mut event_rx = connector.event_rx();
    tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(event) => {
                    use pentest_ui::ConnectorEvent;
                    match &event {
                        ConnectorEvent::StatusChanged(s) => {
                            tracing::info!("[status] {:?}", s);
                        }
                        ConnectorEvent::StepChanged(s) => {
                            tracing::info!("[step] {:?}", s);
                        }
                        ConnectorEvent::Log(line) => {
                            tracing::info!("[log] {}", line.message);
                        }
                        ConnectorEvent::ToolStarted { tool_name, .. } => {
                            tracing::info!("[tool] {} started", tool_name);
                        }
                        ConnectorEvent::ToolCompleted {
                            tool_name,
                            duration_ms,
                            success,
                            ..
                        } => {
                            if *success {
                                tracing::info!(
                                    "[tool] {} completed ({}ms)",
                                    tool_name,
                                    duration_ms
                                );
                            } else {
                                tracing::warn!("[tool] {} failed ({}ms)", tool_name, duration_ms);
                            }
                        }
                        ConnectorEvent::ToolFailed { tool_name, error } => {
                            tracing::error!("[tool] {} error: {}", tool_name, error);
                        }
                        ConnectorEvent::CredentialsUpdated { auth_token, .. } => {
                            tracing::info!(
                                "[auth] credentials updated (token_len={})",
                                auth_token.len()
                            );
                            // Persist so the agent auto-reconnects after restart
                            if !auth_token.is_empty() {
                                let mut s = load_settings();
                                if let Some(ref mut c) = s.last_config {
                                    c.auth_token = auth_token.clone();
                                }
                                let _ = pentest_core::settings::save_settings(&s);
                            }
                        }
                        ConnectorEvent::MatrixTokenObtained { auth_token, .. } => {
                            tracing::info!(
                                "[auth] matrix chat token obtained (token_len={})",
                                auth_token.len()
                            );
                        }
                        ConnectorEvent::ToolProgress {
                            tool_name,
                            step,
                            message,
                            ..
                        } => {
                            tracing::info!("[tool] {} step {}: {}", tool_name, step, message);
                        }
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
            }
        }
    });

    if has_host {
        // Standalone or StrikeHub+Matrix mode: connect to Strike48 and run the
        // message loop (blocks forever, auto-reconnects).
        tracing::info!("Connecting to Strike48...");
        if let Err(e) = connector.connect_and_run().await {
            tracing::error!("Connector exited with error: {}", e);
            std::process::exit(1);
        }
    } else {
        // StrikeHub liveview-only mode: no Matrix host configured, just serve
        // the LiveView UI over the Unix socket and wait for shutdown.
        tracing::info!("StrikeHub mode: serving liveview only (no Matrix URL configured)");
        tokio::signal::ctrl_c().await.ok();
        tracing::info!("Shutting down...");
        connector.shutdown();
    }

    // Flush any queued telemetry before exit so batched events survive termination.
    pentest_core::telemetry::flush();

    Ok(())
}

fn print_usage() {
    eprintln!("Usage: pentest-agent <host:port> [OPTIONS]");
    eprintln!();
    eprintln!("  Headless Strike48 connector agent. Connects to the platform,");
    eprintln!("  registers tools, and serves the workspace app via LiveView.");
    eprintln!("  When STRIKEHUB_SOCKET is set, runs in IPC mode (host is optional).");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --token, -t <jwt>       JWT auth token");
    eprintln!("  --tenant <id>           Tenant ID (default: \"default\")");
    eprintln!("  --instance-id <id>      Instance ID (default: auto-generated)");
    eprintln!("  --aggression, -a <lvl>  Specialist spawning aggressiveness:");
    eprintln!("                            conservative (c) - minimal spawning, fast");
    eprintln!("                            balanced (b)     - default, intelligent");
    eprintln!("                            aggressive (a)   - thorough, more costly");
    eprintln!("                            maximum (max,m)  - exhaustive, expensive");
    eprintln!("  --no-tls                Disable TLS");
    eprintln!("  --help, -h              Show this help");
    eprintln!();
    eprintln!("Environment variables:");
    eprintln!("  STRIKE48_HOST        Server host:port");
    eprintln!("  STRIKE48_URL         Alias for STRIKE48_HOST (StrikeHub)");
    eprintln!("  STRIKE48_API_URL     Alias for STRIKE48_HOST");
    eprintln!("  STRIKE48_TOKEN       JWT auth token");
    eprintln!("  STRIKE48_TENANT      Tenant ID");
    eprintln!("  STRIKE48_INSTANCE_ID Instance ID");
    eprintln!("  STRIKE48_TLS         \"true\" or \"false\"");
    eprintln!(
        "  AGGRESSION_LEVEL     Specialist spawning: conservative|balanced|aggressive|maximum"
    );
    eprintln!("  STRIKEHUB_SOCKET     Unix socket path (IPC mode)");
}

/// Initialize usage telemetry from persisted settings (#278, #527), mirroring
/// the desktop app's startup resolution in `connector_app`:
/// - `telemetry_enabled`: the persisted opt-out flag (on by default);
/// - `device_id`: the persistent per-install identity, generated on first run
///   and persisted so restarts (and `load_connector_config`, which reads the
///   same settings file) keep one stable identity;
/// - easy mode: `resolve_easy_mode` with `false` as the per-app default —
///   headless only serves the full workspace app, while a persisted user
///   choice or a build-time `PICK_EASY_MODE` still wins.
///
/// No-DSN builds (local dev, forks) and opt-out installs stay silent no-ops;
/// `telemetry::init`/`install` log exactly one info line with the resolved
/// state so a silent install is diagnosable from its log file (#527).
fn init_telemetry() {
    let mut settings = load_settings();
    settings.ensure_device_id();
    // Persist the generated device id (plus any migration load_settings
    // performed), matching the desktop app's startup path. Best-effort: a
    // read-only filesystem degrades to a per-run identity rather than a crash.
    let _ = save_settings(&settings);
    let easy_mode = pentest_core::config::resolve_easy_mode(settings.easy_mode, false);
    pentest_core::telemetry::init(settings.telemetry_enabled, &settings.device_id, easy_mode);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the tests below, which mutate process-global env vars
    /// (HOME / XDG_CONFIG_HOME) to point the settings dir at a tempdir. Same
    /// pattern as `ENV_LOCK` in `crates/core/src/config.rs`.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Point the settings dir at a tempdir and return it. HOME covers the
    /// macOS/Windows `dirs::config_dir()` result, XDG_CONFIG_HOME the Linux
    /// one; both land inside the tempdir, so the real settings file is never
    /// touched. (Edition 2021: set_var is safe here — single-threaded test,
    /// serialized by ENV_LOCK.)
    fn isolated_settings_dir() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("HOME", tmp.path());
        std::env::set_var("XDG_CONFIG_HOME", tmp.path());
        tmp
    }

    /// Restore HOME / XDG_CONFIG_HOME. Called before the first assertion of
    /// each scenario so a failing test does not leak env state.
    fn restore_env(prev_home: &Option<String>, prev_xdg: &Option<String>) {
        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        };
        match prev_xdg {
            Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        };
    }

    /// Regression test for #527: the headless startup path must call
    /// `telemetry::init` with the settings-resolved identity. Before the fix,
    /// `main()` never called `telemetry::init` at all (only `flush()`), so
    /// `telemetry::last_identity()` was `None` after a headless-style startup
    /// and no headless deployment could ever report sessions or activity.
    #[test]
    fn headless_startup_initializes_telemetry_with_resolved_identity() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev_home = std::env::var("HOME").ok();
        let prev_xdg = std::env::var("XDG_CONFIG_HOME").ok();

        // --- Scenario 1: fresh install (no settings file). ---
        let _tmp1 = isolated_settings_dir(); // guard: dir lives until end of test
        init_telemetry();
        let first_run = load_settings(); // reads the file init_telemetry persisted
        let first_device_id = first_run.device_id.clone();
        restore_env(&prev_home, &prev_xdg);

        assert!(
            !first_run.device_id.is_empty(),
            "device id must be generated"
        );
        assert!(
            first_run.telemetry_enabled,
            "telemetry is opt-out: enabled by default"
        );
        match pentest_core::telemetry::last_identity() {
            Some((id, easy)) => {
                assert_eq!(id, first_device_id, "init must use the persisted device id");
                assert_eq!(
                    easy,
                    pentest_core::config::resolve_easy_mode(None, false),
                    "headless per-app default is easy mode off (a build-time PICK_EASY_MODE may override)"
                );
            }
            None => panic!("headless startup must call telemetry::init (#527)"),
        }

        // --- Scenario 2: restart with a persisted opt-out and an explicit
        // easy-mode choice. The same device id must be reused (one identity
        // per install) and the persisted values must win. ---
        let _tmp2 = isolated_settings_dir(); // guard: dir lives until end of test
        let mut second_run = first_run;
        second_run.telemetry_enabled = false;
        second_run.easy_mode = Some(true);
        save_settings(&second_run).expect("persist opt-out settings");
        init_telemetry();
        restore_env(&prev_home, &prev_xdg);

        match pentest_core::telemetry::last_identity() {
            Some((id, easy)) => {
                assert_eq!(
                    id, first_device_id,
                    "device id must be stable across restarts"
                );
                assert!(
                    easy,
                    "persisted easy-mode choice must win over the per-app default"
                );
            }
            None => panic!("headless restart must still call telemetry::init (#527)"),
        }
    }
}
