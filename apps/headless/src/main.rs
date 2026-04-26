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
use pentest_core::settings::load_settings;
use pentest_tools::create_tool_registry;
use pentest_ui::LiveViewConnector;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging (stderr only — no window, no file by default)
    pentest_core::logging::init_logging("info");

    let is_strikehub = std::env::var("STRIKEHUB_SOCKET").is_ok();

    let args: Vec<String> = std::env::args().collect();
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
