//! Pentest Connector UI Components
//!
//! Shared Dioxus UI components for all platforms.

pub mod components;
#[cfg(feature = "connector")]
pub mod connector_app;
pub mod download_manager;
pub mod ipc;
#[cfg(feature = "connector")]
pub mod liveview_connector;
pub mod liveview_server;
mod platform_helper;
pub mod session;
#[cfg(feature = "shell-ws")]
pub mod shell_ws;
pub mod theme;
pub mod view_transitions;

pub use components::*;
#[cfg(feature = "connector")]
pub use connector_app::{connector_app, ConnectorAppConfig};
#[cfg(feature = "connector")]
pub use liveview_connector::{ConnectorEvent, LiveViewConnector};
pub use liveview_server::*;
pub use theme::*;

// ---------------------------------------------------------------------------
// Shared app screen routing
// ---------------------------------------------------------------------------

use pentest_core::state::ConnectorStatus;

/// Screen routing state for all connector apps.
#[derive(Debug, Clone, PartialEq)]
pub enum AppScreen {
    Connect,
    Connecting(ConnectingStep),
    Connected(NavPage),
}

/// Compute the current screen from connector status, connecting step, and active page.
pub fn compute_screen(
    status: &ConnectorStatus,
    connecting_step: &Option<ConnectingStep>,
    active_page: &NavPage,
) -> AppScreen {
    match status {
        ConnectorStatus::Disconnected | ConnectorStatus::Error(_) => AppScreen::Connect,
        ConnectorStatus::Connecting | ConnectorStatus::Reconnecting => {
            let step = connecting_step.unwrap_or(ConnectingStep::Connecting);
            AppScreen::Connecting(step)
        }
        ConnectorStatus::Registered => AppScreen::Connected(*active_page),
    }
}

// ---------------------------------------------------------------------------
// Shared connector event loop
// ---------------------------------------------------------------------------

/// Dioxus signals used by the connector event loop.
#[cfg(feature = "connector")]
pub struct EventLoopSignals {
    pub terminal_lines: dioxus::prelude::Signal<Vec<pentest_core::terminal::TerminalLine>>,
    pub status: dioxus::prelude::Signal<ConnectorStatus>,
    pub connecting_step: dioxus::prelude::Signal<Option<ConnectingStep>>,
    pub config: dioxus::prelude::Signal<pentest_core::config::ConnectorConfig>,
    pub settings: dioxus::prelude::Signal<pentest_core::config::AppSettings>,
    pub matrix_api_url: dioxus::prelude::Signal<String>,
    pub matrix_auth_token: dioxus::prelude::Signal<String>,
}

/// Run the connector event loop, dispatching events to the appropriate Dioxus signals.
///
/// This extracts the ~60-line event handler that was duplicated across all three app targets.
#[cfg(feature = "connector")]
pub async fn run_event_loop(
    mut event_rx: tokio::sync::broadcast::Receiver<ConnectorEvent>,
    mut signals: EventLoopSignals,
) {
    use dioxus::prelude::{ReadableExt, WritableExt};
    use pentest_core::settings::save_settings;
    use pentest_core::terminal::TerminalLine;

    loop {
        match event_rx.recv().await {
            Ok(event) => match event {
                ConnectorEvent::StatusChanged(new_status) => {
                    signals.status.set(new_status);
                }
                ConnectorEvent::StepChanged(step) => {
                    signals.connecting_step.set(Some(step));
                }
                ConnectorEvent::Log(line) => {
                    signals.terminal_lines.write().push(line);
                }
                ConnectorEvent::CredentialsUpdated {
                    auth_token,
                    api_url,
                } => {
                    tracing::info!("Saving connector JWT to settings");
                    let mut s = signals.settings.peek().clone();
                    let mut c = signals.config.peek().clone();
                    c.auth_token = auth_token.clone();
                    s.last_config = Some(c);
                    let _ = save_settings(&s);
                    // Only set the API URL here — the auth_token is a connector JWT
                    // (for gRPC). The Matrix server requires a session-backed token
                    // for GraphQL (obtained via browser OAuth / MatrixTokenObtained).
                    if !api_url.is_empty() {
                        signals.matrix_api_url.set(api_url);
                    }
                }
                ConnectorEvent::MatrixTokenObtained {
                    auth_token,
                    api_url,
                } => {
                    tracing::info!(
                        "Matrix access token obtained (chat only, not saving to config)"
                    );
                    if !auth_token.is_empty() && !api_url.is_empty() {
                        signals.matrix_api_url.set(api_url);
                        signals.matrix_auth_token.set(auth_token.clone());
                        crate::session::set_auth_token(&auth_token);
                        crate::session::set_tenant_id(&signals.config.peek().tenant_id);
                        crate::session::set_connector_name(&signals.config.peek().connector_name);
                    }
                }
                ConnectorEvent::ToolStarted { tool_name, params } => {
                    let details = serde_json::to_string_pretty(&params)
                        .unwrap_or_else(|_| params.to_string());
                    signals.terminal_lines.write().push(
                        TerminalLine::info(format!("[tool] {} started", tool_name))
                            .with_details(format!("args: {}", details)),
                    );
                }
                ConnectorEvent::ToolCompleted {
                    tool_name,
                    duration_ms,
                    success,
                    result,
                } => {
                    let details = serde_json::to_string_pretty(&result)
                        .unwrap_or_else(|_| result.to_string());
                    if success {
                        signals.terminal_lines.write().push(
                            TerminalLine::success(format!(
                                "[tool] {} completed ({}ms)",
                                tool_name, duration_ms
                            ))
                            .with_details(details),
                        );
                    } else {
                        signals.terminal_lines.write().push(
                            TerminalLine::error(format!(
                                "[tool] {} returned error ({}ms)",
                                tool_name, duration_ms
                            ))
                            .with_details(details),
                        );
                    }
                }
                ConnectorEvent::ToolFailed { tool_name, error } => {
                    signals.terminal_lines.write().push(
                        TerminalLine::error(format!("[tool] {} failed", tool_name))
                            .with_details(error),
                    );
                }
            },
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
        }
    }
}
