//! Pentest Connector UI Components
//!
//! Shared Dioxus UI components for all platforms.

pub mod auth_flow;
pub(crate) mod clipboard;
pub mod components;
#[cfg(feature = "connector")]
pub mod connector_app;
pub mod download_manager;
pub mod ipc;
#[cfg(feature = "connector")]
pub mod liveview_connector;
pub mod liveview_server;
pub mod logs_feed;
mod platform_helper;
pub mod session;
#[cfg(feature = "shell-ws")]
pub mod shell_ws;
pub mod text;
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
///
/// Log and tool events need nothing here: the connector's `send_event` already
/// wrote their lines to the shared Logs buffer ([`pentest_core::ui_log`]).
#[cfg(feature = "connector")]
pub async fn run_event_loop(
    mut event_rx: tokio::sync::broadcast::Receiver<ConnectorEvent>,
    mut signals: EventLoopSignals,
) {
    use dioxus::prelude::{ReadableExt, WritableExt};
    use pentest_core::settings::save_settings;

    loop {
        match event_rx.recv().await {
            Ok(event) => match event {
                ConnectorEvent::StatusChanged(new_status) => {
                    signals.status.set(new_status);
                }
                ConnectorEvent::StepChanged(step) => {
                    signals.connecting_step.set(Some(step));
                }
                ConnectorEvent::Log(_)
                | ConnectorEvent::ToolStarted { .. }
                | ConnectorEvent::ToolCompleted { .. }
                | ConnectorEvent::ToolFailed { .. }
                | ConnectorEvent::ToolProgress { .. } => {}
                ConnectorEvent::CredentialsUpdated {
                    auth_token,
                    api_url,
                } => {
                    tracing::info!("Saving connector JWT to settings");
                    // Keep the in-memory config signal in sync too: other paths
                    // persist via `last_config = Some(config.peek().clone())`, so
                    // a stale config.auth_token would clobber the fresh JWT on
                    // the next endpoint save.
                    {
                        let mut c = signals.config.write();
                        c.auth_token = auth_token.clone();
                    }
                    let new_config = signals.config.peek().clone();
                    // Persist through the authoritative `settings` signal (not a
                    // detached peek().clone() copy) so a later signal-based
                    // save_settings can't clobber the freshly minted JWT back
                    // off disk. Same pattern as MatrixTokenObtained below.
                    // See pick#374.
                    {
                        let mut s = signals.settings.write();
                        match s.last_config.as_mut() {
                            Some(lc) => lc.auth_token = auth_token,
                            None => s.last_config = Some(new_config),
                        }
                        let _ = save_settings(&s);
                    }
                    // Only set the API URL here — the auth_token is a connector JWT
                    // (for gRPC). The Matrix server requires a session-backed token
                    // for GraphQL (obtained via browser OAuth / MatrixTokenObtained).
                    if !api_url.is_empty() {
                        signals.matrix_api_url.set(api_url);
                    }
                    // The OTT is single-use; once the SDK has persisted
                    // connector credentials we no longer need the staged file.
                    pentest_core::matrix::clear_staged_ott();
                }
                ConnectorEvent::MatrixTokenObtained {
                    auth_token,
                    api_url,
                } => {
                    tracing::info!(
                        "Matrix access token obtained (chat only, not saving to config)"
                    );
                    if !auth_token.is_empty() && !api_url.is_empty() {
                        signals.matrix_api_url.set(api_url.clone());
                        signals.matrix_auth_token.set(auth_token.clone());
                        crate::session::set_auth_token(&auth_token);
                        crate::session::set_tenant_id(&signals.config.peek().tenant_id);
                        crate::session::set_connector_name(&signals.config.peek().connector_name);
                        // Persist for relaunch: token → OS secure store; the API
                        // URL → settings via the authoritative in-memory signal so
                        // a later signal-based save_settings can't clobber it back
                        // to empty (which forced a fresh sign-in every launch).
                        {
                            let mut s = signals.settings.write();
                            s.matrix_api_url = api_url.clone();
                            let _ = save_settings(&s);
                        }
                        crate::session::persist_matrix_token(&auth_token);
                    }
                }
            },
            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
        }
    }
}
