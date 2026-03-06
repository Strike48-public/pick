//! URL-based routing for the workspace UI.
//!
//! This module defines the `Route` enum used by `dioxus-router` to map URL
//! paths to page components.  It replaces the manual `NavPage` enum +
//! `active_page` signal pattern with proper URL-driven navigation.
//!
//! ## Architecture
//!
//! ```text
//!  Browser URL                   Route enum                 Component
//!  ──────────────────────────────────────────────────────────────────────
//!  /                             Home (redirects)           -> /dashboard
//!  /dashboard                    Dashboard                  Dashboard
//!  /tools                        Tools                      ToolsPage
//!  /files                        Files                      FileBrowser
//!  /shell                        Shell                      InteractiveShell
//!  /logs                         Logs                       Terminal (logs)
//!  /settings                     Settings                   SettingsPage
//!  /agents                       Agents                     AgentsPage
//!  /agents/:id                   AgentDetail { id }         AgentDetail
//! ```
//!
//! ## Migration from NavPage
//!
//! The existing `NavPage` enum in `sidebar.rs` drives navigation via:
//! ```ignore
//! let mut active_page = use_signal(|| NavPage::Dashboard);
//! // ... in Sidebar:
//! on_navigate: move |nav_page| active_page.set(nav_page),
//! ```
//!
//! With URL routing, the Sidebar instead pushes routes:
//! ```ignore
//! let nav = use_navigator();
//! nav.push(Route::Dashboard {});
//! ```
//!
//! And WorkspaceApp wraps the tree in `Router::<Route>`:
//! ```ignore
//! rsx! {
//!     Router::<Route> {}
//! }
//! ```
//!
//! ## Dependencies
//!
//! Requires `dioxus` with the `router` feature enabled.  In Dioxus 0.7 the
//! router is included in the main `dioxus` crate — no separate
//! `dioxus-router` dependency is needed.

use dioxus::prelude::*;
use pentest_core::terminal::TerminalLine;

use super::app_state::use_app_state;
use super::app_layout::AppLayout;
use super::chat_panel::ChatPanel;
use super::dashboard::Dashboard;
use super::file_browser::FileBrowser;
use super::shell::InteractiveShell;
use super::icons::{MessageCircle, STRIKE48_SIDEBAR_LOGO_SVG};
use super::settings_page::SettingsPage;
use super::sidebar::{NavPage, Sidebar, ALL_PAGES};
use super::status_bar::StatusBar;
use super::tools_page::ToolsPage;
use super::terminal::Terminal;
use crate::liveview_server::get_workspace_path;
use crate::theme::{responsive_css, tailwind_css, theme_css, utils_css};

// ---------------------------------------------------------------------------
// Route enum
// ---------------------------------------------------------------------------

/// Application routes.
///
/// Each variant maps to a URL path.  The `#[layout(WorkspaceLayout)]`
/// attribute wraps every route in the shared sidebar + chrome.
///
/// NOTE: Dioxus 0.7 derives `Routable` from the `dioxus::prelude` re-export.
/// The `#[route]` and `#[layout]` attributes are processed by the derive macro
/// to build the router table at compile time.
#[derive(Clone, Debug, PartialEq, Routable)]
#[rustfmt::skip]
pub enum Route {
    // All routes share the workspace layout (sidebar + header + chat overlay)
    #[layout(WorkspaceLayout)]

        /// Root path — immediately redirects to /dashboard.
        #[redirect("/", || Route::Dashboard {})]

        /// Dashboard overview page.
        #[route("/dashboard")]
        Dashboard {},

        /// Available pentest tools.
        #[route("/tools")]
        Tools {},

        /// Workspace file browser.
        #[route("/files")]
        Files {},

        /// Interactive shell (PTY).
        #[route("/shell")]
        Shell {},

        /// Terminal log viewer.
        #[route("/logs")]
        Logs {},

        /// Application settings.
        #[route("/settings")]
        Settings {},

        /// Agent management — list all agents.
        #[route("/agents")]
        Agents {},

        /// Agent detail/edit page.
        #[route("/agents/:id")]
        AgentDetail { id: String },
}

// ---------------------------------------------------------------------------
// Route ↔ NavPage bridging
// ---------------------------------------------------------------------------

impl Route {
    /// Convert a `Route` to the corresponding `NavPage` for sidebar highlighting.
    ///
    /// Agent routes don't have a direct NavPage equivalent yet, so they
    /// return `None`.
    pub fn to_nav_page(&self) -> Option<NavPage> {
        match self {
            Route::Dashboard {} => Some(NavPage::Dashboard),
            Route::Tools {} => Some(NavPage::Tools),
            Route::Files {} => Some(NavPage::Files),
            Route::Shell {} => Some(NavPage::Shell),
            Route::Logs {} => Some(NavPage::Logs),
            Route::Settings {} => Some(NavPage::Settings),
            Route::Agents {} | Route::AgentDetail { .. } => None,
        }
    }
}

impl NavPage {
    /// Convert a `NavPage` to the corresponding `Route` for navigation.
    pub fn to_route(&self) -> Route {
        match self {
            NavPage::Dashboard => Route::Dashboard {},
            NavPage::Tools => Route::Tools {},
            NavPage::Files => Route::Files {},
            NavPage::Shell => Route::Shell {},
            NavPage::Logs => Route::Logs {},
            NavPage::Settings => Route::Settings {},
        }
    }
}

// ---------------------------------------------------------------------------
// WorkspaceLayout — shared chrome around all routes
// ---------------------------------------------------------------------------

/// Layout component wrapping every route with the sidebar, mobile header,
/// and chat overlay.
///
/// This replaces the monolithic `WorkspaceApp` component.  State is read
/// from the centralized `AppState` context instead of being threaded via
/// props.
#[component]
pub fn WorkspaceLayout() -> Element {
    let mut state = use_app_state();
    let nav = navigator();

    let chat_visible = state.read().chat_visible;

    // Determine active NavPage from the current route for sidebar highlight.
    let current_route: Route = use_route();
    let active_page = current_route.to_nav_page().unwrap_or(NavPage::Dashboard);

    // Unread log badge
    let unread = state.read().unread_log_count();

    // CSS
    let combined_css = format!("{}\n{}\n{}\n{}", theme_css(), responsive_css(), utils_css(), tailwind_css());

    let status_msg = state.read().status_message.clone();
    let error_msg = state.read().error_message.clone();

    let page_subtitle = match active_page {
        NavPage::Dashboard => {
            let ws = get_workspace_path();
            if ws.is_empty() { None } else { Some(ws) }
        }
        NavPage::Tools => Some("12 connector tools available".to_string()),
        _ => None,
    };

    let page_actions = if active_page == NavPage::Dashboard {
        let mut state_w = state;
        Some(rsx! {
            button {
                class: "desktop-header-btn",
                title: "Chat",
                onclick: move |_| state_w.write().open_chat(None),
                MessageCircle { size: 20 }
            }
        })
    } else {
        None
    };

    rsx! {
        style { {combined_css} }

        AppLayout {
            active_page,
            page_subtitle,
            page_actions,
            on_navigate: move |nav_page: NavPage| {
                if nav_page == NavPage::Logs {
                    state.write().mark_logs_read();
                }
                nav.push(nav_page.to_route());
            },
            connected: true,
            unread_logs: unread,
            status_message: status_msg,
            error_message: error_msg,

            // Page content — rendered by the router via Outlet
            Outlet::<Route> {}

            // Persistent shell — always mounted, toggled via CSS so the PTY
            // session survives navigation to other pages.
            div {
                class: if active_page == NavPage::Shell { "shell-pane-active" } else { "hidden" },
                InteractiveShell {}
            }
        }

        // Chat panel overlay
        ChatPanel {
            visible: chat_visible,
            api_url: state.read().matrix_api_url.clone(),
            auth_token: state.read().matrix_auth_token.clone(),
            tenant_id: crate::session::get_tenant_id(),
            on_close: move |_| state.write().close_chat(),
            send_mailbox: {
                let mailbox_val = state.read().chat_mailbox.clone();
                use_signal(move || mailbox_val)
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Route page components
// ---------------------------------------------------------------------------

// Each of these is a thin wrapper that reads from AppState context and
// renders the existing page component.  This keeps the migration incremental —
// the actual page components (Dashboard, ToolsPage, etc.) don't need to
// change immediately.

/// Dashboard route page.
#[component]
fn Dashboard() -> Element {
    let state = use_app_state();
    let workspace = get_workspace_path();
    let ws_display = if workspace.is_empty() {
        "No workspace path".to_string()
    } else {
        workspace.clone()
    };

    rsx! {
        div { class: "content-area",
            super::dashboard::Dashboard {
                host: ws_display,
                on_open_chat: move |msg: String| state.write().open_chat(Some(msg)),
                on_open_shell: move |_| {
                    let nav = navigator();
                    nav.push(Route::Shell {});
                },
                recent_lines: state.read().terminal_lines.clone(),
            }
        }
    }
}

/// Tools route page.
#[component]
fn Tools() -> Element {
    let state = use_app_state();

    rsx! {
        div { class: "content-area",
            ToolsPage {
                on_open_chat: move |msg: String| state.write().open_chat(Some(msg)),
            }
        }
    }
}

/// Files route page.
#[component]
fn Files() -> Element {
    let workspace = get_workspace_path();

    rsx! {
        div { class: "content-area",
            div { class: "workspace-pane",
                if !workspace.is_empty() {
                    FileBrowser { workspace_path: workspace }
                } else {
                    div { class: "empty-state", "No workspace available" }
                }
            }
        }
    }
}

/// Shell route page — empty placeholder.
///
/// The actual `InteractiveShell` is rendered persistently in `WorkspaceLayout`
/// (outside the Outlet) so the PTY session survives navigation.
#[component]
fn Shell() -> Element {
    rsx! {}
}

/// Logs route page.
#[component]
fn Logs() -> Element {
    let mut state = use_app_state();

    // Mark logs as read when viewing
    state.write().mark_logs_read();

    let lines = state.read().terminal_lines.clone();

    rsx! {
        div { class: "content-area",
            div { class: "main-content flex-col-full",
                div { class: "flex-scroll",
                    Terminal { lines }
                }
            }
        }
    }
}

/// Settings route page.
#[component]
fn Settings() -> Element {
    let mut state = use_app_state();

    // Keep progress + ready state in sync with process-global — survives reconnects.
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let global = crate::download_manager::get_download_progress();
            let current = state.read().download_progress;
            if global != current {
                state.write().download_progress = global;
            }
            // Check if setup completed since last poll.
            if global.is_none() && !state.read().blackarch_downloaded {
                if crate::download_manager::is_blackarch_ready() {
                    state.write().mark_blackarch_downloaded();
                }
            }
        }
    });

    let shell_mode = state.read().shell_mode;
    let blackarch_downloaded = state.read().blackarch_downloaded;
    let download_progress = state.read().download_progress;

    let setup_error = state.read().setup_error.clone();

    rsx! {
        div { class: "content-area",
            SettingsPage {
                show_connection: false,
                blackarch_downloaded,
                download_progress,
                setup_error,
                on_start_download: move |_| {
                    state.write().setup_error = None;
                    state.write().push_terminal_line(TerminalLine::info("Setting up BlackArch environment..."));
                    // Update state immediately so the UI switches to the progress bar
                    // without waiting for the next 500ms poll tick.
                    crate::download_manager::set_global_progress(Some(-1.0));
                    state.write().download_progress = Some(-1.0);
                    spawn(async move {
                        #[cfg(all(feature = "shell-ws", not(target_os = "android")))]
                        {
                            let result = pentest_platform::desktop::sandbox::get_sandbox_manager()
                                .await
                                .map_err(|e| format!("{}", e))
                                .and_then(|m| Ok(m));
                            let result = match result {
                                Ok(manager) => manager.ensure_ready().await.map_err(|e| format!("{}", e)),
                                Err(e) => Err(e),
                            };
                            crate::download_manager::set_global_progress(None);
                            match result {
                                Ok(()) => {
                                    state.write().mark_blackarch_downloaded();
                                    state.write().push_terminal_line(TerminalLine::success("BlackArch environment ready.".to_string()));
                                }
                                Err(e) => {
                                    state.write().setup_error = Some(e.clone());
                                    state.write().push_terminal_line(TerminalLine::error(format!("Setup failed: {}", e)));
                                }
                            }
                        }
                    });
                },
                shell_mode,
                on_shell_mode_change: move |mode: ShellMode| {
                    state.write().set_shell_mode(mode);
                    #[cfg(all(feature = "shell-ws", not(target_os = "android")))]
                    pentest_platform::set_use_sandbox(mode == ShellMode::Proot);
                },
            }
        }
    }
}

/// Agents list route page (delegates to agent_page module).
#[component]
fn Agents() -> Element {
    rsx! {
        div { class: "content-area",
            super::agent_page::AgentsPage {}
        }
    }
}

/// Agent detail/edit route page.
#[component]
fn AgentDetail(id: String) -> Element {
    rsx! {
        div { class: "content-area",
            super::agent_page::AgentDetail { id }
        }
    }
}

// ---------------------------------------------------------------------------
// Router entry point
// ---------------------------------------------------------------------------

/// Top-level entry point that replaces `WorkspaceApp`.
///
/// Provides AppState context, fetches credentials, and mounts the router.
///
/// ```ignore
/// // In main.rs or liveview_server.rs:
/// dioxus::launch(WorkspaceRouter);
/// ```
#[component]
pub fn WorkspaceRouter() -> Element {
    // Provide centralized state once at the root
    let mut state = super::app_state::provide_app_state();

    // Fetch chat credentials (same logic as existing WorkspaceApp)
    let _cred_fetch = use_future(move || async move {
        tracing::info!("[WorkspaceRouter] fetching credentials via /auth/refresh");

        match document::eval(r#"
            try {
                var origin = window.location.origin;
                var resp = await fetch(origin + '/auth/refresh', {
                    method: 'POST',
                    credentials: 'include',
                    headers: { 'Accept': 'application/json' }
                });
                if (!resp.ok) return JSON.stringify({ error: 'HTTP ' + resp.status });
                var data = await resp.json();
                return JSON.stringify({ origin: origin, access_token: data.access_token || '' });
            } catch (e) {
                return JSON.stringify({ error: e.message });
            }
        "#).await {
            Ok(val) => {
                if let Some(json_str) = val.as_str() {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json_str) {
                        if let Some(err) = parsed.get("error").and_then(|v| v.as_str()) {
                            tracing::error!("[WorkspaceRouter] /auth/refresh failed: {}", err);
                        } else {
                            let origin = parsed.get("origin").and_then(|v| v.as_str()).unwrap_or_default();
                            let token = parsed.get("access_token").and_then(|v| v.as_str()).unwrap_or_default();
                            if !origin.is_empty() && !token.is_empty() {
                                tracing::info!(
                                    "[WorkspaceRouter] got access token (origin={} token_len={})",
                                    origin, token.len()
                                );
                                state.write().set_chat_credentials(
                                    origin.to_string(),
                                    token.to_string(),
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("JS eval failed (credential fetch): {e}");
            }
        }
    });

    rsx! {
        Router::<Route> {}
    }
}
