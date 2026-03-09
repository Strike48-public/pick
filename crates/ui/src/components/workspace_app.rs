//! Workspace App — sidebar layout matching the main connector apps
//!
//! This component provides a unified interface exposed through Strike48
//! with a sidebar for navigating between Dashboard, Tools, Files, Shell,
//! and Logs — the same nav items as the desktop/mobile/web apps.
//!
//! `WorkspaceApp` is the top-level orchestrator (signals, effects, layout).
//! `WorkspacePages` handles routing between the individual page views.

use dioxus::prelude::*;

use super::app_layout::AppLayout;
use super::chat_panel::ChatPanel;
use super::dashboard::Dashboard;
use super::file_browser::FileBrowser;
use super::help_modal::HelpModal;
use super::icons::MessageCircle;
use super::keyboard_shortcuts::KeyboardShortcuts;
use super::settings_page::SettingsPage;
use super::shell::InteractiveShell;
use super::sidebar::NavPage;
use super::terminal::Terminal;
use super::tools_page::ToolsPage;
use crate::liveview_server::{get_terminal_lines, get_workspace_path, terminal_lines_count};
use crate::theme::{responsive_css, tailwind_css, theme_css, utils_css};
use pentest_core::config::ShellMode;
use pentest_core::settings::{load_settings, save_settings};
use pentest_core::terminal::TerminalLine;

// ---------------------------------------------------------------------------
// WorkspacePages — page router
// ---------------------------------------------------------------------------

/// Props for [`WorkspacePages`].
#[derive(Props, Clone, PartialEq)]
pub struct WorkspacePagesProps {
    /// Which page is currently active.
    active_page: NavPage,
    /// Workspace root path (e.g. `/workspace`).
    workspace: String,
    /// Live terminal output lines (shared signal — Signal is Copy).
    terminal_lines: Signal<Vec<TerminalLine>>,
    /// Callback to navigate to the chat page, optionally with a pre-filled message.
    on_open_chat: EventHandler<String>,
    /// Callback to navigate to the Shell page.
    on_open_shell: EventHandler<()>,
    /// Whether BlackArch ISO has been downloaded.
    blackarch_downloaded: bool,
    /// Current download progress (0.0–1.0), or None if idle.
    download_progress: Option<f64>,
    /// Error message from the last setup attempt, if any.
    setup_error: Option<String>,
    /// Callback to start the BlackArch ISO download.
    on_start_download: EventHandler<()>,
    /// Current shell mode.
    shell_mode: ShellMode,
    /// Callback when the user changes the shell mode.
    on_shell_mode_change: EventHandler<ShellMode>,
    /// Selected WiFi adapter for scanning.
    #[props(default)]
    wifi_adapter: Option<String>,
    /// Callback when the user changes the WiFi adapter.
    #[props(default)]
    on_wifi_adapter_change: EventHandler<Option<String>>,
    /// Matrix API URL for chat.
    api_url: String,
    /// Auth token for chat.
    auth_token: String,
    /// Tenant/realm name for connector tool pattern resolution.
    tenant_id: String,
    /// Shared chat mailbox for pre-filled messages.
    chat_mailbox: Signal<Option<String>>,
    /// Mailbox for opening a specific conversation by ID.
    conversation_mailbox: Signal<Option<String>>,
}

/// Routes between Dashboard, Tools, Files, Shell, Logs, and Settings.
///
/// This is a pure presentation component — all state lives in the parent
/// `WorkspaceApp` and is threaded through props.
#[component]
pub fn WorkspacePages(props: WorkspacePagesProps) -> Element {
    let page = props.active_page;
    let workspace = props.workspace;
    let terminal_lines = props.terminal_lines;
    let on_open_chat = props.on_open_chat;
    let on_open_shell = props.on_open_shell;

    rsx! {
        div { class: "content-area",
            // Dashboard
            if page == NavPage::Dashboard {
                {
                    let ws_display = if workspace.is_empty() { "No workspace path".to_string() } else { workspace.clone() };
                    rsx! {
                        Dashboard {
                            host: ws_display,
                            on_open_chat: move |msg: String| on_open_chat.call(msg),
                            on_open_shell: move |_| on_open_shell.call(()),
                            recent_lines: terminal_lines.read().clone(),
                        }
                    }
                }
            }

            // Tools
            if page == NavPage::Tools {
                ToolsPage {
                    on_open_chat: move |msg: String| on_open_chat.call(msg),
                }
            }

            // Files — always mounted so directory state is preserved
            div {
                class: if page == NavPage::Files { "workspace-pane" } else { "workspace-pane hidden" },
                if !workspace.is_empty() {
                    FileBrowser { workspace_path: workspace.clone() }
                } else {
                    div {
                        class: "empty-state",
                        "No workspace available"
                    }
                }
            }

            // Shell — always mounted for persistent WebSocket
            div {
                class: if page == NavPage::Shell { "shell-pane-active" } else { "hidden" },
                InteractiveShell {
                    shell_mode: match props.shell_mode {
                        ShellMode::Native => "native".to_string(),
                        ShellMode::Proot => "proot".to_string(),
                    },
                }
            }

            // Chat — full-page view
            if page == NavPage::Chat {
                ChatPanel {
                    visible: true,
                    api_url: props.api_url.clone(),
                    auth_token: props.auth_token.clone(),
                    tenant_id: props.tenant_id.clone(),
                    on_close: move |_| {},
                    send_mailbox: props.chat_mailbox,
                    full_page: true,
                    open_conversation_id: props.conversation_mailbox,
                }
            }

            // Logs
            if page == NavPage::Logs {
                div { class: "main-content flex-col-full",
                    div { class: "flex-scroll",
                        Terminal { lines: terminal_lines.read().clone() }
                    }
                }
            }

            // Settings
            if page == NavPage::Settings {
                SettingsPage {
                    show_connection: false,
                    blackarch_downloaded: props.blackarch_downloaded,
                    download_progress: props.download_progress,
                    setup_error: props.setup_error.clone(),
                    on_start_download: move |_| props.on_start_download.call(()),
                    shell_mode: props.shell_mode,
                    on_shell_mode_change: move |mode: ShellMode| props.on_shell_mode_change.call(mode),
                    wifi_adapter: props.wifi_adapter.clone(),
                    on_wifi_adapter_change: move |adapter: Option<String>| props.on_wifi_adapter_change.call(adapter),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// WorkspaceApp — top-level orchestrator
// ---------------------------------------------------------------------------

/// Workspace App component with full sidebar matching the connector apps.
///
/// Responsibilities:
/// 1. Own all top-level signals (active page, sidebar state, chat credentials).
/// 2. Run async effects (credential fetch).
/// 3. Compose layout: mobile header, sidebar, [`WorkspacePages`], [`ChatPanel`].
#[component]
pub fn WorkspaceApp() -> Element {
    let mut active_page = use_signal(|| NavPage::Dashboard);
    let _sidebar_open = use_signal(|| false); // managed by AppLayout
                                              // Initialise from the global buffer (populated by the connector's send_event)
    let mut terminal_lines = use_signal(get_terminal_lines);
    let mut last_seen_terminal_count = use_signal(|| 0usize);
    let workspace = get_workspace_path();

    // Poll the global terminal buffer every second to pick up new connector events.
    // This is necessary in headless/liveview mode where the connector runs in a
    // separate task and cannot directly write to a Dioxus signal.
    let mut synced_count = use_signal(terminal_lines_count);
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let global_count = terminal_lines_count();
            if global_count != synced_count() {
                terminal_lines.set(get_terminal_lines());
                synced_count.set(global_count);
            }
        }
    });

    // Persisted settings (shell mode, downloads)
    let mut settings = use_signal(|| {
        let s = load_settings();
        let _ = save_settings(&s);
        s
    });
    let mut download_progress: Signal<Option<f64>> =
        use_signal(crate::download_manager::get_download_progress);
    let mut blackarch_downloaded = use_signal(crate::download_manager::is_blackarch_ready);
    let mut setup_error: Signal<Option<String>> = use_signal(|| None);

    // Poll global progress + readiness — survives liveview reconnects because the
    // global progress state lives in a process-wide static, not in component signals.
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let global = crate::download_manager::get_download_progress();
            if global != *download_progress.read() {
                download_progress.set(global);
            }
            // Check if setup completed since last poll.
            if global.is_none()
                && !*blackarch_downloaded.read()
                && crate::download_manager::is_blackarch_ready()
            {
                blackarch_downloaded.set(true);
            }
        }
    });

    // help modal state
    let mut help_visible = use_signal(|| false);

    // chat state — credentials obtained from the Studio session via /auth/refresh
    let mut matrix_api_url = use_signal(String::new);
    let mut matrix_auth_token = use_signal(String::new);
    let mut chat_mailbox: Signal<Option<String>> = use_signal(|| None);
    let mut conversation_mailbox: Signal<Option<String>> = use_signal(|| None);

    // Get a GraphQL access token from the Studio session.
    // Strategy 1: Read window.__MATRIX_SESSION_TOKEN__ (injected by Strike48 proxy)
    // Strategy 2: POST /auth/refresh using the browser's _matrix_sid session cookie
    let _cred_fetch = use_future(move || async move {
        tracing::info!("[WorkspaceApp] fetching credentials...");

        match document::eval(r#"
            try {
                var result = {};
                // Prefer __MATRIX_API_URL__ (injected by StrikeHub proxy) over
                // window.location.origin which may be a custom scheme like connector://
                result.origin = window.__MATRIX_API_URL__ || window.location.origin;
                result.href = window.location.href;

                // Debug: log all __MATRIX* and __st globals
                var globals = {};
                for (var k in window) {
                    if (k.startsWith('__MATRIX') || k.startsWith('__matrix') || k === '__st') {
                        globals[k] = typeof window[k] === 'string' ? window[k].substring(0, 40) + '...' : typeof window[k];
                    }
                }
                var st = new URLSearchParams(window.location.search).get('__st') || '';
                console.log('[WorkspaceApp] credential scan:', JSON.stringify({
                    globals: globals,
                    st_from_url: st ? st.substring(0, 40) + '...' : '(empty)',
                    origin: result.origin,
                    search: window.location.search.substring(0, 100)
                }));

                // Strategy 0: __st query param (iframe session token injected by Strike48 proxy)
                if (st) {
                    result.access_token = st;
                    result.source = 'url_st_param';
                    return JSON.stringify(result);
                }

                // Strategy 1: __MATRIX_SESSION_TOKEN__ (injected by Strike48 proxy)
                var sessionToken = window.__MATRIX_SESSION_TOKEN__ || '';
                if (sessionToken) {
                    result.access_token = sessionToken;
                    result.source = 'session_token_global';
                    return JSON.stringify(result);
                }

                // Strategy 2: __MATRIX_ACCESS_TOKEN__ (Keycloak JWT set by Strike48)
                var accessToken = window.__MATRIX_ACCESS_TOKEN__ || '';
                if (accessToken) {
                    result.access_token = accessToken;
                    result.source = 'access_token_global';
                    return JSON.stringify(result);
                }

                // Strategy 3: __MATRIX_AUTH_TOKEN__ (set by KubeStudio-style injection)
                var authToken = window.__MATRIX_AUTH_TOKEN__ || '';
                if (authToken) {
                    result.access_token = authToken;
                    result.source = 'auth_token_global';
                    return JSON.stringify(result);
                }

                // Strategy 3: POST /auth/refresh with session cookie
                var resp = await fetch(result.origin + '/auth/refresh', {
                    method: 'POST',
                    credentials: 'include',
                    headers: { 'Accept': 'application/json' }
                });
                if (!resp.ok) {
                    result.error = 'HTTP ' + resp.status;
                    return JSON.stringify(result);
                }
                var data = await resp.json();
                result.access_token = data.access_token || '';
                result.source = 'auth_refresh';
                return JSON.stringify(result);
            } catch (e) {
                return JSON.stringify({ error: e.message, origin: window.location.origin, href: window.location.href });
            }
        "#).await {
            Ok(val) => {
                if let Some(json_str) = val.as_str() {
                    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(json_str) {
                        if let Some(err) = parsed.get("error").and_then(|v| v.as_str()) {
                            let origin = parsed.get("origin").and_then(|v| v.as_str()).unwrap_or("?");
                            let href = parsed.get("href").and_then(|v| v.as_str()).unwrap_or("?");
                            tracing::error!(
                                "[WorkspaceApp] credential fetch failed: {} (origin={} href={})",
                                err, origin, href,
                            );
                        } else {
                            let origin = parsed.get("origin").and_then(|v| v.as_str()).unwrap_or_default();
                            let token = parsed.get("access_token").and_then(|v| v.as_str()).unwrap_or_default();
                            let source = parsed.get("source").and_then(|v| v.as_str()).unwrap_or("unknown");
                            if !origin.is_empty() && !token.is_empty() {
                                let preview = if token.len() > 20 { &token[..20] } else { token };
                                let dot_count = token.chars().filter(|c| *c == '.').count();
                                tracing::info!(
                                    "[WorkspaceApp] got token via {} (origin={} len={} dots={} preview={:?})",
                                    source, origin, token.len(), dot_count, preview,
                                );
                                matrix_api_url.set(origin.to_string());
                                matrix_auth_token.set(token.to_string());
                                crate::session::set_auth_token(token);
                            } else {
                                tracing::warn!(
                                    "[WorkspaceApp] credential fetch returned empty (source={} origin={} token_len={})",
                                    source, origin, token.len(),
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

    // Build the combined CSS (theme variables + responsive/sidebar classes + tailwind)
    let combined_css = format!(
        "{}\n{}\n{}\n{}",
        theme_css(),
        responsive_css(),
        utils_css(),
        tailwind_css()
    );

    let page = *active_page.read();

    // Compute unread badge for Logs
    let total_lines = terminal_lines.read().len();
    let unread = if page == NavPage::Logs {
        last_seen_terminal_count.set(total_lines);
        0
    } else {
        total_lines.saturating_sub(*last_seen_terminal_count.read())
    };

    let page_subtitle = match page {
        NavPage::Dashboard => {
            if workspace.is_empty() {
                None
            } else {
                Some(workspace.clone())
            }
        }
        NavPage::Tools => Some("12 connector tools available".to_string()),
        _ => None,
    };

    let page_actions = if page == NavPage::Dashboard {
        Some(rsx! {
            button {
                class: "desktop-header-btn",
                title: "Chat",
                onclick: move |_| {
                    active_page.set(NavPage::Chat);
                },
                MessageCircle { size: 20 }
            }
        })
    } else {
        None
    };

    rsx! {
        style { {combined_css} }

        KeyboardShortcuts {
            on_navigate: move |nav_page: NavPage| {
                if nav_page == NavPage::Logs {
                    last_seen_terminal_count.set(terminal_lines.read().len());
                }
                active_page.set(nav_page);
            },
            on_toggle_help: move |_| help_visible.set(!help_visible()),
            help_visible: *help_visible.read(),
            chat_visible: *active_page.read() == NavPage::Chat,
            on_close_help: move |_| help_visible.set(false),
            on_close_chat: move |_| {},

            AppLayout {
                active_page: page,
                page_subtitle,
                page_actions,
                on_navigate: move |nav_page: NavPage| {
                    if nav_page == NavPage::Logs {
                        last_seen_terminal_count.set(terminal_lines.read().len());
                    }
                    active_page.set(nav_page);
                },
                connected: true,
                unread_logs: unread,
                api_url: matrix_api_url.read().clone(),
                auth_token: matrix_auth_token.read().clone(),
                on_open_conversation: move |conv_id: String| {
                    conversation_mailbox.set(Some(conv_id));
                    active_page.set(NavPage::Chat);
                },

                // Page content — routed by WorkspacePages
                WorkspacePages {
                    active_page: page,
                    workspace: workspace.clone(),
                    terminal_lines,
                    on_open_chat: move |msg: String| {
                        if !msg.is_empty() {
                            chat_mailbox.set(Some(msg));
                        }
                        active_page.set(NavPage::Chat);
                    },
                    on_open_shell: move |_| {
                        active_page.set(NavPage::Shell);
                    },
                    blackarch_downloaded: *blackarch_downloaded.read(),
                    download_progress: *download_progress.read(),
                    setup_error: setup_error.read().clone(),
                    on_start_download: {
                        let terminal_lines = terminal_lines;
                        move |_: ()| {
                            let mut download_progress = download_progress;
                            let mut terminal_lines = terminal_lines;

                            setup_error.set(None);
                            terminal_lines
                                .write()
                                .push(TerminalLine::info("Setting up BlackArch environment..."));

                            // Set immediately so UI shows progress bar without waiting for poll.
                            crate::download_manager::set_global_progress(Some(-1.0));
                            download_progress.set(Some(-1.0));

                            spawn(async move {
                                #[cfg(all(feature = "shell-ws", not(target_os = "android")))]
                                {
                                    let result = match pentest_platform::desktop::sandbox::get_sandbox_manager().await {
                                        Ok(manager) => manager.ensure_ready().await.map_err(|e| format!("{}", e)),
                                        Err(e) => Err(format!("{}", e)),
                                    };
                                    crate::download_manager::set_global_progress(None);
                                    download_progress.set(None);
                                    match result {
                                        Ok(()) => {
                                            blackarch_downloaded.set(true);
                                            terminal_lines.write().push(TerminalLine::success(
                                                "BlackArch environment ready.".to_string(),
                                            ));
                                        }
                                        Err(e) => {
                                            setup_error.set(Some(e.clone()));
                                            terminal_lines.write().push(TerminalLine::error(format!(
                                                "Setup failed: {}",
                                                e
                                            )));
                                        }
                                    }
                                }
                            });
                        }
                    },
                    shell_mode: settings.read().shell_mode,
                    on_shell_mode_change: move |mode: ShellMode| {
                        let mut s = settings.write();
                        s.shell_mode = mode;
                        let _ = save_settings(&s);
                        #[cfg(all(feature = "shell-ws", not(target_os = "android")))]
                        pentest_platform::set_use_sandbox(mode == ShellMode::Proot);
                    },
                    wifi_adapter: settings.read().wifi_adapter.clone(),
                    on_wifi_adapter_change: move |adapter: Option<String>| {
                        let mut s = settings.write();
                        s.wifi_adapter = adapter;
                        let _ = save_settings(&s);
                    },
                    api_url: matrix_api_url.read().clone(),
                    auth_token: matrix_auth_token.read().clone(),
                    tenant_id: crate::session::get_tenant_id(),
                    chat_mailbox,
                    conversation_mailbox,
                }
            }
        }

        // Help modal — rendered outside the app-layout so it overlays everything
        HelpModal {
            visible: *help_visible.read(),
            on_close: move |_| help_visible.set(false),
        }
    }
}
