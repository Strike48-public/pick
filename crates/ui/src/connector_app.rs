//! Shared ConnectorApp component used by all platform targets.
//!
//! Each app (desktop, mobile, web) provides a thin entry-point wrapper
//! that calls [`connector_app`] with a platform-specific [`ConnectorAppConfig`].
//!
//! `connector_app` is the top-level orchestrator (signals, effects, layout).
//! [`ConnectorPages`] handles routing between the individual page views.

use dioxus::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;

use pentest_core::config::{ConnectorConfig, ShellMode};
use pentest_core::settings::{load_settings, save_settings};
use pentest_core::state::ConnectorStatus;
use pentest_core::terminal::TerminalLine;
use pentest_core::tools::ToolRegistry;

use crate::components::icons::MessageCircle;
use crate::components::{
    AppLayout, ChatPanel, ConnectingScreen, ConnectingStep, Dashboard, FileBrowser,
    InteractiveShell, LoginScreen, NavPage, SettingsPage, Terminal, ToolsPage,
    STRIKE48_SIDEBAR_LOGO_SVG,
};
use crate::download_manager::is_blackarch_ready;
use crate::{
    compute_screen, mobile_css, run_event_loop, theme_css, utils_css, AppScreen, EventLoopSignals,
    LiveViewConnector,
};
use crate::liveview_connector::ShutdownHandle;

// ---------------------------------------------------------------------------
// Platform configuration
// ---------------------------------------------------------------------------

/// Platform-specific configuration for the shared connector app.
///
/// All fields are `Copy` so the config can be freely captured in closures.
#[derive(Clone, Copy)]
pub struct ConnectorAppConfig {
    /// Display name shown on the connect screen subtitle, e.g. "Mobile".
    pub platform_name: &'static str,
    /// CSS class for the outermost container div.
    pub container_class: &'static str,
    /// Shell mode passed to `shell_routes()` for the internal liveview server.
    pub shell_route_mode: ShellMode,
    /// If true, override default shell mode to `Proot` on first run (mobile).
    pub default_proot: bool,
    /// Whether to start the internal liveview server when connecting.
    pub start_liveview_server: bool,
    /// Whether to inject CSS via inline `<style>` elements in the RSX.
    /// Desktop/Web handle CSS externally; Mobile needs inline injection.
    pub inject_css: bool,
    /// Extra init messages appended after the platform greeting.
    pub extra_init_messages: &'static [&'static str],
    /// Factory function that creates a `ToolRegistry`.
    pub create_tools: fn() -> ToolRegistry,
    /// Optional sandbox toggle. Desktop/Web pass `pentest_platform::set_use_sandbox`.
    pub set_sandbox: Option<fn(bool)>,
}

// ---------------------------------------------------------------------------
// ConnectorPages — page router
// ---------------------------------------------------------------------------

/// Props for [`ConnectorPages`].
#[derive(Props, Clone, PartialEq)]
pub struct ConnectorPagesProps {
    /// Which page is currently active.
    active_page: NavPage,
    /// Connected host address (shown on Dashboard and Settings).
    host: String,
    /// Live terminal output lines (shared signal — Signal is Copy).
    terminal_lines: Signal<Vec<TerminalLine>>,
    /// Workspace root path, if available.
    workspace_path: Signal<Option<String>>,
    /// Current shell mode string ("native" or "proot").
    shell_mode: String,
    /// Whether BlackArch ISO has been downloaded.
    blackarch_downloaded: bool,
    /// Current download progress (0.0–1.0), or None if idle.
    download_progress: Option<f64>,
    /// Error message from the last setup attempt, if any.
    setup_error: Option<String>,
    /// Callback to navigate to the Shell page.
    on_open_shell: EventHandler<()>,
    /// Callback to open the chat panel, optionally with a pre-filled message.
    on_open_chat: EventHandler<String>,
    /// Callback to disconnect from the server.
    on_disconnect: EventHandler<()>,
    /// Callback to start the BlackArch ISO download.
    on_start_download: EventHandler<()>,
    /// Callback to destroy and reinstall BlackArch rootfs.
    #[props(default)]
    on_reinstall_blackarch: EventHandler<()>,
    /// Current shell mode enum for the Settings page.
    settings_shell_mode: ShellMode,
    /// Callback when the user changes the shell mode in Settings.
    on_shell_mode_change: EventHandler<ShellMode>,
    /// Selected WiFi adapter for scanning.
    #[props(default)]
    wifi_adapter: Option<String>,
    /// Callback when the user changes the WiFi adapter.
    #[props(default)]
    on_wifi_adapter_change: EventHandler<Option<String>>,
    /// Whether screen capture is enabled (Android).
    #[props(default)]
    screen_capture_enabled: bool,
    /// Callback when the user toggles screen capture.
    #[props(default)]
    on_screen_capture_toggle: EventHandler<bool>,
    /// Callback to install a package by name (Android proot only).
    #[props(default)]
    on_install_package: EventHandler<String>,
    /// Set of package names currently being installed.
    #[props(default)]
    installing_packages: Vec<String>,
    /// Set of package names already installed.
    #[props(default)]
    installed_packages: Vec<String>,
    /// Set of package names that failed to install.
    #[props(default)]
    failed_packages: Vec<String>,
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
/// [`connector_app`] and is threaded through props.
#[component]
pub fn ConnectorPages(props: ConnectorPagesProps) -> Element {
    let page = props.active_page;
    let host = props.host;
    let terminal_lines = props.terminal_lines;
    let workspace_path = props.workspace_path;
    let shell_mode = props.shell_mode;
    let on_open_chat = props.on_open_chat;
    let on_open_shell = props.on_open_shell;

    rsx! {
        div { class: "tab-content",
            // Dashboard
            if page == NavPage::Dashboard {
                Dashboard {
                    host: host.clone(),
                    on_open_chat: move |msg: String| on_open_chat.call(msg),
                    on_open_shell: move |_| on_open_shell.call(()),
                    recent_lines: terminal_lines.read().clone(),
                    wifi_adapter: props.wifi_adapter.clone(),
                }
            }

            // Tools
            if page == NavPage::Tools {
                ToolsPage {
                    on_open_chat: move |msg: String| on_open_chat.call(msg),
                }
            }

            // Files
            if page == NavPage::Files {
                {
                    let ws = workspace_path.read().clone().unwrap_or_default();
                    if ws.is_empty() {
                        rsx! {
                            div {
                                class: "empty-state",
                                "No workspace available"
                            }
                        }
                    } else {
                        rsx! {
                            FileBrowser { workspace_path: ws }
                        }
                    }
                }
            }

            // Shell — always rendered, hidden via CSS when not active
            div {
                class: if page == NavPage::Shell { "shell-pane-active" } else { "hidden" },
                InteractiveShell {
                    shell_mode: shell_mode.clone(),
                    active: page == NavPage::Shell,
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
                div { class: "main-content",
                    Terminal { lines: terminal_lines.read().clone() }
                }
            }

            // Settings
            if page == NavPage::Settings {
                SettingsPage {
                    connected: true,
                    host: host.clone(),
                    on_disconnect: move |_| props.on_disconnect.call(()),
                    blackarch_downloaded: props.blackarch_downloaded,
                    download_progress: props.download_progress,
                    setup_error: props.setup_error.clone(),
                    on_start_download: move |_| props.on_start_download.call(()),
                    on_reinstall_blackarch: move |_| props.on_reinstall_blackarch.call(()),
                    shell_mode: props.settings_shell_mode,
                    on_shell_mode_change: move |mode: ShellMode| props.on_shell_mode_change.call(mode),
                    wifi_adapter: props.wifi_adapter.clone(),
                    on_wifi_adapter_change: move |adapter: Option<String>| props.on_wifi_adapter_change.call(adapter),
                    screen_capture_enabled: props.screen_capture_enabled,
                    on_screen_capture_toggle: move |enabled: bool| props.on_screen_capture_toggle.call(enabled),
                    on_install_package: move |pkg: String| props.on_install_package.call(pkg),
                    installing_packages: props.installing_packages.clone(),
                    installed_packages: props.installed_packages.clone(),
                    failed_packages: props.failed_packages.clone(),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shared component
// ---------------------------------------------------------------------------

/// Shared connector app component.
///
/// Call this from a thin platform-specific wrapper component, e.g.:
/// ```ignore
/// #[component]
/// fn DesktopApp() -> Element {
///     pentest_ui::connector_app(DESKTOP_CONFIG)
/// }
/// ```
pub fn connector_app(cfg: ConnectorAppConfig) -> Element {
    // ---- persisted settings ----
    let mut settings = use_signal(move || {
        let mut s = load_settings();
        s.ensure_device_id();
        if cfg.default_proot && s.shell_mode == ShellMode::Native && s.last_config.is_none() {
            s.shell_mode = ShellMode::Proot;
        }
        let _ = save_settings(&s);
        if let Some(set_sb) = cfg.set_sandbox {
            set_sb(s.shell_mode == ShellMode::Proot);
        }
        s
    });
    let device_id = settings.peek().device_id.clone();
    let initial_config = settings
        .peek()
        .last_config
        .clone()
        .map(|mut c| {
            c.instance_id = device_id.clone();
            c
        })
        .unwrap_or_else(|| ConnectorConfig {
            instance_id: device_id.clone(),
            ..Default::default()
        });

    // ---- signals ----
    let mut status = use_signal(|| ConnectorStatus::Disconnected);
    let mut terminal_lines = use_signal(Vec::<TerminalLine>::new);
    let mut config = use_signal(move || initial_config.clone());
    let mut connecting_step: Signal<Option<ConnectingStep>> = use_signal(|| None);
    let mut active_page = use_signal(|| NavPage::Dashboard);
    let workspace_path: Signal<Option<String>> = use_signal(|| None);
    let mut last_seen_terminal_count = use_signal(|| 0usize);

    // download state
    let mut download_progress: Signal<Option<f64>> =
        use_signal(crate::download_manager::get_download_progress);
    let mut blackarch_downloaded = use_signal(is_blackarch_ready);
    let mut setup_error: Signal<Option<String>> = use_signal(|| None);

    // Tool installation state (Android proot)
    let mut installing_packages: Signal<Vec<String>> = use_signal(Vec::new);
    let mut installed_packages: Signal<Vec<String>> = use_signal(Vec::new);
    let mut failed_packages: Signal<Vec<String>> = use_signal(Vec::new);

    // Check which tools are already installed when BlackArch is ready
    #[cfg(target_os = "android")]
    use_effect(move || {
        if !*blackarch_downloaded.read() {
            return;
        }
        spawn(async move {
            let all_pkgs: Vec<&str> = vec![
                "aircrack-ng", "hashcat", "john", "hydra", "reaver", "wifite",
                "bettercap", "hcxdumptool", "hcxtools", "cowpatty", "mdk4", "pixiewps",
            ];
            let found = pentest_platform::android::proot::check_installed_packages(&all_pkgs).await;
            installed_packages.set(found);
        });
    });

    // Poll global progress + readiness — survives liveview reconnects.
    use_future(move || async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let global = crate::download_manager::get_download_progress();
            if global != *download_progress.read() {
                download_progress.set(global);
            }
            if global.is_none() && !*blackarch_downloaded.read() && is_blackarch_ready() {
                blackarch_downloaded.set(true);
            }
        }
    });

    // chat state
    let mut chat_mailbox: Signal<Option<String>> = use_signal(|| None);
    let mut conversation_mailbox: Signal<Option<String>> = use_signal(|| None);
    let matrix_api_url = use_signal(|| {
        std::env::var("MATRIX_API_URL")
            .or_else(|_| std::env::var("MATRIX_URL"))
            .unwrap_or_default()
    });
    let matrix_auth_token = use_signal(|| std::env::var("MATRIX_AUTH_TOKEN").unwrap_or_default());

    use_effect(move || {
        terminal_lines.write().push(TerminalLine::info(format!(
            "Pentest Connector ({}) initialized.",
            cfg.platform_name
        )));
        for msg in cfg.extra_init_messages {
            terminal_lines
                .write()
                .push(TerminalLine::info(msg.to_string()));
        }
    });

    let connector: Signal<Option<Arc<RwLock<LiveViewConnector>>>> = use_signal(|| None);
    let shutdown_handle: Signal<Option<ShutdownHandle>> = use_signal(|| None);

    // ---- connect handler ----
    let mut on_connect = move |(mut new_config, remember): (ConnectorConfig, bool)| {
        let device_id = settings.peek().device_id.clone();
        new_config.instance_id = device_id;

        match ConnectorConfig::normalize_host(&new_config.host) {
            Ok(h) => new_config.host = h,
            Err(e) => {
                terminal_lines.write().push(TerminalLine::error(e));
                return;
            }
        }
        config.set(new_config.clone());
        status.set(ConnectorStatus::Connecting);
        connecting_step.set(Some(ConnectingStep::Connecting));
        terminal_lines.write().push(TerminalLine::info(format!(
            "Connecting to {}...",
            new_config.host
        )));

        if remember {
            let mut s = settings.peek().clone();
            s.last_config = Some(new_config.clone());
            s.auto_connect = true;
            let _ = save_settings(&s);
        }

        let mut connector = connector;
        let mut shutdown_handle = shutdown_handle;
        let mut status = status;
        let mut terminal_lines = terminal_lines;
        let connecting_step = connecting_step;
        let mut workspace_path = workspace_path;

        spawn(async move {
            let tools = (cfg.create_tools)();
            let mut lv_connector = LiveViewConnector::new(new_config, tools);

            // Store shutdown handle BEFORE the write lock is taken — this
            // allows the cancel button to signal shutdown without deadlocking.
            shutdown_handle.set(Some(lv_connector.shutdown_handle()));

            // Extract workspace path
            let ws_path = lv_connector
                .workspace_path()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            tracing::debug!("workspace path: {:?}", ws_path);
            terminal_lines.write().push(TerminalLine::info(format!(
                "Workspace: {}",
                if ws_path.is_empty() {
                    "(none)"
                } else {
                    &ws_path
                }
            )));

            if !ws_path.is_empty() {
                workspace_path.set(Some(ws_path.clone()));
            }

            // Start the liveview server (shell WebSocket, assets) regardless
            // of whether a workspace path exists — the shell needs it.
            #[cfg(feature = "shell-ws")]
            if cfg.start_liveview_server {
                tracing::debug!("starting liveview server");
                if let Err(e) = lv_connector
                    .start_liveview_server(crate::shell_ws::shell_routes(cfg.shell_route_mode))
                    .await
                {
                    tracing::error!("LiveView server failed: {}", e);
                }
            }

            let event_rx = lv_connector.event_rx();
            let lv_connector = Arc::new(RwLock::new(lv_connector));
            connector.set(Some(lv_connector.clone()));

            // Spawn event handler
            spawn(run_event_loop(
                event_rx,
                EventLoopSignals {
                    terminal_lines,
                    status,
                    connecting_step,
                    config,
                    settings,
                    matrix_api_url,
                    matrix_auth_token,
                },
            ));

            // Run connector (blocking)
            {
                let mut conn = lv_connector.write().await;
                if let Err(e) = conn.connect_and_run().await {
                    terminal_lines
                        .write()
                        .push(TerminalLine::error(format!("Connection error: {}", e)));
                    status.set(ConnectorStatus::Error(e));
                }
            }
        });
    };

    // ---- auto-connect ----
    use_effect(move || {
        if let Some(saved_config) = settings.read().last_config.clone() {
            if !saved_config.auth_token.is_empty() || settings.read().auto_connect {
                terminal_lines
                    .write()
                    .push(TerminalLine::info("Auto-connecting with saved settings..."));
                on_connect((saved_config, true));
            }
        }
    });

    // ---- disconnect handler ----
    let mut on_disconnect = move |_: ()| {
        let mut s = load_settings();
        s.auto_connect = false;
        let _ = save_settings(&s);

        // Use the lock-free shutdown handle — connect_and_run holds the
        // write lock, so trying to acquire a read lock would deadlock.
        if let Some(handle) = shutdown_handle.peek().as_ref() {
            handle.shutdown();
        }
        status.set(ConnectorStatus::Disconnected);
        connecting_step.set(None);
        terminal_lines
            .write()
            .push(TerminalLine::info("Disconnected"));
    };

    // ---- setup handler ----
    let on_start_download = move |_: ()| {
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
            let result = match pentest_platform::desktop::sandbox::get_sandbox_manager().await {
                Ok(manager) => manager.ensure_ready().await.map_err(|e| format!("{}", e)),
                Err(e) => Err(format!("{}", e)),
            };

            #[cfg(target_os = "android")]
            let result = pentest_platform::android::proot::ensure_rootfs()
                .await
                .map(|_| ())
                .map_err(|e| format!("{}", e));

            #[cfg(any(target_os = "android", feature = "shell-ws"))]
            {
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
                        terminal_lines
                            .write()
                            .push(TerminalLine::error(format!("Setup failed: {}", e)));
                    }
                }
            }
        });
    };

    // ---- derived state ----
    let current_status = status.read().clone();
    let step = *connecting_step.read();
    let page = *active_page.read();
    let screen = compute_screen(&current_status, &step, &page);

    // Compute unread badge: terminal lines added while not on the Logs page
    let total_lines = terminal_lines.read().len();
    let unread = if page == NavPage::Logs {
        last_seen_terminal_count.set(total_lines);
        0
    } else {
        total_lines.saturating_sub(*last_seen_terminal_count.read())
    };

    let blackarch_ready = *blackarch_downloaded.read();

    // ---- optional inline CSS (mobile only) ----
    let css_block = if cfg.inject_css {
        let css = theme_css();
        let mcss = mobile_css();
        let ucss = utils_css();
        rsx! {
            style { {css} }
            style { {mcss} }
            style { {ucss} }
        }
    } else {
        rsx! {}
    };

    let container_class = cfg.container_class;
    let platform_name = cfg.platform_name;

    rsx! {
        {css_block}

        div { class: "{container_class}",
            match screen {
                AppScreen::Connect => rsx! {
                    div { class: "connect-screen",
                        span {
                            class: "header-logo mb-8",
                            dangerous_inner_html: STRIKE48_SIDEBAR_LOGO_SVG,
                        }
                        h1 { class: "mb-4", "Pentest" }
                        span {
                            class: "connect-subtitle",
                            "{platform_name}"
                        }
                        LoginScreen {
                            config: config.read().clone(),
                            on_connect: on_connect,
                            is_connecting: false,
                        }
                    }
                },

                AppScreen::Connecting(step) => {
                    let host = config.read().host.clone();
                    rsx! {
                        ConnectingScreen {
                            step: step,
                            host: host,
                            on_cancel: move |_| {
                                on_disconnect(());
                            },
                        }
                    }
                },

                AppScreen::Connected(page) => {
                    let host = config.read().host.clone();
                    let shell_mode_str = match settings.read().shell_mode {
                        ShellMode::Native => "native".to_string(),
                        ShellMode::Proot => "proot".to_string(),
                    };

                    // Derive chat API URL: prefer the signal (set by
                    // CredentialsUpdated), fall back to config host so the
                    // ChatPanel has a URL immediately after connection — even
                    // before the auth token arrives.
                    let chat_api_url = {
                        let sig = matrix_api_url.read().clone();
                        if !sig.is_empty() {
                            sig
                        } else if !host.is_empty() {
                            let use_tls = config.read().use_tls;
                            let scheme = if use_tls { "https" } else { "http" };

                            // Strip URL scheme prefixes (grpc://, grpcs://, etc.) first (case-insensitive)
                            let schemes = ["grpc://", "grpcs://", "http://", "https://", "ws://", "wss://"];
                            let host_lower = host.to_lowercase();
                            let mut bare_host = host.as_str();
                            for prefix in &schemes {
                                if host_lower.starts_with(prefix) {
                                    bare_host = &host[prefix.len()..];
                                    break;
                                }
                            }

                            let api_host = bare_host.strip_prefix("connectors-")
                                .unwrap_or(bare_host);
                            format!("{}://{}", scheme, api_host)
                        } else {
                            String::new()
                        }
                    };
                    let page_subtitle = match page {
                        NavPage::Dashboard => Some(host.clone()),
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
                        AppLayout {
                            active_page: page,
                            page_subtitle,
                            page_actions,
                            on_navigate: move |p: NavPage| {
                                if p == NavPage::Logs {
                                    last_seen_terminal_count.set(terminal_lines.peek().len());
                                }
                                active_page.set(p);
                            },
                            connected: true,
                            unread_logs: unread,
                            host: host.clone(),
                            api_url: chat_api_url.clone(),
                            auth_token: matrix_auth_token.read().clone(),
                            on_open_conversation: move |conv_id: String| {
                                conversation_mailbox.set(Some(conv_id));
                                active_page.set(NavPage::Chat);
                            },

                            // Page content — routed by ConnectorPages
                            ConnectorPages {
                                active_page: page,
                                host: host,
                                terminal_lines,
                                workspace_path,
                                shell_mode: shell_mode_str,
                                blackarch_downloaded: blackarch_ready,
                                download_progress: *download_progress.read(),
                                setup_error: setup_error.read().clone(),
                                on_open_chat: move |msg: String| {
                                    if !msg.is_empty() {
                                        chat_mailbox.set(Some(msg));
                                    }
                                    active_page.set(NavPage::Chat);
                                },
                                on_open_shell: move |_| {
                                    active_page.set(NavPage::Shell);
                                },
                                on_disconnect: move |_| on_disconnect(()),
                                on_start_download: on_start_download,
                                on_reinstall_blackarch: move |_| {
                                    let mut download_progress = download_progress;
                                    let mut terminal_lines = terminal_lines;
                                    let mut blackarch_downloaded = blackarch_downloaded;

                                    setup_error.set(None);
                                    blackarch_downloaded.set(false);
                                    terminal_lines.write().push(TerminalLine::info(
                                        "Reinstalling BlackArch environment...".to_string(),
                                    ));
                                    crate::download_manager::set_global_progress(Some(-1.0));
                                    download_progress.set(Some(-1.0));

                                    spawn(async move {
                                        // Destroy existing rootfs
                                        #[cfg(target_os = "android")]
                                        {
                                            if let Err(e) = pentest_platform::android::proot::destroy_rootfs().await {
                                                tracing::warn!("Failed to destroy rootfs: {}", e);
                                            }
                                        }

                                        // Re-run setup
                                        #[cfg(target_os = "android")]
                                        let result = pentest_platform::android::proot::ensure_rootfs()
                                            .await
                                            .map(|_| ())
                                            .map_err(|e| format!("{}", e));

                                        #[cfg(not(target_os = "android"))]
                                        let result: std::result::Result<(), String> = {
                                            // Desktop: re-setup sandbox
                                            #[cfg(feature = "shell-ws")]
                                            match pentest_platform::desktop::sandbox::get_sandbox_manager().await {
                                                Ok(manager) => {
                                                    manager.ensure_ready().await.map_err(|e| format!("{}", e))
                                                }
                                                Err(e) => Err(format!("{}", e)),
                                            }
                                            #[cfg(not(feature = "shell-ws"))]
                                            Ok(())
                                        };

                                        crate::download_manager::set_global_progress(None);
                                        download_progress.set(None);
                                        match result {
                                            Ok(()) => {
                                                blackarch_downloaded.set(true);
                                                terminal_lines.write().push(TerminalLine::success(
                                                    "BlackArch environment reinstalled.".to_string(),
                                                ));
                                            }
                                            Err(e) => {
                                                setup_error.set(Some(e.clone()));
                                                terminal_lines.write().push(TerminalLine::error(
                                                    format!("Reinstall failed: {}", e),
                                                ));
                                            }
                                        }
                                    });
                                },
                                settings_shell_mode: settings.read().shell_mode,
                                on_shell_mode_change: move |mode: ShellMode| {
                                    let mut s = settings.write();
                                    s.shell_mode = mode;
                                    let _ = save_settings(&s);
                                    if let Some(set_sb) = cfg.set_sandbox {
                                        set_sb(mode == ShellMode::Proot);
                                    }
                                },
                                wifi_adapter: settings.read().wifi_adapter.clone(),
                                on_wifi_adapter_change: move |adapter: Option<String>| {
                                    let mut s = settings.write();
                                    s.wifi_adapter = adapter;
                                    let _ = save_settings(&s);
                                },
                                screen_capture_enabled: settings.read().screen_capture_enabled,
                                on_screen_capture_toggle: move |enabled: bool| {
                                    let mut s = settings.write();
                                    s.screen_capture_enabled = enabled;
                                    let _ = save_settings(&s);
                                    if enabled {
                                        crate::platform_helper::request_screen_capture();
                                    }
                                },
                                on_install_package: move |_pkg: String| {
                                    // Install all remaining tools one by one so the UI
                                    // shows progress on each package individually.
                                    let all_tools: Vec<String> = vec![
                                        "aircrack-ng", "hashcat", "john", "hydra", "reaver", "wifite",
                                        "bettercap", "hcxdumptool", "hcxtools", "cowpatty", "mdk4", "pixiewps",
                                    ].into_iter().map(String::from).collect();
                                    let already = installed_packages.read().clone();
                                    let to_install: Vec<String> = all_tools.iter()
                                        .filter(|t| !already.contains(*t))
                                        .cloned()
                                        .collect();
                                    if to_install.is_empty() {
                                        return;
                                    }
                                    failed_packages.set(vec![]);
                                    spawn(async move {
                                        for pkg in &to_install {
                                            // Show this package as currently installing
                                            installing_packages.set(vec![pkg.clone()]);
                                            #[cfg(target_os = "android")]
                                            {
                                                let pkgs = [pkg.as_str()];
                                                match pentest_platform::android::proot::install_packages(&pkgs).await {
                                                    Ok(output) => {
                                                        tracing::info!("Installed {}: {}", pkg, output);
                                                        installed_packages.write().push(pkg.clone());
                                                    }
                                                    Err(e) => {
                                                        tracing::error!("Failed to install {}: {}", pkg, e);
                                                        failed_packages.write().push(pkg.clone());
                                                    }
                                                }
                                            }
                                        }
                                        installing_packages.set(vec![]);
                                    });
                                },
                                installing_packages: installing_packages.read().clone(),
                                installed_packages: installed_packages.read().clone(),
                                failed_packages: failed_packages.read().clone(),
                                api_url: chat_api_url,
                                auth_token: matrix_auth_token.read().clone(),
                                tenant_id: config.read().tenant_id.clone(),
                                chat_mailbox,
                                conversation_mailbox,
                            }
                        }
                    }
                },
            }
        }
    }
}
