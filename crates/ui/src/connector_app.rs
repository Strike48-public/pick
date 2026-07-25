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

use pentest_core::config::{BorderRadius, ConnectorConfig, Density, ShellMode, Theme};
use pentest_core::settings::{load_settings, save_settings};
use pentest_core::state::ConnectorStatus;
use pentest_core::terminal::TerminalLine;
use pentest_core::tools::ToolRegistry;

use crate::auth_flow::{reduce, AuthEvent, AuthFlow};
use crate::components::icons::MessageCircle;
use crate::components::{
    AppLayout, ChatPanel, ConfigForm, ConnectingScreen, ConnectingStep, Dashboard, EasyModeShell,
    FileBrowser, InteractiveShell, NavPage, SettingsPage, Terminal, ToolsPage,
    STRIKE48_SIDEBAR_LOGO_SVG,
};
use crate::download_manager::is_blackarch_ready;
use crate::{
    compute_screen, mobile_css, run_event_loop, utils_css, AppScreen, EventLoopSignals,
    LiveViewConnector,
};

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
    /// When true, render the simplified "Easy Mode" shell (scan + chat) instead
    /// of the full dashboard/sidebar UI. Default target is mobile.
    pub easy_mode: bool,
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
    /// Current theme for appearance settings.
    theme: Theme,
    /// Callback when the user changes the theme.
    on_theme_change: EventHandler<Theme>,
    /// Current border radius for appearance settings.
    border_radius: BorderRadius,
    /// Callback when the user changes the border radius.
    on_border_radius_change: EventHandler<BorderRadius>,
    /// Current density for appearance settings.
    density: Density,
    /// Callback when the user changes the density.
    on_density_change: EventHandler<Density>,
    /// Whether anonymous usage analytics are enabled (#278).
    #[props(default = true)]
    telemetry_enabled: bool,
    /// Callback when the user toggles usage analytics.
    #[props(default)]
    on_telemetry_change: EventHandler<bool>,
    /// Whether Easy Mode is currently active (for the Settings toggle).
    #[props(default)]
    easy_mode_on: bool,
    /// Callback when the user toggles Easy Mode in Settings.
    #[props(default)]
    on_easy_mode_change: EventHandler<bool>,
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
                    shell_mode: props.settings_shell_mode,
                    on_shell_mode_change: move |mode: ShellMode| props.on_shell_mode_change.call(mode),
                    wifi_adapter: props.wifi_adapter.clone(),
                    on_wifi_adapter_change: move |adapter: Option<String>| props.on_wifi_adapter_change.call(adapter),
                    theme: props.theme,
                    on_theme_change: move |t: Theme| props.on_theme_change.call(t),
                    border_radius: props.border_radius,
                    on_border_radius_change: move |r: BorderRadius| props.on_border_radius_change.call(r),
                    density: props.density,
                    on_density_change: move |d: Density| props.on_density_change.call(d),
                    telemetry_enabled: props.telemetry_enabled,
                    on_telemetry_change: move |v: bool| props.on_telemetry_change.call(v),
                    easy_mode_on: props.easy_mode_on,
                    on_easy_mode_change: move |v: bool| props.on_easy_mode_change.call(v),
                    on_theme_imported: move |_| {
                        // Theme imported - could trigger UI refresh here if needed
                        tracing::info!("Custom theme imported successfully");
                    },
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Shared component
// ---------------------------------------------------------------------------

/// Derive the HTTPS(S) Matrix API URL from a connector host string.
/// Delegates to the shared [`pentest_core::connector_registration::derive_api_url`]
/// so the Dioxus app and the crux FFI use ONE implementation.
fn derive_api_url(host: &str, use_tls: bool) -> String {
    pentest_core::connector_registration::derive_api_url(host, use_tls)
}

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

    // ---- easy mode resolution ----
    // The effective Easy Mode flag: persisted Settings choice > build-time
    // PICK_EASY_MODE env > per-app compile default. `resolved_easy` is the
    // startup value used for one-time setup (telemetry tag, PLG env seed,
    // auto-connect). `easy_mode` is a reactive signal the render branch reads and
    // the Settings toggle flips, so switching modes swaps the shell immediately.
    let resolved_easy =
        pentest_core::config::resolve_easy_mode(settings.peek().easy_mode, cfg.easy_mode);
    let mut easy_mode = use_signal(|| resolved_easy);

    // ---- telemetry (#278) ----
    // Initialize once for the app lifetime (the client guard is retained inside
    // the telemetry module). No-op when the user opted out or no DSN was baked in.
    use_hook(|| {
        let enabled = settings.peek().telemetry_enabled;
        pentest_core::telemetry::init(enabled, &device_id, resolved_easy);
    });

    // Easy-mode default PLG connection (#283): when there's no saved config,
    // easy mode seeds host/tenant from the PLG target baked in at BUILD time
    // (option_env! STRIKE48_HOST/STRIKE48_TENANT), falling back to the runtime
    // env on desktop/dev. Mobile apps have no runtime environment, so the host
    // MUST be baked in at build time — same mechanism as the Sentry DSN. Empty
    // token → the existing post-approval flow. If no build-time host is present
    // we fall through to Default (empty host) and the connect form still shows —
    // that form is the override/escape hatch. Nothing is hardcoded in the repo.
    let easy_mode_env_config = if resolved_easy {
        ConnectorConfig::from_baked_or_env().filter(|c| !c.host.is_empty())
    } else {
        None
    };

    let initial_config = settings
        .peek()
        .last_config
        .clone()
        .or_else(|| easy_mode_env_config.clone())
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
    // Error visible on the Connect screen. Connect-phase failures (validation,
    // registration, transport) populate this so the user can see *why* the
    // button "did nothing" instead of finding it logged into a terminal that
    // is only rendered after a successful connection.
    let mut connect_error: Signal<Option<String>> = use_signal(|| None);

    // Explicit easy-mode auth state machine (see auth_flow.rs). Provided as
    // context so EasyModeShell and ChatPanel can read it. `dispatch` (below) is
    // the ONLY writer.
    let flow = use_context_provider(|| Signal::new(AuthFlow::Restoring));

    // Single writer for `flow`. Plain Fn (no RefCell) — signals are Copy and
    // use interior mutability. Rebind captured signals as mut inside the closure
    // to keep the closure an Fn.
    let dispatch = std::rc::Rc::new(move |ev: AuthEvent| {
        let mut flow = flow;
        let auto = settings.peek().auto_connect;
        let prev = flow.peek().clone();
        let next = reduce(prev.clone(), ev.clone(), easy_mode(), auto);
        // Debug-level trace of every auth-flow transition — invaluable for
        // diagnosing sign-in/logout issues; off unless RUST_LOG=debug.
        tracing::debug!("[AUTHFLOW] {:?} --{:?}--> {:?}", prev, ev, next);
        flow.set(next);
    });

    // download state
    let mut download_progress: Signal<Option<f64>> =
        use_signal(crate::download_manager::get_download_progress);
    let mut blackarch_downloaded = use_signal(is_blackarch_ready);
    let mut setup_error: Signal<Option<String>> = use_signal(|| None);

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

    // theme state from settings
    let mut theme = use_signal(move || settings.peek().theme);
    let mut border_radius = use_signal(move || settings.peek().border_radius);
    let mut density = use_signal(move || settings.peek().density);

    // chat state
    let mut chat_mailbox: Signal<Option<String>> = use_signal(|| None);
    let mut conversation_mailbox: Signal<Option<String>> = use_signal(|| None);
    let mut matrix_api_url = use_signal(|| {
        std::env::var("MATRIX_API_URL")
            .or_else(|_| std::env::var("MATRIX_URL"))
            .unwrap_or_default()
    });
    let mut matrix_auth_token =
        use_signal(|| std::env::var("MATRIX_AUTH_TOKEN").unwrap_or_default());

    // Restore a previously-persisted chat token (OS secure store) on startup so
    // relaunching the app doesn't force a fresh browser sign-in. The API URL the
    // token was minted for comes from settings (it isn't known from the live
    // signal yet at startup), so we seed BOTH the token and the API URL signal —
    // otherwise ChatPanel mounts with an empty URL and re-triggers browser auth.
    use_hook(|| {
        if matrix_auth_token.peek().is_empty() {
            if let Some((token, api_url)) = crate::session::restore_matrix_token() {
                tracing::info!("restored persisted chat token; skipping browser sign-in");
                matrix_auth_token.set(token);
                if matrix_api_url.peek().is_empty() {
                    matrix_api_url.set(api_url);
                }
            }
        }
    });

    // Extract candidate config picker (DRY for startup hook and launch effect).
    let pick_candidate = {
        let device_id = device_id.clone();
        let easy_env = easy_mode_env_config.clone();
        move || {
            settings.peek().last_config.clone().or_else(|| {
                easy_env.clone().map(|mut c| {
                    c.instance_id = device_id.clone();
                    c
                })
            })
        }
    };

    // Drive the AuthFlow machine's initial transition: the chat token alone
    // determines the startup route (connector creds are separate and do not
    // gate the easy-mode UI). One-shot.
    {
        let dispatch = std::rc::Rc::clone(&dispatch);
        use_hook(move || {
            let have_token = !matrix_auth_token.peek().is_empty();
            dispatch(AuthEvent::Restored { have_token });
        });
    }

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

    // ---- connect handler ----
    let mut on_connect = move |(mut new_config, remember): (ConnectorConfig, bool)| {
        let device_id = settings.peek().device_id.clone();

        // Clear any stale connect-phase error before retrying.
        connect_error.set(None);

        match ConnectorConfig::normalize_host(&new_config.host) {
            Ok(normalized) => new_config.host = normalized.value,
            Err(e) => {
                // Surface to the form banner (visible) AND log to terminal
                // (debuggable on Dashboard once connected).
                terminal_lines.write().push(TerminalLine::error(e.clone()));
                connect_error.set(Some(e));
                return;
            }
        }

        // Scope the connector identity per env so each Strike48 host gets its own
        // credential + approval. A single global device_id reuses one credential
        // for every env, so a token minted for env A is rejected by env B.
        new_config.instance_id =
            ConnectorConfig::env_scoped_instance_id(&device_id, &new_config.host);

        // Studio addresses App-behavior connectors by tenant UUID, so when
        // the operator typed the slug we need to substitute the canonical
        // UUID before registering. Two sources, tried in order:
        //
        // 1. A UUID env var (`MATRIX_TENANT_ID`, `STRIKE48_TENANT`, or
        //    `TENANT_ID` — whichever carries a UUID). This is the common
        //    case: the operator sets `STRIKE48_TENANT=slug` and pins the
        //    UUID as `MATRIX_TENANT_ID`, then still types the slug in the
        //    form out of habit.
        // 2. The SDK's post-OTT credentials file at
        //    `~/.strike48/credentials/<connector>_<instance>.json`, which
        //    carries the canonical `tenant_id` the server minted.
        //
        // StrikeHub's launcher does the equivalent server-side via
        // `fetch_tenant_id` (`strikehub/crates/sh-core/src/auth.rs`). See
        // pick#223.
        if !ConnectorConfig::is_uuid_like(&new_config.tenant_id) {
            if let Some(env_uuid) = ConnectorConfig::tenant_uuid_from_env() {
                terminal_lines.write().push(TerminalLine::info(format!(
                    "Promoting tenant UUID {} from env (form value: {})",
                    env_uuid, new_config.tenant_id,
                )));
                new_config.tenant_id = env_uuid;
            }
        }
        if let Some(canonical) = ConnectorConfig::read_credentials_tenant_id(
            &new_config.connector_name,
            &new_config.instance_id,
        ) {
            if canonical != new_config.tenant_id {
                terminal_lines.write().push(TerminalLine::info(format!(
                    "Using tenant UUID {} from saved credentials (form value: {})",
                    canonical, new_config.tenant_id,
                )));
                new_config.tenant_id = canonical;
            }
        }
        // Attach the (pseudonymous) PLG tenant to telemetry now that we know it.
        pentest_core::telemetry::set_plg_identity(&new_config.tenant_id);

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
        let mut status = status;
        let mut terminal_lines = terminal_lines;
        let connecting_step = connecting_step;
        let mut workspace_path = workspace_path;
        // Read the live mode so a runtime toggle is honored on the next connect.
        let easy_mode = easy_mode();

        // Clone identity fields before we consume `new_config` in the
        // spawned connector task — we still need them for the first-run
        // OTT self-heal poll below.
        let connector_name_for_poll = new_config.connector_name.clone();
        let instance_id_for_poll = new_config.instance_id.clone();
        let initial_tenant_for_poll = new_config.tenant_id.clone();

        spawn(async move {
            let tools = (cfg.create_tools)();
            let lv_connector = LiveViewConnector::new(new_config, tools);

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

            // Rebind as mut only when shell-ws needs to call start_liveview_server.
            #[cfg(feature = "shell-ws")]
            let mut lv_connector = lv_connector;

            if !ws_path.is_empty() {
                workspace_path.set(Some(ws_path.clone()));

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
            }

            let event_rx = lv_connector.event_rx();
            let lv_connector = Arc::new(RwLock::new(lv_connector));
            connector.set(Some(lv_connector.clone()));

            // First-run OTT self-heal: the SDK writes the canonical tenant
            // UUID to disk once OTT approval completes, but Pick's config
            // still carries whatever the operator typed. Poll for a bounded
            // window so that (a) the current session picks up the UUID for
            // any subsequent connect and (b) settings persist the UUID for
            // the next launch, keeping the slug detour to at most one
            // reconnect. See pick#223.
            {
                let connector_name = connector_name_for_poll;
                let instance_id = instance_id_for_poll;
                let initial_tenant = initial_tenant_for_poll;
                spawn(async move {
                    for _ in 0..60 {
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                        let Some(canonical) = ConnectorConfig::read_credentials_tenant_id(
                            &connector_name,
                            &instance_id,
                        ) else {
                            continue;
                        };
                        if canonical == initial_tenant {
                            return;
                        }
                        let mut s = settings.peek().clone();
                        let updated = match s.last_config.clone() {
                            Some(mut c) => {
                                if c.tenant_id == canonical {
                                    return;
                                }
                                c.tenant_id = canonical.clone();
                                Some(c)
                            }
                            None => None,
                        };
                        if let Some(c) = updated {
                            s.last_config = Some(c);
                            let _ = save_settings(&s);
                            terminal_lines.write().push(TerminalLine::info(format!(
                                "Saved canonical tenant UUID {} for next launch.",
                                canonical
                            )));
                        }
                        return;
                    }
                });
            }

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
                    let display = format!("Connection error: {}", e);
                    tracing::error!("[CONNECT] connect_and_run failed: {e}");
                    terminal_lines
                        .write()
                        .push(TerminalLine::error(display.clone()));
                    if easy_mode {
                        // A staged OTT is single-use; a failed registration
                        // consumed or invalidated it, so drop it (a retry
                        // re-mints a fresh one).
                        pentest_core::matrix::clear_staged_ott();
                        std::env::remove_var("STRIKE48_REGISTRATION_TOKEN_FILE");
                        status.set(ConnectorStatus::Disconnected);
                    } else {
                        // Standard shell: surface to the Connect-screen banner.
                        // status flips to Error which routes there; without this
                        // the error would be silent (terminal isn't rendered).
                        connect_error.set(Some(display));
                        status.set(ConnectorStatus::Error(e));
                    }
                }
            }
        });
    };

    // PLG easy-mode OAuth-first connect: obtain the user JWT, exchange it for a
    // tenant-scoped OTT, stage the OTT for the SDK, then connect. On any failure
    // stop — never fall back to a tokenless connect.
    let plg_sign_in_and_connect = {
        let mut on_connect_clone = on_connect;
        let dispatch = dispatch.clone();
        move |base_config: ConnectorConfig| {
            let mut connecting_step = connecting_step;
            let mut status = status;
            let mut terminal_lines = terminal_lines;
            let mut config = config;
            let mut matrix_auth_token = matrix_auth_token;
            let mut matrix_api_url = matrix_api_url;
            let dispatch = dispatch.clone();
            spawn(async move {
                status.set(ConnectorStatus::Connecting);
                connecting_step.set(Some(ConnectingStep::SigningIn));

                // Drop any process-cached browser token so this sign-in always
                // performs a FRESH login. Otherwise `fetch_matrix_token_browser`
                // returns a stale cached token whose server-side session may be
                // gone (backend: "Auth.verify_token: session not found" ->
                // "Not authenticated"), and retry can never recover because it
                // keeps re-serving the dead token.
                pentest_core::matrix::clear_browser_token_cache();

                // Derive the HTTPS API URL from the connector host using the
                // same logic as the chat_api_url derivation below (connector_app.rs
                // ~801-826). `matrix::normalize_url` is pub(crate) and not
                // reachable from this crate, so use the shared helper added in
                // Step 1b instead.
                let api_url = derive_api_url(&base_config.host, base_config.use_tls);

                let jwt = match pentest_core::matrix::fetch_matrix_token_browser(&api_url).await {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::error!("[CONNECT] fetch_matrix_token_browser failed: {e}");
                        terminal_lines
                            .write()
                            .push(TerminalLine::error(format!("Sign-in failed: {e}")));
                        status.set(ConnectorStatus::Disconnected);
                        connecting_step.set(None);
                        dispatch(AuthEvent::TokenFailed(e.to_string()));
                        return;
                    }
                };

                // The browser-OAuth JWT is a session-backed Studio token — the
                // credential GraphQL requires. Feed it to the chat path NOW
                // (mirrors the MatrixTokenObtained event) so the chat panel uses
                // this fresh token instead of a stale one restored from the secure
                // store at startup, which would fail with "session not found" /
                // "Not authenticated". The connector JWT that the connect flow
                // emits later via CredentialsUpdated is gRPC-only and deliberately
                // does not touch the chat token. Persisting here also means a
                // relaunch restores THIS working token.
                matrix_api_url.set(api_url.clone());
                matrix_auth_token.set(jwt.clone());
                crate::session::set_auth_token(&jwt);
                crate::session::persist_matrix_token(&jwt, &api_url);
                dispatch(AuthEvent::TokenObtained);

                // Exchange the JWT for a tenant-scoped OTT, stage it, and point
                // the SDK at it (STRIKE48_REGISTRATION_TOKEN_FILE) via the shared
                // orchestration so the Dioxus app and crux FFI register the same
                // way.
                let ott =
                    match pentest_core::connector_registration::prepare_connector_registration(
                        &api_url,
                        &jwt,
                        &base_config.connector_name,
                    )
                    .await
                    {
                        Ok(o) => o,
                        Err(e) => {
                            tracing::error!("[CONNECT] prepare_connector_registration failed: {e}");
                            terminal_lines
                                .write()
                                .push(TerminalLine::error(format!("Pre-approval failed: {e}")));
                            status.set(ConnectorStatus::Disconnected);
                            connecting_step.set(None);
                            return;
                        }
                    };

                // Adopt the authoritative tenant so the connector registers under
                // the personal tenant.
                let mut c = base_config;
                c.tenant_id = ott.tenant_id.clone();
                config.set(c.clone());

                terminal_lines.write().push(TerminalLine::info(
                    "Signed in. Registering connector for your workspace...",
                ));
                connecting_step.set(Some(ConnectingStep::Connecting));
                on_connect_clone((c, true));
            });
        }
    };

    // Launch side effects on AuthFlow entry.
    {
        let plg_sign_in_and_connect = plg_sign_in_and_connect.clone();
        let mut launched_signin = use_signal(|| false);
        let mut launched_connect = use_signal(|| false);
        let pick_candidate = pick_candidate.clone();
        use_effect(move || {
            match flow() {
                AuthFlow::SigningIn => {
                    if !*launched_signin.peek() {
                        launched_signin.set(true);
                        launched_connect.set(false);
                        if let Some(c) = pick_candidate() {
                            plg_sign_in_and_connect(c);
                        }
                    }
                }
                AuthFlow::Registering(_) => {
                    // Silent auto-connect path (creds present at startup): connect
                    // without a browser sign-in. Only when we did NOT just sign in.
                    if !*launched_connect.peek() && !*launched_signin.peek() {
                        launched_connect.set(true);
                        if let Some(c) = pick_candidate() {
                            let remember = settings.peek().last_config.is_some();
                            on_connect((c, remember));
                        }
                    }
                }
                _ => {
                    launched_signin.set(false);
                    launched_connect.set(false);
                }
            }
        });
    }


    // Bridge the connector event loop's status/step signals into AuthFlow events.
    {
        let mut last_status = use_signal(|| None::<ConnectorStatus>);
        let dispatch = dispatch.clone();
        use_effect(move || {
            let s = status.read().clone();
            if last_status.peek().as_ref() != Some(&s) {
                last_status.set(Some(s.clone()));
                match s {
                    ConnectorStatus::Registered => dispatch(AuthEvent::ConnectorRegistered),
                    ConnectorStatus::Connecting | ConnectorStatus::Reconnecting => {
                        if let Some(step) = *connecting_step.peek() {
                            dispatch(AuthEvent::ConnectorStep(step));
                        }
                    }
                    _ => {}
                }
            }
        });
    }

    {
        let mut last_step = use_signal(|| None::<ConnectingStep>);
        let dispatch = dispatch.clone();
        use_effect(move || {
            let step = *connecting_step.read();
            if *last_step.peek() != step {
                last_step.set(step);
                if let Some(step) = step {
                    if matches!(*flow.peek(), AuthFlow::Registering(_)) {
                        dispatch(AuthEvent::ConnectorStep(step));
                    }
                }
            }
        });
    }

    // ---- disconnect handler ----
    let on_disconnect = {
        let dispatch = dispatch.clone();
        move |_: ()| {
            let mut s = load_settings();
            s.auto_connect = false;
            let _ = save_settings(&s);

            let connector = connector;
            let mut status = status;
            let mut terminal_lines = terminal_lines;
            let mut connecting_step = connecting_step;
            let dispatch = dispatch.clone();

            spawn(async move {
                // Clone the Arc out and drop the signal borrow before awaiting (see
                // the logout handler): holding connector.peek() across .await races
                // connector.set(...) on reconnect and panics with AlreadyBorrowed.
                let conn_arc = connector.peek().as_ref().cloned();
                if let Some(conn) = conn_arc {
                    conn.read().await.shutdown();
                }
                status.set(ConnectorStatus::Disconnected);
                connecting_step.set(None);
                terminal_lines
                    .write()
                    .push(TerminalLine::info("Disconnected"));
                dispatch(AuthEvent::Disconnected);
            });
        }
    };

    // ---- logout handler (easy mode) ----
    // Full sign-out: drop the chat session token (secure store + process cache),
    // delete the SDK connector credentials so the next launch does a fresh OTT
    // registration, shut the connector down, and route back to the sign-in
    // overlay. Distinct from `on_disconnect`, which only stops the connector but
    // keeps credentials for a silent reconnect.
    let on_logout = {
        let device_id = device_id.clone();
        let dispatch = dispatch.clone();
        move |_: ()| {
            let cfg_now = config.peek().clone();
            let scoped_instance_id = pentest_core::config::ConnectorConfig::env_scoped_instance_id(
                &device_id,
                &cfg_now.host,
            );
            pentest_core::config::ConnectorConfig::clear_credentials(
                &cfg_now.connector_name,
                &scoped_instance_id,
            );
            crate::session::clear_matrix_token();
            crate::session::set_auth_token("");
            pentest_core::matrix::clear_browser_token_cache();
            pentest_core::matrix::clear_staged_ott();

            // Stop auto-connect so we land on sign-in, not a silent reconnect.
            let mut s = load_settings();
            s.auto_connect = false;
            let _ = save_settings(&s);

            let connector = connector;
            let mut status = status;
            let mut matrix_auth_token = matrix_auth_token;
            let mut connecting_step = connecting_step;
            let dispatch = dispatch.clone();
            // Update the UI state SYNCHRONOUSLY, before the async connector
            // shutdown. Previously these ran after `conn.read().await.shutdown()`
            // inside the spawn; if that RwLock read blocks (the event loop can
            // hold the lock), the token clear + LoggedOut dispatch never ran, so
            // the shell stayed "logged in" and logout appeared to do nothing.
            // The token was already cleared from the session store synchronously
            // above; mirror that into the UI signals + flow here, then shut the
            // connector down in the background.
            matrix_auth_token.set(String::new());
            connecting_step.set(None);
            status.set(ConnectorStatus::Disconnected);
            dispatch(AuthEvent::LoggedOut);
            spawn(async move {
                // Clone the Arc out and DROP the signal borrow before awaiting.
                // Holding `connector.peek()` across `.await` keeps the signal
                // borrowed while `connector.set(...)` (connect path) runs,
                // panicking with AlreadyBorrowed on a logout->reconnect race.
                let conn_arc = connector.peek().as_ref().cloned();
                if let Some(conn) = conn_arc {
                    conn.read().await.shutdown();
                }
            });
        }
    };

    // ---- setup handler ----
    // ---- easy-mode toggle (Settings) ----
    // Persist the explicit choice and flip the reactive signal so the shell
    // swaps (easy <-> expert) immediately, no relaunch. Reachable from both the
    // Easy Mode drawer's Settings and the expert SettingsPage so it's never a
    // one-way trap.
    let on_easy_mode_change = move |on: bool| {
        // Update the in-memory `settings` signal, NOT just a fresh load_settings().
        // Other handlers (connect-with-remember, shell mode, telemetry) persist by
        // cloning this signal; if we only wrote a detached copy to disk, the next
        // signal-based save_settings would clobber easy_mode back to None. Writing
        // the signal keeps it authoritative so the choice survives.
        {
            let mut s = settings.write();
            s.easy_mode = Some(on);
            let _ = save_settings(&s);
        }
        easy_mode.set(on);
    };

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
            #[cfg(all(
                feature = "shell-ws",
                not(any(target_os = "android", target_os = "ios"))
            ))]
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
    // Reactive CSS generation - regenerates when theme signals change
    let css_block = if cfg.inject_css {
        let theme_val = *theme.read();
        let radius_val = *border_radius.read();
        let density_val = *density.read();

        let css = crate::theme::generate_theme_css(theme_val, radius_val, density_val);
        let mcss = mobile_css();
        let ucss = utils_css();
        let tcss = crate::view_transitions::theme_transitions_css();
        let toast_css = crate::components::toast_css();
        let matrix_css = crate::components::matrix_rain_css();
        rsx! {
            // Static first-paint fade — its own node so re-injecting the
            // theme CSS below never re-triggers the animation.
            style { {crate::view_transitions::first_paint_fade_css()} }
            style { {css} }
            style { {mcss} }
            style { {ucss} }
            style { {tcss} }
            style { {toast_css} }
            style { {matrix_css} }
        }
    } else {
        rsx! {}
    };

    let container_class = cfg.container_class;
    let platform_name = cfg.platform_name;

    rsx! {
        {css_block}

        div { class: "{container_class}",
            if easy_mode() {
                {
                    let host = config.read().host.clone();
                    let chat_api_url = {
                        let sig = matrix_api_url.read().clone();
                        if !sig.is_empty() {
                            sig
                        } else if !host.is_empty() {
                            derive_api_url(&host, config.read().use_tls)
                        } else {
                            String::new()
                        }
                    };
                    match flow() {
                        AuthFlow::SigningIn => rsx! {
                            ConnectingScreen {
                                step: ConnectingStep::SigningIn,
                                host: host.clone(),
                                on_cancel: move |_| on_disconnect(()),
                            }
                        },
                        AuthFlow::Registering(step) => rsx! {
                            ConnectingScreen {
                                step,
                                host: host.clone(),
                                on_cancel: move |_| on_disconnect(()),
                            }
                        },
                        _ => {
                            let d1 = dispatch.clone();
                            let d2 = dispatch.clone();
                            rsx! {
                                EasyModeShell {
                                    api_url: chat_api_url,
                                    auth_token: matrix_auth_token.read().clone(),
                                    tenant_id: config.read().tenant_id.clone(),
                                    chat_mailbox,
                                    conversation_mailbox,
                                    on_logout: on_logout,
                                    on_easy_mode_change: on_easy_mode_change,
                                    on_sign_in: move |_| d1(AuthEvent::SignInRequested),
                                    on_chat_event: move |ev| d2(ev),
                                }
                            }
                        },
                    }
                }
            } else {
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
                        ConfigForm {
                            config: config.read().clone(),
                            on_connect: on_connect,
                            is_connecting: false,
                            remember: settings.read().auto_connect,
                            external_error: connect_error.read().clone(),
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
                            derive_api_url(&host, config.read().use_tls)
                        } else {
                            String::new()
                        }
                    };

                    {
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
                                    telemetry_enabled: settings.read().telemetry_enabled,
                                    on_telemetry_change: move |v: bool| {
                                        let mut s = settings.write();
                                        s.telemetry_enabled = v;
                                        let _ = save_settings(&s);
                                        // Apply immediately: on disables the
                                        // Sentry client (no events/sessions),
                                        // off re-inits. No relaunch needed.
                                        pentest_core::telemetry::set_enabled(v);
                                    },
                                    easy_mode_on: easy_mode(),
                                    on_easy_mode_change: on_easy_mode_change,
                                    on_disconnect: move |_| on_disconnect(()),
                                    on_start_download: on_start_download,
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
                                    theme: *theme.read(),
                                    on_theme_change: move |t: Theme| {
                                        let mut s = settings.write();
                                        s.theme = t;
                                        let _ = save_settings(&s);
                                        theme.set(t);
                                    },
                                    border_radius: *border_radius.read(),
                                    on_border_radius_change: move |r: BorderRadius| {
                                        let mut s = settings.write();
                                        s.border_radius = r;
                                        let _ = save_settings(&s);
                                        border_radius.set(r);
                                    },
                                    density: *density.read(),
                                    on_density_change: move |d: Density| {
                                        let mut s = settings.write();
                                        s.density = d;
                                        let _ = save_settings(&s);
                                        density.set(d);
                                    },
                                    api_url: chat_api_url,
                                    auth_token: matrix_auth_token.read().clone(),
                                    tenant_id: config.read().tenant_id.clone(),
                                    chat_mailbox,
                                    conversation_mailbox,
                                }
                            }
                        }
                    }
                },
                }
            }
        }
    }
}
