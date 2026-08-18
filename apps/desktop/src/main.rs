//! Pentest Connector Desktop Application

use dioxus::desktop::{Config, LogicalSize, WindowBuilder};
use dioxus::prelude::*;

use pentest_core::config::ShellMode;
use pentest_core::settings::load_settings;
use pentest_ui::{connector_app, mobile_css, utils_css, ConnectorAppConfig};

const DESKTOP_CONFIG: ConnectorAppConfig = ConnectorAppConfig {
    platform_name: "Desktop",
    container_class: "mobile-app",
    shell_route_mode: ShellMode::Native,
    default_proot: true,
    start_liveview_server: true,
    inject_css: false,
    extra_init_messages: &[],
    create_tools: pentest_tools::create_tool_registry,
    set_sandbox: Some(pentest_platform::set_use_sandbox),
    sandbox_available: Some(pentest_platform::sandbox_available_blocking),
    run_wsl_install: Some(pentest_platform::run_wsl_install_blocking),
    poll_wsl_install_result: Some(pentest_platform::poll_wsl_install_result),
    // Per-app fallback default. The effective mode is resolved at runtime as
    // persisted-setting > build-time PICK_EASY_MODE env > this literal, so a
    // desktop build can ship easy-mode-first via PICK_EASY_MODE=true without
    // editing code, and the in-app Settings toggle overrides either.
    easy_mode: false,
};

fn main() {
    // Initialize logging: console + file
    let log_path = pentest_core::logging::init_logging_with_file("debug");

    tracing::info!("Log file: {}", log_path.display());
    tracing::info!("Starting Pentest Connector Desktop");

    // Register the OS credential store as the secure backend for bearer tokens
    // (Windows Credential Manager / macOS Keychain / Linux Secret Service). Without
    // this, `pentest_core::secure_store` has no desktop backend and the Matrix chat
    // token is never persisted — forcing a fresh browser sign-in on every launch.
    // Mirrors the iOS Keychain / Android Keystore registration in apps/mobile.
    pentest_core::secure_store::set_backend(
        pentest_platform::desktop::secure_set,
        pentest_platform::desktop::secure_get,
        pentest_platform::desktop::secure_delete,
    );

    // Register the native OS clipboard so "Copy link" works on Windows, where
    // WebView2 does not expose navigator.clipboard from the custom-protocol
    // origin (the JS path silently no-ops there).
    pentest_core::clipboard::set_clipboard_handler(pentest_platform::desktop::clipboard_copy_text);

    // Load theme from settings
    let settings = load_settings();
    let css = pentest_ui::theme::generate_theme_css(
        settings.theme,
        settings.border_radius,
        settings.density,
    );
    let mcss = mobile_css();
    let ucss = utils_css();

    dioxus::LaunchBuilder::desktop()
        .with_cfg(
            Config::default()
                // No native menu bar — Dioxus adds a default Window/Edit/Help
                // menu otherwise, which is noise for this single-view app.
                .with_menu(None)
                .with_window(
                    WindowBuilder::new()
                        .with_title("Pick")
                        .with_inner_size(LogicalSize::new(480.0, 800.0))
                        .with_min_inner_size(LogicalSize::new(360.0, 600.0)),
                )
                .with_custom_head(format!(r#"<style>{css}{mcss}{ucss}</style>"#)),
        )
        .launch(DesktopApp);
}

#[component]
fn DesktopApp() -> Element {
    connector_app(DESKTOP_CONFIG)
}
