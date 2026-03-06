//! Pentest Connector Mobile Application Entry Point

use dioxus::prelude::*;

use pentest_core::config::ShellMode;
use pentest_ui::{connector_app, ConnectorAppConfig};

const MOBILE_CONFIG: ConnectorAppConfig = ConnectorAppConfig {
    platform_name: "Mobile",
    container_class: "app-container",
    shell_route_mode: ShellMode::Proot,
    default_proot: true,
    start_liveview_server: true,
    inject_css: true,
    extra_init_messages: &[],
    create_tools: pentest_tools::create_tool_registry,
    set_sandbox: None,
};

fn main() {
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Debug)
                .with_tag("PentestConnector"),
        );

        pentest_platform::android::init();

        // Register Android-specific browser opener for OAuth flows
        pentest_core::matrix::set_browser_opener(|url| {
            pentest_platform::android::open_browser(url).map_err(|e| e.to_string())
        });

        // Register OAuth callback port setter — tells OAuthCallbackActivity
        // which port the local Axum server is listening on.
        pentest_core::matrix::set_oauth_port_setter(|port| {
            if let Err(e) = pentest_platform::android::set_oauth_callback_port(port) {
                tracing::warn!("Failed to set OAuth callback port: {e}");
            }
        });
    }

    dioxus::launch(MobileApp);
}

#[component]
fn MobileApp() -> Element {
    connector_app(MOBILE_CONFIG)
}
