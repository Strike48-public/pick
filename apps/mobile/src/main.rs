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
    easy_mode: true,
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

        // Register share handler
        pentest_core::share::set_share_handler(|text| {
            pentest_platform::android::share_text(text).map_err(|e| e.to_string())
        });

        // Register OAuth callback port setter — tells OAuthCallbackActivity
        // which port the local Axum server is listening on.
        pentest_core::matrix::set_oauth_port_setter(|port| {
            if let Err(e) = pentest_platform::android::set_oauth_callback_port(port) {
                tracing::warn!("Failed to set OAuth callback port: {e}");
            }
        });
    }

    #[cfg(target_os = "ios")]
    {
        // Register the iOS native OIDC session (ASWebAuthenticationSession).
        // The loopback-callback flow can't work on iOS — launching a browser
        // backgrounds the app and suspends the callback server — so iOS uses
        // this in-app auth session with a custom-scheme callback instead. It's
        // the iOS analog of Android's OAuthCallbackActivity. The callback scheme
        // (com.strike48.pentest) is declared in the Info.plist via Dioxus.toml.
        pentest_core::matrix::set_web_auth_session(|url, scheme| {
            pentest_platform::ios::present_web_auth_session(url, scheme).map_err(|e| e.to_string())
        });

        // Register iOS browser opener for opening report URLs
        pentest_core::matrix::set_browser_opener(|url| {
            pentest_platform::ios::open_url(url).map_err(|e| e.to_string())
        });

        // Register share handler
        pentest_core::share::set_share_handler(|text| {
            pentest_platform::ios::share_text(text).map_err(|e| e.to_string())
        });
    }

    dioxus::launch(MobileApp);
}

#[component]
fn MobileApp() -> Element {
    connector_app(MOBILE_CONFIG)
}
