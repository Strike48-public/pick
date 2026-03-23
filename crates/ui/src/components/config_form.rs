use dioxus::prelude::*;
use pentest_core::config::ConnectorConfig;
use pentest_core::build_defaults::{DEFAULT_CONNECTOR_HOST, DEFAULT_ENV_LABEL};

/// Props for the login screen.
#[derive(Props, Clone, PartialEq)]
pub struct LoginScreenProps {
    /// Current config (may have host override from settings).
    pub config: ConnectorConfig,
    /// Called with (config, remember=true) when user taps Sign In.
    pub on_connect: EventHandler<(ConnectorConfig, bool)>,
    /// Whether a connection attempt is in progress.
    #[props(default = false)]
    pub is_connecting: bool,
}

/// Minimal login screen with optional advanced host override.
#[component]
pub fn LoginScreen(props: LoginScreenProps) -> Element {
    let mut show_advanced = use_signal(|| false);
    let mut host_override = use_signal(|| {
        let h = &props.config.host;
        if h == DEFAULT_CONNECTOR_HOST || h.is_empty() {
            String::new()
        } else {
            h.clone()
        }
    });

    let has_override = !host_override.read().is_empty();

    let on_sign_in = move |_| {
        let mut config = props.config.clone();
        if has_override {
            config.host = host_override.read().clone();
        } else {
            config.host = DEFAULT_CONNECTOR_HOST.to_string();
        }
        props.on_connect.call((config, true));
    };

    rsx! {
        style { {include_str!("css/login_screen.css")} }

        div { class: "login-screen",
            // Logo
            div { class: "login-logo", "S48" }

            // App name
            div { class: "login-title", "Strike48" }

            // Environment badge
            div {
                class: if DEFAULT_ENV_LABEL == "Development" { "login-env-badge dev" } else { "login-env-badge prod" },
                "{DEFAULT_ENV_LABEL}"
            }

            // Host override label (only shown when overridden)
            if has_override {
                div { class: "login-host-label", "{host_override}" }
            }

            // Sign In button
            button {
                class: "login-button",
                disabled: props.is_connecting,
                onclick: on_sign_in,
                if props.is_connecting { "Connecting..." } else { "Sign In" }
            }

            // Advanced toggle
            div { class: "login-advanced-toggle",
                span {
                    onclick: move |_| show_advanced.toggle(),
                    if *show_advanced.read() { "Hide Advanced" } else { "Advanced" }
                }
            }

            // Advanced panel
            if *show_advanced.read() {
                div { class: "login-advanced-panel",
                    label { "Server Host" }
                    input {
                        r#type: "text",
                        placeholder: "{DEFAULT_CONNECTOR_HOST}",
                        value: "{host_override}",
                        oninput: move |e| host_override.set(e.value()),
                    }
                }
            }
        }
    }
}
