//! Connection configuration form component

use dioxus::prelude::*;
use pentest_core::config::ConnectorConfig;

/// Connection configuration form
#[component]
pub fn ConfigForm(
    config: ConnectorConfig,
    on_connect: EventHandler<(ConnectorConfig, bool)>,
    is_connecting: bool,
    #[props(default = false)] remember: bool,
) -> Element {
    let mut host = use_signal(|| config.host.clone());
    let mut tenant_id = use_signal(|| config.tenant_id.clone());
    let mut auth_token = use_signal(|| config.auth_token.clone());
    let mut error_msg = use_signal(|| None::<String>);
    let mut remember = use_signal(move || remember);

    let handle_submit = move |_| {
        let url = host.read().clone();
        let tenant = tenant_id.read().clone();
        let token = auth_token.read().clone();

        // Validation
        if url.is_empty() {
            error_msg.set(Some("Strike48 host is required".into()));
            return;
        }

        error_msg.set(None);

        let new_config = ConnectorConfig::new(url)
            .tenant_id(tenant)
            .auth_token(token);

        on_connect.call((new_config, *remember.read()));
    };

    rsx! {
        div { class: "config-form",
            h3 { "Connect to Strike48" }

            // Error message
            if let Some(err) = error_msg.read().as_ref() {
                div {
                    class: "error-banner",
                    "{err}"
                }
            }

            div { class: "form-row",
                div { class: "input-group",
                    label { "Strike48 Host" }
                    input {
                        r#type: "text",
                        placeholder: "grpc://localhost:50061",
                        value: "{host}",
                        disabled: is_connecting,
                        oninput: move |e| host.set(e.value()),
                    }
                }
            }

            div { class: "form-row",
                div { class: "input-group",
                    label { "Tenant ID" }
                    input {
                        r#type: "text",
                        placeholder: "default",
                        value: "{tenant_id}",
                        disabled: is_connecting,
                        oninput: move |e| tenant_id.set(e.value()),
                    }
                }
            }

            div { class: "form-row",
                div { class: "input-group",
                    label { "Auth Token" }
                    input {
                        r#type: "password",
                        placeholder: "ott_xxx or JWT token",
                        value: "{auth_token}",
                        disabled: is_connecting,
                        oninput: move |e| auth_token.set(e.value()),
                    }
                    span {
                        class: "form-hint",
                        "Leave empty for post-approval authentication"
                    }
                }
            }

            div { class: "form-row",
                label {
                    class: "checkbox-label",
                    input {
                        r#type: "checkbox",
                        checked: *remember.read(),
                        disabled: is_connecting,
                        oninput: move |e: Event<FormData>| remember.set(e.value() == "true"),
                    }
                    "Remember connection"
                }
            }

            div { class: "form-row",
                button {
                    r#type: "button",
                    class: "success",
                    disabled: is_connecting,
                    onclick: handle_submit,
                    if is_connecting { "Connecting..." } else { "Connect" }
                }
            }
        }
    }
}
