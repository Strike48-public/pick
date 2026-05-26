//! Connection configuration form component

use dioxus::prelude::*;
use pentest_core::config::ConnectorConfig;

/// Connection configuration form.
///
/// Errors from the parent's connect pipeline (host validation, transport
/// failure, registration rejection) are surfaced via `external_error`. Local
/// validation errors (empty host) are shown in the same banner. Inference
/// performed by `ConnectorConfig::normalize_host` is disclosed under the host
/// field so users can verify the resolved transport before connecting — see
/// the doc on `normalize_host` for the rationale.
#[component]
pub fn ConfigForm(
    config: ConnectorConfig,
    on_connect: EventHandler<(ConnectorConfig, bool)>,
    is_connecting: bool,
    #[props(default = false)] remember: bool,
    /// Error pushed in by the parent when connection or validation fails.
    /// Rendered in the same banner as local form errors.
    #[props(default = None)]
    external_error: Option<String>,
) -> Element {
    let mut host = use_signal(|| config.host.clone());
    let mut tenant_id = use_signal(|| config.tenant_id.clone());
    let mut auth_token = use_signal(|| config.auth_token.clone());
    let mut local_error = use_signal(|| None::<String>);
    let mut remember = use_signal(move || remember);

    let handle_submit = move |_| {
        let url = host.read().clone();
        let tenant = tenant_id.read().clone();
        let token = auth_token.read().clone();

        if url.trim().is_empty() {
            local_error.set(Some("Strike48 host is required".into()));
            return;
        }

        local_error.set(None);

        let new_config = ConnectorConfig::new(url)
            .tenant_id(tenant)
            .auth_token(token);

        on_connect.call((new_config, *remember.read()));
    };

    // Live preview of what `normalize_host` will resolve. Only render when
    // inference actually changed the input — keeps the form quiet for users
    // who type the explicit form.
    let host_value = host.read().clone();
    let inference_hint = if host_value.trim().is_empty() {
        None
    } else {
        ConnectorConfig::normalize_host(&host_value)
            .ok()
            .and_then(|n| n.hint())
    };

    let banner_msg = local_error
        .read()
        .clone()
        .or_else(|| external_error.clone());

    rsx! {
        div { class: "config-form",
            h3 { "Connect to Strike48" }

            // Error message (local validation OR parent-supplied connect error)
            if let Some(err) = banner_msg {
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
                        placeholder: "wss://strike48.example.com:443",
                        value: "{host}",
                        disabled: is_connecting,
                        oninput: move |e| host.set(e.value()),
                    }
                    if let Some(hint) = inference_hint {
                        span {
                            class: "form-hint",
                            "{hint}"
                        }
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
