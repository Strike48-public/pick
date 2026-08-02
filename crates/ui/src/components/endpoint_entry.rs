//! Easy-mode "Change server" URL entry.
//!
//! Ed's ask: even in easy mode, let the user point Pick at a different Strike48
//! endpoint than the compile-time baked one — "just ask for a new URL". One
//! field; the API + WS URLs are derived by `normalize_host`, and the tenant is
//! resolved server-side by the OAuth-first pre-approve flow, so we do not ask
//! for it here.

use dioxus::prelude::*;

use pentest_core::config::ConnectorConfig;

/// Props for [`EndpointEntry`].
#[derive(Props, Clone, PartialEq)]
pub struct EndpointEntryProps {
    pub initial: String,
    pub on_save: EventHandler<String>,
    pub on_cancel: EventHandler<()>,
}

/// Modal URL entry for changing the Strike48 endpoint. Validates via
/// `normalize_host`: a valid URL enables Save and shows a "Will connect to: …"
/// preview; an empty or malformed URL shows an inline error and disables Save.
#[component]
pub fn EndpointEntry(props: EndpointEntryProps) -> Element {
    let mut url = use_signal(|| props.initial.clone());

    // Validation + preview, recomputed on every keystroke.
    let value = url.read().clone();
    let trimmed = value.trim().to_string();
    let (hint, error): (Option<String>, Option<String>) = if trimmed.is_empty() {
        (None, None)
    } else {
        match ConnectorConfig::normalize_host(&trimmed) {
            Ok(n) => (
                n.hint()
                    .or_else(|| Some(format!("Will connect to: {}", n.value))),
                None,
            ),
            Err(e) => (None, Some(e)),
        }
    };
    let can_save = !trimmed.is_empty() && error.is_none();

    rsx! {
        div { class: "easy-doc-screen easy-overlay",
            div { class: "easy-signin",
                p { class: "easy-signin-title", "Change Strike48 server" }
                p { class: "easy-signin-sub", "Enter the URL of the Strike48 server to connect to." }
                div { class: "input-group",
                    input {
                        r#type: "text",
                        placeholder: "wss://strike48.example.com:443",
                        value: "{url}",
                        oninput: move |e| url.set(e.value()),
                    }
                    if let Some(hint) = hint {
                        span { class: "form-hint", "{hint}" }
                    }
                    if let Some(err) = error {
                        span { class: "error-banner", "{err}" }
                    }
                }
                button {
                    class: "action-card",
                    disabled: !can_save,
                    onclick: move |_| {
                        let v = url.read().trim().to_string();
                        if !v.is_empty() {
                            props.on_save.call(v);
                        }
                    },
                    span { class: "action-card-label", "Save" }
                }
                button {
                    class: "easy-signin-secondary",
                    onclick: move |_| props.on_cancel.call(()),
                    "Cancel"
                }
            }
        }
    }
}
