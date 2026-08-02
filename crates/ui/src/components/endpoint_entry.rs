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
    /// The URL being edited. Hoisted into the parent [`EasyModeShell`] so it
    /// survives this component remounting — which happens when the parent's
    /// props churn (e.g. auth_token/tenant_id clearing on logout) forces
    /// EasyModeShell to re-render and rebuild the overlay subtree. If the state
    /// lived here in a local `use_signal`, that remount would blank the field
    /// mid-typing; keeping it in the stable parent makes it durable.
    pub url: Signal<String>,
    pub on_save: EventHandler<String>,
    pub on_cancel: EventHandler<()>,
}

/// Modal URL entry for changing the Strike48 endpoint. Validates via
/// `normalize_host`: a valid URL enables Save and shows a "Will connect to: …"
/// preview; an empty or malformed URL shows an inline error and disables Save.
#[component]
pub fn EndpointEntry(props: EndpointEntryProps) -> Element {
    let mut url = props.url;

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
                        // UNCONTROLLED input: `initial_value` (not `value`) seeds the
                        // field with the current host once, via the DOM node's
                        // `defaultValue`. We deliberately avoid the `value` attribute
                        // because dioxus-html marks it `volatile` (elements.rs), so the
                        // diff engine (`diff/node.rs`: `if volatile || attribute_changed`)
                        // RE-WRITES it to the DOM on EVERY re-render regardless of change.
                        // The always-mounted ChatPanel re-renders on its 5s poll loop, so
                        // a controlled `value` would re-apply the signal's value to the
                        // webview <input> mid-typing and blank whatever the user just
                        // typed (the clobber). `initial_value` is non-volatile and only
                        // updates the field while its dirty-value flag is false (before
                        // the user types), so re-renders can't clear it. The hoisted
                        // `url` signal still tracks every keystroke via `oninput`, which
                        // drives the normalize_host hint/error and Save-gating below.
                        initial_value: "{url}",
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
