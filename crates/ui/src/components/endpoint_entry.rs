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
    /// The current host, used to seed the field (via `initial_value`).
    #[props(default)]
    pub current_host: String,
    pub on_save: EventHandler<String>,
    pub on_cancel: EventHandler<()>,
}

/// Modal URL entry for changing the Strike48 endpoint.
///
/// The field is UNCONTROLLED and its value is read once, on submit, from the
/// form event (`FormData::get_first`). This is the idiomatic Dioxus pattern for
/// a simple form and it avoids two traps we previously hit with a value-bound
/// signal:
///   1. `<input value=…>` is `volatile` in dioxus-html — every re-render (the
///      always-mounted ChatPanel re-renders on a 5s poll) re-writes it to the
///      DOM, blanking mid-typing.
///   2. Gating Save on a signal let a stray empty `oninput` (fired when the
///      field remounts on logout prop churn) wipe the value and silently
///      disable Save.
/// Reading the DOM's own value on submit sidesteps both: nothing is bound, and
/// Save's value is whatever is actually in the field. A small local signal backs
/// only the live "Will connect to: …" / error preview, which gates nothing.
#[component]
pub fn EndpointEntry(props: EndpointEntryProps) -> Element {
    // Preview-only state. Seeded from current_host so the hint shows before the
    // user types; updated on input. Never used for the saved value.
    let mut preview = use_signal(|| props.current_host.clone());

    let trimmed = preview.read().trim().to_string();
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

    rsx! {
        div { class: "easy-doc-screen easy-overlay",
            div { class: "easy-signin",
                p { class: "easy-signin-title", "Change Strike48 server" }
                p { class: "easy-signin-sub", "Enter the URL of the Strike48 server to connect to." }
                form {
                    // Read the field once, on submit, from the form event. Enter or
                    // the Save button both fire this.
                    onsubmit: move |e: FormEvent| {
                        e.prevent_default();
                        let raw = match e.get_first("server_url") {
                            Some(FormValue::Text(s)) => s,
                            _ => String::new(),
                        };
                        let v = raw.trim().to_string();
                        // Only save a valid URL; a bad/empty one leaves the inline
                        // error visible (the preview updates on input below).
                        if !v.is_empty() && ConnectorConfig::normalize_host(&v).is_ok() {
                            props.on_save.call(v);
                        }
                    },
                    div { class: "input-group",
                        input {
                            name: "server_url",
                            r#type: "text",
                            placeholder: "wss://strike48.example.com:443",
                            // UNCONTROLLED: `initial_value` (defaultValue) seeds the
                            // field once at mount and is NOT volatile, so re-renders
                            // can't clobber it. No `value:` binding.
                            initial_value: "{props.current_host}",
                            oninput: move |e| preview.set(e.value()),
                        }
                        if let Some(hint) = hint {
                            span { class: "form-hint", "{hint}" }
                        }
                        if let Some(err) = error {
                            span { class: "error-banner", "{err}" }
                        }
                    }
                    button {
                        r#type: "submit",
                        class: "action-card",
                        span { class: "action-card-label", "Save" }
                    }
                    button {
                        r#type: "button",
                        class: "easy-signin-secondary",
                        onclick: move |_| props.on_cancel.call(()),
                        "Cancel"
                    }
                }
            }
        }
    }
}
