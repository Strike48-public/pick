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

/// The DOM id of the URL input. Save reads its value straight from the DOM.
const INPUT_ID: &str = "endpoint-url-input";

/// Modal URL entry for changing the Strike48 endpoint.
///
/// The field is UNCONTROLLED (`initial_value`, no bound `value:`) and Save reads
/// its value **directly from the DOM** on submit. This is the only approach that
/// actually works in Pick's WebKitGTK desktop webview, where the alternatives
/// silently return empty:
///   * a bound `value:` is `volatile` — the always-mounted ChatPanel's 5s
///     re-render rewrites it to the DOM and blanks mid-typing;
///   * `FormData::get_first()` / the `oninput`-backed signal both come back
///     EMPTY for an uncontrolled input on this webview (observed: DOM `value`
///     was correct but the signal/form event were empty, so Save no-op'd and
///     the modal wouldn't close).
/// The DOM node is the single source of truth, so we `eval` its `.value` on
/// submit. The `preview` signal drives ONLY the live hint/error text; it may be
/// wiped by a stray empty `oninput`, which is harmless (it gates nothing).
#[component]
pub fn EndpointEntry(props: EndpointEntryProps) -> Element {
    // Preview-only state for the "Will connect to: …" / error line. NEVER the
    // source of the saved value — see the doc comment.
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

    let current_host = props.current_host.clone();
    // Save: read the DOM input's value via eval (the source of truth on this
    // webview), fall back to current_host if the read fails/empty, validate, then
    // hand it up. Async because document::eval is a future.
    let on_submit = move |e: FormEvent| {
        e.prevent_default();
        let current_host = current_host.clone();
        spawn(async move {
            let dom_val = document::eval(&format!(
                "return (document.getElementById('{INPUT_ID}') || {{}}).value || '';"
            ))
            .await
            .ok()
            .and_then(|v| v.as_str().map(str::to_string))
            .unwrap_or_default();
            let typed = dom_val.trim().to_string();
            let v = if typed.is_empty() {
                current_host.trim().to_string()
            } else {
                typed
            };
            if !v.is_empty() && ConnectorConfig::normalize_host(&v).is_ok() {
                props.on_save.call(v);
            }
        });
    };

    rsx! {
        div { class: "easy-doc-screen easy-overlay",
            div { class: "easy-signin",
                p { class: "easy-signin-title", "Change Strike48 server" }
                p { class: "easy-signin-sub", "Enter the URL of the Strike48 server to connect to." }
                form {
                    onsubmit: on_submit,
                    div { class: "input-group",
                        input {
                            id: "{INPUT_ID}",
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
