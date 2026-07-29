//! Chat input area: auto-resizing textarea + Send button.
//!
//! Two implementations behind `cfg` gates, both exposing the same `ChatInput`
//! component signature.
//!
//! * **macOS / Linux** — the JS bridge (`installChatSendBridge` in `utils.js`).
//!   Native `oninput` on the textarea hits dioxus-liveview 0.7.x's
//!   `convert_form_data`, which unwraps a `None` downcast and aborts the
//!   process on the first keystroke on macOS standalone (#224). The bridge
//!   catches Enter and Send-button clicks on the document instead, then hands
//!   the textarea value back to Rust via `document::eval`'s reverse channel
//!   (`dioxus.send` → `eval.recv`). This mirrors the pattern originally
//!   introduced in #132 and matches KubeStudio's workaround for the same
//!   converter panic class. Auto-resize also happens inside the JS listener,
//!   so we don't pay a WebSocket round trip per keystroke.
//!
//! * **iOS** — the same JS bridge as macOS/Linux. iOS runs in a WKWebView on
//!   the identical dioxus-liveview transport, and native `oninput` there hits
//!   the very same `convert_form_data` `None`-unwrap abort — it crashes the
//!   app on the first keystroke in the message box. The `document::eval`
//!   reverse channel used everywhere else in the iOS build (send bridge,
//!   auto-scroll, focus) delivers fine, so iOS takes the bridge path too.
//!
//! * **Everywhere else** (Windows, Android, …) — native Dioxus events.
//!   The reverse channel does not deliver in the WebView2 + LiveView + iframe
//!   combination StrikeHub uses on Windows (#189), so the JS-bridge send path
//!   would silently break chat there. Native `oninput` works on Windows both
//!   standalone and StrikeHub-hosted (#191). Android has historically
//!   preferred native events too, so it stays on the native path.

use dioxus::prelude::*;

/// Props for [`ChatInput`].
#[derive(Props, Clone, PartialEq)]
pub struct ChatInputProps {
    /// Called with the message text when the user submits.
    pub on_send: EventHandler<String>,
    /// True while a message is being sent to the API.
    pub is_sending: Signal<bool>,
    /// True while the agent is processing a response.
    pub agent_thinking: Signal<bool>,
}

/// Auto-resizing textarea + Send button — JS-bridge variant (macOS / Linux).
///
/// A long-lived `document::eval` installs delegated `input`, `keydown`, and
/// `click` listeners on the document (see `installChatSendBridge` in
/// `utils.js`) and parks awaiting a never-resolved promise so `dioxus.send`
/// stays callable. Each Enter-press or Send-button click flushes the textarea
/// text back to Rust via the reverse channel; no `oninput` handler is bound
/// on the textarea, so dioxus-liveview never invokes `convert_form_data`.
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "ios"))]
#[component]
pub fn ChatInput(props: ChatInputProps) -> Element {
    let is_sending = props.is_sending;
    let agent_thinking = props.agent_thinking;
    let disabled = is_sending() || agent_thinking();
    let on_send = props.on_send;

    // Re-focus the textarea when the agent finishes (disabled → enabled).
    use_effect(move || {
        if !disabled {
            spawn(async move {
                let _ = document::eval(
                    "var el=document.querySelector('.chat-textarea');if(el){el.focus();}",
                )
                .await;
            });
        }
    });

    // Long-lived JS↔Rust send bridge. The eval installs document-level
    // delegated listeners (idempotent — see utils.js) and parks awaiting
    // a never-resolved promise so `dioxus.send` stays callable. Each call
    // from JS surfaces here as one `eval.recv()` result.
    use_hook(|| {
        spawn(async move {
            let mut eval = document::eval(
                r#"
                while (typeof window.installChatSendBridge !== 'function') {
                    await new Promise(function(r) { setTimeout(r, 50); });
                }
                installChatSendBridge(function(text) { dioxus.send(text); });
                await new Promise(function() {});
                "#,
            );
            while let Ok(text) = eval.recv::<String>().await {
                on_send.call(text);
            }
        });
    });

    rsx! {
        form {
            class: "chat-input-area chat-input-form",
            // Neutralise the browser's native submit path. Sends are dispatched
            // by the JS bridge on Enter / Send-button click; leaving submit
            // unbound would let Enter attempt an iframe navigation.
            action: "javascript:void(0)",
            onsubmit: move |evt| { evt.prevent_default(); },
            textarea {
                class: "chat-input chat-textarea",
                name: "message",
                rows: "1",
                style: "min-height: 40px; max-height: 200px; overflow-y: auto; resize: none;",
                placeholder: if disabled { "Waiting for response..." } else { "Type a message..." },
                disabled: disabled,
            }
            button {
                class: "chat-send-btn",
                // type=button so the browser doesn't fire an implicit form
                // submit — the JS bridge handles the click directly.
                r#type: "button",
                disabled: disabled,
                "Send"
            }
        }
    }
}

/// Auto-resizing textarea + Send button — native-events variant (Windows and
/// other non-desktop-Unix targets).
///
/// We deliberately do NOT bind `oninput` / read `evt.value()`: on the desktop
/// WebView2 + LiveView transport a form event does not carry a usable
/// `SerializedFormData` payload, so `evt.value()` is always empty (and the
/// upstream converter used to panic on it — see the vendored dioxus-liveview
/// patch). Instead we read the textarea's value from the DOM via
/// `document::eval` at send time. Enter submits, Shift+Enter inserts a newline;
/// the auto-resize runs in a JS listener installed once. `onkeydown`
/// (KeyboardData) and `onclick` (MouseData) DO downcast fine on this transport.
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "ios")))]
#[component]
pub fn ChatInput(props: ChatInputProps) -> Element {
    let is_sending = props.is_sending;
    let agent_thinking = props.agent_thinking;
    let disabled = is_sending() || agent_thinking();
    let on_send = props.on_send;

    // Re-focus the textarea when agent finishes (disabled → enabled).
    use_effect(move || {
        if !disabled {
            spawn(async move {
                let _ = document::eval(
                    "var el=document.querySelector('.chat-textarea');if(el){el.focus();}",
                )
                .await;
            });
        }
    });

    // Install a one-time JS `input` listener that auto-resizes the textarea, so
    // we never need a Rust `oninput` (which would hit the broken form-data
    // path). Idempotent via a flag on the element.
    use_hook(|| {
        spawn(async move {
            let _ = document::eval(
                r#"
                (function(){
                    var el = document.querySelector('.chat-textarea');
                    if (el && !el.__autoResizeBound) {
                        el.__autoResizeBound = true;
                        el.addEventListener('input', function() {
                            el.style.height = 'auto';
                            el.style.height = Math.min(Math.max(el.scrollHeight, 40), 200) + 'px';
                        });
                    }
                })();
                "#,
            )
            .await;
        });
    });

    // Read the textarea value from the DOM, clear + reset it, and send. The
    // one-shot `dioxus.send` reverse channel resolves on the standalone desktop
    // WebView2 (it also backs focus/auto-scroll/OAuth here), so we get the value
    // without ever touching `convert_form_data`.
    let flush_and_send = move || {
        spawn(async move {
            let mut eval = document::eval(
                r#"
                var el = document.querySelector('.chat-textarea');
                var v = el ? el.value : '';
                if (el) { el.value = ''; el.style.height = '40px'; }
                dioxus.send(v);
                "#,
            );
            if let Ok(text) = eval.recv::<String>().await {
                let text = text.trim().to_string();
                if !text.is_empty() {
                    on_send.call(text);
                }
            }
        });
    };

    // Enter submits; Shift+Enter falls through to insert a newline.
    let on_keydown = move |evt: Event<KeyboardData>| {
        if evt.key() == Key::Enter && !evt.modifiers().shift() {
            evt.prevent_default();
            flush_and_send();
        }
    };

    let on_click = move |evt: Event<MouseData>| {
        evt.prevent_default();
        flush_and_send();
    };

    rsx! {
        form {
            class: "chat-input-area chat-input-form",
            action: "javascript:void(0)",
            onsubmit: move |evt| { evt.prevent_default(); },
            textarea {
                class: "chat-input chat-textarea",
                name: "message",
                rows: "1",
                style: "min-height: 40px; max-height: 200px; overflow-y: auto; resize: none;",
                placeholder: if disabled { "Waiting for response..." } else { "Type a message..." },
                disabled: disabled,
                onkeydown: on_keydown,
            }
            button {
                class: "chat-send-btn",
                r#type: "button",
                disabled: disabled,
                onclick: on_click,
                "Send"
            }
        }
    }
}
