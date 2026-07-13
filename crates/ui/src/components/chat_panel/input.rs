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
//! * **Everywhere else** (Windows, Android, iOS, …) — native Dioxus events.
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
#[cfg(any(target_os = "macos", target_os = "linux"))]
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
/// other non-desktop-Unix targets). Kept intentionally as the pattern #191
/// restored to unbreak StrikeHub-hosted Pick on Windows/WebView2.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[component]
pub fn ChatInput(props: ChatInputProps) -> Element {
    let is_sending = props.is_sending;
    let agent_thinking = props.agent_thinking;
    let disabled = is_sending() || agent_thinking();
    let on_send = props.on_send;

    let mut input_text = use_signal(String::new);

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

    let on_input = move |evt: Event<FormData>| {
        input_text.set(evt.value());
        spawn(async move {
            let _ = document::eval(
                "var el=document.querySelector('.chat-textarea');\
                 if(el){el.style.height='auto';\
                 el.style.height=Math.min(Math.max(el.scrollHeight,40),200)+'px';}",
            )
            .await;
        });
    };

    let on_keydown = move |evt: Event<KeyboardData>| {
        if evt.key() == Key::Enter && !evt.modifiers().shift() {
            evt.prevent_default();
            let text = input_text.read().trim().to_string();
            if !text.is_empty() {
                input_text.set(String::new());
                spawn(async move {
                    let _ = document::eval(
                        "var el=document.querySelector('.chat-textarea');\
                         if(el){el.value='';el.style.height='40px';}",
                    )
                    .await;
                });
                on_send.call(text);
            }
        }
    };

    let on_click = move |evt: Event<MouseData>| {
        evt.prevent_default();
        let text = input_text.read().trim().to_string();
        if !text.is_empty() {
            input_text.set(String::new());
            spawn(async move {
                let _ = document::eval(
                    "var el=document.querySelector('.chat-textarea');\
                     if(el){el.value='';el.style.height='40px';}",
                )
                .await;
            });
            on_send.call(text);
        }
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
                oninput: on_input,
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
