//! Chat input area: auto-resizing textarea + Send button.
//!
//! All keystrokes, Enter-to-send, and Send-button clicks are handled by a
//! delegated JavaScript listener (`installChatSendBridge` in utils.js). Sends
//! are funneled back to Rust via a long-lived `document::eval` channel.
//!
//! This bypasses dioxus's `onsubmit` / `onkeydown` / `oninput` event path,
//! which trips the `.unwrap()` in dioxus-liveview-0.7.x's `convert_form_data`
//! and `convert_keyboard_data` once the conversation accumulates DOM state
//! (#130). A pleasant side effect is that we no longer pay a WebSocket round
//! trip per keystroke for auto-resize.

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

/// Auto-resizing textarea + Send button with Enter-to-submit behaviour.
///
/// The textarea grows from a minimum of 40px up to 200px as the user types.
/// Plain Enter sends the message; Shift+Enter inserts a newline. Both auto-
/// resize and send dispatch happen entirely on the client; the only Rust
/// involvement is receiving the submitted text via the eval channel below.
#[component]
pub fn ChatInput(props: ChatInputProps) -> Element {
    let is_sending = props.is_sending;
    let agent_thinking = props.agent_thinking;
    let disabled = is_sending() || agent_thinking();
    let on_send = props.on_send;

    // Re-focus the textarea when agent finishes (disabled → enabled)
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
                // Wait for utils.js to define the bridge installer. utils.js
                // is injected once by ChatPanel; if it hasn't run yet, this
                // loop polls briefly until the function appears.
                while (typeof window.installChatSendBridge !== 'function') {
                    await new Promise(function(r) { setTimeout(r, 50); });
                }
                installChatSendBridge(function(text) { dioxus.send(text); });
                // Park forever so the eval (and `dioxus.send`) stay alive.
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
            // action="javascript:void(0)" is a defensive no-op in case the JS
            // bridge listener somehow misses a submit (e.g. before utils.js
            // has loaded). With no `onsubmit` handler the browser will not
            // attempt navigation regardless.
            action: "javascript:void(0)",
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
                r#type: "submit",
                disabled: disabled,
                "Send"
            }
        }
    }
}
