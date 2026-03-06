//! Chat input area: auto-resizing textarea, send button, and keyboard handler.

use dioxus::html::FormValue;
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
/// The textarea grows from a minimum of 40px up to 200px as the user types,
/// using a JS eval to measure `scrollHeight`. Plain Enter sends the message;
/// Shift+Enter inserts a newline. After sending, the height resets to minimum.
#[component]
pub fn ChatInput(props: ChatInputProps) -> Element {
    let is_sending = props.is_sending;
    let agent_thinking = props.agent_thinking;
    let disabled = is_sending() || agent_thinking();

    let send_from_form = {
        let on_send = props.on_send;
        move |evt: Event<FormData>| {
            evt.prevent_default();
            let text = match evt.get_first("message") {
                Some(FormValue::Text(s)) => s,
                _ => String::new(),
            };
            on_send.call(text);

            // Reset textarea height back to minimum after submit
            spawn(async move {
                let _ = document::eval(
                    r#"
                    var el = document.querySelector('.chat-textarea');
                    if (el) {
                        el.style.height = '40px';
                    }
                "#,
                )
                .await;
            });
        }
    };

    let on_keydown = move |evt: Event<KeyboardData>| {
        if evt.key() == Key::Enter && !evt.modifiers().shift() {
            evt.prevent_default();
            // Use requestSubmit() so the form's onsubmit handler fires
            // (which calls prevent_default and processes the message).
            spawn(async move {
                if let Err(e) = document::eval("submitForm('.chat-input-form')").await {
                    tracing::warn!("JS eval failed (form submit): {e}");
                }
            });
        }
    };

    let on_input = move |_evt: Event<FormData>| {
        // Auto-resize: reset to auto then clamp between 40px and 200px
        spawn(async move {
            let _ = document::eval(
                r#"
                var el = document.querySelector('.chat-textarea');
                if (el) {
                    el.style.height = 'auto';
                    el.style.height = Math.min(Math.max(el.scrollHeight, 40), 200) + 'px';
                }
            "#,
            )
            .await;
        });
    };

    rsx! {
        form {
            class: "chat-input-area chat-input-form",
            // Prevent native form navigation in LiveView mode — prevent_default
            // travels over WebSocket and may arrive after the browser acts.
            action: "javascript:void(0)",
            onsubmit: send_from_form,
            textarea {
                class: "chat-input chat-textarea",
                name: "message",
                rows: "1",
                style: "min-height: 40px; max-height: 200px; overflow-y: auto; resize: none;",
                placeholder: if disabled { "Waiting for response..." } else { "Type a message..." },
                disabled: disabled,
                onkeydown: on_keydown,
                oninput: on_input,
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
