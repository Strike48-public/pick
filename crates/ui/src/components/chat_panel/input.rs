//! Chat input area: auto-resizing textarea + Send button.
//!
//! Uses native Dioxus events (`oninput`, `onkeydown`, `onclick`) for the send
//! path, matching KubeStudio's pattern. This deliberately reverts the JS-bridge
//! rerouting from #132 while keeping the per-bubble `onmounted` removal in
//! `messages.rs` — that removal is what actually fixed #130 (panic in
//! `dioxus-liveview` 0.7.x `convert_mounted_data`). Sending through
//! `document::eval`'s reverse channel (`dioxus.send`) doesn't deliver on
//! Windows/WebView2 when Pick is hosted inside StrikeHub's iframe, which
//! silently broke chat send on the Windows MSI (see issue #189).

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
/// Plain Enter sends the message; Shift+Enter inserts a newline.
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

    // Auto-resize textarea client-side so we don't pay a WebSocket round trip
    // per keystroke. Height clamped between 40px and 200px (matches CSS).
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
            // Neutralise the browser's native submit path. Sends are dispatched
            // by onkeydown / onclick; leaving submit unbound would let Enter
            // attempt an iframe navigation.
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
