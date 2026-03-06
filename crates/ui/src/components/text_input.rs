//! Reusable text input component with optional label.
//!
//! Mirrors the strike48/ui `TextInput` API: value, onchange, placeholder,
//! disabled, input_type, label, and class.

use dioxus::prelude::*;

const TEXT_INPUT_CSS: &str = include_str!("css/text_input.css");

/// A reusable text input with optional label.
#[component]
pub fn TextInput(
    /// Current value of the input.
    value: String,
    /// Called when the input value changes.
    #[props(default)]
    onchange: EventHandler<String>,
    /// Placeholder text.
    #[props(default)]
    placeholder: String,
    /// Whether the input is disabled.
    #[props(default)]
    disabled: bool,
    /// HTML input type (e.g. "text", "password", "email").
    #[props(default = "text".to_string())]
    input_type: String,
    /// Optional label displayed above the input.
    #[props(default)]
    label: Option<String>,
    /// Additional CSS class appended to the input element.
    #[props(default)]
    class: String,
) -> Element {
    let input_class = if class.is_empty() {
        "text-input".to_string()
    } else {
        format!("text-input {class}")
    };

    rsx! {
        style { {TEXT_INPUT_CSS} }

        div { class: "input-wrapper",
            if let Some(ref label_text) = label {
                label { class: "input-label", "{label_text}" }
            }

            input {
                class: "{input_class}",
                r#type: "{input_type}",
                value: "{value}",
                placeholder: "{placeholder}",
                disabled: disabled,
                oninput: move |e| onchange.call(e.value()),
            }
        }
    }
}
