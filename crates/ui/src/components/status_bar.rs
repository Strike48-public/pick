use dioxus::prelude::*;

/// A hint displayed in the status bar (e.g., "? Help").
#[derive(Clone, PartialEq)]
pub struct ShortcutHint {
    pub keys: String,
    pub description: String,
}

#[derive(Props, Clone, PartialEq)]
pub struct StatusBarProps {
    /// Current status message (informational).
    #[props(default = None)]
    status_message: Option<String>,
    /// Current error message (displayed in destructive color).
    #[props(default = None)]
    error_message: Option<String>,
    /// Keyboard shortcut hints to display on the right.
    #[props(default = vec![])]
    shortcut_hints: Vec<ShortcutHint>,
}

const STATUS_BAR_CSS: &str = include_str!("css/status_bar.css");

#[component]
pub fn StatusBar(props: StatusBarProps) -> Element {
    // Determine the message and its CSS class.
    let (message, msg_class) = if let Some(ref err) = props.error_message {
        (err.clone(), "status-bar-message error")
    } else if let Some(ref status) = props.status_message {
        (status.clone(), "status-bar-message")
    } else {
        ("Ready".to_string(), "status-bar-message")
    };

    rsx! {
        style { {STATUS_BAR_CSS} }

        div { class: "status-bar",
            // Left side: status or error message
            span { class: "{msg_class}", "{message}" }

            // Right side: keyboard shortcut hints
            div { class: "status-bar-hints",
                for hint in props.shortcut_hints.iter() {
                    span { class: "status-bar-hint",
                        kbd { "{hint.keys}" }
                        "{hint.description}"
                    }
                }
            }
        }
    }
}
