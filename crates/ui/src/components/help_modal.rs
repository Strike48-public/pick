//! Help modal — keyboard shortcuts reference overlay

use dioxus::prelude::*;

/// Props for [`HelpModal`].
#[derive(Props, Clone, PartialEq)]
pub struct HelpModalProps {
    /// Whether the modal is visible.
    visible: bool,
    /// Called when the modal should close (backdrop click, close button, Escape).
    on_close: EventHandler<()>,
}

/// Modal overlay listing all keyboard shortcuts.
///
/// Follows the same backdrop + card pattern as [`AlertDialog`](super::AlertDialog).
#[component]
pub fn HelpModal(props: HelpModalProps) -> Element {
    if !props.visible {
        return rsx! {};
    }

    rsx! {
        style { {HELP_MODAL_CSS} }

        div {
            class: "help-modal-backdrop",
            onclick: move |_| props.on_close.call(()),

            div {
                class: "help-modal",
                onclick: move |evt| evt.stop_propagation(),

                // Header
                div { class: "help-modal-header",
                    h2 { class: "help-modal-title", "Keyboard Shortcuts" }
                    button {
                        class: "help-modal-close",
                        onclick: move |_| props.on_close.call(()),
                        "\u{00d7}" // multiplication sign (x)
                    }
                }

                // Sections
                div { class: "help-modal-body",

                    // Navigation section
                    div { class: "help-modal-section",
                        div { class: "help-modal-section-title", "Navigation" }
                        ShortcutRow { key_label: "1", description: "Dashboard" }
                        ShortcutRow { key_label: "2", description: "Tools" }
                        ShortcutRow { key_label: "3", description: "Files" }
                        ShortcutRow { key_label: "4", description: "Shell" }
                        ShortcutRow { key_label: "c", description: "Chat" }
                        ShortcutRow { key_label: "5", description: "Logs" }
                        ShortcutRow { key_label: "6", description: "Settings" }
                    }

                    // General section
                    div { class: "help-modal-section",
                        div { class: "help-modal-section-title", "General" }
                        ShortcutRow { key_label: "?", description: "Show this help" }
                        ShortcutRow { key_label: "Esc", description: "Close panel / modal" }
                    }
                }

                // Footer
                div { class: "help-modal-footer",
                    "Press "
                    kbd { class: "help-modal-key", "?" }
                    " or "
                    kbd { class: "help-modal-key", "Esc" }
                    " to close"
                }
            }
        }
    }
}

/// Single row: styled key badge + description text.
#[component]
fn ShortcutRow(key_label: &'static str, description: &'static str) -> Element {
    rsx! {
        div { class: "help-modal-row",
            kbd { class: "help-modal-key", "{key_label}" }
            span { class: "help-modal-desc", "{description}" }
        }
    }
}

const HELP_MODAL_CSS: &str = include_str!("css/help_modal.css");
