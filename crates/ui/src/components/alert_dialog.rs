//! AlertDialog component — modal confirmation dialog with cancel/confirm actions

use dioxus::prelude::*;

use super::button::{Button, ButtonSize, ButtonVariant};

#[derive(Props, Clone, PartialEq)]
pub struct AlertDialogProps {
    /// Whether the dialog is visible
    visible: bool,
    /// Dialog title
    title: String,
    /// Dialog description/message
    #[props(default = String::new())]
    description: String,
    /// Label for confirm button (default: "Confirm")
    #[props(default = "Confirm".to_string())]
    confirm_label: String,
    /// Label for cancel button (default: "Cancel")
    #[props(default = "Cancel".to_string())]
    cancel_label: String,
    /// Whether the confirm action is destructive (red button)
    #[props(default = false)]
    destructive: bool,
    /// Called when user confirms
    on_confirm: EventHandler<()>,
    /// Called when user cancels (or clicks backdrop)
    on_cancel: EventHandler<()>,
}

/// Modal confirmation dialog with backdrop overlay, title, description,
/// and cancel/confirm action buttons.
#[component]
pub fn AlertDialog(props: AlertDialogProps) -> Element {
    if !props.visible {
        return rsx! {};
    }

    let confirm_variant = if props.destructive {
        ButtonVariant::Destructive
    } else {
        ButtonVariant::Primary
    };

    rsx! {
        style { {include_str!("css/alert_dialog.css")} }

        // Backdrop — clicking it cancels
        div {
            class: "alert-dialog-backdrop",
            onclick: move |_| props.on_cancel.call(()),

            // Dialog card — stop propagation so clicking inside doesn't cancel
            div {
                class: "alert-dialog",
                onclick: move |evt| evt.stop_propagation(),

                // Title
                h2 { class: "alert-dialog-title", "{props.title}" }

                // Description (only if non-empty)
                if !props.description.is_empty() {
                    p { class: "alert-dialog-description", "{props.description}" }
                }

                // Action buttons
                div { class: "alert-dialog-actions",
                    Button {
                        variant: ButtonVariant::Outline,
                        size: ButtonSize::Small,
                        on_click: move |_| props.on_cancel.call(()),
                        "{props.cancel_label}"
                    }
                    Button {
                        variant: confirm_variant,
                        size: ButtonSize::Small,
                        on_click: move |_| props.on_confirm.call(()),
                        "{props.confirm_label}"
                    }
                }
            }
        }
    }
}
