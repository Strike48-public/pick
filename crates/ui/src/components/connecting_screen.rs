//! Connecting screen with animated step indicators

use dioxus::prelude::*;

/// Steps shown in the connecting screen UI.
/// Mirrors the enum in liveview_connector but lives in the shared UI crate
/// so any frontend can render it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectingStep {
    Connecting,
    Registering,
    WaitingForApproval,
    ExchangingToken,
    Finalizing,
}

/// Visual steps displayed as dots (collapsed from the 5 internal steps).
const DISPLAY_STEPS: [&str; 3] = ["Connecting", "Approval", "Session"];

/// Map a ConnectingStep to a 0–2 display-step index.
fn display_index(step: ConnectingStep) -> u8 {
    match step {
        ConnectingStep::Connecting | ConnectingStep::Registering => 0,
        ConnectingStep::WaitingForApproval => 1,
        ConnectingStep::ExchangingToken | ConnectingStep::Finalizing => 2,
    }
}

/// Animated connecting screen with three step-indicator dots.
#[component]
pub fn ConnectingScreen(
    step: ConnectingStep,
    host: String,
    on_cancel: EventHandler<()>,
) -> Element {
    let active = display_index(step);

    let status_text = match step {
        ConnectingStep::Connecting => "Opening connection...",
        ConnectingStep::Registering => "Registering connector...",
        ConnectingStep::WaitingForApproval => "Awaiting approval",
        ConnectingStep::ExchangingToken => "Exchanging credentials...",
        ConnectingStep::Finalizing => "Finalizing session...",
    };

    rsx! {
        style { {include_str!("css/connecting_screen.css")} }

        div { class: "connecting-screen",
            // Host label
            div {
                class: "connecting-host",
                "{host}"
            }

            // Step indicator dots
            div { class: "step-indicator",
                for (i, _label) in DISPLAY_STEPS.iter().enumerate() {
                    {
                        let i = i as u8;
                        let dot_class = if i < active {
                            "step-dot completed"
                        } else if i == active {
                            "step-dot active"
                        } else {
                            "step-dot pending"
                        };
                        rsx! {
                            if i > 0 {
                                div { class: "step-connector" }
                            }
                            div { class: "{dot_class}" }
                        }
                    }
                }
            }

            // Step labels
            div { class: "step-labels",
                for label in DISPLAY_STEPS {
                    span { "{label}" }
                }
            }

            // Status text
            if step == ConnectingStep::WaitingForApproval {
                div { class: "approval-instruction",
                    "{status_text}"
                }
                div {
                    class: "connecting-hint",
                    "Open the Strike48 web UI and accept this connector."
                }
            } else {
                div {
                    class: "text-dim",
                    "{status_text}"
                }
            }

            // Cancel
            button {
                class: "connecting-cancel-btn",
                onclick: move |_| on_cancel.call(()),
                "Cancel"
            }
        }
    }
}
