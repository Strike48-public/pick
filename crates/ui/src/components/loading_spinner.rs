//! Loading spinner component with optional message

use dioxus::prelude::*;

/// Size presets for the spinner.
#[derive(Clone, Copy, PartialEq, Default)]
pub enum SpinnerSize {
    Sm,
    #[default]
    Md,
    Lg,
}

impl SpinnerSize {
    /// Returns inline CSS for width/height based on the size variant.
    fn dimension_px(&self) -> &'static str {
        match self {
            SpinnerSize::Sm => "16px",
            SpinnerSize::Md => "24px",
            SpinnerSize::Lg => "40px",
        }
    }
}

/// Animated CSS-border spinner with an optional text message below.
#[component]
pub fn LoadingSpinner(
    #[props(default)] size: SpinnerSize,
    #[props(default = None)] message: Option<String>,
) -> Element {
    let dim = size.dimension_px();

    rsx! {
        style { {include_str!("css/loading_spinner.css")} }
        div { class: "loading-spinner-container",
            div {
                class: "loading-spinner-circle",
                style: "width: {dim}; height: {dim};",
            }
            if let Some(msg) = &message {
                span { class: "loading-spinner-message", "{msg}" }
            }
        }
    }
}
