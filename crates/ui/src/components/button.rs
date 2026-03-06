//! Reusable Button component with variant and size support.
//!
//! API mirrors the strike48/ui Button: uses `data-style` and `data-size`
//! HTML attributes for variant/size selection, and forwards arbitrary HTML
//! attributes via `#[props(extends=GlobalAttributes)]`.

use dioxus::prelude::*;

/// Visual style variant for the button.
#[derive(Clone, Copy, PartialEq, Default)]
#[non_exhaustive]
pub enum ButtonVariant {
    #[default]
    Primary,
    Secondary,
    Destructive,
    Outline,
    Ghost,
    Link,
}

impl ButtonVariant {
    pub fn class(&self) -> &'static str {
        match self {
            ButtonVariant::Primary => "primary",
            ButtonVariant::Secondary => "secondary",
            ButtonVariant::Destructive => "destructive",
            ButtonVariant::Outline => "outline",
            ButtonVariant::Ghost => "ghost",
            ButtonVariant::Link => "link",
        }
    }
}

/// Size presets for the button.
#[derive(Clone, Copy, PartialEq, Default)]
#[non_exhaustive]
pub enum ButtonSize {
    Small,
    #[default]
    Medium,
    Large,
    Icon,
}

impl ButtonSize {
    pub fn class(&self) -> &'static str {
        match self {
            ButtonSize::Small => "small",
            ButtonSize::Medium => "medium",
            ButtonSize::Large => "large",
            ButtonSize::Icon => "icon",
        }
    }
}

const BUTTON_CSS: &str = include_str!("css/button.css");

/// A styled button with configurable variant, size, and attribute forwarding.
///
/// Mirrors the strike48/ui Button API — uses `data-style` and `data-size`
/// HTML attributes and forwards arbitrary HTML attributes to the underlying
/// `<button>` element.
#[component]
pub fn Button(
    #[props(default)] variant: ButtonVariant,
    #[props(default)] size: ButtonSize,
    #[props(default)] disabled: bool,
    #[props(extends = GlobalAttributes)]
    #[props(extends = button)]
    attributes: Vec<Attribute>,
    on_click: Option<EventHandler<MouseEvent>>,
    children: Element,
) -> Element {
    rsx! {
        style { {BUTTON_CSS} }

        button {
            class: "button",
            "data-style": variant.class(),
            "data-size": size.class(),
            disabled: disabled,
            onclick: move |event| {
                if let Some(f) = &on_click {
                    f.call(event);
                }
            },
            ..attributes,
            {children}
        }
    }
}
