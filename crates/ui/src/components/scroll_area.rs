//! Scroll area wrapper with themed scrollbar styling

use dioxus::prelude::*;

/// A container div with `overflow-y: auto` and cross-browser themed scrollbar.
#[component]
pub fn ScrollArea(#[props(default = String::new())] class: String, children: Element) -> Element {
    let wrapper_class = if class.is_empty() {
        "scroll-area".to_string()
    } else {
        format!("scroll-area {class}")
    };

    rsx! {
        style { {include_str!("css/scroll_area.css")} }
        div { class: "{wrapper_class}",
            {children}
        }
    }
}
