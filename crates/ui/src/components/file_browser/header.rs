//! Breadcrumb navigation component for the file browser.

use dioxus::prelude::*;

/// Breadcrumb navigation (only visible when inside a subdirectory).
#[component]
pub(super) fn Header(current_path: String, on_navigate: EventHandler<String>) -> Element {
    if current_path.is_empty() {
        return rsx! {};
    }

    let parts: Vec<&str> = current_path.split('/').filter(|s| !s.is_empty()).collect();

    rsx! {
        nav { class: "breadcrumbs",
            a {
                href: "#",
                onclick: move |e| {
                    e.prevent_default();
                    on_navigate.call(String::new());
                },
                "Files"
            }
            for (i, part) in parts.iter().enumerate() {
                span { class: "sep", "/" }
                {
                    let partial: String = parts[..=i].join("/");
                    rsx! {
                        a {
                            href: "#",
                            onclick: move |e| {
                                e.prevent_default();
                                on_navigate.call(partial.clone());
                            },
                            "{part}"
                        }
                    }
                }
            }
        }
    }
}
