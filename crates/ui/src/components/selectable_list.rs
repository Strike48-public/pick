//! Selectable list component — clickable rows with optional subtitle

use dioxus::prelude::*;

/// A single item in the selectable list.
#[derive(Clone, PartialEq)]
pub struct ListItem {
    /// Unique identifier for this item.
    pub id: String,
    /// Primary display text.
    pub label: String,
    /// Optional secondary text shown below the label.
    pub subtitle: Option<String>,
}

/// A vertical list of clickable items with selection highlight.
#[component]
pub fn SelectableList(
    items: Vec<ListItem>,
    #[props(default = None)] selected_id: Option<String>,
    on_select: EventHandler<String>,
    #[props(default = "No items".to_string())] empty_message: String,
) -> Element {
    rsx! {
        style { {include_str!("css/selectable_list.css")} }

        if items.is_empty() {
            div { class: "selectable-list-empty", "{empty_message}" }
        } else {
            ul { class: "selectable-list",
                for item in items.iter() {
                    {
                        let is_selected = selected_id.as_deref() == Some(item.id.as_str());
                        let item_class = if is_selected {
                            "selectable-list-item selected"
                        } else {
                            "selectable-list-item"
                        };
                        let id = item.id.clone();
                        rsx! {
                            li {
                                key: "{item.id}",
                                class: "{item_class}",
                                onclick: move |_| on_select.call(id.clone()),
                                div { class: "selectable-list-item-label", "{item.label}" }
                                if let Some(ref subtitle) = item.subtitle {
                                    div { class: "selectable-list-item-subtitle", "{subtitle}" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
