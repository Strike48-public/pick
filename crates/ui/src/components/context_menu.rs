//! ContextMenu component — positioned popup menu triggered by right-click or long-press

use dioxus::prelude::*;

/// A single item in the context menu.
#[derive(Clone, PartialEq)]
pub struct ContextMenuItem {
    /// Unique identifier passed to `on_select`
    pub id: String,
    /// Display label
    pub label: String,
    /// Whether this action is destructive (shown in red)
    pub destructive: bool,
}

#[derive(Props, Clone, PartialEq)]
pub struct ContextMenuProps {
    /// Whether the menu is visible
    visible: bool,
    /// X position in pixels from the left edge of the viewport
    x: f64,
    /// Y position in pixels from the top edge of the viewport
    y: f64,
    /// Menu items to display
    items: Vec<ContextMenuItem>,
    /// Called when an item is selected; passes the item's `id`
    on_select: EventHandler<String>,
    /// Called when the menu should close (e.g. backdrop click)
    on_close: EventHandler<()>,
}

/// Floating context menu rendered at an absolute (x, y) position.
/// An invisible full-screen backdrop catches outside clicks to close the menu.
#[component]
pub fn ContextMenu(props: ContextMenuProps) -> Element {
    if !props.visible {
        return rsx! {};
    }

    let left_px = format!("{}px", props.x);
    let top_px = format!("{}px", props.y);
    let menu_style = format!("left: {left_px}; top: {top_px};");

    rsx! {
        style { {include_str!("css/context_menu.css")} }

        // Invisible full-screen backdrop to catch outside clicks
        div {
            class: "context-menu-backdrop",
            onclick: move |_| props.on_close.call(()),
        }

        // The menu itself, positioned at (x, y)
        div {
            class: "context-menu",
            style: "{menu_style}",
            onclick: move |evt| evt.stop_propagation(),

            for item in props.items.iter() {
                {
                    let item_id = item.id.clone();
                    let item_class = if item.destructive {
                        "context-menu-item destructive"
                    } else {
                        "context-menu-item"
                    };
                    rsx! {
                        div {
                            class: item_class,
                            onclick: move |_| props.on_select.call(item_id.clone()),
                            "{item.label}"
                        }
                    }
                }
            }
        }
    }
}
