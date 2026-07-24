//! Tools page — categorized grid of all connector tools.
//!
//! Renders directly from the live tool registry (`pentest_tools::catalog::
//! tools_overview`) rather than a hand-maintained list, so every registered
//! tool appears and new tools show up automatically. Clicking a tool opens the
//! chat pre-seeded with a prompt to use it.

use std::collections::HashSet;

use dioxus::prelude::*;

use super::icons::ChevronDown;
use super::tool_category::{category_icon, humanize_category};

/// Tools page — displays all registered connector tools grouped by category.
#[component]
pub fn ToolsPage(on_open_chat: EventHandler<String>) -> Element {
    // The registry is process-global and cheap to enumerate; compute once per
    // mount and hold the result.
    let tools = use_hook(pentest_tools::catalog::tools_overview);
    let categories = pentest_tools::catalog::tools_overview_categories(&tools);
    let total = tools.len();

    // Category keys currently expanded. Collapsed by default so the page stays
    // scannable as the catalog grows; a collapsed category renders only its
    // header (its cards are not built). Toggled by clicking the header.
    let mut expanded = use_signal(HashSet::<String>::new);

    rsx! {
        style { {include_str!("css/tools_page.css")} }

        div { class: "tools-page",
            div { class: "tools-body",
                div { class: "text-dim-sm", style: "margin-bottom: 8px;",
                    "{total} tools available" }
                for category in categories {
                    {
                        let count = tools.iter().filter(|t| t.category == category).count();
                        let is_expanded = expanded().contains(&category);
                        let click_category = category.clone();
                        let key_category = category.clone();
                        rsx! {
                    div { class: "tools-category",
                        div {
                            class: "tools-category-header",
                            role: "button",
                            tabindex: 0,
                            "aria-expanded": "{is_expanded}",
                            onclick: move |_| {
                                let mut set = expanded.write();
                                if !set.remove(&click_category) {
                                    set.insert(click_category.clone());
                                }
                            },
                            onkeydown: move |evt: Event<KeyboardData>| {
                                let key = evt.key();
                                if key == Key::Enter
                                    || matches!(key, Key::Character(ref c) if c == " ")
                                {
                                    evt.prevent_default();
                                    let mut set = expanded.write();
                                    if !set.remove(&key_category) {
                                        set.insert(key_category.clone());
                                    }
                                }
                            },
                            span {
                                class: if is_expanded { "tools-category-caret expanded" } else { "tools-category-caret" },
                                ChevronDown { size: 14 }
                            }
                            span {
                                class: "tools-category-icon",
                                {category_icon(&category)}
                            }
                            h3 { class: "tools-category-title", "{humanize_category(&category)}" }
                            span { class: "tools-category-count", "{count}" }
                        }
                        if is_expanded {
                        div { class: "tools-grid",
                            for tool in tools.iter().filter(|t| t.category == category).cloned() {
                                {
                                    let prompt = format!(
                                        "Use the {} tool — {}",
                                        tool.name,
                                        tool.description.to_lowercase()
                                    );
                                    rsx! {
                                        div {
                                            class: "tool-card dashboard-card",
                                            style: "cursor: pointer;",
                                            onclick: move |_| on_open_chat.call(prompt.clone()),
                                            div { class: "tool-card-name", "{tool.name}" }
                                            div { class: "tool-card-desc", "{tool.description}" }
                                        }
                                    }
                                }
                            }
                        }
                        }
                    }
                        }
                    }
                }
            }
        }
    }
}
