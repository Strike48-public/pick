//! Tools page — categorized grid of all connector tools.
//!
//! Renders directly from the live tool registry (`pentest_tools::catalog::
//! tools_overview`) rather than a hand-maintained list, so every registered
//! tool appears and new tools show up automatically. Clicking a tool opens the
//! chat pre-seeded with a prompt to use it.

use dioxus::prelude::*;

use super::icons::{Folder, Lock, Network, Search, Shield, Terminal, Wifi};

/// Humanize a stable category key into a section label.
fn humanize_category(category: &str) -> &'static str {
    match category {
        "network" => "Network",
        "web" => "Web",
        "active_directory" => "Active Directory",
        "credentials" => "Credentials",
        "post_exploit" => "Post-Exploitation",
        "wireless" => "Wireless",
        "recon" => "Reconnaissance",
        "forensics" => "Forensics",
        "system" => "System",
        "files" => "Files",
        _ => "Other",
    }
}

/// Icon per category key.
fn render_category_icon(category: &str) -> Element {
    match category {
        "network" => rsx! { Network { size: 18 } },
        "web" => rsx! { Search { size: 18 } },
        "active_directory" => rsx! { Lock { size: 18 } },
        "credentials" => rsx! { Lock { size: 18 } },
        "post_exploit" => rsx! { Shield { size: 18 } },
        "wireless" => rsx! { Wifi { size: 18 } },
        "recon" => rsx! { Search { size: 18 } },
        "forensics" => rsx! { Search { size: 18 } },
        "system" => rsx! { Terminal { size: 18 } },
        "files" => rsx! { Folder { size: 18 } },
        _ => rsx! { Terminal { size: 18 } },
    }
}

/// Tools page — displays all registered connector tools grouped by category.
#[component]
pub fn ToolsPage(on_open_chat: EventHandler<String>) -> Element {
    // The registry is process-global and cheap to enumerate; compute once per
    // mount and hold the result.
    let tools = use_hook(pentest_tools::catalog::tools_overview);
    let categories = pentest_tools::catalog::tools_overview_categories(&tools);
    let total = tools.len();

    rsx! {
        style { {include_str!("css/tools_page.css")} }

        div { class: "tools-page",
            div { class: "tools-body",
                div { class: "text-dim-sm", style: "margin-bottom: 8px;",
                    "{total} tools available" }
                for category in categories {
                    div { class: "tools-category",
                        div { class: "tools-category-header",
                            span {
                                class: "tools-category-icon",
                                {render_category_icon(&category)}
                            }
                            h3 { class: "tools-category-title", "{humanize_category(&category)}" }
                        }
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
