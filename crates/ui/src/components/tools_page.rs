//! Tools page — categorized grid of available connector tools

use dioxus::prelude::*;

use super::icons::{Folder, Network, Search, Terminal};

struct ToolInfo {
    name: &'static str,
    description: &'static str,
}

struct ToolCategory {
    label: &'static str,
    tools: &'static [ToolInfo],
}

const CATEGORIES: &[ToolCategory] = &[
    ToolCategory {
        label: "Reconnaissance",
        tools: &[
            ToolInfo {
                name: "device_info",
                description: "System info, hostname, OS, architecture",
            },
            ToolInfo {
                name: "network_discover",
                description: "ARP + mDNS + SSDP host discovery",
            },
            ToolInfo {
                name: "ssdp_discover",
                description: "UPnP/SSDP service discovery",
            },
        ],
    },
    ToolCategory {
        label: "Network",
        tools: &[
            ToolInfo {
                name: "port_scan",
                description: "TCP port scanning with banner grab",
            },
            ToolInfo {
                name: "wifi_scan",
                description: "Nearby wireless network enumeration",
            },
            ToolInfo {
                name: "arp_table",
                description: "Local ARP cache and neighbor table",
            },
            ToolInfo {
                name: "traffic_capture",
                description: "Packet capture on network interfaces",
            },
        ],
    },
    ToolCategory {
        label: "System",
        tools: &[
            ToolInfo {
                name: "execute_command",
                description: "Run shell commands on the target",
            },
            ToolInfo {
                name: "screenshot",
                description: "Capture screen or display output",
            },
        ],
    },
    ToolCategory {
        label: "Files",
        tools: &[
            ToolInfo {
                name: "list_files",
                description: "Directory listing with metadata",
            },
            ToolInfo {
                name: "read_file",
                description: "Read file contents from target",
            },
            ToolInfo {
                name: "write_file",
                description: "Write or create files on target",
            },
        ],
    },
];

fn render_category_icon(idx: usize) -> Element {
    match idx {
        0 => rsx! { Search { size: 18 } },   // Reconnaissance
        1 => rsx! { Network { size: 18 } },  // Network
        2 => rsx! { Terminal { size: 18 } }, // System
        3 => rsx! { Folder { size: 18 } },   // Files
        _ => rsx! { Search { size: 18 } },
    }
}

/// Tools page — displays all available connector tools organized by category
#[component]
pub fn ToolsPage(on_open_chat: EventHandler<String>) -> Element {
    rsx! {
        style { {include_str!("css/tools_page.css")} }

        div { class: "tools-page",
            div { class: "tools-body",
                for (idx, cat) in CATEGORIES.iter().enumerate() {
                    div { class: "tools-category",
                        div { class: "tools-category-header",
                            span {
                                class: "tools-category-icon",
                                {render_category_icon(idx)}
                            }
                            h3 { class: "tools-category-title", "{cat.label}" }
                        }
                        div { class: "tools-grid",
                            for tool in cat.tools.iter() {
                                {
                                    let prompt = format!("Use the {} tool — {}", tool.name, tool.description.to_lowercase());
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
