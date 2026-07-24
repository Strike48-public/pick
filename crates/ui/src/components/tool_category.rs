//! Shared rendering helpers for tool catalog categories.
//!
//! Both the read-only Tools page (`tools_page`) and the Settings Tools panel
//! (`settings_page`) group tools by a stable snake_case category key derived
//! from [`pentest_core::tools::ToolCategory`]. These helpers keep the section
//! labels and icons identical across both surfaces so the two never drift
//! (previously each maintained its own divergent `humanize_category` map).

use dioxus::prelude::*;

use super::icons::{Folder, Lock, Network, Search, Shield, Terminal, Wifi};

/// Humanize a stable category key into a section label.
///
/// Covers both the catalog categories (from `ToolCategory`) and the extra keys
/// the read-only overview can emit (`system`, `files`). Unknown keys fall back
/// to "Other".
pub fn humanize_category(category: &str) -> &'static str {
    match category {
        "network" => "Network Scanning",
        "web" => "Web - Scanning & Exploit",
        "web_discovery" => "Web - Content Discovery",
        "proxy" => "Proxies",
        "active_directory" => "Active Directory & Windows",
        "credentials" => "Password Attacks",
        "exploitation" => "Exploitation",
        "post_exploit" => "Post-Exploitation",
        "sniffing" => "Sniffing & Spoofing",
        "wireless" => "Wireless",
        "recon" => "Recon & OSINT",
        "crypto" => "TLS / Crypto",
        "forensics" => "Forensics",
        "utilities" => "Utilities",
        "system" => "System",
        "files" => "Files",
        _ => "Other",
    }
}

/// Icon for a category key. Unknown keys fall back to a terminal glyph.
pub fn category_icon(category: &str) -> Element {
    match category {
        "network" => rsx! { Network { size: 18 } },
        "web" | "web_discovery" => rsx! { Search { size: 18 } },
        "proxy" => rsx! { Network { size: 18 } },
        "active_directory" | "credentials" => rsx! { Lock { size: 18 } },
        "exploitation" | "post_exploit" => rsx! { Shield { size: 18 } },
        "sniffing" => rsx! { Wifi { size: 18 } },
        "wireless" => rsx! { Wifi { size: 18 } },
        "recon" | "forensics" => rsx! { Search { size: 18 } },
        "crypto" => rsx! { Lock { size: 18 } },
        "utilities" => rsx! { Terminal { size: 18 } },
        "files" => rsx! { Folder { size: 18 } },
        _ => rsx! { Terminal { size: 18 } },
    }
}
