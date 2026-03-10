//! Sidebar navigation component — flat top-level nav items

use dioxus::prelude::*;
use pentest_core::matrix::{ChatClient, ConversationInfo, MatrixChatClient};
use std::sync::Arc;

use super::chat_panel::format_relative_time;
use super::icons::{
    Folder, House, MessageSquare, ScrollText, Settings, Terminal, Wrench,
    STRIKE48_SIDEBAR_LOGO_SVG, X,
};

/// Navigation pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavPage {
    Dashboard,
    Tools,
    Files,
    Shell,
    Chat,
    Logs,
    Settings,
}

impl NavPage {
    /// Render the lucide icon component for this page.
    pub fn render_icon(&self, size: usize) -> Element {
        match self {
            NavPage::Dashboard => rsx! { House { size } },
            NavPage::Tools => rsx! { Wrench { size } },
            NavPage::Files => rsx! { Folder { size } },
            NavPage::Shell => rsx! { Terminal { size } },
            NavPage::Chat => rsx! { MessageSquare { size } },
            NavPage::Logs => rsx! { ScrollText { size } },
            NavPage::Settings => rsx! { Settings { size } },
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            NavPage::Dashboard => "Dashboard",
            NavPage::Tools => "Tools",
            NavPage::Files => "Files",
            NavPage::Shell => "Shell",
            NavPage::Chat => "Chat",
            NavPage::Logs => "Logs",
            NavPage::Settings => "Settings",
        }
    }
}

/// Pages shown in the sidebar.
pub const ALL_PAGES: [NavPage; 7] = [
    NavPage::Dashboard,
    NavPage::Tools,
    NavPage::Files,
    NavPage::Shell,
    NavPage::Chat,
    NavPage::Logs,
    NavPage::Settings,
];

/// Sidebar component with flat top-level nav items.
#[component]
pub fn Sidebar(
    active_page: NavPage,
    on_navigate: EventHandler<NavPage>,
    sidebar_open: bool,
    on_close: EventHandler<()>,
    unread_logs: usize,
    #[props(default)] connected: bool,
    #[props(default)] host: String,
    #[props(default)] api_url: String,
    #[props(default)] auth_token: String,
    #[props(default)] on_open_conversation: EventHandler<String>,
) -> Element {
    let open_class = if sidebar_open {
        "sidebar open"
    } else {
        "sidebar"
    };

    // -----------------------------------------------------------------------
    // Fetch recent conversations reactively
    // -----------------------------------------------------------------------
    // Convert String props to local Signals so use_effect can track changes.
    let mut sig_api_url = use_signal(String::new);
    let mut sig_auth_token = use_signal(String::new);
    if *sig_api_url.peek() != api_url {
        sig_api_url.set(api_url.clone());
    }
    if *sig_auth_token.peek() != auth_token {
        sig_auth_token.set(auth_token.clone());
    }

    let mut recent_convos: Signal<Vec<ConversationInfo>> = use_signal(Vec::new);

    use_effect(move || {
        let url = sig_api_url.read().clone();
        let token = sig_auth_token.read().clone();
        if url.is_empty() || token.is_empty() {
            return;
        }
        spawn(async move {
            let mut client = MatrixChatClient::new(url);
            client.set_auth_token(token);
            let client: Arc<dyn ChatClient> = Arc::new(client);
            // Resolve the pentest-connector agent so we only show its conversations
            let agent_id = match client.list_agents().await {
                Ok(agents) => agents
                    .iter()
                    .find(|a| a.name.to_lowercase().contains("pentest-connector"))
                    .map(|a| a.id.clone()),
                Err(e) => {
                    tracing::warn!("Sidebar: failed to fetch agents: {e}");
                    None
                }
            };
            match client.list_conversations(agent_id.as_deref()).await {
                Ok(mut list) => {
                    // Sort by updated_at in reverse order (newest first)
                    list.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
                    recent_convos.set(list);
                }
                Err(e) => tracing::warn!("Sidebar: failed to fetch conversations: {e}"),
            }
        });
    });

    rsx! {
        style { {include_str!("css/sidebar.css")} }

        nav { class: "{open_class}",
            // Header
            div { class: "sidebar-header",
                div { class: "sidebar-header-brand",
                    span {
                        class: "header-logo",
                        dangerous_inner_html: STRIKE48_SIDEBAR_LOGO_SVG,
                    }
                    span { class: "sidebar-header-title", "Pentest" }
                }
                button {
                    class: "sidebar-close-btn",
                    onclick: move |_| on_close.call(()),
                    X { size: 20 }
                }
            }

            // Nav items
            div { class: "sidebar-flat-nav",
                for page in ALL_PAGES {
                    {
                        let is_active = page == active_page;
                        let class_name = if is_active { "sidebar-flat-item active" } else { "sidebar-flat-item" };
                        rsx! {
                            div {
                                class: "{class_name}",
                                onclick: move |_| {
                                    on_navigate.call(page);
                                    on_close.call(());
                                },
                                span { class: "sidebar-flat-icon", {page.render_icon(20)} }
                                span { class: "sidebar-flat-label", "{page.label()}" }
                                if matches!(page, NavPage::Logs) && unread_logs > 0 {
                                    span { class: "sidebar-badge", "{unread_logs}" }
                                }
                            }

                            // Recent conversations below the Chat nav item
                            if matches!(page, NavPage::Chat) && !recent_convos.read().is_empty() {
                                div { class: "sidebar-recent-convos",
                                    for conv in recent_convos.read().iter().take(5) {
                                        {
                                            let cid = conv.id.clone();
                                            let title = if conv.title.is_empty() {
                                                "Untitled".to_string()
                                            } else if conv.title.len() > 28 {
                                                format!("{}...", &conv.title[..25])
                                            } else {
                                                conv.title.clone()
                                            };
                                            let time_str = format_relative_time(&conv.updated_at);
                                            rsx! {
                                                div {
                                                    key: "{cid}",
                                                    class: "sidebar-recent-item",
                                                    onclick: move |_| {
                                                        on_open_conversation.call(cid.clone());
                                                        on_close.call(());
                                                    },
                                                    span { class: "sidebar-recent-title", "{title}" }
                                                    span { class: "sidebar-recent-time", "{time_str}" }
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

            // Status row at bottom
            if !host.is_empty() {
                div { class: "sidebar-status-row",
                    div {
                        class: if connected { "status-dot connected" } else { "status-dot disconnected" },
                    }
                    span { class: "sidebar-status-text", "{host}" }
                }
            }
        }
    }
}
