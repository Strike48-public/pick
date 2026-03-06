//! App layout wrapper — sidebar + unified header + content + status bar

use dioxus::prelude::*;

use super::chat_panel::{ChatHeaderActions, ChatHeaderCtx};
use super::icons::{Menu, STRIKE48_SIDEBAR_LOGO_SVG};
use super::sidebar::{NavPage, Sidebar};
use super::status_bar::StatusBar;

/// Shared layout wrapper used by all three apps.
///
/// The desktop-header serves as the universal page header on both desktop and
/// mobile.  On desktop the hamburger is hidden; on mobile the logo/title are
/// hidden and the hamburger is shown.
#[component]
pub fn AppLayout(
    active_page: NavPage,
    on_navigate: EventHandler<NavPage>,
    connected: bool,
    unread_logs: usize,
    #[props(default)] host: String,
    #[props(default)] api_url: String,
    #[props(default)] auth_token: String,
    #[props(default)] on_open_conversation: EventHandler<String>,
    #[props(default)] page_subtitle: Option<String>,
    #[props(default)] page_actions: Option<Element>,
    #[props(default)] status_message: Option<String>,
    #[props(default)] error_message: Option<String>,
    children: Element,
) -> Element {
    let mut sidebar_open = use_signal(|| false);

    // Provide context signal for ChatPanel (full-page mode) to publish its
    // header actions. ChatPanel writes Some(ChatHeaderCtx) when mounted in
    // full-page mode; we render those actions in the desktop header bar.
    let chat_header_ctx: Signal<Option<ChatHeaderCtx>> = use_context_provider(|| Signal::new(None));

    let on_close = move |_: ()| {
        sidebar_open.set(false);
    };

    // Read chat header context as owned data (clone once per render, not a Signal handle).
    let chat_ctx: Option<ChatHeaderCtx> = if active_page == NavPage::Chat {
        chat_header_ctx.read().clone()
    } else {
        None
    };

    rsx! {
        style { {include_str!("css/app_layout.css")} }

        div { class: "app-layout",
            // Backdrop (mobile only, visible when drawer open)
            if *sidebar_open.read() {
                div {
                    class: "sidebar-backdrop",
                    onclick: move |_| sidebar_open.set(false),
                }
            }

            // Sidebar / Drawer
            Sidebar {
                active_page,
                on_navigate,
                sidebar_open: *sidebar_open.read(),
                on_close,
                unread_logs,
                connected,
                host: host.clone(),
                api_url,
                auth_token,
                on_open_conversation,
            }

            // Main column (header + content + status bar)
            div { class: "main-column",
                // Unified page header bar
                header { class: "desktop-header",
                    // Hamburger (mobile only, hidden on desktop via CSS)
                    button {
                        class: "desktop-header-hamburger",
                        onclick: move |_| sidebar_open.set(true),
                        Menu { size: 24 }
                    }

                    // Left: logo + breadcrumb title + optional subtitle
                    div { class: "desktop-header-left",
                        span {
                            class: "desktop-header-logo",
                            dangerous_inner_html: STRIKE48_SIDEBAR_LOGO_SVG,
                        }
                        span { class: "desktop-header-title", "Strike48" }
                        div { class: "desktop-header-text",
                            span { class: "desktop-header-breadcrumb", "/ {active_page.label()}" }
                            if let Some(ref sub) = page_subtitle {
                                span { class: "desktop-header-subtitle", "{sub}" }
                            }
                        }
                    }

                    // Right: page-specific actions (or chat header actions in full-page mode)
                    div { class: "desktop-header-right",
                        if let Some(ctx) = chat_ctx {
                            ChatHeaderActions { ctx }
                        }
                        if let Some(actions) = page_actions {
                            {actions}
                        }
                    }
                }

                // Content area
                div { class: "content-area",
                    {children}
                }

                // Status bar
                StatusBar {
                    status_message,
                    error_message,
                }
            }
        }
    }
}
