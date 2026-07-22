//! Easy Mode — a simplified shell (network scan + chat) for non-expert users.

use dioxus::prelude::*;

use pentest_core::matrix::DocumentSummary;

use super::chat_panel::ChatHeaderCtx;
use super::icons::{FileText, History, Network, Plus, STRIKE48_S_BADGE_SVG};
use crate::components::{ChatPanel, ConversationDocs, DocumentViewer, DocumentsPanel};

/// The canned chat message the Easy Mode "Scan" button sends. It instructs the
/// server-side agent to enumerate local interfaces, scan the local subnet, and
/// write a report document of the findings. Kept as one place so the wording is
/// consistent and testable.
pub fn easy_mode_scan_prompt() -> String {
    "Discover the devices on my local network: enumerate my network interfaces, \
     scan the local subnet for reachable hosts and their open services, then write \
     a clear report document summarizing what you found."
        .to_string()
}

/// Props for [`EasyModeShell`]. Mirrors the inputs the standard chat path uses.
#[derive(Props, Clone, PartialEq)]
pub struct EasyModeShellProps {
    pub api_url: String,
    pub auth_token: String,
    pub tenant_id: String,
    /// Shared mailbox: writing Some(msg) makes the chat auto-send it.
    pub chat_mailbox: Signal<Option<String>>,
    /// Mailbox to open a specific conversation by ID.
    pub conversation_mailbox: Signal<Option<String>>,
}

/// The simplified Easy Mode screen: a scan action card above a full-page chat.
#[component]
pub fn EasyModeShell(props: EasyModeShellProps) -> Element {
    let mut chat_mailbox = props.chat_mailbox;
    // ChatPanel publishes its header actions (new chat, history toggle, agent
    // select) into this context; AppLayout does the same in the standard shell.
    // Easy Mode consumes it below to drive the top-bar icons.
    let chat_header_ctx: Signal<Option<ChatHeaderCtx>> =
        use_context_provider(|| Signal::new(None::<ChatHeaderCtx>));

    let needs_sign_in = use_context::<Signal<bool>>();
    let retry_tick = use_context::<Signal<u32>>();

    // Track the selected agent ID for the DocumentsPanel (which self-refreshes).
    let agent_id = use_signal(|| None::<String>);
    // The report currently open in the full-screen viewer (None = normal shell).
    let mut viewing = use_signal(|| None::<DocumentSummary>);
    // True once a conversation has messages — hides the Scan card.
    let conversation_active = use_signal(|| false);
    // The active conversation's ID — scopes the bottom documents strip to docs
    // written in THIS conversation (the top-bar Docs icon lists all reports).
    let conversation_id = use_signal(|| None::<String>);
    // Whether the full-screen Reports list overlay is open (Docs icon).
    let mut show_docs = use_signal(|| false);

    // The Matrix auth token arrives asynchronously: the connector registers, the
    // browser-OAuth callback writes it into the session store, and this
    // always-mounted panel must re-render so ChatPanel re-reads it and fetches
    // agents. Subscribe to the reactive token store and feed it to ChatPanel's
    // `auth_token` prop so the token landing triggers that re-render.
    let mut auth_token = use_signal(|| {
        let t = crate::session::get_auth_token();
        if t.is_empty() {
            props.auth_token.clone()
        } else {
            t
        }
    });
    use_future(move || async move {
        let mut rx = crate::session::watch_auth_token();
        while rx.changed().await.is_ok() {
            let t = rx.borrow().clone();
            if !t.is_empty() {
                auth_token.set(t);
            }
        }
    });

    let ctx = chat_header_ctx.read().clone();
    let has_ctx = ctx.is_some();

    // The base shell (brand bar + scan card + chat) is ALWAYS rendered so the
    // ChatPanel — and thus the live conversation — stays mounted. The report
    // viewer, reports list, and sign-in retry are layered OVER it as overlays
    // rather than early-returns that would unmount the chat and lose the
    // conversation when the user taps Back.
    rsx! {
        // ---- Overlays (mounted on top of the shell) ----
        if let Some(doc) = viewing() {
            // .easy-doc-screen is a fixed full-viewport layer; the viewer's own
            // bar handles the safe area (no double notch padding).
            div { class: "easy-doc-screen easy-overlay",
                DocumentViewer {
                    api_url: props.api_url.clone(),
                    auth_token: auth_token(),
                    doc: doc,
                    on_back: move |_| viewing.set(None),
                }
            }
        }
        if show_docs() {
            div { class: "easy-doc-screen easy-overlay",
                div { class: "easy-doc-viewer-bar",
                    button {
                        class: "easy-doc-back",
                        "aria-label": "Back",
                        onclick: move |_| show_docs.set(false),
                        "‹"
                    }
                    span { class: "easy-doc-viewer-title", "Reports" }
                }
                div { class: "easy-docs-list-body",
                    DocumentsPanel {
                        api_url: props.api_url.clone(),
                        auth_token: auth_token(),
                        agent_id: agent_id,
                        on_open: move |doc: DocumentSummary| {
                            show_docs.set(false);
                            viewing.set(Some(doc));
                        },
                    }
                }
            }
        }
        if needs_sign_in() {
            {
                let mut needs_sign_in = needs_sign_in;
                let mut retry_tick = retry_tick;
                rsx! {
                    div { class: "easy-doc-screen easy-overlay",
                        div { class: "easy-signin",
                            p { class: "easy-signin-title", "Sign in to connect to Strike48" }
                            p { class: "easy-signin-sub", "We could not complete sign-in. Tap retry to try again." }
                            button {
                                class: "action-card",
                                onclick: move |_| {
                                    needs_sign_in.set(false);
                                    retry_tick.set(retry_tick() + 1);
                                },
                                span { class: "action-card-label", "Retry sign-in" }
                            }
                        }
                    }
                }
            }
        }

        div { class: "easy-mode",
            // Co-brand top bar: Strike48 "S" badge + "Pick" + action icons.
            div { class: "easy-brandbar",
                span { class: "easy-brand-badge", dangerous_inner_html: STRIKE48_S_BADGE_SVG }
                span { class: "easy-brand-word", "Pick" }
                // Action icons (right): new chat, history, docs. Wired to the
                // ChatPanel header actions it publishes via context.
                div { class: "easy-brand-actions",
                    if has_ctx {
                        {
                            let ctx_nc = ctx.clone();
                            let ctx_hi = ctx.clone();
                            rsx! {
                                button {
                                    class: "easy-icon-btn",
                                    "aria-label": "New chat",
                                    onclick: move |_| {
                                        if let Some(c) = ctx_nc.as_ref() { c.on_new_chat.call(()); }
                                    },
                                    Plus { size: 20 }
                                }
                                button {
                                    class: "easy-icon-btn",
                                    "aria-label": "Chat history",
                                    onclick: move |_| {
                                        if let Some(c) = ctx_hi.as_ref() { c.on_toggle_history.call(()); }
                                    },
                                    History { size: 20 }
                                }
                            }
                        }
                    }
                    button {
                        class: "easy-icon-btn",
                        "aria-label": "Reports",
                        onclick: move |_| show_docs.set(true),
                        FileText { size: 20 }
                    }
                }
            }
            // Scan card: only shown on an empty chat; once a conversation starts
            // it hides, and New Chat brings it back.
            if !conversation_active() {
                div { class: "action-grid",
                    div {
                        class: "action-card",
                        onclick: move |_| {
                            pentest_core::telemetry::record(
                                pentest_core::telemetry::Activity::ScanStart,
                                &[("channel", "easy")],
                            );
                            chat_mailbox.set(Some(easy_mode_scan_prompt()));
                        },
                        span { class: "action-card-icon", Network { size: 24 } }
                        span { class: "action-card-label", "Scan My Network" }
                    }
                }
            }
            div { class: "easy-mode-chat",
                ChatPanel {
                    visible: true,
                    api_url: props.api_url.clone(),
                    auth_token: auth_token(),
                    tenant_id: props.tenant_id.clone(),
                    on_close: move |_| {},
                    send_mailbox: props.chat_mailbox,
                    full_page: true,
                    open_conversation_id: props.conversation_mailbox,
                    selected_agent_out: Some(agent_id),
                    conversation_active_out: Some(conversation_active),
                    conversation_id_out: Some(conversation_id),
                }
            }
            // Conversation-scoped documents strip: shows reports written in the
            // CURRENT conversation, pinned to the bottom. The top-bar Docs icon
            // still lists all reports across conversations.
            ConversationDocs {
                api_url: props.api_url.clone(),
                auth_token: auth_token(),
                agent_id,
                conversation_id,
                on_open: move |doc: DocumentSummary| viewing.set(Some(doc)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_prompt_mentions_network_and_report_document() {
        let p = easy_mode_scan_prompt().to_lowercase();
        assert!(
            p.contains("network"),
            "prompt should mention the network: {p}"
        );
        assert!(
            p.contains("report document"),
            "prompt must ask the agent to write a report document: {p}"
        );
    }
}
