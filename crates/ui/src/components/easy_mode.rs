//! Easy Mode — a simplified shell (network scan + chat) for non-expert users.

use dioxus::prelude::*;

use pentest_core::matrix::{DocumentSummary, MatrixChatClient, ReportMeta};

use super::chat_panel::{format_relative_time, ChatHeaderCtx};
use super::icons::{
    ChevronLeft, FileText, LogOut, Menu, Network, Plus, Settings, STRIKE48_S_BADGE_SVG,
};
use crate::components::documents_panel::sev_badge_class;
use crate::components::{ChatPanel, ConversationDocs, DocumentViewer, DocumentsPanel};
use pentest_core::settings::{load_settings, save_settings};

/// The canned chat message the Easy Mode "Scan" button sends. It instructs the
/// server-side agent to enumerate local interfaces, scan the local subnet, and
/// write a report document of the findings. Kept as one place so the wording is
/// consistent and testable.
pub fn easy_mode_scan_prompt() -> String {
    pentest_core::easy_mode_scan_prompt()
}

/// Build the resume-card sub-line. `relative` is an already-formatted
/// relative time (e.g. "1h ago") from `format_relative_time`, so we do NOT
/// append another "ago". Adds a report affordance hint when one exists.
fn resume_sub_line(relative: &str, has_report: bool) -> String {
    if has_report {
        format!("{relative} · report attached")
    } else {
        relative.to_string()
    }
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
    /// Full sign-out: clears the chat token + connector creds and returns to the
    /// sign-in screen. Fired from the drawer's "Log out".
    pub on_logout: EventHandler<()>,
    /// Toggle Easy Mode off (switches to the expert shell). Fired from the
    /// drawer's Settings. Persisted + applied immediately by the parent.
    pub on_easy_mode_change: EventHandler<bool>,
    /// Fired when the user taps "Sign in" on the overlay.
    pub on_sign_in: EventHandler<()>,
    /// Fired when chat-level auth events occur (ChatReady, ChatAuthDead).
    pub on_chat_event: EventHandler<crate::auth_flow::AuthEvent>,
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

    let flow = use_context::<Signal<crate::auth_flow::AuthFlow>>();

    // Track the selected agent ID for the DocumentsPanel (which self-refreshes).
    let agent_id = use_signal(|| None::<String>);
    // The report currently open in the full-screen viewer (None = normal shell).
    let mut viewing = use_signal(|| None::<DocumentSummary>);
    // True once a conversation has messages — hides the Scan card.
    let conversation_active = use_signal(|| false);
    // The active conversation's ID — scopes the bottom documents strip to docs
    // written in THIS conversation (the top-bar Docs icon lists all reports).
    let conversation_id = use_signal(|| None::<String>);
    // Reports for the current agent — powers the Home resume card's "Open report"
    // affordance and the drawer Reports count. Same source as DocumentsPanel;
    // fetched here so the Home screen has it without opening the reports overlay.
    let mut docs = use_signal(Vec::<DocumentSummary>::new);
    // Parsed frontmatter for the resume card's selected report (badge rendering).
    let mut report_meta = use_signal(|| None::<ReportMeta>);
    // Whether the full-screen Reports list overlay is open (Docs icon).
    let mut show_docs = use_signal(|| false);
    // Left slide-over navigation drawer (hamburger).
    let mut drawer_open = use_signal(|| false);
    // Full-screen Settings overlay (opened from the drawer).
    let mut show_settings = use_signal(|| false);
    // Telemetry opt-out mirror for the Settings toggle. Seeded from persisted
    // settings; flipping it applies to the core immediately and persists.
    let mut telemetry_on = use_signal(|| load_settings().telemetry_enabled);
    let on_logout = props.on_logout;
    let on_easy_mode_change = props.on_easy_mode_change;

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
            // Mirror BOTH directions: a new token signs in, an empty token
            // (logout clears it) must clear the shell's copy too — otherwise the
            // shell keeps the stale token, still looks signed in, and logout
            // appears to do nothing.
            auth_token.set(t);
        }
    });

    {
        // Poll the report list once signed in so a report generated mid-session
        // (e.g. after a scan) refreshes the resume card + Reports badge without
        // needing a token/agent change. A single use_hook-spawned loop re-reads
        // the token/agent signals each pass, so it follows agent switches and
        // logout without spawning a new loop per change (which would leak).
        let api_url = props.api_url.clone();
        use_hook(move || {
            spawn(async move {
                loop {
                    let token = auth_token.peek().clone();
                    let aid = agent_id.peek().clone();
                    if token.is_empty() || api_url.is_empty() {
                        // Logged out / not signed in yet: drop any prior
                        // session's reports so the badge and resume card don't
                        // flash a stale count on the next sign-in.
                        if !docs.peek().is_empty() {
                            docs.set(Vec::new());
                        }
                    } else {
                        let client = pentest_core::matrix::MatrixChatClient::new(api_url.clone())
                            .with_auth_token(token);
                        if let Ok(mut list) = client.list_documents(aid.as_deref()).await {
                            // Newest first (timestamp is ISO-8601, lexical sort works).
                            list.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                            docs.set(list);
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            });
        });
    }

    // Fetch the resume card's report metadata for the severity badge.
    {
        let api_url = props.api_url.clone();
        use_effect(move || {
            let token = auth_token();
            let all_docs = docs();
            // Find the report for the most recent conversation (same logic as the resume card).
            let chat_ctx = chat_header_ctx.read();
            let recent_conv = chat_ctx.as_ref().and_then(|c| c.conversations.first());
            let report_id = recent_conv.and_then(|conv| {
                all_docs.iter().find(|d| d.conversation_id == conv.id).map(|d| (d.id.clone(), d.conversation_id.clone()))
            });
            if let Some((doc_id, conv_id)) = report_id {
                if token.is_empty() || api_url.is_empty() {
                    return;
                }
                let api_url = api_url.clone();
                let token = token.clone();
                spawn(async move {
                    let client = MatrixChatClient::new(api_url).with_auth_token(token);
                    if let Ok(content) = client.get_document_content(&conv_id, &doc_id).await {
                        report_meta.set(Some(ReportMeta::parse(&content)));
                    }
                });
            } else {
                report_meta.set(None);
            }
        });
    }

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
        // ---- Navigation drawer (left slide-over) ----
        // Scrim + panel are always mounted so the 0.22s slide animates both ways;
        // `.is-open` toggles the transform and scrim opacity.
        div {
            class: if drawer_open() { "easy-drawer-scrim is-open" } else { "easy-drawer-scrim" },
            onclick: move |_| drawer_open.set(false),
        }
        nav {
            class: if drawer_open() { "easy-drawer is-open" } else { "easy-drawer" },
            // Brand header
            div { class: "easy-drawer-brand",
                span { class: "easy-brand-badge", dangerous_inner_html: STRIKE48_S_BADGE_SVG }
                span { class: "easy-brand-word", "Pick" }
            }
            div { class: "easy-drawer-sep" }
            // Primary destinations
            button {
                class: "easy-drawer-item",
                onclick: move |_| {
                    drawer_open.set(false);
                    if let Some(c) = chat_header_ctx.peek().as_ref() { c.on_new_chat.call(()); }
                },
                span { class: "easy-drawer-item-icon", Plus { size: 18 } }
                "New chat"
            }
            button {
                class: "easy-drawer-item",
                onclick: move |_| {
                    drawer_open.set(false);
                    show_docs.set(true);
                },
                span { class: "easy-drawer-item-icon", FileText { size: 18 } }
                "Reports"
                {
                    let n = docs.read().len();
                    if n > 0 {
                        rsx! { span { class: "easy-drawer-badge", "{n}" } }
                    } else {
                        rsx! {}
                    }
                }
            }
            button {
                class: "easy-drawer-item",
                onclick: move |_| {
                    drawer_open.set(false);
                    telemetry_on.set(load_settings().telemetry_enabled);
                    show_settings.set(true);
                },
                span { class: "easy-drawer-item-icon", Settings { size: 18 } }
                "Settings"
            }
            div { class: "easy-drawer-sep" }
            // Recent chats
            div { class: "easy-drawer-section-label", "Recent chats" }
            div { class: "easy-drawer-recent",
                {
                    let convs = chat_header_ctx
                        .read()
                        .as_ref()
                        .map(|c| c.conversations.clone())
                        .unwrap_or_default();
                    if convs.is_empty() {
                        rsx! { div { class: "easy-drawer-recent-empty", "No conversations yet" } }
                    } else {
                        rsx! {
                            for conv in convs {
                                {
                                    let id = conv.id.clone();
                                    let title = if conv.title.trim().is_empty() {
                                        "Untitled chat".to_string()
                                    } else {
                                        conv.title.clone()
                                    };
                                    rsx! {
                                        button {
                                            class: "easy-drawer-recent-item",
                                            onclick: move |_| {
                                                drawer_open.set(false);
                                                if let Some(c) = chat_header_ctx.peek().as_ref() {
                                                    c.on_select_conversation.call(id.clone());
                                                }
                                            },
                                            "{title}"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            div { class: "easy-drawer-sep" }
            // Log out (bottom)
            button {
                class: "easy-drawer-item easy-drawer-logout",
                onclick: move |_| {
                    drawer_open.set(false);
                    on_logout.call(());
                },
                span { class: "easy-drawer-item-icon", LogOut { size: 18 } }
                "Log out"
            }
        }
        // ---- Settings overlay ----
        if show_settings() {
            div { class: "easy-doc-screen easy-overlay",
                div { class: "easy-doc-viewer-bar",
                    button {
                        class: "easy-doc-back",
                        "aria-label": "Back",
                        onclick: move |_| show_settings.set(false),
                        span { class: "easy-drawer-item-icon", ChevronLeft { size: 20 } }
                    }
                    span { class: "easy-doc-viewer-title", "Settings" }
                }
                div { class: "easy-settings-body",
                    div { class: "easy-settings-row",
                        div { class: "easy-settings-text",
                            div { class: "easy-settings-label", "Usage analytics" }
                            div { class: "easy-settings-desc",
                                "Share anonymous usage + crash data to help improve Pick. No scan results, targets, or personal data are sent."
                            }
                        }
                        // Button, not checkbox — see the Easy Mode toggle note
                        // below (dioxus-liveview form-data converter panics on
                        // checkbox onchange). Click flips the persisted flag.
                        button {
                            class: if telemetry_on() { "easy-toggle easy-toggle-on" } else { "easy-toggle" },
                            "aria-label": "Toggle usage analytics",
                            onclick: move |_| {
                                let on = !telemetry_on();
                                telemetry_on.set(on);
                                pentest_core::telemetry::set_enabled(on);
                                let mut s = load_settings();
                                s.telemetry_enabled = on;
                                let _ = save_settings(&s);
                            },
                            span { class: "easy-toggle-track" }
                        }
                    }
                    // Easy Mode toggle. On here (this IS easy mode); turning it
                    // off immediately swaps to the expert shell.
                    div { class: "easy-settings-row",
                        div { class: "easy-settings-text",
                            div { class: "easy-settings-label", "Easy Mode" }
                            div { class: "easy-settings-desc",
                                "The simplified scan + chat view. Turn off for the full expert interface (dashboard, tools, shell, files)."
                            }
                        }
                        // A button, NOT an <input type=checkbox>. Dioxus-liveview's
                        // form-data converter panics (events.rs convert_form_data
                        // unwrap) on the checkbox `onchange` payload; a button's
                        // `onclick` carries no form data and is safe. Styled as an
                        // on-state switch via .easy-toggle-track.
                        button {
                            class: "easy-toggle easy-toggle-on",
                            "aria-label": "Turn off Easy Mode",
                            onclick: move |_| {
                                show_settings.set(false);
                                on_easy_mode_change.call(false);
                            },
                            span { class: "easy-toggle-track" }
                        }
                    }
                }
            }
        }
        if matches!(flow(), crate::auth_flow::AuthFlow::AwaitingGesture | crate::auth_flow::AuthFlow::Failed { reauth: true, .. } | crate::auth_flow::AuthFlow::Disconnected) {
            div { class: "easy-doc-screen easy-overlay",
                div { class: "easy-signin",
                    p { class: "easy-signin-title", "Sign in to connect to Strike48" }
                    p { class: "easy-signin-sub", "Sign in to register this connector and start scanning. We'll open your browser to complete sign-in." }
                    button {
                        class: "action-card",
                        onclick: move |_| {
                            props.on_sign_in.call(());
                        },
                        span { class: "action-card-label", "Sign in" }
                    }
                }
            }
        }

        div { class: "easy-mode",
            // Co-brand top bar: hamburger (left) + Strike48 "S" badge + "Pick".
            // Navigation lives entirely in the slide-over drawer (crux parity).
            div { class: "easy-brandbar",
                // Show the drawer handle once we're Connected (the authoritative
                // AuthFlow state — signed in AND connector registered). Gating on
                // the local `auth_token` signal was fragile: it can diverge from
                // the session token the chat actually uses, hiding the handle even
                // while the chat works. Pre-Connected states (sign-in pending) have
                // nothing to navigate to, so the handle stays hidden then.
                if matches!(flow(), crate::auth_flow::AuthFlow::Connected { .. }) {
                    button {
                        class: "easy-icon-btn easy-menu-btn",
                        "aria-label": "Menu",
                        // Refresh the recent-chats list into the shared ctx snapshot
                        // (fetch-only — NOT on_toggle_history, which would open
                        // ChatPanel's own dropdown and stack it on top of the drawer).
                        onclick: move |_| {
                            if let Some(c) = chat_header_ctx.peek().as_ref() {
                                c.on_refresh_conversations.call(());
                            }
                            drawer_open.set(true);
                        },
                        Menu { size: 22 }
                    }
                }
                span { class: "easy-brand-badge", dangerous_inner_html: STRIKE48_S_BADGE_SVG }
                span { class: "easy-brand-word", "Pick" }
            }
            // Home (hero + resume card): shown on an empty chat once we're Connected.
            // Hidden once a conversation starts (New Chat brings it back), and while
            // sign-in is still pending — the ChatPanel shows the "complete sign-in
            // in the browser" message then, and a Scan button would do nothing.
            // Gated on the authoritative `flow` (not the local auth_token signal,
            // which can diverge from the session token the chat uses).
            if !conversation_active() && matches!(flow(), crate::auth_flow::AuthFlow::Connected { .. }) {
                div { class: "easy-home",
                    div { class: "easy-home-hero",
                        span { class: "easy-hero-badge", dangerous_inner_html: STRIKE48_S_BADGE_SVG }
                        h1 { class: "easy-hero-title", "What's on your network?" }
                        p { class: "easy-hero-sub",
                            "One click enumerates every live host, its open services, and the risk they carry."
                        }
                        button {
                            class: "easy-hero-scan",
                            onclick: move |_| {
                                pentest_core::telemetry::record(
                                    pentest_core::telemetry::Activity::ScanStart,
                                    &[("channel", "easy"), ("source", "easy_mode_button")],
                                );
                                chat_mailbox.set(Some(easy_mode_scan_prompt()));
                            },
                            span { class: "easy-hero-scan-icon", Network { size: 21 } }
                            "Scan My Network"
                        }
                    }
                    // Resume card — only when a recent conversation exists.
                    {
                        let recent = chat_header_ctx
                            .read()
                            .as_ref()
                            .and_then(|c| c.conversations.first().cloned());
                        if let Some(conv) = recent {
                            let title = if conv.title.trim().is_empty() {
                                "Untitled chat".to_string()
                            } else {
                                conv.title.clone()
                            };
                            let relative = format_relative_time(&conv.updated_at);
                            // Latest report for THIS conversation, if any.
                            let report = docs
                                .read()
                                .iter()
                                .find(|d| d.conversation_id == conv.id)
                                .cloned();
                            let sub = resume_sub_line(&relative, report.is_some());
                            let conv_id = conv.id.clone();
                            rsx! {
                                div { class: "easy-home-cards",
                                    div { class: "easy-home-card",
                                        div { class: "easy-card-eye", "Pick up where you left off" }
                                        div { class: "easy-home-card-title", "{title}" }
                                        div { class: "easy-home-card-sub",
                                            "{sub}"
                                            if let Some(m) = report_meta() {
                                                {
                                                    let b = m.badge();
                                                    rsx! {
                                                        span { class: "easy-sev-badge {sev_badge_class(b.kind)}", "{b.label}" }
                                                    }
                                                }
                                            }
                                        }
                                        if let Some(doc) = report {
                                            button {
                                                class: "easy-home-card-btn",
                                                onclick: move |_| viewing.set(Some(doc.clone())),
                                                "Open report"
                                            }
                                        } else {
                                            button {
                                                class: "easy-home-card-btn",
                                                onclick: move |_| {
                                                    if let Some(c) = chat_header_ctx.peek().as_ref() {
                                                        c.on_select_conversation.call(conv_id.clone());
                                                    }
                                                },
                                                "Resume chat"
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            rsx! {}
                        }
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
                    easy_mode: true,
                    open_conversation_id: props.conversation_mailbox,
                    selected_agent_out: Some(agent_id),
                    conversation_active_out: Some(conversation_active),
                    conversation_id_out: Some(conversation_id),
                    on_chat_event: props.on_chat_event,
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
    fn scan_prompt_requires_document_write() {
        let p = easy_mode_scan_prompt();
        assert!(
            p.to_lowercase().contains("network"),
            "prompt should mention the network: {p}"
        );
        // Easy mode has no separate report step, so the scan prompt must
        // explicitly require the platform document_write tool (not write_file)
        // so a shareable Document is created for the docs strip / share flow.
        assert!(
            p.contains("document_write"),
            "prompt must direct the agent to use document_write: {p}"
        );
    }

    #[test]
    fn resume_sub_line_with_report() {
        assert_eq!(resume_sub_line("1h ago", true), "1h ago · report attached");
    }

    #[test]
    fn resume_sub_line_without_report() {
        assert_eq!(resume_sub_line("3d ago", false), "3d ago");
    }
}
