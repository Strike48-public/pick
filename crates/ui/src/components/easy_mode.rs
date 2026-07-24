//! Easy Mode — a simplified shell (network scan + chat) for non-expert users.

use dioxus::prelude::*;

use pentest_core::matrix::DocumentSummary;

use super::chat_panel::ChatHeaderCtx;
use super::icons::{
    ChevronLeft, FileText, LogOut, Menu, Network, Plus, Settings, STRIKE48_S_BADGE_SVG,
};
use crate::components::{ChatPanel, ConversationDocs, DocumentViewer, DocumentsPanel};
use crate::connector_app::ForceSignIn;
use pentest_core::settings::{load_settings, save_settings};

/// The canned chat message the Easy Mode "Scan" button sends. It instructs the
/// server-side agent to enumerate local interfaces, scan the local subnet, and
/// write a report document of the findings. Kept as one place so the wording is
/// consistent and testable.
pub fn easy_mode_scan_prompt() -> String {
    pentest_core::easy_mode_scan_prompt()
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
    // Forces the next auto-connect down the fresh-browser SignIn path (set by the
    // retry button); provided by connector_app alongside needs_sign_in.
    let force_sign_in = use_context::<ForceSignIn>().0;

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
            if !t.is_empty() {
                auth_token.set(t);
            }
        }
    });

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
        if needs_sign_in() {
            {
                let mut needs_sign_in = needs_sign_in;
                let mut retry_tick = retry_tick;
                let mut force_sign_in = force_sign_in;
                rsx! {
                    div { class: "easy-doc-screen easy-overlay",
                        div { class: "easy-signin",
                            p { class: "easy-signin-title", "Sign in to connect to Strike48" }
                            p { class: "easy-signin-sub", "Sign in to register this connector and start scanning. We'll open your browser to complete sign-in." }
                            button {
                                class: "action-card",
                                onclick: move |_| {
                                    // Force a fresh browser login: existing connector
                                    // creds must NOT short-circuit to a silent reconnect
                                    // that never re-opens the browser (that loops).
                                    force_sign_in.set(true);
                                    needs_sign_in.set(false);
                                    retry_tick.set(retry_tick() + 1);
                                },
                                span { class: "action-card-label", "Sign in" }
                            }
                        }
                    }
                }
            }
        }

        div { class: "easy-mode",
            // Co-brand top bar: hamburger (left) + Strike48 "S" badge + "Pick".
            // Navigation lives entirely in the slide-over drawer (crux parity).
            div { class: "easy-brandbar",
                // Hide the drawer handle until we're signed in (no chat token yet
                // = browser sign-in pending): there are no conversations/reports to
                // navigate to, and the drawer's Logout/Settings would act on a
                // half-connected state. Matches the hidden Scan card below.
                if !auth_token().is_empty() {
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
            // Scan card: only shown on an empty chat once we're signed in. Hidden
            // once a conversation starts (New Chat brings it back), and while the
            // browser sign-in is still pending (no chat token yet) — the ChatPanel
            // shows the "complete sign-in in the browser" message in that window,
            // and a Scan button there would do nothing.
            if !conversation_active() && !auth_token().is_empty() {
                div { class: "action-grid",
                    div {
                        class: "action-card",
                        onclick: move |_| {
                            // Record scan.start tagged with its source so
                            // button-initiated scans are distinguishable from typed
                            // ones in the trace data.
                            pentest_core::telemetry::record(
                                pentest_core::telemetry::Activity::ScanStart,
                                &[("channel", "easy"), ("source", "easy_mode_button")],
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
}
