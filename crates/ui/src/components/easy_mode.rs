//! Easy Mode — a simplified shell (network scan + chat) for non-expert users.

use dioxus::prelude::*;

use pentest_core::matrix::DocumentSummary;

use super::chat_panel::ChatHeaderCtx;
use super::icons::{Network, STRIKE48_S_BADGE_SVG};
use crate::components::{ChatPanel, DocumentViewer, DocumentsPanel};

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
    // ChatPanel consumes this context via `use_context` (and panics if absent).
    // In the standard shell `AppLayout` provides it; Easy Mode has no AppLayout,
    // so we provide it here. Easy Mode has no header bar to render the actions
    // into, so nothing reads the value -- it just needs to exist.
    use_context_provider(|| Signal::new(None::<ChatHeaderCtx>));

    // Track the selected agent ID and refresh nonce for the DocumentsPanel.
    let agent_id = use_signal(|| None::<String>);
    let refresh_nonce = use_signal(|| 0u32);
    // The report currently open in the full-screen viewer (None = normal shell).
    let mut viewing = use_signal(|| None::<DocumentSummary>);

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

    // A report open in the viewer replaces the whole Easy Mode screen so it's
    // genuinely full-screen (matches the app's signal-driven navigation).
    if let Some(doc) = viewing() {
        return rsx! {
            div { class: "easy-mode",
                DocumentViewer {
                    api_url: props.api_url.clone(),
                    auth_token: auth_token(),
                    doc: doc,
                    on_back: move |_| viewing.set(None),
                }
            }
        };
    }

    rsx! {
        div { class: "easy-mode",
            // Co-brand top bar: Strike48 "S" badge + lowercase "pick" wordmark,
            // with a "STRIKE48" tag on the right. Positions Pick as a Strike48
            // product per the brand identity.
            div { class: "easy-brandbar",
                span { class: "easy-brand-badge", dangerous_inner_html: STRIKE48_S_BADGE_SVG }
                span { class: "easy-brand-word", "pick" }
                span { class: "easy-brand-by", "Strike48" }
            }
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
                }
            }
            DocumentsPanel {
                api_url: props.api_url.clone(),
                auth_token: auth_token(),
                agent_id: agent_id,
                refresh_nonce: refresh_nonce,
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
