//! Easy Mode Documents: a compact list showing the latest scan report, plus a
//! full-screen [`DocumentViewer`] that renders a report's markdown in-app and
//! offers share actions.
//!
//! The list only *opens* reports (tap a row). All sharing lives in the viewer.
//! `EasyModeShell` owns which document is open and swaps the whole screen to the
//! viewer, so the report is genuinely full-screen rather than nested in the
//! list's slot. External sharing always uses the public `/s/:token` link so
//! recipients without an account can view.
//!
//! On launch the most recent *existing* report is shown under a muted "Previous
//! report" label so it isn't mistaken for the current run's output; once a newer
//! report appears (after a scan + reload) the label clears.

use dioxus::document;
use dioxus::prelude::*;
use pentest_core::matrix::{DocumentSummary, MatrixChatClient};
use pentest_core::rendering::render_markdown_raw;
use pentest_core::social_share::{share_intent_url, SocialNetwork};

/// Build the JS snippet that copies `url` to the clipboard. `serde_json`
/// produces a spec-valid JS string literal (safe for any input), unlike
/// `{:?}` which emits `\u{..}` brace-escapes that are invalid JavaScript.
fn clipboard_js(url: &str) -> String {
    let literal = serde_json::to_string(url).unwrap_or_else(|_| "\"\"".to_string());
    format!("navigator.clipboard && navigator.clipboard.writeText({literal})")
}

/// Add `preview=1` to a share URL. Without it, the `/s/:token` route redirects
/// to the Studio SPA documents view; `preview=1` renders the report's markdown
/// inline as a standalone page.
fn preview_url(url: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}preview=1")
}

// ---------------------------------------------------------------------------
// DocumentsPanel — the compact list (open only; no sharing here)
// ---------------------------------------------------------------------------

#[derive(Props, Clone, PartialEq)]
pub struct DocumentsPanelProps {
    pub api_url: String,
    pub auth_token: String,
    /// The Easy Mode agent id, to filter the document list. May be None until
    /// the chat panel has selected an agent.
    pub agent_id: Signal<Option<String>>,
    /// Bump to force a refresh (e.g. after a scan completes).
    pub refresh_nonce: Signal<u32>,
    /// Fired when the user taps a report; the parent opens the full-screen viewer.
    pub on_open: EventHandler<DocumentSummary>,
}

#[component]
pub fn DocumentsPanel(props: DocumentsPanelProps) -> Element {
    let api_url = props.api_url.clone();
    let auth_token = props.auth_token.clone();
    let agent_id = props.agent_id;
    let refresh_nonce = props.refresh_nonce;

    // Easy Mode shows only the single most-recently-created report (repeated
    // scans each write a new document, so a full list accumulates duplicates).
    let mut latest = use_signal(|| None::<DocumentSummary>);
    let mut loading = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    // Bumped by the in-panel Refresh button to force a reload on demand.
    let mut manual_nonce = use_signal(|| 0u32);
    // Timestamp of the report present at the first successful load this session.
    // While the shown report still matches it, it's a *previous* report; once a
    // newer report replaces it the label clears.
    let mut baseline_ts = use_signal(|| None::<String>);

    // (Re)load when token, agent, the external nonce, or the manual nonce changes.
    {
        let api_url = api_url.clone();
        let auth_token = auth_token.clone();
        use_effect(move || {
            let _ = refresh_nonce();          // subscribe (bumped after a scan)
            let _ = manual_nonce();           // subscribe (Refresh button)
            let aid = agent_id();              // subscribe
            let api_url = api_url.clone();
            let auth_token = auth_token.clone();
            if auth_token.is_empty() || api_url.is_empty() {
                return;
            }
            loading.set(true);
            error.set(None);
            spawn(async move {
                let client = MatrixChatClient::new(api_url).with_auth_token(auth_token);
                match client.list_documents(aid.as_deref()).await {
                    Ok(list) => {
                        let doc = pentest_core::matrix::latest_document(list);
                        if baseline_ts.peek().is_none() {
                            if let Some(ref d) = doc {
                                baseline_ts.set(Some(d.timestamp.clone()));
                            }
                        }
                        latest.set(doc);
                    }
                    Err(e) => error.set(Some(format!("Couldn't load reports: {e}"))),
                }
                loading.set(false);
            });
        });
    }

    // Is the currently-shown report the pre-existing one from session start?
    let is_previous = match (latest(), baseline_ts()) {
        (Some(doc), Some(base)) => doc.timestamp == base,
        _ => false,
    };

    rsx! {
        div { class: "easy-docs",
            div { class: "easy-docs-header",
                span { "Reports" }
                button {
                    class: "easy-docs-refresh",
                    onclick: move |_| { manual_nonce += 1; },
                    "Refresh"
                }
            }
            if loading() {
                div { class: "easy-docs-empty", "Loading reports..." }
            } else if let Some(err) = error() {
                div { class: "easy-docs-error", "{err}" }
            } else if let Some(doc) = latest() {
                {
                    let title = doc.title.clone();
                    let open_doc = doc.clone();
                    rsx! {
                        if is_previous {
                            div { class: "easy-docs-prev-label", "Previous report" }
                        }
                        div {
                            class: "easy-docs-row easy-docs-row-tappable",
                            onclick: move |_| props.on_open.call(open_doc.clone()),
                            span { class: "easy-docs-title", "{title}" }
                            span { class: "easy-docs-chevron", "›" }
                        }
                    }
                }
            } else {
                div { class: "easy-docs-empty", "Run a scan to generate your first report." }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// DocumentViewer — full-screen report render + share actions
// ---------------------------------------------------------------------------

#[derive(Props, Clone, PartialEq)]
pub struct DocumentViewerProps {
    pub api_url: String,
    pub auth_token: String,
    pub doc: DocumentSummary,
    /// Fired when the user leaves the viewer (back button).
    pub on_back: EventHandler<()>,
}

#[component]
pub fn DocumentViewer(props: DocumentViewerProps) -> Element {
    let api_url = props.api_url.clone();
    let auth_token = props.auth_token.clone();
    let doc = props.doc.clone();

    let mut html = use_signal(String::new);
    let mut load_error = use_signal(|| None::<String>);
    let mut toast = use_signal(|| None::<String>);

    // Fetch + render the document's markdown once on mount.
    {
        let api_url = api_url.clone();
        let auth_token = auth_token.clone();
        let conv = doc.conversation_id.clone();
        let doc_id = doc.id.clone();
        use_effect(move || {
            let api_url = api_url.clone();
            let auth_token = auth_token.clone();
            let conv = conv.clone();
            let doc_id = doc_id.clone();
            spawn(async move {
                let client = MatrixChatClient::new(api_url).with_auth_token(auth_token);
                match client.get_document_content(&conv, &doc_id).await {
                    Ok(md) => html.set(render_markdown_raw(&md)),
                    Err(e) => load_error.set(Some(format!("Couldn't load report: {e}"))),
                }
            });
        });
    }

    // Shared helper: create the public link then run `after(url)`.
    let title = doc.title.clone();
    let conv_id = doc.conversation_id.clone();
    let document_id = doc.id.clone();

    rsx! {
        div { class: "easy-doc-viewer",
            div { class: "easy-doc-viewer-bar",
                button {
                    class: "easy-doc-back",
                    onclick: move |_| props.on_back.call(()),
                    "‹ Back"
                }
                span { class: "easy-doc-viewer-title", "{title}" }
            }
            div {
                class: "markdown-body easy-doc-viewer-body",
                if let Some(err) = load_error() {
                    div { class: "easy-docs-error", "{err}" }
                } else if html().is_empty() {
                    div { class: "easy-docs-empty", "Loading report..." }
                } else {
                    div { dangerous_inner_html: "{html}" }
                }
            }
            div { class: "easy-doc-share-sheet",
                if let Some(msg) = toast() {
                    div { class: "easy-docs-toast", "{msg}" }
                }
                div { class: "easy-doc-share-title", "Share this report" }
                div { class: "easy-doc-share-primary",
                    {
                        let (a, t, c, d) = (api_url.clone(), auth_token.clone(), conv_id.clone(), document_id.clone());
                        rsx! {
                            button {
                                class: "easy-doc-btn easy-doc-btn-primary",
                                onclick: move |_| {
                                    let (a, t, c, d) = (a.clone(), t.clone(), c.clone(), d.clone());
                                    spawn(async move {
                                        let client = MatrixChatClient::new(a).with_auth_token(t);
                                        match client.create_shared_link(&c, &d).await {
                                            Ok(url) => {
                                                let _ = document::eval(&clipboard_js(&url));
                                                let _ = pentest_core::share::share_text(&url);
                                                toast.set(Some(format!("Link copied: {url}")));
                                            }
                                            Err(e) => toast.set(Some(format!("Sharing unavailable: {e}"))),
                                        }
                                    });
                                },
                                "Share link"
                            }
                        }
                    }
                    {
                        let (a, t, c, d) = (api_url.clone(), auth_token.clone(), conv_id.clone(), document_id.clone());
                        rsx! {
                            button {
                                class: "easy-doc-btn easy-doc-btn-ghost",
                                onclick: move |_| {
                                    let (a, t, c, d) = (a.clone(), t.clone(), c.clone(), d.clone());
                                    spawn(async move {
                                        let client = MatrixChatClient::new(a).with_auth_token(t);
                                        match client.create_shared_link(&c, &d).await {
                                            Ok(url) => {
                                                if let Err(e) = pentest_core::matrix::open_url_in_browser(&preview_url(&url)) {
                                                    toast.set(Some(format!("Couldn't open report: {e}")));
                                                }
                                            }
                                            Err(e) => toast.set(Some(format!("Couldn't open report: {e}"))),
                                        }
                                    });
                                },
                                "Open in browser"
                            }
                        }
                    }
                }
                div { class: "easy-doc-social-grid",
                    for network in SocialNetwork::all() {
                        {
                            let (a, t, c, d, ttl) = (
                                api_url.clone(), auth_token.clone(),
                                conv_id.clone(), document_id.clone(), title.clone(),
                            );
                            rsx! {
                                button {
                                    class: "easy-doc-social-btn social-{network.key()}",
                                    onclick: move |_| {
                                        let (a, t, c, d, ttl) = (a.clone(), t.clone(), c.clone(), d.clone(), ttl.clone());
                                        spawn(async move {
                                            let client = MatrixChatClient::new(a).with_auth_token(t);
                                            match client.create_shared_link(&c, &d).await {
                                                Ok(url) => match share_intent_url(network, &url, &ttl) {
                                                    Ok(intent) => {
                                                        if let Err(e) = pentest_core::matrix::open_url_in_browser(&intent) {
                                                            toast.set(Some(format!("Couldn't open share: {e}")));
                                                        }
                                                    }
                                                    Err(e) => toast.set(Some(format!("Couldn't build share link: {e}"))),
                                                },
                                                Err(e) => toast.set(Some(format!("Sharing unavailable: {e}"))),
                                            }
                                        });
                                    },
                                    "{network.label()}"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_js_produces_valid_js_string_literal() {
        assert_eq!(
            clipboard_js("https://studio.example.test/s/abc123"),
            r#"navigator.clipboard && navigator.clipboard.writeText("https://studio.example.test/s/abc123")"#
        );
    }

    #[test]
    fn clipboard_js_escapes_quotes_and_backslashes() {
        // A hostile/odd URL must not break out of the JS string literal.
        let js = clipboard_js(r#"a"b\c"#);
        assert_eq!(
            js,
            r#"navigator.clipboard && navigator.clipboard.writeText("a\"b\\c")"#
        );
    }

    #[test]
    fn preview_url_appends_preview_param() {
        assert_eq!(
            preview_url("https://studio.example.test/s/tok"),
            "https://studio.example.test/s/tok?preview=1"
        );
    }

    #[test]
    fn preview_url_uses_ampersand_when_query_present() {
        assert_eq!(
            preview_url("https://studio.example.test/s/tok?x=1"),
            "https://studio.example.test/s/tok?x=1&preview=1"
        );
    }
}
