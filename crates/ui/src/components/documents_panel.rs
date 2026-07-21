//! Easy Mode Documents: shows the latest scan report, opens it in an in-app
//! markdown viewer (or the browser), and creates public shareable links.
//!
//! Tapping a report renders its markdown inside the app (no browser, no login).
//! The viewer also offers "Open in browser" (the public `/s/:token?preview=1`
//! page) and "Share" (copies the public URL + OS share sheet). External sharing
//! always uses the public share URL so recipients without an account can view.
//!
//! On launch the most recent *existing* report is shown under a muted "Previous
//! report" label so it isn't mistaken for the current run's output; once a newer
//! report appears (after a scan + reload) the label clears.

use dioxus::document;
use dioxus::prelude::*;
use pentest_core::matrix::{DocumentSummary, MatrixChatClient};
use pentest_core::rendering::render_markdown_raw;

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

/// The open document being viewed in-app: the report plus its rendered content.
#[derive(Clone, PartialEq)]
struct ViewerState {
    title: String,
    conversation_id: String,
    document_id: String,
    /// Pre-rendered HTML (from the document's markdown).
    html: String,
}

#[derive(Props, Clone, PartialEq)]
pub struct DocumentsPanelProps {
    pub api_url: String,
    pub auth_token: String,
    /// The Easy Mode agent id, to filter the document list. May be None until
    /// the chat panel has selected an agent.
    pub agent_id: Signal<Option<String>>,
    /// Bump to force a refresh (e.g. after a scan completes).
    pub refresh_nonce: Signal<u32>,
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
    let mut toast = use_signal(|| None::<String>);
    // Bumped by the in-panel Refresh button to force a reload on demand.
    let mut manual_nonce = use_signal(|| 0u32);
    // Timestamp of the report present at the first successful load this session.
    // While the shown report still matches it, it's a *previous* report (label
    // it as such); once a newer report replaces it the label clears.
    let mut baseline_ts = use_signal(|| None::<String>);
    // The document currently open in the in-app viewer.
    let mut viewing = use_signal(|| None::<ViewerState>);
    // Whether the viewer is busy fetching content.
    let mut opening = use_signal(|| false);

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
                        // Record the first-seen report as the session baseline so
                        // it can be labeled "Previous report" until a newer one lands.
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

    // In-app viewer overlay takes over the panel when a report is open.
    if let Some(view) = viewing() {
        let open_conv = view.conversation_id.clone();
        let open_doc = view.document_id.clone();
        let open_api = api_url.clone();
        let open_tok = auth_token.clone();
        let share_conv = view.conversation_id.clone();
        let share_doc = view.document_id.clone();
        let share_api = api_url.clone();
        let share_tok = auth_token.clone();
        return rsx! {
            div { class: "easy-doc-viewer",
                div { class: "easy-doc-viewer-bar",
                    button {
                        class: "easy-doc-back",
                        onclick: move |_| viewing.set(None),
                        "‹ Back"
                    }
                    span { class: "easy-doc-viewer-title", "{view.title}" }
                }
                if let Some(msg) = toast() {
                    div { class: "easy-docs-toast", "{msg}" }
                }
                div {
                    class: "markdown-body easy-doc-viewer-body",
                    dangerous_inner_html: "{view.html}",
                }
                div { class: "easy-doc-viewer-actions",
                    button {
                        class: "easy-docs-secondary",
                        onclick: move |_| {
                            let (api_url, auth_token) = (open_api.clone(), open_tok.clone());
                            let (conv, doc_id) = (open_conv.clone(), open_doc.clone());
                            spawn(async move {
                                let client = MatrixChatClient::new(api_url).with_auth_token(auth_token);
                                match client.create_shared_link(&conv, &doc_id).await {
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
                    button {
                        class: "easy-docs-share",
                        onclick: move |_| {
                            let (api_url, auth_token) = (share_api.clone(), share_tok.clone());
                            let (conv, doc_id) = (share_conv.clone(), share_doc.clone());
                            spawn(async move {
                                let client = MatrixChatClient::new(api_url).with_auth_token(auth_token);
                                match client.create_shared_link(&conv, &doc_id).await {
                                    Ok(url) => {
                                        let _ = document::eval(&clipboard_js(&url));
                                        let _ = pentest_core::share::share_text(&url);
                                        toast.set(Some(format!("Link copied: {url}")));
                                    }
                                    Err(e) => toast.set(Some(format!("Sharing unavailable: {e}"))),
                                }
                            });
                        },
                        "Share"
                    }
                }
            }
        };
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
            if let Some(msg) = toast() {
                div { class: "easy-docs-toast", "{msg}" }
            }
            if loading() {
                div { class: "easy-docs-empty", "Loading reports..." }
            } else if let Some(err) = error() {
                div { class: "easy-docs-error", "{err}" }
            } else if let Some(doc) = latest() {
                {
                    let title = doc.title.clone();
                    // Tap title -> in-app viewer (fetch markdown, then render).
                    let open_api_url = api_url.clone();
                    let open_token = auth_token.clone();
                    let open_conv = doc.conversation_id.clone();
                    let open_doc = doc.id.clone();
                    let open_title = doc.title.clone();
                    // Share button -> public link + copy + OS share sheet.
                    let share_api_url = api_url.clone();
                    let share_token = auth_token.clone();
                    let share_conv = doc.conversation_id.clone();
                    let share_doc = doc.id.clone();
                    rsx! {
                        if is_previous {
                            div { class: "easy-docs-prev-label", "Previous report" }
                        }
                        div { class: "easy-docs-row",
                            span {
                                class: "easy-docs-title",
                                onclick: move |_| {
                                    if opening() { return; }
                                    let api_url = open_api_url.clone();
                                    let auth_token = open_token.clone();
                                    let conv = open_conv.clone();
                                    let doc_id = open_doc.clone();
                                    let title = open_title.clone();
                                    opening.set(true);
                                    spawn(async move {
                                        let client = MatrixChatClient::new(api_url).with_auth_token(auth_token);
                                        match client.get_document_content(&conv, &doc_id).await {
                                            Ok(md) => viewing.set(Some(ViewerState {
                                                title,
                                                conversation_id: conv,
                                                document_id: doc_id,
                                                html: render_markdown_raw(&md),
                                            })),
                                            Err(e) => toast.set(Some(format!("Couldn't open report: {e}"))),
                                        }
                                        opening.set(false);
                                    });
                                },
                                "{title}"
                            }
                            button {
                                class: "easy-docs-share",
                                onclick: move |_| {
                                    let api_url = share_api_url.clone();
                                    let auth_token = share_token.clone();
                                    let conv = share_conv.clone();
                                    let doc_id = share_doc.clone();
                                    spawn(async move {
                                        let client = MatrixChatClient::new(api_url).with_auth_token(auth_token);
                                        match client.create_shared_link(&conv, &doc_id).await {
                                            Ok(url) => {
                                                let _ = document::eval(&clipboard_js(&url));
                                                let _ = pentest_core::share::share_text(&url);
                                                toast.set(Some(format!("Link copied: {url}")));
                                            }
                                            Err(e) => toast.set(Some(format!("Sharing unavailable: {e}"))),
                                        }
                                    });
                                },
                                "Share"
                            }
                        }
                    }
                }
            } else {
                div { class: "easy-docs-empty", "Run a scan to generate your first report." }
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
