//! Easy Mode Documents list: shows scan reports, opens them in the browser,
//! and creates shareable links (copy + OS share sheet).
//!
//! Both "open" (tap the title) and "share" go through `create_shared_link`:
//! the shareable `/s/:token` page renders the report's markdown as HTML, and it
//! is the only web route that shows a single document (there is no hosted
//! per-document viewer, and the Studio conversation page lives under
//! `/pincharts/conversations/:id` and shows the whole conversation, not the
//! report). Opening the share link therefore gives the user the actual report.

use dioxus::document;
use dioxus::prelude::*;
use pentest_core::matrix::{DocumentSummary, MatrixChatClient};

/// Build the JS snippet that copies `url` to the clipboard. `serde_json`
/// produces a spec-valid JS string literal (safe for any input), unlike
/// `{:?}` which emits `\u{..}` brace-escapes that are invalid JavaScript.
fn clipboard_js(url: &str) -> String {
    let literal = serde_json::to_string(url).unwrap_or_else(|_| "\"\"".to_string());
    format!("navigator.clipboard && navigator.clipboard.writeText({literal})")
}

/// Add `preview=1` to a share URL. Without it, the `/s/:token` route redirects
/// to the Studio SPA documents view; `preview=1` makes it render the report's
/// markdown inline as a standalone page, which is what "open this report" wants.
fn preview_url(url: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}preview=1")
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

    let mut docs = use_signal(Vec::<DocumentSummary>::new);
    let mut loading = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);
    let mut toast = use_signal(|| None::<String>);
    // Bumped by the in-panel Refresh button to force a reload on demand.
    let mut manual_nonce = use_signal(|| 0u32);

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
                    Ok(list) => docs.set(list),
                    Err(e) => error.set(Some(format!("Couldn't load reports: {e}"))),
                }
                loading.set(false);
            });
        });
    }

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
            } else if docs().is_empty() {
                div { class: "easy-docs-empty", "Run a scan to generate your first report." }
            } else {
                for doc in docs() {
                    {
                        // Each closure below is `move`, so give each its own owned clones.
                        let title = doc.title.clone();
                        // For open-in-browser (tap title): create + open the share link.
                        let open_api_url = api_url.clone();
                        let open_token = auth_token.clone();
                        let open_conv = doc.conversation_id.clone();
                        let open_doc = doc.id.clone();
                        // For share (button): create link + copy + OS share sheet.
                        let share_api_url = api_url.clone();
                        let share_token = auth_token.clone();
                        let share_conv = doc.conversation_id.clone();
                        let share_doc = doc.id.clone();
                        rsx! {
                            div { class: "easy-docs-row",
                                span {
                                    class: "easy-docs-title",
                                    onclick: move |_| {
                                        let api_url = open_api_url.clone();
                                        let auth_token = open_token.clone();
                                        let conv = open_conv.clone();
                                        let doc_id = open_doc.clone();
                                        spawn(async move {
                                            let client = MatrixChatClient::new(api_url).with_auth_token(auth_token);
                                            // The /s/:token page renders the report markdown; open it
                                            // in the system browser via the registered opener.
                                            match client.create_shared_link(&conv, &doc_id).await {
                                                Ok(url) => {
                                                    // preview=1 renders the report markdown inline
                                                    // (without it the /s/ route redirects to the SPA).
                                                    // open_url_in_browser uses the registered opener
                                                    // (mobile) and falls back to open::that (desktop/web).
                                                    let open = preview_url(&url);
                                                    if let Err(e) = pentest_core::matrix::open_url_in_browser(&open) {
                                                        toast.set(Some(format!("Couldn't open report: {e}")));
                                                    }
                                                }
                                                Err(e) => toast.set(Some(format!("Couldn't open report: {e}"))),
                                            }
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
                                                    // Copy to clipboard (WebView) + OS share sheet.
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
