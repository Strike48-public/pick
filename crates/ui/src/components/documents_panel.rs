//! Easy Mode Documents list: shows scan reports, opens them in the browser,
//! and creates shareable links (copy + OS share sheet).

use dioxus::prelude::*;
use dioxus::document;
use pentest_core::matrix::{studio_web_base, DocumentSummary, MatrixChatClient};

/// Build the Studio conversation URL a document opens to.
pub fn conversation_url(web_base: &str, conversation_id: &str) -> String {
    format!("{}/conversations/{}", web_base.trim_end_matches('/'), conversation_id)
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

    // (Re)load when token, agent, or nonce changes.
    {
        let api_url = api_url.clone();
        let auth_token = auth_token.clone();
        use_effect(move || {
            let _ = refresh_nonce();          // subscribe
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

    let web_base = studio_web_base(&api_url);

    rsx! {
        div { class: "easy-docs",
            div { class: "easy-docs-header", "Reports" }
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
                        // For open-in-browser:
                        let open_url = conversation_url(&web_base, &doc.conversation_id);
                        // For share:
                        let share_api_url = api_url.clone();
                        let share_token = auth_token.clone();
                        let share_conv = doc.conversation_id.clone();
                        let share_doc = doc.id.clone();
                        rsx! {
                            div { class: "easy-docs-row",
                                span {
                                    class: "easy-docs-title",
                                    onclick: move |_| {
                                        // Open in system browser via the registered opener.
                                        let _ = pentest_core::matrix::open_browser(&open_url);
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
                                                    let js = format!(
                                                        "navigator.clipboard && navigator.clipboard.writeText({:?})",
                                                        url
                                                    );
                                                    let _ = document::eval(&js);
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
    fn conversation_url_builds_studio_path() {
        assert_eq!(
            conversation_url("https://studio.example.test", "conv-1"),
            "https://studio.example.test/conversations/conv-1"
        );
    }

    #[test]
    fn conversation_url_trims_trailing_slash() {
        assert_eq!(
            conversation_url("https://studio.example.test/", "c"),
            "https://studio.example.test/conversations/c"
        );
    }
}
