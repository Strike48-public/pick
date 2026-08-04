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
//! The Reports overlay ([`DocumentsPanel`]) lists every report the agent has
//! written, newest first. The bottom chat strip ([`ConversationDocs`]) is scoped
//! to the current conversation.

use dioxus::document;
use dioxus::prelude::*;
use pentest_core::matrix::{BadgeKind, DocumentSummary, MatrixChatClient, ReportMeta};
use pentest_core::rendering::render_markdown_raw;
use pentest_core::social_share::{share_intent_url, SocialNetwork};

/// Shared client-side helpers + chart/mermaid post-processor (the same assets
/// the chat panel injects). The document viewer renders report markdown that can
/// contain ```mermaid``` / ```echarts``` fences, so it needs these loaded and
/// then triggered against its own container.
const UTILS_JS: &str = include_str!("../assets/utils.js");
const CHART_PROCESSOR_JS: &str = include_str!("../assets/chart_processor.js");

/// Build the JS snippet that copies `url` to the clipboard. `serde_json`
/// produces a spec-valid JS string literal (safe for any input), unlike
/// `{:?}` which emits `\u{..}` brace-escapes that are invalid JavaScript.
fn clipboard_js(url: &str) -> String {
    let literal = serde_json::to_string(url).unwrap_or_else(|_| "\"\"".to_string());
    format!("navigator.clipboard && navigator.clipboard.writeText({literal})")
}

/// Copy `url` to the clipboard, preferring the native OS clipboard handler
/// (registered by desktop targets) and falling back to the webview's
/// `navigator.clipboard`. The JS path silently no-ops in WebView2 on Windows
/// (no `navigator.clipboard` from the custom-protocol origin), so desktop must
/// go through the native handler; mobile/web have no handler and use the JS
/// path, which works in their (WebKit) renderers.
async fn copy_to_clipboard(url: &str) {
    if pentest_core::clipboard::copy_text(url).is_ok() {
        return;
    }
    let _ = document::eval(&clipboard_js(url)).await;
}

/// Add `preview=1` to a share URL. Delegates to the shared
/// `pentest_core::matrix::preview_url` so Easy Mode's crux shells and the Dioxus
/// app build the preview link identically.
fn preview_url(url: &str) -> String {
    pentest_core::matrix::preview_url(url)
}

/// Map a severity badge bucket to its CSS modifier class. `pub(crate)` so the
/// easy-mode resume card can reuse it.
pub(crate) fn sev_badge_class(kind: BadgeKind) -> &'static str {
    match kind {
        BadgeKind::Critical | BadgeKind::High => "sev-err",
        BadgeKind::Medium => "sev-warn",
        BadgeKind::Low | BadgeKind::Info => "sev-muted",
        BadgeKind::Clean => "sev-ok",
    }
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
    /// Fired when the user taps a report; the parent opens the full-screen viewer.
    pub on_open: EventHandler<DocumentSummary>,
}

#[component]
pub fn DocumentsPanel(props: DocumentsPanelProps) -> Element {
    let api_url = props.api_url.clone();
    let auth_token = props.auth_token.clone();
    let agent_id = props.agent_id;

    // The Reports overlay lists every report the agent has written, newest first.
    let mut docs = use_signal(Vec::<DocumentSummary>::new);
    let mut loading = use_signal(|| false);
    let mut error = use_signal(|| None::<String>);

    // Parsed frontmatter per document id (filled async after the summary list
    // loads; capped so a large report set doesn't fan out unbounded).
    // doc id -> parsed frontmatter. The value is `Option`: `Some(meta)` when the
    // report carried a frontmatter block, `None` for a legacy report (so it is
    // memoized as "fetched, no metadata" and its row stays title+date with no
    // badge, rather than re-fetching every poll or showing a false "clean").
    let mut meta_map = use_signal(std::collections::HashMap::<String, Option<ReportMeta>>::new);

    // Keep the report list current automatically: reload when token/agent change,
    // then poll on an interval so a scan's new report appears on its own — no
    // manual refresh. Polling stops implicitly when the component unmounts (the
    // spawned future is dropped with the panel).
    {
        let api_url = api_url.clone();
        let auth_token = auth_token.clone();
        use_effect(move || {
            let aid = agent_id(); // subscribe: reload when the agent resolves
            let api_url = api_url.clone();
            let auth_token = auth_token.clone();
            if auth_token.is_empty() || api_url.is_empty() {
                return;
            }
            loading.set(true);
            error.set(None);
            spawn(async move {
                // Poll every 5s. Each pass rebuilds a lightweight client and
                // updates `docs`; the first pass clears the loading state.
                loop {
                    let client =
                        MatrixChatClient::new(api_url.clone()).with_auth_token(auth_token.clone());
                    match client.list_documents(aid.as_deref()).await {
                        Ok(mut list) => {
                            // Newest first (timestamp is ISO-8601, so lexical sort works).
                            list.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                            docs.set(list);
                            error.set(None);
                        }
                        Err(e) => error.set(Some(format!("Couldn't load reports: {e}"))),
                    }
                    loading.set(false);
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            });
        });
    }

    // Fetch report metadata for the first 20 visible docs (capped fan-out).
    {
        let api_url = api_url.clone();
        let auth_token = auth_token.clone();
        use_effect(move || {
            let list = docs();
            if auth_token.is_empty() || api_url.is_empty() {
                return;
            }
            for doc in list.into_iter().take(20) {
                if meta_map.peek().contains_key(&doc.id) {
                    continue;
                }
                let api_url = api_url.clone();
                let auth_token = auth_token.clone();
                spawn(async move {
                    let client = MatrixChatClient::new(api_url).with_auth_token(auth_token);
                    match client
                        .get_document_content(&doc.conversation_id, &doc.id)
                        .await
                    {
                        Ok(content) => {
                            meta_map
                                .write()
                                .insert(doc.id.clone(), ReportMeta::parse(&content));
                        }
                        Err(e) => {
                            // Memoize as "fetched, no metadata" so a transient
                            // failure doesn't re-fan-out every poll, and surface
                            // it in the log rather than dropping it silently.
                            tracing::warn!("report metadata fetch failed for {}: {e}", doc.id);
                            meta_map.write().insert(doc.id.clone(), None);
                        }
                    }
                });
            }
        });
    }

    let items = docs();

    rsx! {
        div { class: "easy-docs",
            // No in-content "Reports" header: the overlay title bar already
            // labels this screen "Reports" (see EasyModeShell), so a second
            // heading here is redundant.
            if loading() {
                div { class: "easy-docs-empty", "Loading reports..." }
            } else if let Some(err) = error() {
                div { class: "easy-docs-error", "{err}" }
            } else if items.is_empty() {
                div { class: "easy-docs-empty", "Run a scan to generate your first report." }
            } else {
                for doc in items {
                    {
                        let title = doc.title.clone();
                        let open_doc = doc.clone();
                        // Flatten: not-yet-fetched (None) and legacy-no-frontmatter
                        // (Some(None)) both render as no metadata / no badge.
                        let meta = meta_map.read().get(&doc.id).cloned().flatten();
                        rsx! {
                            div {
                                class: "easy-docs-row easy-docs-row-tappable",
                                onclick: move |_| props.on_open.call(open_doc.clone()),
                                div { class: "easy-docs-row-main",
                                    span { class: "easy-docs-title", "{title}" }
                                    if let Some(m) = meta.as_ref() {
                                        div { class: "easy-docs-meta",
                                            if let Some(scope) = m.scope.as_ref() {
                                                span { class: "easy-docs-scope", "{scope}" }
                                            }
                                            if let (Some(h), Some(s)) = (m.hosts, m.services) {
                                                span { class: "easy-docs-counts", "{h} hosts · {s} services" }
                                            }
                                        }
                                    }
                                }
                                if let Some(m) = meta.as_ref() {
                                    {
                                        let b = m.badge();
                                        rsx! {
                                            span { class: "easy-sev-badge {sev_badge_class(b.kind)}", "{b.label}" }
                                        }
                                    }
                                }
                                span { class: "easy-docs-chevron", "›" }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ConversationDocs — bottom strip scoped to the CURRENT conversation
// ---------------------------------------------------------------------------

#[derive(Props, Clone, PartialEq)]
pub struct ConversationDocsProps {
    pub api_url: String,
    pub auth_token: String,
    /// The Easy Mode agent id (documents are fetched per agent, then filtered
    /// to the active conversation below).
    pub agent_id: Signal<Option<String>>,
    /// The active conversation's id. When None (no conversation yet) the strip
    /// renders nothing.
    pub conversation_id: Signal<Option<String>>,
    /// Fired when the user taps a report row.
    pub on_open: EventHandler<DocumentSummary>,
}

/// A compact bottom strip listing reports written in the *current* conversation.
/// Distinct from [`DocumentsPanel`] (the top-bar Docs overlay lists ALL reports);
/// this is conversation-scoped and only appears once the active conversation has
/// produced at least one document.
#[component]
pub fn ConversationDocs(props: ConversationDocsProps) -> Element {
    let api_url = props.api_url.clone();
    let auth_token = props.auth_token.clone();
    let agent_id = props.agent_id;
    let conversation_id = props.conversation_id;

    // Reports belonging to the active conversation, newest first.
    let mut docs = use_signal(Vec::<DocumentSummary>::new);
    // doc id -> parsed frontmatter (Option: Some(meta) if the report carried a
    // block, None for legacy). Memoized so a report is fetched once.
    let mut meta_map = use_signal(std::collections::HashMap::<String, Option<ReportMeta>>::new);

    // The conversation id the currently-running poll loop is scoped to. Guards
    // against (a) blanking the list on a transient `None` cid and (b) spawning a
    // second poll loop every time this effect re-runs (agent_id/conversation_id
    // are signals that can churn on unrelated chat updates — a fresh `spawn` per
    // re-run leaked overlapping infinite loops, all calling `docs.set`, which is
    // what made the panel flicker ~1×/sec instead of updating on its own 5s tick).
    let mut polling_cid = use_signal(|| None::<String>);
    {
        let api_url = api_url.clone();
        let auth_token = auth_token.clone();
        use_effect(move || {
            let aid = agent_id();
            let cid = conversation_id();
            let api_url = api_url.clone();
            let auth_token = auth_token.clone();

            // No conversation yet, or not connected. Do NOT clear `docs` here —
            // a transient `None` (e.g. mid chat-state update) would blank the
            // panel and it would repopulate on the next poll, causing a flicker.
            // Keep the last-known list; it's replaced only when a real query for
            // an actual conversation resolves, or when the conversation changes.
            let Some(cid) = cid else {
                return;
            };
            if auth_token.is_empty() || api_url.is_empty() {
                return;
            }

            // Only (re)start the poll loop when the conversation actually changes.
            // If we're already polling this cid, the running loop keeps it fresh —
            // re-running the effect for an unrelated dep change must not spawn a
            // second loop.
            if polling_cid.peek().as_deref() == Some(cid.as_str()) {
                return;
            }
            // Conversation switched: clear the previous chat's docs so they don't
            // linger, then mark this cid as the one we're polling.
            docs.set(Vec::new());
            polling_cid.set(Some(cid.clone()));

            spawn(async move {
                // Poll so a report written mid-conversation appears on its own.
                // Exit when the active conversation has moved on (a newer effect
                // run took over), so stale loops don't accumulate.
                loop {
                    if polling_cid.peek().as_deref() != Some(cid.as_str()) {
                        break;
                    }
                    let client =
                        MatrixChatClient::new(api_url.clone()).with_auth_token(auth_token.clone());
                    if let Ok(list) = client.list_documents(aid.as_deref()).await {
                        // Only apply if still the active conversation (the await
                        // may have outlived a conversation switch).
                        if polling_cid.peek().as_deref() == Some(cid.as_str()) {
                            let mut mine: Vec<DocumentSummary> = list
                                .into_iter()
                                .filter(|d| d.conversation_id == cid)
                                .collect();
                            // Newest first (ISO-8601 timestamp, lexical sort works).
                            mine.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                            docs.set(mine);
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            });
        });
    }

    // Fetch + parse frontmatter for the conversation's reports (few per chat, so
    // no cap needed); memoized per doc id so each is fetched once.
    {
        let api_url = api_url.clone();
        let auth_token = auth_token.clone();
        use_effect(move || {
            let list = docs();
            if auth_token.is_empty() || api_url.is_empty() {
                return;
            }
            for doc in list {
                if meta_map.peek().contains_key(&doc.id) {
                    continue;
                }
                let api_url = api_url.clone();
                let auth_token = auth_token.clone();
                spawn(async move {
                    let client = MatrixChatClient::new(api_url).with_auth_token(auth_token);
                    match client
                        .get_document_content(&doc.conversation_id, &doc.id)
                        .await
                    {
                        Ok(content) => {
                            meta_map
                                .write()
                                .insert(doc.id.clone(), ReportMeta::parse(&content));
                        }
                        Err(e) => {
                            // Memoize as "fetched, no metadata" so a transient
                            // failure doesn't re-fan-out every poll, and surface
                            // it in the log rather than dropping it silently.
                            tracing::warn!("report metadata fetch failed for {}: {e}", doc.id);
                            meta_map.write().insert(doc.id.clone(), None);
                        }
                    }
                });
            }
        });
    }

    let items = docs();
    if items.is_empty() {
        return rsx! {};
    }

    rsx! {
        div { class: "easy-conv-docs",
            div { class: "easy-conv-docs-header",
                span { class: "easy-conv-docs-icon", "\u{1F4C4}" }
                span { "Documents from this chat" }
            }
            for doc in items {
                {
                    let title = doc.title.clone();
                    let open_doc = doc.clone();
                    // Flatten: not-yet-fetched (None) and legacy (Some(None)) both
                    // render as no metadata.
                    let meta = meta_map.read().get(&doc.id).cloned().flatten();
                    rsx! {
                        div {
                            class: "easy-conv-docs-row",
                            onclick: move |_| props.on_open.call(open_doc.clone()),
                            div { class: "easy-conv-docs-main",
                                span { class: "easy-conv-docs-title", "{title}" }
                                if let Some(m) = meta.as_ref() {
                                    div { class: "easy-conv-docs-meta",
                                        if let Some(scope) = m.scope.as_ref() {
                                            span { class: "easy-conv-docs-scope", "{scope}" }
                                        }
                                        {
                                            let n = m.finding_count();
                                            if n > 0 {
                                                rsx! {
                                                    span { class: "easy-conv-docs-findings",
                                                        "{n} finding" {if n == 1 { "" } else { "s" }}
                                                    }
                                                }
                                            } else {
                                                rsx! {}
                                            }
                                        }
                                    }
                                }
                            }
                            if let Some(m) = meta.as_ref() {
                                {
                                    let b = m.badge();
                                    rsx! {
                                        span { class: "easy-sev-badge {sev_badge_class(b.kind)}", "{b.label}" }
                                    }
                                }
                            }
                            span { class: "easy-docs-chevron", "\u{203A}" }
                        }
                    }
                }
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
    // Whether the top-right share menu is open.
    let mut share_open = use_signal(|| false);

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
                    Ok(md) => {
                        let (_fm, body) = pentest_core::rendering::split_frontmatter(&md);
                        html.set(render_markdown_raw(body));
                        // Load the shared chart/mermaid libs (idempotent) then
                        // render any ```mermaid```/```echarts``` fences inside the
                        // viewer's own container. The chat panel does the same for
                        // `.chat-messages`; here we target the doc body.
                        let _ = document::eval(UTILS_JS).await;
                        let _ = document::eval(CHART_PROCESSOR_JS).await;
                        if let Err(e) =
                            document::eval("triggerChartPostProcess('.easy-doc-viewer-body')").await
                        {
                            tracing::warn!("doc viewer chart post-process failed: {e}");
                        }
                    }
                    Err(e) => load_error.set(Some(format!("Couldn't load report: {e}"))),
                }
            });
        });
    }

    // Shared helper: create the public link then run `after(url)`.
    let title = doc.title.clone();
    let conv_id = doc.conversation_id.clone();
    let document_id = doc.id.clone();

    // One place to build the public link then run an action with the URL.
    let run_with_link = {
        let api_url = api_url.clone();
        let auth_token = auth_token.clone();
        let conv_id = conv_id.clone();
        let document_id = document_id.clone();
        move |action: ShareAction, network: Option<SocialNetwork>, title: String| {
            let (a, t, c, d) = (
                api_url.clone(),
                auth_token.clone(),
                conv_id.clone(),
                document_id.clone(),
            );
            share_open.set(false);
            spawn(async move {
                let client = MatrixChatClient::new(a).with_auth_token(t);
                match client.create_shared_link(&c, &d).await {
                    Ok(url) => match action {
                        ShareAction::Copy => {
                            copy_to_clipboard(&url).await;
                            toast.set(Some("Link copied".to_string()));
                        }
                        ShareAction::NativeSheet => {
                            copy_to_clipboard(&url).await;
                            let _ = pentest_core::share::share_text(&url);
                        }
                        ShareAction::OpenBrowser => {
                            if let Err(e) =
                                pentest_core::matrix::open_url_in_browser(&preview_url(&url))
                            {
                                toast.set(Some(format!("Couldn't open report: {e}")));
                            }
                        }
                        ShareAction::Social => {
                            if let Some(net) = network {
                                match share_intent_url(net, &url, &title) {
                                    Ok(intent) => {
                                        if let Err(e) =
                                            pentest_core::matrix::open_url_in_browser(&intent)
                                        {
                                            toast.set(Some(format!("Couldn't open share: {e}")));
                                        }
                                    }
                                    Err(e) => {
                                        toast.set(Some(format!("Couldn't build share link: {e}")))
                                    }
                                }
                            }
                        }
                    },
                    Err(e) => toast.set(Some(format!("Sharing unavailable: {e}"))),
                }
            });
        }
    };

    rsx! {
        div { class: "easy-doc-viewer",
            div { class: "easy-doc-viewer-bar",
                button {
                    class: "easy-doc-back",
                    "aria-label": "Back",
                    onclick: move |_| props.on_back.call(()),
                    "‹"
                }
                span { class: "easy-doc-viewer-title", "{title}" }
                // Top-right share icon → opens our share menu, anchored to the
                // bar's bottom edge (top:100%) so it never overlaps the bar and
                // needs no guessed pixel offset.
                button {
                    class: "easy-doc-share-btn",
                    "aria-label": "Share report",
                    onclick: move |_| { let v = share_open(); share_open.set(!v); },
                    dangerous_inner_html: SHARE_ICON_SVG,
                }
                // Share menu nested in the bar so it anchors to the bar's bottom
                // edge (CSS top:100%) — no guessed pixel offset.
                if share_open() {
                    div { class: "easy-doc-share-menu",
                        {
                            let (r, ttl) = (run_with_link.clone(), title.clone());
                            rsx! {
                                button {
                                    class: "easy-doc-menu-item",
                                    onclick: move |_| r.clone()(ShareAction::NativeSheet, None, ttl.clone()),
                                    span { class: "easy-doc-menu-icon", dangerous_inner_html: SHARE_ICON_SVG }
                                    "Share…"
                                }
                            }
                        }
                        {
                            let (r, ttl) = (run_with_link.clone(), title.clone());
                            rsx! {
                                button {
                                    class: "easy-doc-menu-item",
                                    onclick: move |_| r.clone()(ShareAction::Copy, None, ttl.clone()),
                                    "Copy link"
                                }
                            }
                        }
                        {
                            let (r, ttl) = (run_with_link.clone(), title.clone());
                            rsx! {
                                button {
                                    class: "easy-doc-menu-item",
                                    onclick: move |_| r.clone()(ShareAction::OpenBrowser, None, ttl.clone()),
                                    "Open in browser"
                                }
                            }
                        }
                        div { class: "easy-doc-menu-sep" }
                        for network in SocialNetwork::all() {
                            {
                                let (r, ttl) = (run_with_link.clone(), title.clone());
                                rsx! {
                                    button {
                                        class: "easy-doc-menu-item",
                                        onclick: move |_| r.clone()(ShareAction::Social, Some(network), ttl.clone()),
                                        "{network.label()}"
                                    }
                                }
                            }
                        }
                    }
                }
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
            if let Some(msg) = toast() {
                div { class: "easy-doc-toast-float", "{msg}" }
            }
            // Full-screen scrim to catch taps outside the menu (closes it).
            if share_open() {
                div {
                    class: "easy-doc-share-scrim",
                    onclick: move |_| share_open.set(false),
                }
            }
        }
    }
}

/// What a share-menu item does once the public link exists.
#[derive(Clone, Copy)]
enum ShareAction {
    Copy,
    NativeSheet,
    OpenBrowser,
    Social,
}

/// Share glyph (lucide "share-2") for the viewer titlebar + native-share item.
const SHARE_ICON_SVG: &str = r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>"#;

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
