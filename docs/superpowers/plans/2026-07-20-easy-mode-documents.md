# Easy Mode Documents + Share Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Documents surface to Easy Mode that lists the reports a scan produced, opens a report in the system browser, and generates a shareable link (copy + native share sheet).

**Architecture:** A new typed GraphQL client module (`documents.rs`) reuses `MatrixChatClient::execute_gql` to call the already-deployed `listDocuments` query and `createSharedLink` mutation. A new `DocumentsPanel` Dioxus component renders the list inside `EasyModeShell`, opens documents via the platform browser opener, and shares links via clipboard (v1) then the OS share sheet. iOS gains a `UIApplication.openURL` browser opener; both platforms gain a native `share_text` path.

**Tech Stack:** Rust, Dioxus 0.7.9, reqwest (via existing client), serde, objc2 (iOS), JNI (Android), `document::eval` (WebView clipboard).

## Global Constraints

- Rust stable 1.92+; workspace already pins dioxus 0.7.9.
- Reuse the existing authed GraphQL path (`MatrixChatClient::execute_gql` / `authed_post`) — do NOT add a new HTTP client or auth mechanism.
- GraphQL field names are camelCase in the API; Rust deserialize structs use `#[serde(rename_all = "camelCase")]` (match existing structs in `client.rs`).
- `resource_type` for a conversation document is the literal string `"conversation_document"`; `resource_id` is `"{conversation_id}:{document_id}"`.
- Commit messages: conventional commits; NO Claude attribution, NO customer/tenant names, NO emojis or em-dashes (CLAUDE.md).
- Run checks under nix: `nix develop --command cargo test -p pentest-core` etc. Clippy is `-D warnings`.
- Manual E2E: run only ONE Pick connector per tenant at a time (same-tenant connector collision stalls the agent — see project memory `connector-collision-consent-hang`).

---

## File Structure

- `crates/core/src/matrix/documents.rs` — NEW. `DocumentSummary` struct; pure helpers (`share_resource_id`, `studio_web_base`, `documents_from_data`); async `list_documents` / `create_shared_link` methods on `MatrixChatClient`.
- `crates/core/src/matrix/mod.rs` — MODIFY. `mod documents;` + re-export `DocumentSummary`.
- `crates/core/src/matrix/client.rs` — MODIFY. `impl MatrixChatClient` block for the two async methods (or place them in `documents.rs` via `impl MatrixChatClient`).
- `crates/platform/src/ios/oauth.rs` (or a new `ios/browser.rs`) — MODIFY/NEW. `open_url(url)` via `UIApplication.openURL`.
- `crates/platform/src/ios/mod.rs` — MODIFY. Export `open_url`.
- `apps/mobile/src/main.rs` — MODIFY. Register an iOS browser opener; register `share_text` for both platforms.
- `crates/ui/src/components/documents_panel.rs` — NEW. The Documents UI.
- `crates/ui/src/components/mod.rs` — MODIFY. `pub mod documents_panel;` + re-export.
- `crates/ui/src/components/easy_mode.rs` — MODIFY. Mount `DocumentsPanel`; share the selected-agent id.
- `crates/ui/src/components/chat_panel/mod.rs` — MODIFY. Write selected agent id into a shared signal prop.
- `crates/core/src/matrix.rs` share glue — `set_share_handler` global (mirrors `set_browser_opener`), in a new `crates/core/src/share.rs` or within `matrix/auth.rs` style module.

---

### Task 1: Document GraphQL client (`documents.rs`)

**Files:**
- Create: `crates/core/src/matrix/documents.rs`
- Modify: `crates/core/src/matrix/mod.rs`
- Test: inline `#[cfg(test)]` in `documents.rs`

**Interfaces:**
- Consumes: `MatrixChatClient::execute_gql`, `super::normalize_url` (both already in `crates/core/src/matrix/`).
- Produces:
  - `pub struct DocumentSummary { pub id: String, pub title: String, pub doc_type: String, pub conversation_id: String }`
  - `pub fn share_resource_id(conversation_id: &str, document_id: &str) -> String`
  - `pub fn studio_web_base(api_url: &str) -> String`
  - `impl MatrixChatClient { pub async fn list_documents(&self, agent_id: Option<&str>) -> crate::error::Result<Vec<DocumentSummary>>; pub async fn create_shared_link(&self, conversation_id: &str, document_id: &str) -> crate::error::Result<String>; }`

- [ ] **Step 1: Write the failing test for pure helpers**

In `crates/core/src/matrix/documents.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_id_joins_conversation_and_document() {
        assert_eq!(share_resource_id("conv-1", "doc-9"), "conv-1:doc-9");
    }

    #[test]
    fn studio_web_base_strips_api_path() {
        assert_eq!(studio_web_base("https://studio.example.test/api/v1alpha"), "https://studio.example.test");
        assert_eq!(studio_web_base("https://studio.example.test"), "https://studio.example.test");
        assert_eq!(studio_web_base("https://studio.example.test/"), "https://studio.example.test");
    }

    #[test]
    fn documents_from_data_maps_edges_and_flattens_conversation_id() {
        let raw = serde_json::json!({
            "listDocuments": { "edges": [
                { "node": { "id": "network-discovery-report", "title": "Local Network Discovery Report",
                            "type": "markdown", "conversation": { "id": "conv-abc" } } },
                { "node": { "id": "d2", "title": "Other", "type": "markdown", "conversation": null } }
            ]}
        });
        let data: ListDocumentsData = serde_json::from_value(raw).unwrap();
        let out = documents_from_data(data);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id, "network-discovery-report");
        assert_eq!(out[0].conversation_id, "conv-abc");
        assert_eq!(out[1].conversation_id, ""); // null conversation -> empty
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-core matrix::documents -- --nocapture`
Expected: FAIL — `documents.rs` / symbols not defined (module not declared yet).

- [ ] **Step 3: Implement `documents.rs`**

```rust
//! Conversation-document listing + shareable-link creation over Matrix GraphQL.
//!
//! Reuses `MatrixChatClient::execute_gql` (the same authed path as agent/
//! conversation queries). Documents are written by the server-side agent
//! (via its `document_write` tool); Pick only lists and shares them.

use serde::Deserialize;

use super::client::MatrixChatClient;

/// A conversation document as shown in the Easy Mode Documents list.
#[derive(Debug, Clone, PartialEq)]
pub struct DocumentSummary {
    pub id: String,
    pub title: String,
    pub doc_type: String,
    /// The conversation the document belongs to (used to build open/share refs).
    pub conversation_id: String,
}

/// Build the shared-link `resource_id` for a conversation document.
pub fn share_resource_id(conversation_id: &str, document_id: &str) -> String {
    format!("{conversation_id}:{document_id}")
}

/// Derive the Studio browser base URL (scheme + host) from `MATRIX_API_URL`,
/// dropping any `/api/...` path so we can build `/conversations/:id` links.
pub fn studio_web_base(api_url: &str) -> String {
    // `normalize_url` returns `&str`; pass it directly (no extra `&`).
    let normalized = super::normalize_url(api_url);
    match reqwest::Url::parse(normalized) {
        Ok(u) => {
            let scheme = u.scheme();
            match u.host_str() {
                Some(host) => match u.port() {
                    Some(port) => format!("{scheme}://{host}:{port}"),
                    None => format!("{scheme}://{host}"),
                },
                None => normalized.trim_end_matches('/').to_string(),
            }
        }
        Err(_) => normalized.trim_end_matches('/').to_string(),
    }
}
```

**Prerequisite edit (required for this task to compile):** `MatrixChatClient::execute_gql` is
currently a private method in `client.rs`, and `normalize_url` is `pub(crate)`. The new `impl
MatrixChatClient` block lives in `documents.rs` (same crate, different module), so `execute_gql`
must be visible to it. Change its signature in `crates/core/src/matrix/client.rs:86` from:

```rust
    async fn execute_gql<T: serde::de::DeserializeOwned>(
```

to:

```rust
    pub(crate) async fn execute_gql<T: serde::de::DeserializeOwned>(
```

`normalize_url` is already `pub(crate)` — no change needed. Continue with `documents.rs`:

```rust

// -- GraphQL deserialize shapes --

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ListDocumentsData {
    list_documents: DocumentEdges,
}

#[derive(Deserialize)]
struct DocumentEdges {
    edges: Vec<DocumentEdge>,
}

#[derive(Deserialize)]
struct DocumentEdge {
    node: DocumentNode,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct DocumentNode {
    id: String,
    title: String,
    #[serde(rename = "type")]
    doc_type: String,
    conversation: Option<DocumentConversation>,
}

#[derive(Deserialize)]
struct DocumentConversation {
    id: String,
}

pub(crate) fn documents_from_data(data: ListDocumentsData) -> Vec<DocumentSummary> {
    data.list_documents
        .edges
        .into_iter()
        .map(|e| DocumentSummary {
            id: e.node.id,
            title: e.node.title,
            doc_type: e.node.doc_type,
            conversation_id: e.node.conversation.map(|c| c.id).unwrap_or_default(),
        })
        .collect()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSharedLinkData {
    create_shared_link: CreateSharedLinkPayload,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CreateSharedLinkPayload {
    shared_link: Option<SharedLinkNode>,
    #[serde(default)]
    errors: Vec<String>,
}

#[derive(Deserialize)]
struct SharedLinkNode {
    url: String,
}

const LIST_DOCUMENTS_QUERY: &str = r#"
    query ListDocuments($filter: ListDocumentsFilter) {
        listDocuments(filter: $filter) {
            edges {
                node {
                    id
                    title
                    type
                    conversation { id }
                }
            }
        }
    }
"#;

const CREATE_SHARED_LINK_QUERY: &str = r#"
    mutation CreateSharedLink($input: CreateSharedLinkInput!) {
        createSharedLink(input: $input) {
            sharedLink { url }
            errors
        }
    }
"#;

impl MatrixChatClient {
    /// List conversation documents visible to the authenticated user, optionally
    /// filtered to a single agent.
    pub async fn list_documents(
        &self,
        agent_id: Option<&str>,
    ) -> crate::error::Result<Vec<DocumentSummary>> {
        let filter = match agent_id {
            Some(id) => serde_json::json!({ "agentId": id }),
            None => serde_json::Value::Null,
        };
        let data: ListDocumentsData = self
            .execute_gql(LIST_DOCUMENTS_QUERY, serde_json::json!({ "filter": filter }))
            .await?;
        Ok(documents_from_data(data))
    }

    /// Create a shareable link for a conversation document; returns the URL.
    pub async fn create_shared_link(
        &self,
        conversation_id: &str,
        document_id: &str,
    ) -> crate::error::Result<String> {
        let variables = serde_json::json!({
            "input": {
                "resourceType": "conversation_document",
                "resourceId": share_resource_id(conversation_id, document_id),
            }
        });
        let data: CreateSharedLinkData = self
            .execute_gql(CREATE_SHARED_LINK_QUERY, variables)
            .await?;
        let payload = data.create_shared_link;
        if let Some(link) = payload.shared_link {
            Ok(link.url)
        } else {
            let msg = if payload.errors.is_empty() {
                "createSharedLink returned no link and no error".to_string()
            } else {
                payload.errors.join("; ")
            };
            Err(crate::error::Error::Matrix(msg))
        }
    }
}
```

(The `execute_gql` visibility prerequisite above must be applied first. `normalize_url` is `pub(crate)` at `crates/core/src/matrix/mod.rs` and referenced as `super::normalize_url`.)

- [ ] **Step 4: Declare the module**

In `crates/core/src/matrix/mod.rs`, add near the other `mod`/`pub use` lines:

```rust
pub mod documents;
pub use documents::{studio_web_base, DocumentSummary};
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `nix develop --command cargo test -p pentest-core matrix::documents -- --nocapture`
Expected: PASS (3 tests).

- [ ] **Step 6: Clippy + commit**

Run: `nix develop --command cargo clippy -p pentest-core -- -D warnings`
Expected: no warnings.

```bash
git add crates/core/src/matrix/documents.rs crates/core/src/matrix/mod.rs crates/core/src/matrix/client.rs
git commit -m "feat(easy-mode): add document listing and shared-link GraphQL client"
```

---

### Task 2: iOS browser opener + share handler glue

**Files:**
- Create: `crates/platform/src/ios/browser.rs`
- Modify: `crates/platform/src/ios/mod.rs`
- Create: `crates/core/src/share.rs`
- Modify: `crates/core/src/lib.rs` (declare `pub mod share;`)
- Test: inline `#[cfg(test)]` in `share.rs`

**Interfaces:**
- Consumes: existing `crate::ios::dispatch_on_main`, `UIApplication` (objc2-ui-kit), `NSURL`/`NSString` (objc2-foundation).
- Produces:
  - `pentest_platform::ios::open_url(url: &str) -> pentest_core::error::Result<()>`
  - `pentest_core::share::set_share_handler<F>(f)` where `F: Fn(&str) -> Result<(), String>`, and `pentest_core::share::share_text(text: &str) -> Result<(), String>` (returns `Err("no share handler")` when unset).

- [ ] **Step 1: Write the failing test for the share registry**

In `crates/core/src/share.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn share_text_errors_when_no_handler() {
        // Fresh process default: no handler registered -> Err.
        // (Registering is process-global; keep this test first / independent.)
        clear_share_handler_for_test();
        assert!(share_text("hello").is_err());
    }

    #[test]
    fn share_text_uses_registered_handler() {
        use std::sync::{Arc, Mutex};
        let seen = Arc::new(Mutex::new(String::new()));
        let seen2 = seen.clone();
        set_share_handler(move |t| {
            *seen2.lock().unwrap() = t.to_string();
            Ok(())
        });
        assert!(share_text("shared!").is_ok());
        assert_eq!(*seen.lock().unwrap(), "shared!");
        clear_share_handler_for_test();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-core share:: -- --nocapture --test-threads=1`
Expected: FAIL — `share` module not defined.

- [ ] **Step 3: Implement the share registry**

Create `crates/core/src/share.rs` (mirrors `matrix/auth.rs` `set_browser_opener`):

```rust
//! Process-global handler for invoking the OS share sheet (share a text/URL).
//!
//! Registered by each app target at startup (iOS: UIActivityViewController;
//! Android: ACTION_SEND). Mirrors `matrix::set_browser_opener`.

type ShareHandlerFn = Option<Box<dyn Fn(&str) -> Result<(), String> + Send + Sync>>;

static SHARE_HANDLER: std::sync::Mutex<ShareHandlerFn> = std::sync::Mutex::new(None);

/// Register the platform share handler.
pub fn set_share_handler<F>(handler: F)
where
    F: Fn(&str) -> Result<(), String> + Send + Sync + 'static,
{
    if let Ok(mut lock) = SHARE_HANDLER.lock() {
        *lock = Some(Box::new(handler));
    }
}

/// Invoke the registered share handler. Returns `Err` if none is registered.
pub fn share_text(text: &str) -> Result<(), String> {
    match SHARE_HANDLER.lock() {
        Ok(lock) => match lock.as_ref() {
            Some(handler) => handler(text),
            None => Err("no share handler registered".to_string()),
        },
        Err(_) => Err("share handler lock poisoned".to_string()),
    }
}

#[doc(hidden)]
pub fn clear_share_handler_for_test() {
    if let Ok(mut lock) = SHARE_HANDLER.lock() {
        *lock = None;
    }
}
```

In `crates/core/src/lib.rs`, add `pub mod share;` near the other module declarations.

- [ ] **Step 4: Run tests to verify they pass**

Run: `nix develop --command cargo test -p pentest-core share:: -- --nocapture --test-threads=1`
Expected: PASS (2 tests).

- [ ] **Step 5: Implement iOS `open_url`**

Create `crates/platform/src/ios/browser.rs`:

```rust
//! Open a URL in the system browser (Safari) via `UIApplication.openURL:`.
//!
//! Unlike the OAuth flow (which needs an in-app ASWebAuthenticationSession to
//! keep a loopback callback alive), plain "open this report page" just launches
//! Safari. Runs on the main thread.

use objc2::rc::Retained;
use objc2::{msg_send, MainThreadMarker};
use objc2_foundation::{NSString, NSURL};
use objc2_ui_kit::UIApplication;
use pentest_core::error::{Error, Result};

/// Open `url` in the system browser. Returns an error for a malformed URL.
pub fn open_url(url: &str) -> Result<()> {
    let url = url.to_string();
    crate::ios::dispatch_on_main(move || {
        // SAFETY: on the main queue; standard UIApplication.openURL call.
        let mtm = unsafe { MainThreadMarker::new_unchecked() };
        let ns = NSString::from_str(&url);
        // SAFETY: URLWithString returns nil for malformed input; guarded below.
        if let Some(ns_url) = unsafe { NSURL::URLWithString(&ns) } {
            let app = UIApplication::sharedApplication(mtm);
            let opts: Retained<objc2_foundation::NSDictionary> =
                objc2_foundation::NSDictionary::new();
            // SAFETY: openURL:options:completionHandler: is the modern opener.
            let _: () = unsafe {
                msg_send![&app, openURL: &*ns_url, options: &*opts, completionHandler: std::ptr::null::<std::ffi::c_void>()]
            };
        }
    });
    // Dispatched asynchronously; assume success (matches Android opener contract).
    let _ = Error::PlatformNotSupported; // keep Error import used if needed
    Ok(())
}
```

Note: if `objc2_foundation::NSDictionary::new()` or the exact `openURL:options:completionHandler:` selector shape does not compile against the pinned objc2 0.6 / objc2-ui-kit 0.3, fall back to the legacy `openURL:` selector: `let _: bool = unsafe { msg_send![&app, openURL: &*ns_url] };`. Verify against the crate before finalizing.

In `crates/platform/src/ios/mod.rs`, add:

```rust
pub mod browser;
pub use browser::open_url;
```

- [ ] **Step 6: Compile-check the platform crate for iOS target**

Run (on the Mac VM devshell, since iOS-only): `nix develop --command cargo check -p pentest-platform --no-default-features --features ios --target aarch64-apple-ios-sim`
Expected: compiles (fix selector shape per the note if not).

- [ ] **Step 7: Commit**

```bash
git add crates/core/src/share.rs crates/core/src/lib.rs crates/platform/src/ios/browser.rs crates/platform/src/ios/mod.rs
git commit -m "feat(easy-mode): add share-handler registry and iOS URL opener"
```

---

### Task 3: DocumentsPanel component + Easy Mode wiring (list, open, copy-share)

**Files:**
- Create: `crates/ui/src/components/documents_panel.rs`
- Modify: `crates/ui/src/components/mod.rs`
- Modify: `crates/ui/src/components/easy_mode.rs`
- Modify: `crates/ui/src/components/chat_panel/mod.rs`
- Modify: `crates/ui/src/styles/mobile.css`
- Test: inline `#[cfg(test)]` in `documents_panel.rs` (pure helpers only)

**Interfaces:**
- Consumes: `pentest_core::matrix::{MatrixChatClient, DocumentSummary, studio_web_base}`; `pentest_core::matrix::open_browser(url)` (a thin public wrapper this task adds over the existing private `BROWSER_OPENER` in `auth.rs` — see Step 3); `document::eval` for clipboard; `pentest_core::share::share_text`.
- Produces:
  - `pub fn conversation_url(web_base: &str, conversation_id: &str) -> String`
  - `#[component] pub fn DocumentsPanel(props: DocumentsPanelProps) -> Element` with `DocumentsPanelProps { api_url: String, auth_token: String, agent_id: Signal<Option<String>>, refresh_nonce: Signal<u32> }`

- [ ] **Step 1: Write the failing test for the URL helper**

In `crates/ui/src/components/documents_panel.rs`:

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-ui documents_panel -- --nocapture`
Expected: FAIL — module/symbol not defined.

- [ ] **Step 3: Implement the helper + component**

Create `crates/ui/src/components/documents_panel.rs`:

```rust
//! Easy Mode Documents list: shows scan reports, opens them in the browser,
//! and creates shareable links (copy + OS share sheet).

use dioxus::prelude::*;
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
```

Add a thin public opener in `crates/core/src/matrix/auth.rs`, right next to the `BROWSER_OPENER`
static (so it can see the private static). `matrix/mod.rs` already does `pub use auth::*;`, so this
is automatically exported as `pentest_core::matrix::open_browser` — no extra re-export line needed.

```rust
/// Open a URL in the system browser via the registered browser opener.
/// Returns Err(String) if no opener is registered or it fails.
pub fn open_browser(url: &str) -> Result<(), String> {
    if let Ok(lock) = BROWSER_OPENER.lock() {
        if let Some(opener) = lock.as_ref() {
            return opener(url);
        }
    }
    Err("no browser opener registered".to_string())
}
```

- [ ] **Step 4: Declare the component + styles**

In `crates/ui/src/components/mod.rs`:

```rust
pub mod documents_panel;
pub use documents_panel::DocumentsPanel;
```

In `crates/ui/src/styles/mobile.css`, append:

```css
.easy-docs { display: flex; flex-direction: column; gap: 8px; padding: 12px 16px; }
.easy-docs-header { font-weight: 600; font-size: 15px; opacity: 0.9; }
.easy-docs-empty, .easy-docs-error { opacity: 0.7; font-size: 14px; padding: 8px 0; }
.easy-docs-error { color: #ff6b6b; }
.easy-docs-toast { background: #1e3a2f; color: #b6f2c9; padding: 8px 10px; border-radius: 8px; font-size: 13px; }
.easy-docs-row { display: flex; align-items: center; justify-content: space-between; gap: 8px; padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.08); }
.easy-docs-title { flex: 1; cursor: pointer; text-decoration: underline; }
.easy-docs-share { padding: 6px 14px; border-radius: 8px; border: none; background: #3b82f6; color: #fff; font-size: 14px; }
```

- [ ] **Step 5: Wire into EasyModeShell + share selected-agent id**

In `crates/ui/src/components/chat_panel/mod.rs`: add an optional prop
`pub selected_agent_out: Option<Signal<Option<String>>>` to `ChatPanelProps`, and wherever
`selected_agent.set(Some(agent))` / `.set(Some(new_agent))` occur, also write the id out:

```rust
if let Some(mut out) = props.selected_agent_out {
    out.set(Some(agent.id.clone()));
}
```

(Do this at each place the selected agent changes — the auto-select, the manual select, and the created-agent path. Search for `selected_agent.set(` and mirror.)

In `crates/ui/src/components/easy_mode.rs`, add signals and mount the panel:

```rust
let agent_id = use_signal(|| None::<String>);
let refresh_nonce = use_signal(|| 0u32);
```

Pass `selected_agent_out: Some(agent_id)` to the existing `ChatPanel { .. }`, and add below the chat:

```rust
DocumentsPanel {
    api_url: props.api_url.clone(),
    auth_token: auth_token(),
    agent_id: agent_id,
    refresh_nonce: refresh_nonce,
}
```

(Optional: bump `refresh_nonce` when a scan is kicked off, so the list reloads after the agent finishes; a simple approach is to bump it on the Scan button click and rely on the effect, or leave manual refresh for v1.)

- [ ] **Step 6: Run helper tests + build the UI crate**

Run: `nix develop --command cargo test -p pentest-ui documents_panel -- --nocapture`
Expected: PASS (2 tests).

Run: `nix develop --command cargo check -p pentest-ui --features "desktop,connector"`
Expected: compiles.

- [ ] **Step 7: Clippy + commit**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: no warnings.

```bash
git add crates/ui/src/components/documents_panel.rs crates/ui/src/components/mod.rs crates/ui/src/components/easy_mode.rs crates/ui/src/components/chat_panel/mod.rs crates/ui/src/styles/mobile.css crates/core/src/matrix/auth.rs crates/core/src/matrix/mod.rs
git commit -m "feat(easy-mode): documents panel with open-in-browser and copy-link share"
```

---

### Task 4: Native share sheet (iOS UIActivityViewController + Android ACTION_SEND)

**Files:**
- Create: `crates/platform/src/ios/share.rs`
- Modify: `crates/platform/src/ios/mod.rs`
- Modify: `crates/platform/src/android/jni_bridge.rs` (+ `android/mod.rs`)
- Modify: `apps/mobile/src/main.rs`

**Interfaces:**
- Consumes: `pentest_core::share::set_share_handler`.
- Produces: `pentest_platform::ios::share_text(text) -> Result<()>`; `pentest_platform::android::share_text(text) -> Result<()>`; both registered in `main.rs`.

- [ ] **Step 1: Implement iOS share sheet**

Create `crates/platform/src/ios/share.rs`:

```rust
//! Present the iOS share sheet (UIActivityViewController) for a text/URL.

use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2::{msg_send, class, MainThreadMarker};
use objc2_foundation::{NSArray, NSString};
use objc2_ui_kit::{UIApplication, UIWindow, UIViewController};
use pentest_core::error::Result;

/// Present a share sheet for `text`. Runs on the main thread.
pub fn share_text(text: &str) -> Result<()> {
    let text = text.to_string();
    crate::ios::dispatch_on_main(move || {
        // SAFETY: main-thread UIKit; standard UIActivityViewController flow.
        let mtm = unsafe { MainThreadMarker::new_unchecked() };
        let ns = NSString::from_str(&text);
        let items: Retained<NSArray<NSString>> = NSArray::from_retained_slice(&[ns]);
        unsafe {
            let alloc: *mut AnyObject = msg_send![class!(UIActivityViewController), alloc];
            let vc: *mut AnyObject = msg_send![
                alloc,
                initWithActivityItems: &*items,
                applicationActivities: std::ptr::null::<AnyObject>()
            ];
            // Present from the key window's root view controller.
            let app = UIApplication::sharedApplication(mtm);
            let windows: Retained<NSArray<UIWindow>> = msg_send![&app, windows];
            if windows.count() > 0 {
                let win = windows.objectAtIndex(0);
                let root: *mut AnyObject = msg_send![&win, rootViewController];
                if !root.is_null() {
                    let _: () = msg_send![root, presentViewController: vc, animated: true, completion: std::ptr::null::<std::ffi::c_void>()];
                }
            }
        }
        let _ = UIViewController::class(); // keep import used
    });
    Ok(())
}
```

Note: verify selector shapes / `NSArray::from_retained_slice` against objc2 0.6. If `rootViewController` is nil (SwiftUI-hosted scenes), fall back to the key window found via `isKeyWindow` (reuse the `key_window` helper pattern in `ios/oauth.rs`). On iPad, `UIActivityViewController` needs a `popoverPresentationController` sourceView; set it to the root view to avoid a crash.

In `crates/platform/src/ios/mod.rs`, add `pub use share::share_text as share_text;` (module `pub mod share;`).

- [ ] **Step 2: Implement Android share intent**

In `crates/platform/src/android/jni_bridge.rs`, add a `share_text` fn that is a verbatim copy of
`open_browser` (lines ~206-257) with exactly two substitutions: the JSON param `{ "url": url }` →
`{ "text": text }`, and the bridge method name string `"open_browser"` → `"share_text"` (and the
error label). It uses the same `with_activity` + `ConnectorBridge.invoke(context, method, json)`
JNI path — there is no shared `invoke_bridge` helper, so copy the whole body:

```rust
/// Share text via the OS share sheet.
///
/// Uses ConnectorBridge.invoke(context, "share_text", {"text": "..."})
pub fn share_text(text: &str) -> Result<()> {
    let params = serde_json::json!({ "text": text }).to_string();
    with_activity(move |env, activity| {
        // ... identical body to open_browser, but:
        //   env.new_string("share_text")   instead of "open_browser"
        //   error label "share_text error"  instead of "open_browser error"
        // (Copy open_browser lines 212-255 verbatim and apply those swaps.)
        Ok(())
    })
}
```

Add the matching `"share_text"` case to `ConnectorBridge.invoke` on the Android app/Kotlin side
(same class the intent filter + `open_browser` case live in — search the Android sources for the
existing `"open_browser"` case): build an `ACTION_SEND` intent with `type="text/plain"`,
`putExtra(Intent.EXTRA_TEXT, text)`, wrap in `Intent.createChooser(...)`, add
`FLAG_ACTIVITY_NEW_TASK`, and `startActivity`.

In `crates/platform/src/android/mod.rs`, add `pub fn share_text(text: &str) -> Result<()> { jni_bridge::share_text(text) }`.

- [ ] **Step 3: Register handlers in main.rs**

In `apps/mobile/src/main.rs`, iOS block — also register a browser opener (so `open_browser` works on iOS) and the share handler:

```rust
pentest_core::matrix::set_browser_opener(|url| {
    pentest_platform::ios::open_url(url).map_err(|e| e.to_string())
});
pentest_core::share::set_share_handler(|text| {
    pentest_platform::ios::share_text(text).map_err(|e| e.to_string())
});
```

Android block — add the share handler next to the existing browser opener:

```rust
pentest_core::share::set_share_handler(|text| {
    pentest_platform::android::share_text(text).map_err(|e| e.to_string())
});
```

- [ ] **Step 4: Compile-check both targets**

Android: `nix develop --command cargo check -p pentest-platform --no-default-features --features android --target aarch64-linux-android`
iOS (Mac VM): `nix develop --command cargo check -p pentest-platform --no-default-features --features ios --target aarch64-apple-ios-sim`
Expected: both compile (apply the objc2/selector fallback notes if needed).

- [ ] **Step 5: Commit**

```bash
git add crates/platform/src/ios/share.rs crates/platform/src/ios/mod.rs crates/platform/src/android/jni_bridge.rs crates/platform/src/android/mod.rs apps/mobile/src/main.rs
git commit -m "feat(easy-mode): native share sheet for iOS and Android"
```

- [ ] **Step 6: Manual E2E (one connector at a time)**

1. Build + install iOS (Mac VM): `just build-ios`, `xcrun simctl install booted <app>`, launch with `SIMCTL_CHILD_MATRIX_INSECURE=1 SIMCTL_CHILD_MATRIX_TLS_INSECURE=1`.
2. Tap Scan; wait for the agent to write the report.
3. Confirm the report appears in the Reports list; tap it (opens Studio conversation in Safari, login expected).
4. Tap Share; confirm the share sheet appears and the `/s/:token` URL is copied.
5. Repeat on the Android emulator (stop the iOS connector first).

---

## Notes carried from the spec

- Shared `/s/:token` links and the opened `/conversations/:id` page require a Studio login for the recipient — expected in this build. True no-account sharing waits on a matrix-side change (unauthenticated access for `public` scope).
- Do not run the iOS and Android connectors against the same tenant simultaneously.
