# Easy Mode Phase 2 — Documents + Share — Design Spec

- **Date:** 2026-07-20
- **Status:** Design approved (brainstorm); pending spec review → implementation plan
- **Repo:** Strike48-public/pick
- **Builds on:** `docs/superpowers/specs/2026-07-18-easy-mode-design.md` (Phase 1 shell + scan + chat, shipped)
- **Backend dependency:** Strike48/matrix `feat/matrix/doc-share-link-rebased` (PR #1390),
  deployed in the operator's cluster with `document_sharing_enabled` ON.

## 1. Overview & purpose

Phase 1 of Easy Mode shipped: a one-tap **Scan** card and a full-page **Chat**. The scan already
instructs the agent to write a report document, and that works — verified live, the agent
persisted a `"Local Network Discovery Report"` (markdown) via the platform's `document_write`
tool. What's missing is the **Documents** half of the original Easy Mode vision: a place to
**list** the reports a scan produced, **open** them, and **share** them.

This spec adds that Documents surface to `EasyModeShell`. It is composed entirely from existing
Pick rails (user-scoped auth token from the OIDC flow, the authed GraphQL client) plus the
document/share GraphQL API already deployed on the matrix branch. No new connector→document API
and no new matrix code are required for the Phase 2 core.

## 2. Goals / non-goals

**Goals**
- List the documents this Easy Mode connector's agent produced (title, type, created time).
- Open a document by launching its Studio conversation page in the system browser.
- Share a document: create a shareable link, copy it to the clipboard, and offer the OS share
  sheet.
- Degrade gracefully: document listing and chat/scan never break each other; sharing failures
  are surfaced inline without taking down the list.

**Non-goals (YAGNI)**
- No in-app markdown preview/viewer (open-in-browser is the chosen path).
- No link management/revocation UI (`shared_links` / `revoke_shared_link` exist but are out of
  scope for this build).
- No matrix-side change. In particular we do NOT fix the "public link still requires login"
  behavior here — that is a separate matrix-side effort (see §7 R2). We ship the client
  plumbing now; it upgrades for free once that lands.
- No new scanner code, no auto-update, no signing.

## 3. Verified backend facts (live cluster, `feat/matrix/doc-share-link-rebased`)

- **Documents persist and are listable.** The Phase 1 scan wrote a real document:
  `{ id: "network-discovery-report", title: "Local Network Discovery Report", type: "markdown",
  conversation_id, created_at, updated_at, content }`.
- **GraphQL surface exists and is authenticated** (`AuthHelpers.authenticate` middleware — Pick's
  OIDC user token satisfies it):
  - Query `list_documents(filter: {agent_id})` — Relay connection over `:document` nodes.
  - Query `document(conversation_id, document_id)` — a single document (not used in this build;
    open-in-browser is used instead).
  - Mutation `create_shared_link(input: create_shared_link_input) -> create_shared_link_payload`
    where the payload is `{ shared_link { id, url, ... }, errors }`.
  - Mutation `revoke_shared_link`, query `shared_links` — exist, out of scope.
- **`create_shared_link_input`** fields: `resource_type` (non-null string), `resource_id`
  (non-null string), `expires_in_seconds?`, `max_accesses?`, `access_scope?`,
  `recipient_emails?`.
- **`resource_id` format** for a conversation document is `"{conversation_id}:{document_id}"`
  (resolved via `MatrixData.Conversations.find_document`).
- **The share `url` is returned directly** on the mutation payload (`shared_link.url`).
- **No hosted per-document viewer route exists.** A single document can only be rendered over the
  web via `/s/:token` (share link) or the Studio SPA conversation view
  (`/conversations/:id`). Both require a Studio login session.

## 4. Integration spine

```
EasyModeShell (crates/ui/src/components/easy_mode.rs)
 ├─ [Scan] card            (Phase 1, unchanged)
 ├─ [Chat] full-page       (Phase 1, unchanged)
 └─ DocumentsPanel         (NEW)
      │
      │ list:   query list_documents(filter:{agent_id: <easy-mode agent>})
      │            -> [{ id, title, doc_type, conversation_id, created_at }]
      │ open:   browser-open  {studio_web_base}/conversations/{conversation_id}
      │            (accepts Studio login; see §7 R2)
      │ share:  mutation create_shared_link(input:{
      │            resource_type: "conversation_document",
      │            resource_id:   "{conversation_id}:{document_id}" })
      │            -> shared_link.url
      │          then: copy to clipboard + OS share sheet
      ▼
   crates/core/src/matrix/documents.rs  (NEW typed GraphQL client)
      reuses the existing authed GraphQL POST helper (same client path as
      createAgent / getConversation over MATRIX_API_URL)
```

## 5. Components

### 5.1 `crates/core/src/matrix/documents.rs` (new, ~150 lines)
- `DocumentSummary { id: String, title: String, doc_type: String, conversation_id: String,
  created_at: String }` — serde struct matching the GraphQL `document` node fields we render.
- `async fn list_documents(client: &MatrixChatClient, agent_id: Option<&str>)
  -> Result<Vec<DocumentSummary>>` — issues the `list_documents` connection query, maps
  `edges[].node` → `DocumentSummary`. When `agent_id` is `Some`, passes
  `filter: { agent_id }` so only this connector's reports show (not every tenant document).
- `async fn create_shared_link(client: &MatrixChatClient, conversation_id: &str,
  document_id: &str) -> Result<String>` — issues the mutation with
  `resource_type: "conversation_document"`, `resource_id: "{conversation_id}:{document_id}"`;
  returns `payload.shared_link.url`; if `payload.errors` is non-empty, returns an `Err`
  carrying the joined messages.
- Reuses the existing authed GraphQL request plumbing used by `MatrixChatClient`
  (`crates/core/src/matrix/`). No new HTTP client, no new auth path.
- `fn studio_web_base(api_url: &str) -> String` — derive the Studio browser base from
  `MATRIX_API_URL` (scheme + host, drop `/api/...`). Used to build the open-in-browser URL.

### 5.2 `crates/ui/src/components/documents_panel.rs` (new)
- Fetches document list on mount; refreshes on demand and after a scan run completes.
- Renders a list row per document: title, relative created time, a small type icon.
- **Tap row →** browser-open `{studio_web_base}/conversations/{conversation_id}` via the
  platform browser opener (Android `set_browser_opener`; iOS `UIApplication.openURL`, already
  wired from the OAuth work).
- **Share button per row →** `create_shared_link(...)`; on success copy `url` to clipboard and
  invoke the OS share sheet; show a toast/snackbar with the URL. On error, inline message.
- States: loading, empty ("Run a scan to generate your first report."), error
  ("Couldn't load reports — retry").
- Styling reuses `.action-card` / `.dashboard-card` and the existing Easy Mode safe-area
  padding (`crates/ui/src/styles/mobile.css`).

### 5.3 `EasyModeShell` wiring (`crates/ui/src/components/easy_mode.rs`)
- Mount `DocumentsPanel` in the Easy Mode layout. On phones chat is the tall element; documents
  occupy a secondary/collapsible section in the same scroll. Provide the Easy Mode agent id so
  the panel can filter.

### 5.4 Native share sheet (the one genuinely new native bit)
- iOS: `UIActivityViewController` presented from the key window (same
  `crates/platform/src/ios/` pattern used for the OAuth presentation context).
- Android: `ACTION_SEND` intent with `text/plain`.
- A `pentest_platform` trait method (e.g. `share_text(&str)`), registered per platform like the
  existing browser opener. Fallback when unavailable: clipboard copy + toast only.

## 6. Platform coverage
- **iOS & Android:** full documents list + open-in-browser + share (link, copy, native sheet).
- **Desktop/web (Easy Mode opt-in):** list + open-in-browser + copy link; share sheet falls back
  to clipboard copy.
- Listing/sharing behavior is otherwise identical across platforms (all server-side).

## 7. Risks / open questions (updated from Phase 1 spec, re-verified live)
- **R1 — Auth context (RESOLVED).** `list_documents` / `create_shared_link` require an
  authenticated user context. Pick's OIDC flow provides a user token; the queries are
  `authenticate`-gated and work with it. No connector-only limitation blocks Phase 2.
- **R2 — Shared/opened pages require login (CONFIRMED, accepted for this build).** The
  `/s/:token` controller (`shared_link_controller.ex`) routes every non-bot visitor through
  `ensure_authenticated_access`, redirecting to `/auth/login` — even for `public` scope. The
  Studio `/conversations/:id` page likewise needs a session, and the system browser has no
  Studio cookie, so open-in-browser will prompt the owner to log into Studio once. This is
  accepted for this build. True no-account sharing ("text a link to a spouse") requires a
  matrix-side change (allow unauthenticated access for `public` scope) tracked separately; when
  it lands, the links we already create open cleanly with no client change.
- **R3 — Agent reliably writes the report (RESOLVED).** Verified the scan persists a markdown
  report document. Keep the Phase 1 seed prompt that asks for a report document.
- **R4 — Document read path (RESOLVED).** `list_documents` connection query is the read path;
  no need to go through the agent `document_list` tool.
- **R5 — Which URL for open-in-browser.** Chosen: Studio conversation page
  `/conversations/:conversation_id` (the document lives in that conversation; there is no
  per-document viewer route). Alternative considered — create a share link and open `/s/:token`
  — is heavier (a mutation per open) and equally login-gated, so not used for plain "open".

## 8. Testing
- **Rust unit:** `list_documents` response mapping (edges → summaries; empty vs N);
  `create_shared_link` input shape + `url`/`errors` extraction; `studio_web_base` derivation
  from `MATRIX_API_URL`; `resource_id` formatting (`"{conv}:{doc}"`).
- **Integration:** mocked GraphQL — list (empty / N docs / transport error), share
  (success / non-empty `errors` / transport error).
- **Manual / E2E** (cluster with #1390 + flag on): scan → report appears in the list → tap opens
  the Studio conversation in the browser → Share creates `/s/:token`, copies it, fires the share
  sheet. Run on iOS sim and Android emulator **one connector at a time** (same-tenant connector
  collision stalls the agent — see project memory `connector-collision-consent-hang`).
- **Regression:** standard (non-easy) mode and desktop unaffected when `easy_mode = false`;
  Phase 1 scan + chat still work.

## 9. Out of scope (parked)
- In-app markdown preview/viewer.
- Link management / revoke UI (`shared_links`, `revoke_shared_link`).
- Matrix-side public-access fix (unauthenticated `/s/:token` for `public` scope).
- Auto-update, signing, expert-UI changes.
