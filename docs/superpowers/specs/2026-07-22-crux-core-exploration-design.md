# Crux Core Exploration — Design (Slice 1)

**Status:** Approved for planning
**Date:** 2026-07-22
**Branch:** josh/catching-up (exploration, additive)

## Goal

Stand up a pure `crux_core` App that models Pick's **Easy Mode** scan flow, backed
by the existing `pentest-core` crate through a Rust effect-middleware — a sibling to
the Dioxus app that shares the same core. Slice 1 ships **the shared crate + typegen
only, no shell**, verified by deterministic Rust tests. It de-risks the longer-term
plan: (1) Crux core under Dioxus, (2) native Swift (iOS) + Kotlin (Android) views atop
the same core, (3) graduate platforms off Dioxus as each native shell reaches parity.

**Non-negotiable:** zero changes to the shipping Dioxus / app crates. This is purely
additive.

## Why this is feasible (codebase findings)

- `crates/core` (`pentest-core`) and `crates/tools` are **UI-independent** — zero
  Dioxus dependencies. The Matrix GraphQL client, auth, pre-approval, documents, and
  tools are pure and reusable as the shared core.
- The Easy Mode chat/scan **state machine currently lives in `crates/ui`** (~4,500
  lines across `chat_panel/`, ~40 Dioxus signal/effect hooks in `mod.rs`) — this is
  the logic a Crux `App`/`Model`/`update` would own. There is already a
  message-passing seam (`ConnectorEvent`) that maps naturally to Crux Events.

## Crux version reference (verified against crates.io 2026-07-22)

- `crux_core = "0.19"` (latest stable, 0.19.0), `crux_http = "0.19"` (0.19.0),
  `crux_macros = "0.10"`. `crux_time`/`crux_kv`/`crux_platform` not needed in slice 1.
- Modern **Command-based** `update` (returns `Command<Effect, Event>`); the old
  capability-callback style (`caps.http.get().send()`) is obsolete — do NOT use it.
- Typegen is **facet / facet-generate** via an in-crate `codegen` binary — NOT the old
  `crux_core::typegen` / `crux_cli bindgen`. Boundary types need `#[derive(Facet)]`;
  boundary enums need `#[repr(C)]`; the effect enum uses `#[effect(facet_typegen)]`.
- A future Dioxus shell uses the in-process `Core<App>` path (no bincode/FFI). Native
  shells (later) use BoltFFI + facet-generated Swift/Kotlin types.
- Crux is **pre-1.0 and moving fast** (0.19, 54 releases) — pin exact versions; expect
  the Command API surface may need minor adjustment at compile time.

## Global Constraints

- Slice 1 = `crates/crux-core` + `crates/crux-middleware` + generated Swift/Kotlin
  types + tests. No shell of any kind.
- The App is **pure / sans-I/O**: `update` returns Commands, never performs I/O or
  blocks. All network I/O happens in the middleware on a background thread.
- Reuse `pentest-core` DTOs and logic verbatim; do not reimplement Matrix/auth.
- Additive by default. The ONLY permitted changes to shipping code are
  **behavior-identical call-site swaps** when a pure helper is extracted from
  `crates/ui` into a shared crate (see "Extract-to-pure-and-share") — the Dioxus app
  must remain behavior-identical and keep building/passing. No changes to `apps/*`.
- Neither new crate may depend on `crates/ui` (it is Dioxus-coupled) — they depend only
  on `crates/core` (`pentest-core`), `crates/tools`/`crates/platform` if needed, and the
  `strike48-connector` SDK.
- The `ViewModel` is fully render-ready and platform-agnostic (no Rust-only types leak;
  markdown stays a string; timestamps pre-formatted; enums for status) so a native view
  is a pure function of `ViewModel` with no business logic.
- Pin exact crux versions. `cargo fmt` + `clippy -D warnings` clean.
- Commit rules: conventional commits; no attribution lines, no customer/tenant names,
  no emojis, no em-dashes.

## Architecture

```
crates/crux-core       (NEW, pure/sans-I/O)
  App: Model, Event, ViewModel, Effect
  update(Event,&mut Model)->Command<Effect,Event>;  view(&Model)->ViewModel
  Emits Effect::Pentest(op) + Effect::Render. No reqwest/ws.
        | Effect::Pentest(op)                    ^ Event (results)
        v                                         |
crates/crux-middleware (NEW, does the I/O)
  EffectMiddleware: fulfills PentestOperation via pentest-core on a bg thread;
  passes Effect::Render through to the shell.
        | path dep
        v
crates/core (pentest-core)  — UNCHANGED, UI-independent
  matrix::{client, auth, pre_approval, documents, types}
```

## Components

### `Effect`
```rust
#[effect(facet_typegen)]
pub enum Effect {
    Render(RenderOperation),
    Pentest(PentestOperation),
}
```

### `PentestOperation` (middleware-fulfilled; coarse, so the App stays pure)
```rust
pub enum PentestOperation {
    SignIn { api_url: String },
    Connect { api_url: String, tenant: String, token: String },
    SendScan { conversation_id: Option<String>, prompt: String },
    SendMessage { conversation_id: Option<String>, text: String },
    PollConversation { conversation_id: String },
    ListConversations,
    LoadConversation { conversation_id: String },
    ListDocuments { agent_id: Option<String> },
    GetDocumentContent { document_id: String },
    CreateSharedLink { conversation_id: String, document_id: String },
}
```
Each resolves with a `PentestOutcome` variant (`SignedIn{token}`, `Connected`,
`ScanQueued{conversation_id}`, `ConversationDelta{messages, tool_calls, done}`,
`Conversations{list}`, `Documents{list}`, `DocumentContent{markdown}`,
`SharedLink{url}`, `Error{message}`).

Opening a URL / invoking the OS share sheet is a **shell** action (the ViewModel hands
the native view the share URL string) — not an effect.

### `Event`
```rust
pub enum Event {
    // user intents
    StartScan,
    SendMessage(String),
    NewChat,
    OpenHistory,
    CloseHistory,
    SelectConversation(String),
    OpenDocument(String),
    CloseDocument,
    CreateShareLink(String),
    RetrySignIn,
    DismissError,
    // effect results (bound via .then_send)
    SignInResult(Result<String, String>),
    ConnectResult(Result<(), String>),
    ScanResult(Result<String, String>),
    ConversationDelta(Result<ConversationDelta, String>),
    ConversationsResult(Result<Vec<ConversationRef>, String>),
    LoadConversationResult(Result<Vec<MessageView>, String>),
    DocumentsResult(Result<Vec<DocRef>, String>),
    DocumentContentResult(Result<DocView, String>),
    ShareLinkResult(Result<String, String>),
}
```

### `Model` (private state)
Connection phase (`SigningIn | Connecting | Registering | Connected | NeedsSignIn`),
`conversation_id: Option<String>`, `messages: Vec<ChatMessage>`, `tool_calls`,
`conversation_docs`, `all_documents`, `history`, `open_document`, `scan_active: bool`,
`history_open: bool`, `error: Option<String>`.

### `ViewModel` (render-ready, platform-agnostic — what any shell binds to)
```rust
pub struct ViewModel {
    pub screen: Screen,                  // Scan | Chat | Documents | DocViewer | NeedsSignIn
    pub connection: ConnectionView,      // phase + human label
    pub messages: Vec<MessageView>,      // sender, kind (User|Agent|Text|ToolCall), text/markdown, tool status
    pub scan_in_progress: bool,
    pub show_scan_card: bool,            // hidden once a conversation is active
    pub conversation_docs: Vec<DocRef>,  // "documents from this chat"
    pub all_documents: Vec<DocRef>,      // top-bar Docs list
    pub history: Vec<ConversationRef>,   // title + pre-formatted relative time
    pub open_document: Option<DocView>,  // { title, markdown_body, share_url: Option<String> }
    pub needs_sign_in: bool,
    pub error: Option<String>,
}
```

### Reused from `pentest-core` verbatim
`DocumentSummary`, Matrix message/conversation types, `OttData`, auth/pre-approval
logic. The App references these DTOs; the middleware calls the real client.

### Extract-to-pure-and-share (opportunistic, only where it's a clean win)
Where Easy Mode logic in `crates/ui` is already **pure but entangled with Dioxus
signals**, extract that pure logic into a shared location (prefer `pentest-core`, or a
small new `crates/core` submodule) so BOTH the Dioxus app and the Crux App consume one
implementation instead of the Crux App reimplementing it. This is the concrete
"share code as needed" step toward graduating off Dioxus. Candidates observed:

- **Conversation-delta merge** — computing new messages/tool-calls to append given a
  fetched conversation vs current state (today inline in `chat_panel`).
- **Connection-phase mapping** — the SigningIn/Connecting/Registering/Connected/
  NeedsSignIn state derivation (today driven by signals in `connector_app.rs`).
- **`plg_connect_decision`** already lives in `pentest-core` — reuse directly.
- **document_write / scan prompt** text (`easy_mode::easy_mode_scan_prompt`) — move the
  pure string builder to `pentest-core` so both shells share it.

Rules for extraction: only move code that is **already pure** (no `Signal`, no
`use_effect`, no I/O); make the smallest focused extraction; **update the Dioxus call
site to use the shared function** (a permitted, minimal change to `crates/ui` — it
must remain behavior-identical and keep the app building). If an extraction would
require reshaping Dioxus-coupled code, do NOT do it in slice 1 — the Crux App models
that logic itself and we revisit sharing in the Dioxus-over-Crux phase. Each extraction
is its own small, separately-reviewable step with tests.

## Middleware & Data Flow

`crates/crux-middleware` implements Crux's `EffectMiddleware`: intercepts
`Effect::Pentest(op)`, runs the real I/O on a background thread with `pentest-core`,
and feeds the result back as an `Event`. `Effect::Render` passes through untouched.

Op → `pentest-core` mapping:

| PentestOperation | pentest-core call |
|---|---|
| `SignIn` | `matrix::auth::fetch_matrix_token_browser` (+ future token-exchange) |
| `Connect` | `pentest-core` connect pieces + `strike48-connector` SDK directly (NOT `crates/ui`'s `LiveViewConnector`, which is Dioxus-coupled — the middleware must not depend on `crates/ui`) |
| `SendScan` / `SendMessage` | `MatrixChatClient::send_message` |
| `PollConversation` | conversation fetch → diff into `ConversationDelta`, re-emit until `done` |
| `ListConversations` / `LoadConversation` | client conversation queries |
| `ListDocuments` | `matrix::documents::list_documents` |
| `GetDocumentContent` | `client.get_document_content` |
| `CreateSharedLink` | `documents::create_shared_link` (public scope) |

Scan data flow:
```
Event::StartScan
  -> update: model.scan_active=true; emit Pentest(SendScan).then_send(ScanResult)
  -> middleware send_message (bg) -> ScanResult(Ok(conv_id))
  -> update: store conv_id; emit Pentest(PollConversation).then_send(ConversationDelta)
  -> middleware fetch -> ConversationDelta{messages,tool_calls,done:false}
  -> update: merge into model; if !done re-emit PollConversation; emit Render
  -> ... until done:true -> emit ListDocuments -> docs land in ViewModel
```

- **Purity:** `update` never blocks/does I/O — only returns Commands. Middleware runs
  off the `process_event` thread (must not block it).
- **Polling loop:** modeled as the App re-emitting `PollConversation` on each non-final
  delta — deterministic and testable with canned responses.
- **Errors:** every op resolves to `Result`; `Err(msg)` sets `model.error` /
  `needs_sign_in` and emits Render. No panics cross the boundary.
- **Threading:** middleware owns a small tokio handle to call `pentest-core`'s async
  client; internal to the crate — the App and future shells never see it.

## Testing, Typegen & Deliverables

### Unit tests (`crates/crux-core`, deterministic, no network)
Using Crux's `AppTester` (drive `update`, inspect emitted effects, resolve with canned
outcomes):

- `start_scan_emits_send_scan_effect` — StartScan sets scan_active, emits
  `Pentest(SendScan)` bound to `ScanResult`; ViewModel `show_scan_card` false.
- `scan_result_starts_polling` — `ScanResult(Ok(conv))` stores conversation_id, emits
  `Pentest(PollConversation)`.
- `conversation_delta_merges_and_reloops` — `ConversationDelta{done:false}` merges
  messages/tool-calls and re-emits `PollConversation`; ViewModel exposes tool-call rows.
- `final_delta_lists_documents` — `ConversationDelta{done:true}` stops the loop and
  emits `ListDocuments`; resolved docs appear in `conversation_docs`.
- `signin_failure_sets_needs_sign_in` — `SignInResult(Err)` → ViewModel
  `needs_sign_in=true`, screen `NeedsSignIn`; `RetrySignIn` re-emits `SignIn`.
- `open_document_and_share` — `OpenDocument` → `GetDocumentContent`; `CreateShareLink`
  → `CreateSharedLink`; ViewModel `open_document.share_url` populated.
- `view_is_pure_function_of_model` — distinct Models render distinct ViewModels; no I/O.

### Middleware test (`crates/crux-middleware`)
A mapping test that each `PentestOperation` routes to the intended `pentest-core`
entrypoint, via a trait-seam/mock over the Matrix client (no real network) — asserts
op→call mapping and outcome shaping. Live end-to-end is out of slice 1.

### Typegen deliverable
A feature-gated `codegen` binary using `facet-generate`
(`TypeRegistry::register_app::<PickApp>()`) emitting **Swift + Kotlin** foreign types
into `crates/crux-core/generated/`. A CI-runnable check asserts codegen runs clean and
produces non-empty Swift + Kotlin output containing the `ViewModel`/`Event` types —
proving the surface is native-ready without building a shell.

### Deliverables
1. `crates/crux-core` — pure App (Model/Event/Effect/ViewModel/update/view) modeling
   Easy Mode; `#[derive(Facet)]` + `#[repr(C)]` on boundary types.
2. `crates/crux-middleware` — `EffectMiddleware` wrapping `pentest-core`.
3. Generated Swift + Kotlin types + the `codegen` bin.
4. Any opportunistic pure-logic extractions from `crates/ui` into `pentest-core`
   (each behavior-identical, with the Dioxus call site updated and unit tests), where
   they are a clean win per "Extract-to-pure-and-share".
5. The test suite above; `cargo test` / `clippy` clean; the Dioxus app still builds.

## Out of scope (YAGNI)
- Any shell: Dioxus-over-Crux, SwiftUI, Jetpack Compose.
- Expert console (multi-agent validate→report pipeline), telemetry, file browser.
- Live-network / on-device tests.
These are subsequent phases in the "graduate off Dioxus" roadmap.

## Roadmap context (beyond slice 1)
1. Slice 1 (this spec): shared crux-core + middleware + typegen, tested.
2. Dioxus-over-Crux shell: swap the Dioxus easy-mode state machine to consume
   `Core<App>` (in-process, no FFI) — proves parity with the shipping app.
3. Native shells: SwiftUI (iOS) + Jetpack Compose (Android) over BoltFFI + generated
   types, each a pure function of `ViewModel`.
4. Graduate platforms off Dioxus one at a time as each native shell reaches parity.
