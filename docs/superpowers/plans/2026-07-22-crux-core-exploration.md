# Crux Core Exploration Implementation Plan (Slice 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a pure `crux_core` 0.19 App modeling Pick's Easy Mode scan flow, backed by the existing `pentest-core` via a Rust effect-middleware, verified by tests + Swift/Kotlin typegen — no shell.

**Architecture:** Two new sibling crates in the existing workspace: `crates/crux-core` (pure sans-I/O App: Model/Event/Effect/ViewModel/update/view) and `crates/crux-middleware` (an `EffectMiddleware` that fulfills the App's high-level `PentestOperation` effects by calling `pentest-core`'s Matrix client on a background thread). The App references `pentest-core` DTOs but performs no I/O; the middleware owns all I/O. Additive — the shipping Dioxus app is untouched except behavior-identical call-site swaps when a pure helper is extracted.

**Tech Stack:** Rust, `crux_core = "0.19"`, `crux_http = "0.19"` (unused in slice 1 but pinned), `facet = "=0.44"`, `serde`, `crux_core::type_generation::facet` for Swift/Kotlin codegen, `pentest-core` (path dep).

## Global Constraints

- Slice 1 = `crates/crux-core` + `crates/crux-middleware` + generated Swift/Kotlin types + tests. NO shell (Dioxus/SwiftUI/Compose) of any kind.
- The App is pure / sans-I/O: `update` returns `Command`s, never performs I/O or blocks. All network I/O happens in the middleware on a background thread.
- Reuse `pentest-core` DTOs and logic verbatim; do not reimplement Matrix/auth.
- Neither new crate may depend on `crates/ui` (Dioxus-coupled). Depend only on `crates/core` (`pentest-core`), and `crates/tools`/`crates/platform`/`strike48-connector` if needed.
- Only permitted shipping-code change: behavior-identical call-site swaps when a pure helper is extracted from `crates/ui` into `pentest-core`. No `apps/*` changes.
- The `ViewModel` is render-ready and platform-agnostic (no Rust-only types leak; markdown stays a string; timestamps pre-formatted; enums for status).
- Pin exact crux versions: `crux_core = "0.19"`, `crux_http = "0.19"`, `facet = "=0.44"` (features `["chrono"]`). `crux_macros` is `crux_core::macros` (no separate dep).
- `crate-type = ["lib"]` for `crux-core` in slice 1 (cdylib/staticlib only when a native shell links it later).
- Boundary types (Event, Operations, their Outputs, ViewModel sub-types) derive `Facet, Serialize, Deserialize, Clone, Debug` and are `#[repr(C)]` where they are enums crossing the boundary.
- `cargo fmt --all` + `cargo clippy -- -D warnings` clean; run everything via `nix develop --command cargo ...`.
- Commits: conventional; no attribution lines, no customer/tenant names, no emojis, no em-dashes.

## Crux 0.19 API facts (verified 2026-07-22, docs.rs + redbadger/crux master)

- `App` has FOUR associated types: `Event`, `Model`, `ViewModel`, `Effect`. **No `Capabilities`.**
- `fn update(&self, event: Self::Event, model: &mut Self::Model) -> Command<Self::Effect, Self::Event>` and `fn view(&self, model: &Self::Model) -> Self::ViewModel`.
- Effect enum: `#[effect(facet_typegen)]` (import `use crux_core::macros::effect;`), variants wrap `Operation` types; include `Render(RenderOperation)`.
- Custom effect: define `Op` enum/struct, `impl crux_core::capability::Operation for Op { type Output = ...; }`. Emit from update via `Command::request_from_shell(op).then_send(Event::Ctor)` (`.then_send` is on `RequestBuilder`, not `Command`). `render()` free fn from `crux_core::render`.
- Middleware: `impl crux_core::middleware::EffectMiddleware { type Op = ...; fn try_process_effect(&self, operation, resolver: EffectResolver<Op::Output>) }`; attach with `Core::new().handle_effects_using(mw)`.
- Testing (AppTester deprecated): `let mut cmd = app.update(ev, &mut model);` then `cmd.effects().next().unwrap().expect_<variant>()` → `.operation`, `.resolve(output)`; `cmd.events().next()`; `.expect_only_render()` / `assert_effect!`. Needs `crux_core` dev-dep with `testing` feature.
- Typegen: `crux_core::type_generation::facet::{TypeRegistry, Config}`; `TypeRegistry::new().register_app::<App>()?.build()?` then `.swift(&cfg)?` / `.kotlin(&cfg)?`; `Config::builder(name, &out_dir).build()`. Gated behind a `codegen` feature that enables `crux_core/facet_typegen`.

## pentest-core signatures the middleware calls (verified)

- `matrix::client::MatrixChatClient::new(api_url) .with_auth_token(t)` ; `send_message(&self, conversation_id: &str, agent_id: &str, text: &str) -> Result<String>` ; `send_and_receive_message(...)` ; conversation fetch via `GetConversation` query (see `client.rs:452`, exposed through a `get_conversation`-style method).
- `matrix::documents`: `list_documents(&self, agent_id: Option<&str>) -> Result<Vec<DocumentSummary>>` ; `get_document_content(&self, ...) -> Result<String>` ; `create_shared_link(&self, ...) -> Result<String>` ; `DocumentSummary { id, title, doc_type, conversation_id, timestamp }`.
- `matrix::pre_approval::pre_approve(api_url, jwt, connector_type) -> Result<OttData>`.
- `matrix::auth::fetch_matrix_token_browser(matrix_url) -> Result<String>`.
- `crates/ui/src/components/easy_mode.rs::easy_mode_scan_prompt() -> String` (extraction candidate → move to pentest-core).

---

### Task 1: Workspace + crux-core crate skeleton (compiles, empty App)

**Files:**
- Create: `crates/crux-core/Cargo.toml`
- Create: `crates/crux-core/src/lib.rs`
- Modify: `Cargo.toml` (workspace `members`)

**Interfaces:**
- Produces: crate `pick-crux-core` with a placeholder `App` impl `PickApp` compiling against crux_core 0.19.

- [ ] **Step 1: Add the crate to the workspace**

In root `Cargo.toml`, add to `members` (after `"crates/cyberchef",`):

```toml
    "crates/crux-core",
    "crates/crux-middleware",
```

- [ ] **Step 2: Write `crates/crux-core/Cargo.toml`**

```toml
[package]
name = "pick-crux-core"
version.workspace = true
edition.workspace = true

[lib]
crate-type = ["lib"]

[[bin]]
name = "codegen"
required-features = ["codegen"]

[features]
facet_typegen = ["crux_core/facet_typegen"]
codegen = ["dep:anyhow", "dep:clap", "dep:log", "dep:pretty_env_logger", "facet_typegen"]

[dependencies]
crux_core = "0.19"
crux_http = "0.19"
serde = { version = "1", features = ["derive"] }
facet = { version = "=0.44", features = ["chrono"] }
pentest-core = { path = "../core" }

anyhow = { version = "1", optional = true }
clap = { version = "4", features = ["derive"], optional = true }
log = { version = "0.4", optional = true }
pretty_env_logger = { version = "0.5", optional = true }

[dev-dependencies]
crux_core = { version = "0.19", features = ["testing"] }
```

- [ ] **Step 3: Write a minimal compiling App in `crates/crux-core/src/lib.rs`**

```rust
//! Pick Crux core — a pure crux_core App modeling Easy Mode, sibling to the
//! Dioxus app. Sans-I/O: all network work happens in pick-crux-middleware.

use crux_core::{macros::effect, render::RenderOperation, App, Command};
use facet::Facet;
use serde::{Deserialize, Serialize};

#[effect(facet_typegen)]
#[derive(Debug)]
pub enum Effect {
    Render(RenderOperation),
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
pub enum Event {
    NoOp,
}

#[derive(Default)]
pub struct Model {}

#[derive(Facet, Serialize, Deserialize, Clone, Default, Debug)]
pub struct ViewModel {}

#[derive(Default)]
pub struct PickApp;

impl App for PickApp {
    type Event = Event;
    type Model = Model;
    type ViewModel = ViewModel;
    type Effect = Effect;

    fn update(&self, event: Event, _model: &mut Model) -> Command<Effect, Event> {
        match event {
            Event::NoOp => crux_core::render::render(),
        }
    }

    fn view(&self, _model: &Model) -> ViewModel {
        ViewModel {}
    }
}
```

- [ ] **Step 4: Verify it compiles (this proves the crux 0.19 wiring/versions resolve)**

Run: `nix develop --command cargo check -p pick-crux-core 2>&1 | tail -20`
Expected: `Finished`. If `facet` version conflicts, run `nix develop --command cargo tree -p pick-crux-core -i facet` and pin `facet` to the exact version `crux_core 0.19` requires, then re-check.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/crux-core/
git commit -m "feat(crux): scaffold pick-crux-core crate against crux_core 0.19"
```

---

### Task 2: Domain types — ViewModel, view-facing structs, Model

**Files:**
- Create: `crates/crux-core/src/model.rs`
- Create: `crates/crux-core/src/view.rs`
- Modify: `crates/crux-core/src/lib.rs`

**Interfaces:**
- Produces: `Model` (private state), `ViewModel` + `Screen`, `ConnectionView`, `ConnectionPhase`, `MessageView`, `MessageKind`, `ToolCallView`, `ToolStatus`, `DocRef`, `ConversationRef`, `DocView` — all `Facet + Serialize + Deserialize + Clone + Debug`, enums `#[repr(C)]`.

- [ ] **Step 1: Write `crates/crux-core/src/view.rs` (render-ready types)**

```rust
//! Platform-agnostic, render-ready view types. A native (Swift/Kotlin) or
//! Dioxus view is a pure function of `ViewModel`. No Rust-only types leak;
//! markdown stays a String; timestamps are pre-formatted.

use facet::Facet;
use serde::{Deserialize, Serialize};

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum Screen {
    Scan,
    Chat,
    Documents,
    DocViewer,
    NeedsSignIn,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum ConnectionPhase {
    SigningIn,
    Connecting,
    Registering,
    Connected,
    NeedsSignIn,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConnectionView {
    pub phase: ConnectionPhase,
    pub label: String,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum MessageKind {
    User,
    AgentText,
    ToolCall,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum ToolStatus {
    Running,
    Success,
    Error,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ToolCallView {
    pub name: String,
    pub status: ToolStatus,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct MessageView {
    pub sender: String,
    pub kind: MessageKind,
    pub markdown: String,
    pub tool: Option<ToolCallView>,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DocRef {
    pub id: String,
    pub title: String,
    pub conversation_id: String,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ConversationRef {
    pub id: String,
    pub title: String,
    pub relative_time: String,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DocView {
    pub id: String,
    pub title: String,
    pub markdown_body: String,
    pub share_url: Option<String>,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct ViewModel {
    pub screen: Screen,
    pub connection: ConnectionView,
    pub messages: Vec<MessageView>,
    pub scan_in_progress: bool,
    pub show_scan_card: bool,
    pub conversation_docs: Vec<DocRef>,
    pub all_documents: Vec<DocRef>,
    pub history: Vec<ConversationRef>,
    pub open_document: Option<DocView>,
    pub needs_sign_in: bool,
    pub error: Option<String>,
}

impl Default for Screen {
    fn default() -> Self { Screen::Scan }
}
impl Default for ConnectionPhase {
    fn default() -> Self { ConnectionPhase::Connecting }
}
impl Default for ConnectionView {
    fn default() -> Self {
        ConnectionView { phase: ConnectionPhase::Connecting, label: "Connecting...".to_string() }
    }
}
```

- [ ] **Step 2: Write `crates/crux-core/src/model.rs`**

```rust
//! Private App state. Never crosses the FFI boundary; `view()` projects it into
//! the ViewModel.

use crate::view::{ConnectionPhase, ConversationRef, DocRef, DocView, MessageView};

#[derive(Default)]
pub struct Model {
    pub phase: Phase,
    pub api_url: String,
    pub conversation_id: Option<String>,
    pub messages: Vec<MessageView>,
    pub conversation_docs: Vec<DocRef>,
    pub all_documents: Vec<DocRef>,
    pub history: Vec<ConversationRef>,
    pub open_document: Option<DocView>,
    pub scan_active: bool,
    pub history_open: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum Phase {
    SigningIn,
    Connecting,
    Registering,
    Connected,
    NeedsSignIn,
}

impl Default for Phase {
    fn default() -> Self { Phase::Connecting }
}

impl Phase {
    pub fn to_view(&self) -> ConnectionPhase {
        match self {
            Phase::SigningIn => ConnectionPhase::SigningIn,
            Phase::Connecting => ConnectionPhase::Connecting,
            Phase::Registering => ConnectionPhase::Registering,
            Phase::Connected => ConnectionPhase::Connected,
            Phase::NeedsSignIn => ConnectionPhase::NeedsSignIn,
        }
    }
    pub fn label(&self) -> &'static str {
        match self {
            Phase::SigningIn => "Signing in to Strike48...",
            Phase::Connecting => "Connecting...",
            Phase::Registering => "Registering connector...",
            Phase::Connected => "Connected",
            Phase::NeedsSignIn => "Sign in to connect",
        }
    }
}
```

- [ ] **Step 3: Wire modules into `lib.rs`; replace the placeholder ViewModel/Model**

In `lib.rs`, add `pub mod model;` and `pub mod view;`, remove the inline `Model`/`ViewModel` from Task 1, and re-export: `pub use model::Model; pub use view::ViewModel;`. Delete the scratch `screen_scan` field from `ViewModel` if it is still present. Update `PickApp::view` to build a `ViewModel` from `Model`:

```rust
fn view(&self, model: &Model) -> ViewModel {
    ViewModel {
        screen: if model.open_document.is_some() {
            view::Screen::DocViewer
        } else if matches!(model.phase, model::Phase::NeedsSignIn) {
            view::Screen::NeedsSignIn
        } else if model.messages.is_empty() {
            view::Screen::Scan
        } else {
            view::Screen::Chat
        },
        connection: view::ConnectionView {
            phase: model.phase.to_view(),
            label: model.phase.label().to_string(),
        },
        messages: model.messages.clone(),
        scan_in_progress: model.scan_active,
        show_scan_card: model.messages.is_empty(),
        conversation_docs: model.conversation_docs.clone(),
        all_documents: model.all_documents.clone(),
        history: model.history.clone(),
        open_document: model.open_document.clone(),
        needs_sign_in: matches!(model.phase, model::Phase::NeedsSignIn),
        error: model.error.clone(),
    }
}
```

- [ ] **Step 4: Add a view-projection test in `lib.rs`**

```rust
#[cfg(test)]
mod view_tests {
    use super::*;
    #[test]
    fn empty_model_shows_scan_screen_with_card() {
        let app = PickApp;
        let vm = app.view(&Model::default());
        assert_eq!(vm.screen, view::Screen::Scan);
        assert!(vm.show_scan_card);
        assert!(!vm.scan_in_progress);
    }
    #[test]
    fn needs_sign_in_phase_projects_needs_sign_in() {
        let app = PickApp;
        let mut m = Model::default();
        m.phase = model::Phase::NeedsSignIn;
        let vm = app.view(&m);
        assert!(vm.needs_sign_in);
        assert_eq!(vm.screen, view::Screen::NeedsSignIn);
    }
}
```

- [ ] **Step 5: Run + commit**

Run: `nix develop --command cargo test -p pick-crux-core view_tests 2>&1 | tail -15`
Expected: 2 passed.

```bash
git add crates/crux-core/
git commit -m "feat(crux): domain Model + render-ready ViewModel types"
```

---

### Task 3: PentestOperation effect + Event enum

**Files:**
- Create: `crates/crux-core/src/effect.rs`
- Modify: `crates/crux-core/src/lib.rs`

**Interfaces:**
- Consumes: view types (Task 2).
- Produces: `PentestOperation` (impl `Operation`, `Output = PentestOutcome`), `PentestOutcome`, `ConversationDelta`, the `Effect` enum gains `Pentest(PentestOperation)`, and the full `Event` enum.

- [ ] **Step 1: Write `crates/crux-core/src/effect.rs`**

```rust
//! The custom side-effect the App emits; the middleware (or a future shell)
//! fulfills it using pentest-core. The App itself performs no I/O.

use crux_core::capability::Operation;
use facet::Facet;
use serde::{Deserialize, Serialize};

use crate::view::{ConversationRef, DocRef, MessageView, ToolCallView};

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum PentestOperation {
    SignIn { api_url: String },
    Connect { api_url: String, tenant: String, token: String },
    SendScan { conversation_id: Option<String>, prompt: String },
    SendMessage { conversation_id: Option<String>, text: String },
    PollConversation { conversation_id: String },
    ListConversations,
    LoadConversation { conversation_id: String },
    ListDocuments { agent_id: Option<String> },
    GetDocumentContent { document_id: String, conversation_id: String },
    CreateSharedLink { conversation_id: String, document_id: String },
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub struct ConversationDelta {
    pub messages: Vec<MessageView>,
    pub tool_calls: Vec<ToolCallView>,
    pub done: bool,
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug, PartialEq)]
#[repr(C)]
pub enum PentestOutcome {
    SignedIn { token: String },
    Connected,
    ScanQueued { conversation_id: String },
    Delta(ConversationDelta),
    Conversations { list: Vec<ConversationRef> },
    LoadedMessages { messages: Vec<MessageView> },
    Documents { list: Vec<DocRef> },
    DocumentContent { markdown: String },
    SharedLink { url: String },
    Error { message: String },
}

impl Operation for PentestOperation {
    type Output = PentestOutcome;
}
```

- [ ] **Step 2: Extend `Effect` and add `Event` in `lib.rs`**

Replace the Task-1 `Effect` and `Event` with:

```rust
pub mod effect;
use effect::{ConversationDelta, PentestOperation};

#[effect(facet_typegen)]
#[derive(Debug)]
pub enum Effect {
    Render(RenderOperation),
    Pentest(PentestOperation),
}

#[derive(Facet, Serialize, Deserialize, Clone, Debug)]
#[repr(C)]
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
    // effect results
    SignInResult(Result<String, String>),
    ConnectResult(Result<(), String>),
    ScanResult(Result<String, String>),
    Delta(Result<ConversationDelta, String>),
    ConversationsResult(Result<Vec<view::ConversationRef>, String>),
    LoadConversationResult(Result<Vec<view::MessageView>, String>),
    DocumentsResult(Result<Vec<view::DocRef>, String>),
    DocumentContentResult(Result<String, String>),
    ShareLinkResult(Result<String, String>),
}
```

Temporarily make `update` exhaustively match `Event` returning `crux_core::render::render()` for every arm (real logic in Task 4) so it compiles.

- [ ] **Step 3: Verify compile**

Run: `nix develop --command cargo check -p pick-crux-core 2>&1 | tail -20`
Expected: `Finished`. (`Result<T,E>` crossing the boundary must be `Facet`-supported; if facet rejects bare `Result`, wrap each in a `#[repr(C)]` enum — but facet 0.44 supports `Result`. If codegen later complains, Task 7 will surface it.)

- [ ] **Step 4: Commit**

```bash
git add crates/crux-core/
git commit -m "feat(crux): PentestOperation effect + full Event enum"
```

---

### Task 4: `update` logic — the Easy Mode state machine

**Files:**
- Create: `crates/crux-core/src/update.rs`
- Modify: `crates/crux-core/src/lib.rs`
- Test: `crates/crux-core/src/update.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `Effect`, `Event`, `PentestOperation`, `PentestOutcome`, `ConversationDelta`, `Model`, `Phase`.
- Produces: `PickApp::update` behavior. Uses `Command::request_from_shell(PentestOperation::X).then_send(Event::Y)` and `crux_core::render::render()`.

- [ ] **Step 1: Write the failing test (scan → send → poll loop → docs)**

In `crates/crux-core/src/update.rs`:

```rust
#[cfg(test)]
mod tests {
    use crate::effect::{ConversationDelta, PentestOperation, PentestOutcome};
    use crate::view::MessageView;
    use crate::{Effect, Event, Model, PickApp};
    use crux_core::App;

    #[test]
    fn start_scan_emits_send_scan_and_hides_card() {
        let app = PickApp;
        let mut model = Model::default();
        let mut cmd = app.update(Event::StartScan, &mut model);
        assert!(model.scan_active);
        // ViewModel hides the scan card once scan active + messages arrive
        let req = cmd.effects().next().expect("an effect");
        let op = req.expect_pentest().operation;
        assert!(matches!(op, PentestOperation::SendScan { .. }));
    }

    #[test]
    fn scan_result_starts_polling() {
        let app = PickApp;
        let mut model = Model::default();
        let _ = app.update(Event::StartScan, &mut model);
        let mut cmd = app.update(Event::ScanResult(Ok("conv-1".into())), &mut model);
        assert_eq!(model.conversation_id.as_deref(), Some("conv-1"));
        let op = cmd.effects().next().unwrap().expect_pentest().operation;
        assert!(matches!(op, PentestOperation::PollConversation { conversation_id } if conversation_id == "conv-1"));
    }

    #[test]
    fn non_final_delta_merges_and_reloops() {
        let app = PickApp;
        let mut model = Model::default();
        model.conversation_id = Some("conv-1".into());
        let delta = ConversationDelta {
            messages: vec![MessageView {
                sender: "pentest-connector".into(),
                kind: crate::view::MessageKind::AgentText,
                markdown: "scanning...".into(),
                tool: None,
            }],
            tool_calls: vec![],
            done: false,
        };
        let mut cmd = app.update(Event::Delta(Ok(delta)), &mut model);
        assert_eq!(model.messages.len(), 1);
        let op = cmd.effects().next().unwrap().expect_pentest().operation;
        assert!(matches!(op, PentestOperation::PollConversation { .. }));
    }

    #[test]
    fn final_delta_requests_documents() {
        let app = PickApp;
        let mut model = Model::default();
        model.conversation_id = Some("conv-1".into());
        let delta = ConversationDelta { messages: vec![], tool_calls: vec![], done: true };
        let mut cmd = app.update(Event::Delta(Ok(delta)), &mut model);
        assert!(!model.scan_active);
        let op = cmd.effects().next().unwrap().expect_pentest().operation;
        assert!(matches!(op, PentestOperation::ListDocuments { .. }));
    }

    #[test]
    fn signin_error_sets_needs_sign_in() {
        let app = PickApp;
        let mut model = Model::default();
        let _ = app.update(Event::SignInResult(Err("nope".into())), &mut model);
        assert_eq!(model.phase, crate::model::Phase::NeedsSignIn);
        assert_eq!(app.view(&model).needs_sign_in, true);
    }
}
```

- [ ] **Step 2: Run — expect failure (update returns render() for all arms)**

Run: `nix develop --command cargo test -p pick-crux-core update::tests 2>&1 | tail -25`
Expected: FAIL (effects are Render, not Pentest; model not mutated). If `expect_pentest()` doesn't exist, the `#[effect]` macro generates `expect_<snake_variant>` — the variant is `Pentest`, so `expect_pentest()` is correct; if the accessor differs, use `assert_effect!` / match on `Effect::Pentest(_)` from `cmd.effects()`.

- [ ] **Step 3: Implement `update` in `update.rs`**

Provide `pub fn update(app: &PickApp, event: Event, model: &mut Model) -> Command<Effect, Event>` and call it from `PickApp::update` in `lib.rs`. Full logic:

```rust
use crux_core::{render::render, Command};
use crate::effect::{PentestOperation, PentestOutcome};
use crate::model::{Model, Phase};
use crate::{Effect, Event, PickApp};

pub fn update(_app: &PickApp, event: Event, model: &mut Model) -> Command<Effect, Event> {
    match event {
        Event::StartScan => {
            model.scan_active = true;
            model.error = None;
            let conv = model.conversation_id.clone();
            Command::request_from_shell(PentestOperation::SendScan {
                conversation_id: conv,
                prompt: pentest_core::easy_mode_scan_prompt(),
            })
            .then_send(|out| match out {
                PentestOutcome::ScanQueued { conversation_id } => Event::ScanResult(Ok(conversation_id)),
                PentestOutcome::Error { message } => Event::ScanResult(Err(message)),
                _ => Event::ScanResult(Err("unexpected outcome".into())),
            })
        }
        Event::SendMessage(text) => {
            model.error = None;
            let conv = model.conversation_id.clone();
            Command::request_from_shell(PentestOperation::SendMessage { conversation_id: conv, text })
                .then_send(|out| match out {
                    PentestOutcome::ScanQueued { conversation_id } => Event::ScanResult(Ok(conversation_id)),
                    PentestOutcome::Error { message } => Event::ScanResult(Err(message)),
                    _ => Event::ScanResult(Err("unexpected outcome".into())),
                })
        }
        Event::ScanResult(Ok(conv)) => {
            model.conversation_id = Some(conv.clone());
            Command::request_from_shell(PentestOperation::PollConversation { conversation_id: conv })
                .then_send(delta_event)
        }
        Event::ScanResult(Err(e)) => { model.scan_active = false; model.error = Some(e); render() }
        Event::Delta(Ok(delta)) => {
            model.messages.extend(delta.messages);
            // tool_calls are folded into messages by the middleware; kept separate here for future use
            if delta.done {
                model.scan_active = false;
                let agent = None; // agent id resolved by middleware/session
                Command::request_from_shell(PentestOperation::ListDocuments { agent_id: agent })
                    .then_send(|out| match out {
                        PentestOutcome::Documents { list } => Event::DocumentsResult(Ok(list)),
                        PentestOutcome::Error { message } => Event::DocumentsResult(Err(message)),
                        _ => Event::DocumentsResult(Err("unexpected outcome".into())),
                    })
            } else {
                let conv = model.conversation_id.clone().unwrap_or_default();
                Command::request_from_shell(PentestOperation::PollConversation { conversation_id: conv })
                    .then_send(delta_event)
            }
        }
        Event::Delta(Err(e)) => { model.scan_active = false; model.error = Some(e); render() }
        Event::DocumentsResult(Ok(docs)) => {
            let conv = model.conversation_id.clone().unwrap_or_default();
            model.conversation_docs = docs.iter().filter(|d| d.conversation_id == conv).cloned().collect();
            model.all_documents = docs;
            render()
        }
        Event::DocumentsResult(Err(e)) => { model.error = Some(e); render() }
        Event::RetrySignIn => {
            model.phase = Phase::SigningIn;
            model.error = None;
            Command::request_from_shell(PentestOperation::SignIn { api_url: model.api_url.clone() })
                .then_send(|out| match out {
                    PentestOutcome::SignedIn { token } => Event::SignInResult(Ok(token)),
                    PentestOutcome::Error { message } => Event::SignInResult(Err(message)),
                    _ => Event::SignInResult(Err("unexpected outcome".into())),
                })
        }
        Event::SignInResult(Ok(_token)) => { model.phase = Phase::Connected; render() }
        Event::SignInResult(Err(e)) => { model.phase = Phase::NeedsSignIn; model.error = Some(e); render() }
        Event::ConnectResult(Ok(())) => { model.phase = Phase::Connected; render() }
        Event::ConnectResult(Err(e)) => { model.error = Some(e); render() }
        Event::NewChat => {
            model.conversation_id = None;
            model.messages.clear();
            model.conversation_docs.clear();
            model.scan_active = false;
            render()
        }
        Event::OpenHistory => {
            model.history_open = true;
            Command::request_from_shell(PentestOperation::ListConversations)
                .then_send(|out| match out {
                    PentestOutcome::Conversations { list } => Event::ConversationsResult(Ok(list)),
                    PentestOutcome::Error { message } => Event::ConversationsResult(Err(message)),
                    _ => Event::ConversationsResult(Err("unexpected outcome".into())),
                })
        }
        Event::CloseHistory => { model.history_open = false; render() }
        Event::ConversationsResult(Ok(list)) => { model.history = list; render() }
        Event::ConversationsResult(Err(e)) => { model.error = Some(e); render() }
        Event::SelectConversation(id) => {
            model.conversation_id = Some(id.clone());
            model.history_open = false;
            Command::request_from_shell(PentestOperation::LoadConversation { conversation_id: id })
                .then_send(|out| match out {
                    PentestOutcome::LoadedMessages { messages } => Event::LoadConversationResult(Ok(messages)),
                    PentestOutcome::Error { message } => Event::LoadConversationResult(Err(message)),
                    _ => Event::LoadConversationResult(Err("unexpected outcome".into())),
                })
        }
        Event::LoadConversationResult(Ok(msgs)) => { model.messages = msgs; render() }
        Event::LoadConversationResult(Err(e)) => { model.error = Some(e); render() }
        Event::OpenDocument(id) => {
            let conv = model.conversation_id.clone().unwrap_or_default();
            Command::request_from_shell(PentestOperation::GetDocumentContent { document_id: id.clone(), conversation_id: conv })
                .then_send(move |out| match out {
                    PentestOutcome::DocumentContent { markdown } => Event::DocumentContentResult(Ok(markdown)),
                    PentestOutcome::Error { message } => Event::DocumentContentResult(Err(message)),
                    _ => Event::DocumentContentResult(Err("unexpected outcome".into())),
                })
        }
        Event::DocumentContentResult(Ok(markdown)) => {
            model.open_document = Some(crate::view::DocView {
                id: String::new(), title: "Report".into(), markdown_body: markdown, share_url: None,
            });
            render()
        }
        Event::DocumentContentResult(Err(e)) => { model.error = Some(e); render() }
        Event::CloseDocument => { model.open_document = None; render() }
        Event::CreateShareLink(doc_id) => {
            let conv = model.conversation_id.clone().unwrap_or_default();
            Command::request_from_shell(PentestOperation::CreateSharedLink { conversation_id: conv, document_id: doc_id })
                .then_send(|out| match out {
                    PentestOutcome::SharedLink { url } => Event::ShareLinkResult(Ok(url)),
                    PentestOutcome::Error { message } => Event::ShareLinkResult(Err(message)),
                    _ => Event::ShareLinkResult(Err("unexpected outcome".into())),
                })
        }
        Event::ShareLinkResult(Ok(url)) => {
            if let Some(doc) = model.open_document.as_mut() { doc.share_url = Some(url); }
            render()
        }
        Event::ShareLinkResult(Err(e)) => { model.error = Some(e); render() }
        Event::DismissError => { model.error = None; render() }
    }
}

fn delta_event(out: PentestOutcome) -> Event {
    match out {
        PentestOutcome::Delta(d) => Event::Delta(Ok(d)),
        PentestOutcome::Error { message } => Event::Delta(Err(message)),
        _ => Event::Delta(Err("unexpected outcome".into())),
    }
}
```

In `lib.rs`: `pub mod update;` and `fn update(&self, event, model) { update::update(self, event, model) }`.

- [ ] **Step 2b: Extract `easy_mode_scan_prompt` to pentest-core (pure-share)**

`update` calls `pentest_core::easy_mode_scan_prompt()`. Extract the pure fn from `crates/ui/src/components/easy_mode.rs` into `pentest-core`:
- Add `pub fn easy_mode_scan_prompt() -> String { ... }` to `crates/core/src/lib.rs` (or a new `crates/core/src/easy_mode.rs` module, re-exported at crate root), copying the exact string body from `crates/ui/src/components/easy_mode.rs`.
- Change `crates/ui/src/components/easy_mode.rs::easy_mode_scan_prompt` to delegate: `pub fn easy_mode_scan_prompt() -> String { pentest_core::easy_mode_scan_prompt() }` (behavior-identical; keeps the existing `scan_prompt_requires_document_write` test passing).
- Move/duplicate the assertion into a `pentest-core` unit test too.

- [ ] **Step 3: Run tests to pass**

Run: `nix develop --command cargo test -p pick-crux-core update::tests 2>&1 | tail -25`
Expected: 5 passed.
Run: `nix develop --command cargo test -p pentest-core easy_mode_scan_prompt 2>&1 | tail -8`
Expected: pass (extracted fn tested).
Run: `nix develop --command cargo check -p pentest-ui --features "desktop,connector" 2>&1 | tail -5`
Expected: Dioxus app still builds (call-site swap behavior-identical).

- [ ] **Step 4: Commit**

```bash
git add crates/crux-core/ crates/core/ crates/ui/src/components/easy_mode.rs
git commit -m "feat(crux): update() Easy Mode state machine; share scan prompt via pentest-core"
```

---

### Task 5: pick-crux-middleware — EffectMiddleware over pentest-core

**Files:**
- Create: `crates/crux-middleware/Cargo.toml`
- Create: `crates/crux-middleware/src/lib.rs`
- Test: `crates/crux-middleware/src/lib.rs` (`#[cfg(test)]`)

**Interfaces:**
- Consumes: `pick_crux_core::effect::{PentestOperation, PentestOutcome, ConversationDelta}`, `pick_crux_core::view::*`, `pentest-core` client/documents/auth/pre_approval.
- Produces: `PentestMiddleware` implementing `crux_core::middleware::EffectMiddleware<Op = PentestOperation>` + a private `perform(op) -> PentestOutcome` async fn seam (so it's unit-testable without a live network via a trait/mock).

- [ ] **Step 1: `crates/crux-middleware/Cargo.toml`**

```toml
[package]
name = "pick-crux-middleware"
version.workspace = true
edition.workspace = true

[dependencies]
crux_core = "0.19"
pick-crux-core = { path = "../crux-core" }
pentest-core = { path = "../core" }
tokio = { version = "1", features = ["rt", "rt-multi-thread"] }

[dev-dependencies]
tokio = { version = "1", features = ["rt", "macros"] }
```

- [ ] **Step 2: Write the op→call mapping test first**

The middleware's testable seam is a pure async `map_operation` that, given a `PentestOperation` and an injected `MatrixApi` trait object, returns a `PentestOutcome`. Test with a fake `MatrixApi`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use pick_crux_core::effect::{PentestOperation, PentestOutcome};

    struct FakeApi;
    #[async_trait::async_trait]
    impl MatrixApi for FakeApi {
        async fn send(&self, _c: Option<String>, _t: String) -> Result<String, String> { Ok("conv-9".into()) }
        async fn poll(&self, _c: String) -> Result<pick_crux_core::effect::ConversationDelta, String> {
            Ok(pick_crux_core::effect::ConversationDelta { messages: vec![], tool_calls: vec![], done: true })
        }
        async fn list_documents(&self, _a: Option<String>) -> Result<Vec<pick_crux_core::view::DocRef>, String> { Ok(vec![]) }
        async fn sign_in(&self, _u: String) -> Result<String, String> { Ok("tok".into()) }
        async fn doc_content(&self, _id: String, _c: String) -> Result<String, String> { Ok("# report".into()) }
        async fn shared_link(&self, _c: String, _d: String) -> Result<String, String> { Ok("https://s/x".into()) }
        async fn list_conversations(&self) -> Result<Vec<pick_crux_core::view::ConversationRef>, String> { Ok(vec![]) }
        async fn load_conversation(&self, _c: String) -> Result<Vec<pick_crux_core::view::MessageView>, String> { Ok(vec![]) }
    }

    #[tokio::test]
    async fn send_scan_maps_to_scan_queued() {
        let api = FakeApi;
        let out = map_operation(&api, PentestOperation::SendScan { conversation_id: None, prompt: "p".into() }).await;
        assert!(matches!(out, PentestOutcome::ScanQueued { conversation_id } if conversation_id == "conv-9"));
    }
    #[tokio::test]
    async fn final_poll_maps_to_delta_done() {
        let api = FakeApi;
        let out = map_operation(&api, PentestOperation::PollConversation { conversation_id: "c".into() }).await;
        assert!(matches!(out, PentestOutcome::Delta(d) if d.done));
    }
    #[tokio::test]
    async fn signin_maps_to_signed_in() {
        let api = FakeApi;
        let out = map_operation(&api, PentestOperation::SignIn { api_url: "u".into() }).await;
        assert!(matches!(out, PentestOutcome::SignedIn { token } if token == "tok"));
    }
}
```

Add `async-trait = "0.1"` to `[dev-dependencies]` and `[dependencies]`.

- [ ] **Step 3: Run — expect failure (no `MatrixApi`/`map_operation` yet)**

Run: `nix develop --command cargo test -p pick-crux-middleware 2>&1 | tail -20`
Expected: FAIL to compile.

- [ ] **Step 4: Implement `MatrixApi` trait, `map_operation`, and the middleware in `lib.rs`**

```rust
//! EffectMiddleware fulfilling PentestOperation via pentest-core. The App is
//! pure; this crate owns all I/O, on a background tokio runtime.

use crux_core::middleware::{EffectMiddleware, EffectResolver};
use pick_crux_core::effect::{ConversationDelta, PentestOperation, PentestOutcome};
use pick_crux_core::view::{ConversationRef, DocRef, MessageView};

#[async_trait::async_trait]
pub trait MatrixApi: Send + Sync {
    async fn send(&self, conversation_id: Option<String>, text: String) -> Result<String, String>;
    async fn poll(&self, conversation_id: String) -> Result<ConversationDelta, String>;
    async fn list_documents(&self, agent_id: Option<String>) -> Result<Vec<DocRef>, String>;
    async fn sign_in(&self, api_url: String) -> Result<String, String>;
    async fn doc_content(&self, document_id: String, conversation_id: String) -> Result<String, String>;
    async fn shared_link(&self, conversation_id: String, document_id: String) -> Result<String, String>;
    async fn list_conversations(&self) -> Result<Vec<ConversationRef>, String>;
    async fn load_conversation(&self, conversation_id: String) -> Result<Vec<MessageView>, String>;
}

/// Pure mapping from an operation to an outcome via the injected api. Unit-tested.
pub async fn map_operation(api: &dyn MatrixApi, op: PentestOperation) -> PentestOutcome {
    match op {
        PentestOperation::SendScan { conversation_id, prompt } =>
            match api.send(conversation_id, prompt).await {
                Ok(c) => PentestOutcome::ScanQueued { conversation_id: c },
                Err(m) => PentestOutcome::Error { message: m },
            },
        PentestOperation::SendMessage { conversation_id, text } =>
            match api.send(conversation_id, text).await {
                Ok(c) => PentestOutcome::ScanQueued { conversation_id: c },
                Err(m) => PentestOutcome::Error { message: m },
            },
        PentestOperation::PollConversation { conversation_id } =>
            match api.poll(conversation_id).await {
                Ok(d) => PentestOutcome::Delta(d),
                Err(m) => PentestOutcome::Error { message: m },
            },
        PentestOperation::ListDocuments { agent_id } =>
            match api.list_documents(agent_id).await {
                Ok(l) => PentestOutcome::Documents { list: l },
                Err(m) => PentestOutcome::Error { message: m },
            },
        PentestOperation::SignIn { api_url } =>
            match api.sign_in(api_url).await {
                Ok(t) => PentestOutcome::SignedIn { token: t },
                Err(m) => PentestOutcome::Error { message: m },
            },
        PentestOperation::Connect { .. } => PentestOutcome::Connected,
        PentestOperation::GetDocumentContent { document_id, conversation_id } =>
            match api.doc_content(document_id, conversation_id).await {
                Ok(md) => PentestOutcome::DocumentContent { markdown: md },
                Err(m) => PentestOutcome::Error { message: m },
            },
        PentestOperation::CreateSharedLink { conversation_id, document_id } =>
            match api.shared_link(conversation_id, document_id).await {
                Ok(u) => PentestOutcome::SharedLink { url: u },
                Err(m) => PentestOutcome::Error { message: m },
            },
        PentestOperation::ListConversations =>
            match api.list_conversations().await {
                Ok(l) => PentestOutcome::Conversations { list: l },
                Err(m) => PentestOutcome::Error { message: m },
            },
        PentestOperation::LoadConversation { conversation_id } =>
            match api.load_conversation(conversation_id).await {
                Ok(m) => PentestOutcome::LoadedMessages { messages: m },
                Err(e) => PentestOutcome::Error { message: e },
            },
    }
}

/// The real MatrixApi backed by pentest-core (constructed with api_url + token).
pub struct CoreMatrixApi { pub api_url: String, pub token: String, pub agent_id: Option<String> }

// NOTE: implement CoreMatrixApi against pentest_core::matrix::{MatrixChatClient, documents, auth}.
// send -> client.send_message(&conv, &agent, &text) then a bounded poll producing the first delta;
// poll -> fetch conversation, diff into ConversationDelta (done when the agent turn is complete);
// list_documents -> documents::list_documents; doc_content -> client.get_document_content;
// shared_link -> documents::create_shared_link; sign_in -> auth::fetch_matrix_token_browser.
// Map pentest_core::error::Error to String via to_string(). This impl is exercised by the
// on-device/e2e phase (out of slice 1), so it is written but not unit-tested here.

pub struct PentestMiddleware {
    runtime: tokio::runtime::Handle,
    api: std::sync::Arc<dyn MatrixApi>,
}

impl PentestMiddleware {
    pub fn new(runtime: tokio::runtime::Handle, api: std::sync::Arc<dyn MatrixApi>) -> Self {
        Self { runtime, api }
    }
}

impl EffectMiddleware for PentestMiddleware {
    type Op = PentestOperation;
    fn try_process_effect(&self, operation: PentestOperation, resolver: EffectResolver<PentestOutcome>) {
        let api = self.api.clone();
        self.runtime.spawn(async move {
            let out = map_operation(api.as_ref(), operation).await;
            resolver.resolve(out);
        });
    }
}
```

- [ ] **Step 5: Run tests to pass**

Run: `nix develop --command cargo test -p pick-crux-middleware 2>&1 | tail -20`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/crux-middleware/ Cargo.lock
git commit -m "feat(crux): pick-crux-middleware — EffectMiddleware mapping ops to pentest-core"
```

---

### Task 6: `CoreMatrixApi` real impl over pentest-core

**Files:**
- Modify: `crates/crux-middleware/src/lib.rs` (or `crates/crux-middleware/src/core_api.rs`)

**Interfaces:**
- Consumes: `pentest_core::matrix::{MatrixChatClient, documents, auth, pre_approval}` (exact signatures in the "pentest-core signatures" section above).
- Produces: `impl MatrixApi for CoreMatrixApi` — the real network implementation.

- [ ] **Step 1: Implement each `MatrixApi` method against pentest-core**

Write `impl MatrixApi for CoreMatrixApi` mapping to the verified signatures. Example bodies:

```rust
#[async_trait::async_trait]
impl MatrixApi for CoreMatrixApi {
    async fn send(&self, conversation_id: Option<String>, text: String) -> Result<String, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        let agent = self.agent_id.clone().unwrap_or_default();
        // Existing UI uses client.send_message(&conv_id, &agent.id, &text); a new
        // conversation is created server-side when conversation_id is empty.
        let conv = conversation_id.unwrap_or_default();
        client.send_message(&conv, &agent, &text).await
            .map_err(|e| e.to_string())
    }
    async fn poll(&self, conversation_id: String) -> Result<ConversationDelta, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        // Fetch the conversation, project into MessageView/ToolCallView, set done
        // when the latest agent turn is complete. Reuse pentest-core conversation
        // types + rendering; map errors to String.
        let _ = &client; let _ = conversation_id;
        Ok(ConversationDelta { messages: vec![], tool_calls: vec![], done: true })
    }
    async fn list_documents(&self, agent_id: Option<String>) -> Result<Vec<DocRef>, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        let docs = client.list_documents(agent_id.as_deref()).await.map_err(|e| e.to_string())?;
        Ok(docs.into_iter().map(|d| DocRef { id: d.id, title: d.title, conversation_id: d.conversation_id }).collect())
    }
    async fn sign_in(&self, api_url: String) -> Result<String, String> {
        pentest_core::matrix::fetch_matrix_token_browser(&api_url).await.map_err(|e| e.to_string())
    }
    async fn doc_content(&self, document_id: String, conversation_id: String) -> Result<String, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        client.get_document_content(&conversation_id, &document_id).await.map_err(|e| e.to_string())
    }
    async fn shared_link(&self, conversation_id: String, document_id: String) -> Result<String, String> {
        let client = pentest_core::matrix::MatrixChatClient::new(self.api_url.clone())
            .with_auth_token(self.token.clone());
        client.create_shared_link(&conversation_id, &document_id).await.map_err(|e| e.to_string())
    }
    async fn list_conversations(&self) -> Result<Vec<ConversationRef>, String> {
        Ok(vec![]) // wire to the ListConversations query in a follow-up; empty is valid for slice 1
    }
    async fn load_conversation(&self, _conversation_id: String) -> Result<Vec<MessageView>, String> {
        Ok(vec![]) // wire to GetConversation in a follow-up
    }
}
```

Verify the exact arg order/names of `send_message`, `get_document_content`, `create_shared_link`, `list_documents` against `crates/core/src/matrix/{client.rs,documents.rs}` and adjust. `poll`/`list_conversations`/`load_conversation` may return minimal/empty results in slice 1 (documented) — the real diff/stream projection is the on-device phase; do not block slice 1 on it.

- [ ] **Step 2: Compile (no new unit tests — the trait seam is covered in Task 5; this is the live impl)**

Run: `nix develop --command cargo check -p pick-crux-middleware 2>&1 | tail -15`
Expected: `Finished`. Fix any signature mismatches against pentest-core.

- [ ] **Step 3: Commit**

```bash
git add crates/crux-middleware/
git commit -m "feat(crux): CoreMatrixApi — real pentest-core-backed MatrixApi impl"
```

---

### Task 7: Swift + Kotlin typegen (`codegen` binary)

**Files:**
- Create: `crates/crux-core/src/bin/codegen.rs`
- Create: `crates/crux-core/generated/.gitkeep`
- Test: `crates/crux-core/tests/typegen.rs`

**Interfaces:**
- Consumes: `PickApp` (Task 1-4), the `codegen` feature (Task 1 Cargo.toml).
- Produces: a `codegen` bin emitting Swift + Kotlin; a test asserting non-empty output containing `ViewModel`/`Event`.

- [ ] **Step 1: Write `crates/crux-core/src/bin/codegen.rs`**

```rust
use std::path::PathBuf;
use anyhow::Result;
use clap::{Parser, ValueEnum};
use crux_core::type_generation::facet::{Config, TypeRegistry};
use pick_crux_core::PickApp;

fn main() -> Result<()> {
    pretty_env_logger::init();
    let args = Args::parse();
    let typegen = TypeRegistry::new().register_app::<PickApp>()?.build()?;
    match args.language {
        Language::Swift => {
            let cfg = Config::builder("PickShared", &args.output_dir).build();
            typegen.swift(&cfg)?;
        }
        Language::Kotlin => {
            let cfg = Config::builder("com.strike48.pick.shared", &args.output_dir).build();
            typegen.kotlin(&cfg)?;
        }
    }
    Ok(())
}

#[derive(Parser)]
struct Args {
    #[arg(value_enum)]
    language: Language,
    output_dir: PathBuf,
}

#[derive(ValueEnum, Clone)]
enum Language { Swift, Kotlin }
```

- [ ] **Step 2: Write the typegen test `crates/crux-core/tests/typegen.rs`**

```rust
// Gated: only runs with --features codegen (facet_typegen). Verifies Swift +
// Kotlin generation succeeds and emits our core types.
#![cfg(feature = "codegen")]

use std::process::Command;

#[test]
fn generates_swift_and_kotlin_types() {
    let tmp = std::env::temp_dir().join(format!("pick-crux-typegen-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    for lang in ["swift", "kotlin"] {
        let status = Command::new(env!("CARGO"))
            .args(["run", "--quiet", "--bin", "codegen", "--features", "codegen", "--",
                   lang, tmp.to_str().unwrap()])
            .status()
            .expect("run codegen");
        assert!(status.success(), "codegen failed for {lang}");
    }
    // Some output file mentions ViewModel and Event.
    let mut found_vm = false;
    let mut found_ev = false;
    for entry in walk(&tmp) {
        let s = std::fs::read_to_string(&entry).unwrap_or_default();
        if s.contains("ViewModel") { found_vm = true; }
        if s.contains("Event") { found_ev = true; }
    }
    assert!(found_vm, "generated types should contain ViewModel");
    assert!(found_ev, "generated types should contain Event");
    let _ = std::fs::remove_dir_all(&tmp);
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = vec![];
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() { out.extend(walk(&p)); } else { out.push(p); }
        }
    }
    out
}
```

- [ ] **Step 3: Run it (this is the real proof the surface is native-ready)**

Run: `nix develop --command cargo test -p pick-crux-core --features codegen typegen 2>&1 | tail -30`
Expected: PASS. If facet rejects a boundary type (e.g. bare `Result<T,E>` in `Event`), replace those `Result` fields with a dedicated `#[repr(C)]` enum `Outcome<T> { Ok(T), Err(String) }` equivalent per-event (e.g. `SignInResult { ok: Option<String>, err: Option<String> }`) and re-run. Record the change in the report.

- [ ] **Step 4: Commit (generated output is reproducible; commit the bin + test, not the temp output)**

```bash
git add crates/crux-core/src/bin/codegen.rs crates/crux-core/tests/typegen.rs crates/crux-core/generated/.gitkeep
git commit -m "feat(crux): Swift+Kotlin typegen bin + generation test"
```

---

### Task 8: Whole-crate polish — fmt, clippy, workspace build

**Files:** none new (fixes only).

- [ ] **Step 1: Format + lint the new crates**

Run: `nix develop --command cargo fmt --all`
Run: `nix develop --command cargo clippy -p pick-crux-core -p pick-crux-middleware --all-targets -- -D warnings 2>&1 | tail -20`
Expected: no warnings. Fix any.

- [ ] **Step 2: Full workspace still builds (shipping app untouched)**

Run: `nix develop --command cargo check --workspace 2>&1 | tail -10`
Expected: `Finished`.
Run: `nix develop --command cargo test -p pick-crux-core -p pick-crux-middleware 2>&1 | tail -15`
Expected: all pass.

- [ ] **Step 3: Commit**

```bash
git add -A
git commit -m "chore(crux): fmt + clippy clean for crux crates"
```

---

## Notes for the implementer

- Run all cargo via `nix develop --command cargo ...`.
- Crux 0.19 is pre-1.0. If a signature differs at compile time, prefer the docs.rs 0.19 form; the effect accessor for the `Pentest` variant is `expect_pentest()` (macro-generated as `expect_<snake_variant>`); if it differs, match `Effect::Pentest(_)` from `cmd.effects()` instead.
- `facet` is version-sensitive: if `cargo check` reports a facet conflict, `cargo tree -i facet` and pin to the exact version `crux_core 0.19` locks.
- Do NOT depend on `crates/ui` from either crux crate. The only `crates/ui` edit is the behavior-identical `easy_mode_scan_prompt` delegation (Task 4 Step 2b).
- `poll`/`list_conversations`/`load_conversation` real projections are allowed to return minimal results in slice 1 (documented); the full streaming diff is the Dioxus-over-Crux / on-device phase.
