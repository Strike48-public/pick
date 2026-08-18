# Easy-Mode AuthFlow State Machine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the scattered easy-mode auth signals (`needs_sign_in`, `force_sign_in`, `retry_tick`) with one explicit `AuthFlow` enum + pure `reduce()` reducer that is the sole writer of easy-mode login/connection state, eliminating the double-sign-in bug.

**Architecture:** A new pure, Dioxus-free module `crates/ui/src/auth_flow.rs` holds `AuthFlow`, `AuthEvent`, and `reduce()`. `connector_app` owns a single `Signal<AuthFlow>` plus a `dispatch(event)` closure — the only writer. The easy-mode render branch, `EasyModeShell`, and `ChatPanel`'s auth-failure recovery all derive from / dispatch into `flow`. Expert mode is untouched.

**Tech Stack:** Rust, Dioxus 0.7 (signals/effects), the existing `crates/ui` connector app. Tests are plain `#[test]` unit tests in the new module.

## Global Constraints

- **Easy mode only.** Expert mode keeps its existing `compute_screen`/`ConfigForm`/lazy-browser-auth path. Never route expert mode through `AuthFlow`.
- **`auth_flow.rs` is pure:** no `dioxus::` imports, no I/O. Only `reduce()` + the two enums + `ConnectingStep` (imported from `crate::components::ConnectingStep`, which is `Copy`). This keeps it unit-testable.
- **`dispatch` is the sole writer of `flow`.** No component calls `flow.set(...)` directly.
- **`SignInRequested` is idempotent:** it advances state only from `AwaitingGesture`; from any other state it returns the state unchanged. This is the structural fix for the double-sign-in.
- **Optimistic-then-downgrade for restored tokens:** a restored chat token enters `Connected { chat_ready: false }` (no overlay); a later `ChatAuthDead` downgrades to `Failed { reauth: true }` (overlay). The app is never in "logged-in shell + overlay" simultaneously.
- **Overlay visibility** is derived purely as `matches!(flow, AwaitingGesture | Failed { reauth: true })` — never from token emptiness.
- **Incremental:** every task leaves the workspace compiling and the app runnable. The old signals are removed only in the final task, after `reduce` is the sole writer.
- Do **not** touch: `crates/core/src/matrix/auth.rs` (OAuth transport), `crates/ui/src/session.rs` / `crates/core/src/config.rs` (persistence), or the `AlreadyBorrowed` connector-borrow-across-await fixes in `on_disconnect`/`on_logout`.
- Verify build with: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings` (CI runs `-D warnings`). Reducer unit tests: `nix develop --command cargo test -p pentest-ui --lib auth_flow`.

## Reference: current code (read before starting)

- `ConnectingStep` (Copy enum): `crates/ui/src/components/connecting_screen.rs:9` — variants `SigningIn, Connecting, Registering, WaitingForApproval, ExchangingToken, Finalizing`.
- `ConnectorStatus`: `crates/core/src/state.rs:7` — `Disconnected, Connecting, Registered, Reconnecting, Error(String)`.
- Easy-mode render short-circuit: `crates/ui/src/connector_app.rs:1072` (`if easy_mode() && !matches!(screen, AppScreen::Connected(_) | AppScreen::Connecting(_))`), the `match screen` at `:1098`, the `if easy_mode()` inside `Connected` at `:1155`.
- Auto-connect effect (to be removed): `connector_app.rs:783-857` (keyed on `retry_tick()`, reads+writes `force_sign_in`).
- Disconnected→needs_sign_in effect: `connector_app.rs:867-875`.
- `plg_sign_in_and_connect` closure: `connector_app.rs:681`.
- `on_logout`: `connector_app.rs` (~910-952); `on_disconnect`: (~883-901).
- Signal declarations: `needs_sign_in` `:369`, `retry_tick` `:370`, `force_sign_in` (via `ForceSignIn`) `:378`; `ForceSignIn` newtype `:41`, exported `lib.rs:23`.
- `EasyModeShell`: `crates/ui/src/components/easy_mode.rs` — contexts at `:51-55`, token watch `:91-99`, overlay-driving effect `:101-114`, sign-in overlay + button `:304-330` (button fan-out sets `force_sign_in`+`needs_sign_in`+`retry_tick`).
- `ChatPanel`: `crates/ui/src/components/chat_panel/mod.rs` — auth-fail recovery `:594-617`, `agents_loaded` set sites `:513,525,537,557`.
- Connector event loop: `crates/ui/src/lib.rs:88-137` (`run_event_loop`, `EventLoopSignals`).
- Reducer test style to mirror: `crates/core/src/config.rs:1414` (`plg_connect_decision_matrix`).

---

### Task 1: Pure `auth_flow` module + reducer with full transition-table tests

**Files:**
- Create: `crates/ui/src/auth_flow.rs`
- Modify: `crates/ui/src/lib.rs` (add `pub mod auth_flow;` after line 5's `pub mod components;`)

**Interfaces:**
- Consumes: `crate::components::ConnectingStep` (Copy enum).
- Produces:
  - `pub enum AuthFlow { Restoring, Disconnected, AwaitingGesture, SigningIn, Registering(ConnectingStep), Connected { chat_ready: bool }, Failed { reason: String, reauth: bool } }` — `#[derive(Debug, Clone, PartialEq)]`.
  - `pub enum AuthEvent { Restored { have_token: bool }, CredsFound, CredsAbsent, SignInRequested, TokenObtained, TokenFailed(String), ConnectorStep(ConnectingStep), ConnectorRegistered, ChatReady, ChatAuthDead, LoggedOut, Disconnected }` — `#[derive(Debug, Clone, PartialEq)]`.
  - `pub fn reduce(state: AuthFlow, event: AuthEvent, easy: bool, auto: bool) -> AuthFlow`.

- [ ] **Step 1: Create the module with the two enums and the reducer**

Create `crates/ui/src/auth_flow.rs`:

```rust
//! Explicit state machine for the easy-mode login/connection flow.
//!
//! This is the single source of truth for "where is the user in signing in and
//! connecting". It replaces the scattered `needs_sign_in` / `force_sign_in` /
//! `retry_tick` signals whose interactions caused a double-sign-in (the
//! sign-in effect re-ran because it wrote a signal it read, and a restored
//! dead token made the shell render logged-in while the overlay also showed).
//!
//! Pure and Dioxus-free so it can be unit-tested exhaustively. The UI layer
//! (`connector_app`) holds a `Signal<AuthFlow>` and mutates it ONLY through a
//! `dispatch(event)` closure that calls [`reduce`].

use crate::components::ConnectingStep;

/// Where the easy-mode user is in the sign-in + connect lifecycle.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthFlow {
    /// Startup, before the first decision is made.
    Restoring,
    /// Transient disconnected state; startup logic decides the next step.
    Disconnected,
    /// Sign-in overlay shown, waiting for the user's tap.
    AwaitingGesture,
    /// Browser / native OAuth is in flight.
    SigningIn,
    /// Connector `connect_and_run` in progress, post-token. Carries the
    /// sub-step for the connecting screen.
    Registering(ConnectingStep),
    /// Connector registered. `chat_ready` folds "agents loaded".
    Connected { chat_ready: bool },
    /// Sign-in/connect failed. `reauth` = the chat token is dead and we should
    /// offer the sign-in overlay again.
    Failed { reason: String, reauth: bool },
}

/// Events that drive [`AuthFlow`] transitions. Emitted by the UI layer from
/// user actions, the connector event loop, and the chat panel.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthEvent {
    /// Startup: whether a persisted chat token was restored.
    Restored { have_token: bool },
    /// Startup: SDK connector credentials exist on disk.
    CredsFound,
    /// Startup: no connector credentials on disk.
    CredsAbsent,
    /// The user tapped the "Sign in" button. The ONLY way to reach SigningIn.
    SignInRequested,
    /// A chat token was obtained (browser/native OAuth returned).
    TokenObtained,
    /// OAuth failed.
    TokenFailed(String),
    /// Connector connect progressed to a sub-step.
    ConnectorStep(ConnectingStep),
    /// Connector finished registering.
    ConnectorRegistered,
    /// Agents loaded — chat is usable.
    ChatReady,
    /// The chat token is dead (server rejected it).
    ChatAuthDead,
    /// The user logged out.
    LoggedOut,
    /// The connector transport dropped.
    Disconnected,
}

/// Pure transition function. `easy` is the resolved easy-mode flag and `auto`
/// is the persisted `auto_connect` setting; together they decide the startup
/// branch. In expert mode (`easy == false`) the caller does not route through
/// this machine, but `reduce` still returns a sensible value.
pub fn reduce(state: AuthFlow, event: AuthEvent, easy: bool, auto: bool) -> AuthFlow {
    use AuthEvent as E;
    use AuthFlow as S;

    match (state, event) {
        // ---- Startup ------------------------------------------------------
        // A restored token is trusted optimistically: show the shell, no
        // overlay. A later ChatAuthDead downgrades to Failed { reauth }.
        (S::Restoring, E::Restored { have_token: true }) => S::Connected { chat_ready: false },
        // No token: decide by creds + auto_connect (mirrors plg_connect_decision).
        (S::Restoring, E::Restored { have_token: false }) => S::Disconnected,
        (S::Disconnected, E::CredsFound) if auto => S::Registering(ConnectingStep::Connecting),
        (S::Disconnected, E::CredsFound) => S::AwaitingGesture,
        (S::Disconnected, E::CredsAbsent) => S::AwaitingGesture,

        // ---- The gesture (idempotent) ------------------------------------
        // Only AwaitingGesture advances; any other state is unchanged, so a
        // duplicate dispatch cannot launch a second sign-in.
        (S::AwaitingGesture, E::SignInRequested) => S::SigningIn,
        (other, E::SignInRequested) => other,

        // ---- Sign-in in flight -------------------------------------------
        (S::SigningIn, E::TokenObtained) => S::Registering(ConnectingStep::SigningIn),
        (S::SigningIn, E::TokenFailed(reason)) => S::Failed { reason, reauth: true },

        // ---- Connector connect -------------------------------------------
        (S::Registering(_), E::ConnectorStep(step)) => S::Registering(step),
        (S::Registering(_), E::ConnectorRegistered) => S::Connected { chat_ready: false },

        // ---- Connected ----------------------------------------------------
        (S::Connected { .. }, E::ChatReady) => S::Connected { chat_ready: true },
        (S::Connected { .. }, E::ChatAuthDead) => S::Failed {
            reason: "Your session expired".to_string(),
            reauth: true,
        },

        // ---- Global transitions ------------------------------------------
        (_, E::LoggedOut) => S::AwaitingGesture,
        (_, E::Disconnected) => S::Disconnected,

        // Anything else is a no-op (keep current state). `easy` is reserved for
        // future expert/easy divergence; unused branches keep it referenced.
        (state, _) => {
            let _ = easy;
            state
        }
    }
}
```

Add to `crates/ui/src/lib.rs` immediately after `pub mod components;` (line 5):

```rust
pub mod auth_flow;
```

- [ ] **Step 2: Add the transition-table test module (write failing tests first)**

Append to `crates/ui/src/auth_flow.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::components::ConnectingStep;

    // The double-sign-in fix: SignInRequested advances only from AwaitingGesture.
    #[test]
    fn sign_in_requested_is_idempotent() {
        assert_eq!(
            reduce(AuthFlow::AwaitingGesture, AuthEvent::SignInRequested, true, false),
            AuthFlow::SigningIn
        );
        // From SigningIn (already in flight) it's a no-op.
        assert_eq!(
            reduce(AuthFlow::SigningIn, AuthEvent::SignInRequested, true, false),
            AuthFlow::SigningIn
        );
        // From Connected it's a no-op.
        assert_eq!(
            reduce(
                AuthFlow::Connected { chat_ready: true },
                AuthEvent::SignInRequested,
                true,
                false
            ),
            AuthFlow::Connected { chat_ready: true }
        );
    }

    // Restored token → optimistic Connected (no overlay).
    #[test]
    fn restored_token_is_optimistically_connected() {
        assert_eq!(
            reduce(AuthFlow::Restoring, AuthEvent::Restored { have_token: true }, true, true),
            AuthFlow::Connected { chat_ready: false }
        );
    }

    // Dead token downgrades Connected → Failed { reauth }.
    #[test]
    fn chat_auth_dead_downgrades_to_failed_reauth() {
        let s = reduce(
            AuthFlow::Connected { chat_ready: false },
            AuthEvent::ChatAuthDead,
            true,
            true,
        );
        assert!(matches!(s, AuthFlow::Failed { reauth: true, .. }));
    }

    // No token at startup: creds + auto → silent connect; else → overlay.
    #[test]
    fn startup_no_token_branches_on_creds_and_auto() {
        let disc = reduce(AuthFlow::Restoring, AuthEvent::Restored { have_token: false }, true, true);
        assert_eq!(disc, AuthFlow::Disconnected);
        // creds present + auto → auto-connect
        assert_eq!(
            reduce(AuthFlow::Disconnected, AuthEvent::CredsFound, true, true),
            AuthFlow::Registering(ConnectingStep::Connecting)
        );
        // creds present but auto off → overlay (user must tap)
        assert_eq!(
            reduce(AuthFlow::Disconnected, AuthEvent::CredsFound, true, false),
            AuthFlow::AwaitingGesture
        );
        // no creds → overlay
        assert_eq!(
            reduce(AuthFlow::Disconnected, AuthEvent::CredsAbsent, true, true),
            AuthFlow::AwaitingGesture
        );
    }

    // Sign-in → token → registering → connected happy path.
    #[test]
    fn happy_path_signin_to_connected() {
        let s = AuthFlow::AwaitingGesture;
        let s = reduce(s, AuthEvent::SignInRequested, true, false);
        assert_eq!(s, AuthFlow::SigningIn);
        let s = reduce(s, AuthEvent::TokenObtained, true, false);
        assert_eq!(s, AuthFlow::Registering(ConnectingStep::SigningIn));
        let s = reduce(s, AuthEvent::ConnectorStep(ConnectingStep::Registering), true, false);
        assert_eq!(s, AuthFlow::Registering(ConnectingStep::Registering));
        let s = reduce(s, AuthEvent::ConnectorRegistered, true, false);
        assert_eq!(s, AuthFlow::Connected { chat_ready: false });
        let s = reduce(s, AuthEvent::ChatReady, true, false);
        assert_eq!(s, AuthFlow::Connected { chat_ready: true });
    }

    // Logout always returns to the sign-in overlay.
    #[test]
    fn logout_returns_to_awaiting_gesture() {
        assert_eq!(
            reduce(AuthFlow::Connected { chat_ready: true }, AuthEvent::LoggedOut, true, true),
            AuthFlow::AwaitingGesture
        );
    }

    // Token failure during sign-in → Failed { reauth }.
    #[test]
    fn token_failure_is_reauth_failure() {
        let s = reduce(AuthFlow::SigningIn, AuthEvent::TokenFailed("boom".into()), true, false);
        assert_eq!(s, AuthFlow::Failed { reason: "boom".into(), reauth: true });
    }
}
```

- [ ] **Step 3: Run the tests, verify they pass**

Run: `nix develop --command cargo test -p pentest-ui --lib auth_flow`
Expected: all 7 tests pass. (If a test fails, the reducer in Step 1 has a transition wrong — fix the reducer, not the test.)

- [ ] **Step 4: Clippy the crate**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: `Finished` with no warnings. (The module is unused by callers yet; `reduce`/enums are `pub` so no dead-code warning.)

- [ ] **Step 5: Commit**

```bash
git add crates/ui/src/auth_flow.rs crates/ui/src/lib.rs
git commit -m "feat(easy-mode): pure AuthFlow state machine + reducer (unwired)"
```

---

### Task 2: Introduce `flow` signal + `dispatch`, mirroring into the old signals

This task adds the state machine to `connector_app` and makes `dispatch` the writer, while **also** keeping the old `needs_sign_in`/`force_sign_in` signals in sync (mirroring) so the existing render/effects keep working unchanged. Nothing observable changes yet — this is the safety scaffold for Tasks 3-6.

**Files:**
- Modify: `crates/ui/src/connector_app.rs`

**Interfaces:**
- Consumes: `crate::auth_flow::{AuthFlow, AuthEvent, reduce}` (Task 1).
- Produces (in `connector_app` scope, used by Tasks 3-6):
  - `flow: Signal<AuthFlow>` provided via `use_context_provider` so `EasyModeShell`/`ChatPanel` can read it.
  - `dispatch: impl Fn(AuthEvent)` closure (Copy-capturing signals) that sets `flow` via `reduce` AND mirrors: on `AwaitingGesture`/`Failed{reauth:true}` sets `needs_sign_in=true` else `false`.

- [ ] **Step 1: Add the import**

At the top of `crates/ui/src/connector_app.rs`, with the other `use` lines, add:

```rust
use crate::auth_flow::{reduce, AuthEvent, AuthFlow};
```

- [ ] **Step 2: Declare the `flow` signal + seed it from startup inputs**

In `connector_app`, immediately after the `force_sign_in` provider (`:378`), add:

```rust
    // Explicit easy-mode auth state machine (replaces needs_sign_in/force_sign_in/
    // retry_tick — see auth_flow.rs). Provided as context so EasyModeShell and
    // ChatPanel can read it. `dispatch` (below) is the ONLY writer.
    let flow = use_context_provider(|| Signal::new(AuthFlow::Restoring));
```

- [ ] **Step 3: Add the `dispatch` closure (mirrors into old signals)**

Immediately after the `flow` declaration, add:

```rust
    // Single writer for `flow`. Mirrors into the legacy `needs_sign_in` signal so
    // the existing render/effects keep working during the incremental migration
    // (removed in the final task once nothing reads the legacy signals).
    let dispatch = {
        let mut flow = flow;
        let mut needs_sign_in = needs_sign_in;
        let easy_mode = easy_mode;
        let settings = settings;
        move |ev: AuthEvent| {
            let auto = settings.peek().auto_connect;
            let next = reduce(flow.peek().clone(), ev, easy_mode(), auto);
            let overlay =
                matches!(next, AuthFlow::AwaitingGesture | AuthFlow::Failed { reauth: true, .. });
            flow.set(next);
            if *needs_sign_in.peek() != overlay {
                needs_sign_in.set(overlay);
            }
        }
    };
```

- [ ] **Step 4: Seed the machine once at startup**

Find the chat-token restore `use_hook` (`connector_app.rs:421-431`). Immediately AFTER it, add a one-shot hook that emits the startup events:

```rust
    // Drive the AuthFlow machine's initial transition from the same inputs the
    // legacy effects used: restored token, then creds presence. One-shot.
    {
        let dispatch = dispatch.clone();
        let device_id = device_id.clone();
        let easy_env = easy_mode_env_config.clone();
        use_hook(move || {
            let have_token = !matrix_auth_token.peek().is_empty();
            dispatch(AuthEvent::Restored { have_token });
            if !have_token {
                // Mirror the auto-connect effect's candidate/creds check.
                let candidate = settings.peek().last_config.clone().or_else(|| {
                    easy_env.clone().map(|mut c| {
                        c.instance_id = device_id.clone();
                        c
                    })
                });
                if let Some(candidate) = candidate {
                    let scoped = pentest_core::config::ConnectorConfig::env_scoped_instance_id(
                        &device_id,
                        &candidate.host,
                    );
                    let creds = pentest_core::config::ConnectorConfig::credentials_present(
                        &candidate.connector_name,
                        &scoped,
                    );
                    dispatch(if creds { AuthEvent::CredsFound } else { AuthEvent::CredsAbsent });
                } else {
                    dispatch(AuthEvent::CredsAbsent);
                }
            }
        });
    }
```

Note: `dispatch` must be `Clone`. Since it captures only `Copy` signals + `easy_mode`/`settings` (also `Copy` signals), derive clone by making it a plain closure and cloning captured `String`s where needed. If the borrow checker complains about `dispatch.clone()`, wrap `dispatch` in `std::rc::Rc::new(dispatch)` at declaration and clone the `Rc`.

- [ ] **Step 5: Build + clippy**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: `Finished`, no warnings. (`flow` is written by `dispatch` and read by the mirror; if clippy warns `flow` is never read, that's expected until Task 5 — silence it by prefixing the binding `let _flow_unused_until_task5 = flow;`? No — instead, temporarily read it: this is acceptable because Task 5 adds the real read within the same PR. If a warning blocks, add `#[allow(unused)]` on the `flow` line with a `// removed in Task 5` comment.)

- [ ] **Step 6: Manual smoke test (desktop)**

Run the desktop app (`/tmp/run-pick-direct.sh` via Bash `run_in_background: true`) and confirm behavior is unchanged: with stored creds it auto-connects to the shell; the sign-in button still works. (Mirroring keeps old paths live.)

- [ ] **Step 7: Commit**

```bash
git add crates/ui/src/connector_app.rs
git commit -m "feat(easy-mode): add AuthFlow signal + dispatch, mirroring legacy signals"
```

---

### Task 3: Launch sign-in from the transition, kill the self-triggering effect

Replace the `retry_tick`-keyed auto-connect effect (the double-fire source) with dispatch-driven launches. This is the core bug fix.

**Files:**
- Modify: `crates/ui/src/connector_app.rs`

**Interfaces:**
- Consumes: `dispatch`, `flow`, `plg_sign_in_and_connect`, `on_connect` (existing).
- Produces: an effect keyed on `flow()` that launches `plg_sign_in_and_connect` on entry to `SigningIn` and `on_connect` on entry to `Registering` from a creds-based startup.

- [ ] **Step 1: Add a flow-driven launch effect**

Add this effect near the old auto-connect effect (which you will delete in Step 2). It fires side effects on state entry, guarded so each launches once:

```rust
    // Launch side effects on AuthFlow entry. Replaces the retry_tick effect,
    // whose read+write of force_sign_in caused it to re-run and double-fire.
    {
        let plg_sign_in_and_connect = plg_sign_in_and_connect.clone();
        let mut launched_signin = use_signal(|| false);
        let mut launched_connect = use_signal(|| false);
        let candidate_for_connect = /* same candidate expression as Task 2 Step 4 */;
        use_effect(move || {
            match flow() {
                AuthFlow::SigningIn => {
                    if !*launched_signin.peek() {
                        launched_signin.set(true);
                        launched_connect.set(false);
                        if let Some(c) = candidate_for_connect.clone() {
                            plg_sign_in_and_connect(c);
                        }
                    }
                }
                AuthFlow::Registering(_) => {
                    // Silent auto-connect path (creds present at startup): connect
                    // without a browser sign-in. Only when we did NOT just sign in.
                    if !*launched_connect.peek() && !*launched_signin.peek() {
                        launched_connect.set(true);
                        if let Some(c) = candidate_for_connect.clone() {
                            let remember = settings.peek().last_config.is_some();
                            on_connect((c, remember));
                        }
                    }
                }
                _ => {
                    launched_signin.set(false);
                    launched_connect.set(false);
                }
            }
        });
    }
```

Extract the `candidate_for_connect` expression (saved-config-else-PLG-env, from Task 2 Step 4) into a small local closure or `let` above both hooks so it isn't duplicated (DRY). Name it `pick_candidate: impl Fn() -> Option<ConnectorConfig>`.

- [ ] **Step 2: Delete the old auto-connect effect**

Remove the entire `use_effect` at `connector_app.rs:783-857` (the one starting `let _ = retry_tick();`). Its responsibilities are now: startup seeding (Task 2 Step 4) + launch-on-entry (Step 1 above).

- [ ] **Step 3: Point `plg_sign_in_and_connect`'s completion at dispatch**

Inside `plg_sign_in_and_connect` (`:681`), the token-obtained and failure branches currently set `status`/`needs_sign_in`. Add dispatch calls alongside (do not remove the `status` sets — the connecting screen still reads status in Task 5's interim):
- On successful `fetch_matrix_token_browser` → `dispatch(AuthEvent::TokenObtained)`.
- On failure → `dispatch(AuthEvent::TokenFailed(e.to_string()))`.

- [ ] **Step 4: Build + clippy**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: `Finished`, no warnings.

- [ ] **Step 5: Manual test — the double-sign-in is gone**

Run the desktop app, log out to reach the sign-in button, tap **Sign in ONCE**. Expected: exactly one browser sign-in occurs (watch `/tmp/*.log` for a single `[BROWSER_AUTH] Opening browser` / one `plg_sign_in_and_connect`), then the shell loads. Previously this required two taps.

- [ ] **Step 6: Commit**

```bash
git add crates/ui/src/connector_app.rs
git commit -m "fix(easy-mode): launch sign-in from AuthFlow transition (kills double-fire)"
```

---

### Task 4: Route logout / disconnect / event-loop through dispatch

**Files:**
- Modify: `crates/ui/src/connector_app.rs` (handlers)
- Modify: `crates/ui/src/lib.rs` (event loop → dispatch bridge)

**Interfaces:**
- Consumes: `dispatch`.
- Produces: `LoggedOut`/`Disconnected`/`ConnectorRegistered`/`ConnectorStep` events flowing into `flow`.

- [ ] **Step 1: on_logout emits LoggedOut**

In `on_logout` (`connector_app.rs` ~910-952), inside the spawned block after clearing token/creds, add `dispatch(AuthEvent::LoggedOut);`. Keep the existing `matrix_auth_token.set(String::new())` etc.

- [ ] **Step 2: on_disconnect emits Disconnected**

In `on_disconnect` (~883-901), after `status.set(ConnectorStatus::Disconnected)`, add `dispatch(AuthEvent::Disconnected);`.

- [ ] **Step 3: Bridge the connector event loop to dispatch**

The event loop (`lib.rs:88-137`) runs in a spawned task with `EventLoopSignals` and cannot call the UI `dispatch` directly. Instead, keep the loop writing `status`/`connecting_step` as today, and add a small effect in `connector_app` that translates status/step changes into events:

```rust
    // Bridge the connector event loop's status/step signals into AuthFlow events.
    {
        let mut last_status = use_signal(|| None::<ConnectorStatus>);
        use_effect(move || {
            let s = status.read().clone();
            if last_status.peek().as_ref() != Some(&s) {
                last_status.set(Some(s.clone()));
                match s {
                    ConnectorStatus::Registered => dispatch(AuthEvent::ConnectorRegistered),
                    ConnectorStatus::Connecting | ConnectorStatus::Reconnecting => {
                        if let Some(step) = *connecting_step.peek() {
                            dispatch(AuthEvent::ConnectorStep(step));
                        }
                    }
                    _ => {}
                }
            }
        });
    }
```

Also add a small effect translating `connecting_step` changes to `ConnectorStep` while `Registering`:

```rust
    {
        let mut last_step = use_signal(|| None::<ConnectingStep>);
        use_effect(move || {
            let step = *connecting_step.read();
            if *last_step.peek() != step {
                last_step.set(step);
                if let Some(step) = step {
                    if matches!(flow.peek(), AuthFlow::Registering(_)) {
                        dispatch(AuthEvent::ConnectorStep(step));
                    }
                }
            }
        });
    }
```

- [ ] **Step 4: Build + clippy**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: `Finished`, no warnings.

- [ ] **Step 5: Manual test**

Run desktop: verify the connecting screen advances (Connecting → Registered → shell) and logout returns to the sign-in button. `flow` now tracks the connector lifecycle.

- [ ] **Step 6: Commit**

```bash
git add crates/ui/src/connector_app.rs crates/ui/src/lib.rs
git commit -m "feat(easy-mode): route logout/disconnect/connector events into AuthFlow"
```

---

### Task 5: Render the easy-mode branch from `flow`; ChatPanel emits ChatReady/ChatAuthDead

**Files:**
- Modify: `crates/ui/src/connector_app.rs` (render, ~1072-1160)
- Modify: `crates/ui/src/components/chat_panel/mod.rs` (recovery ~594-617, agent-load ~513-557)

**Interfaces:**
- Consumes: `flow` (from context in ChatPanel; local in connector_app).
- Produces: easy-mode routing derived from `flow`; `ChatReady`/`ChatAuthDead` events.

- [ ] **Step 1: Replace the easy-mode render short-circuit**

At `connector_app.rs:1072`, replace the condition `if easy_mode() && !matches!(screen, AppScreen::Connected(_) | AppScreen::Connecting(_))` and the easy-mode arm inside `Connected` (`:1155`) with a single easy-mode block that matches `flow()`:

```rust
    if easy_mode() {
        match flow() {
            AuthFlow::SigningIn => rsx! { ConnectingScreen { step: ConnectingStep::SigningIn, host: host.clone(), on_cancel: move |_| on_disconnect(()) } },
            AuthFlow::Registering(step) => rsx! { ConnectingScreen { step, host: host.clone(), on_cancel: move |_| on_disconnect(()) } },
            // Restoring / Disconnected / AwaitingGesture / Failed / Connected all
            // render the shell; the overlay inside EasyModeShell is driven by flow.
            _ => rsx! {
                EasyModeShell {
                    api_url: chat_api_url.clone(),
                    auth_token: matrix_auth_token.read().clone(),
                    tenant_id: config.read().tenant_id.clone(),
                    chat_mailbox,
                    conversation_mailbox,
                    on_logout: on_logout,
                    on_easy_mode_change: on_easy_mode_change,
                }
            },
        }
    } else {
        // ... existing expert-mode `match screen { ... }` unchanged ...
    }
```

Compute `host` and `chat_api_url` once before the branch (they already exist in the `Connected` arm — hoist them). Keep the expert `else` branch exactly as-is.

- [ ] **Step 2: EasyModeShell overlay driven by flow**

In `crates/ui/src/components/easy_mode.rs`: replace the `needs_sign_in` context read (`:51`) with a `flow` context read: `let flow = use_context::<Signal<AuthFlow>>();` (import `crate::auth_flow::AuthFlow`). Change the overlay guard (`:304` `if needs_sign_in()`) to `if matches!(flow(), AuthFlow::AwaitingGesture | AuthFlow::Failed { reauth: true, .. })`. Delete the token-emptiness effect (`:101-114`).

- [ ] **Step 3: Sign-in button emits SignInRequested**

The overlay button (`easy_mode.rs:316-323`) currently sets `force_sign_in`+`needs_sign_in`+`retry_tick`. `EasyModeShell` cannot call `connector_app`'s `dispatch` directly; provide dispatch via context. In `connector_app` Task 2, additionally `use_context_provider(|| SignInDispatch(...))`. Simplest: provide a `Signal<AuthFlow>` write path by giving EasyModeShell a callback prop `on_sign_in: EventHandler<()>` wired in the render to `move |_| dispatch(AuthEvent::SignInRequested)`. Add the prop to `EasyModeShellProps`, pass it in both render sites, and make the button `onclick: move |_| props.on_sign_in.call(())`.

- [ ] **Step 4: ChatPanel emits ChatReady / ChatAuthDead via a callback prop**

Add `#[props(default)] on_chat_event: EventHandler<crate::auth_flow::AuthEvent>` to ChatPanel. In `connector_app`'s EasyModeShell→ChatPanel chain, thread it to `move |ev| dispatch(ev)`. In ChatPanel:
- Where agents finish loading (`agents_loaded.set(true)` sites `:513,525,537,557`), also call `props.on_chat_event.call(AuthEvent::ChatReady)`.
- In the auth-fail recovery (`:594-617`), replace the `needs_sign_in`/`retry_tick` pokes with `props.on_chat_event.call(AuthEvent::ChatAuthDead)`.

(EasyModeShell passes `on_chat_event` through to its inner ChatPanel; add the prop to EasyModeShellProps too.)

- [ ] **Step 5: Build + clippy**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: `Finished`, no warnings.

- [ ] **Step 6: Manual test — full matrix**

Run desktop. Verify: (a) stored valid token → straight to shell, no overlay; (b) logout → overlay with Sign in button; (c) single tap → one sign-in → shell; (d) simulate dead token (log out at PLG then relaunch) → shell briefly then overlay (Failed{reauth}). No "logged-in + overlay" state.

- [ ] **Step 7: Commit**

```bash
git add crates/ui/src/connector_app.rs crates/ui/src/components/easy_mode.rs crates/ui/src/components/chat_panel/mod.rs
git commit -m "feat(easy-mode): render + shell + chat panel derive from AuthFlow"
```

---

### Task 6: Remove the legacy signals; make `reduce` the sole writer

**Files:**
- Modify: `crates/ui/src/connector_app.rs`, `crates/ui/src/components/easy_mode.rs`, `crates/ui/src/lib.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `needs_sign_in`, `retry_tick`, `force_sign_in`, `ForceSignIn` deleted.

- [ ] **Step 1: Drop the mirror in dispatch**

In `connector_app`'s `dispatch` (Task 2 Step 3), remove the `needs_sign_in` mirroring block — `flow` is now the only state.

- [ ] **Step 2: Delete the signals + providers**

Remove `needs_sign_in` (`:369`), `retry_tick` (`:370`), the `force_sign_in`/`ForceSignIn` provider (`:378`), the `ForceSignIn` newtype (`:41`), the disconnected→needs_sign_in effect (`:867-875`), and any remaining reads. In `EasyModeShell` remove the `retry_tick`/`force_sign_in` context reads (`:52-55`).

- [ ] **Step 3: Remove the `ForceSignIn` export**

In `crates/ui/src/lib.rs:23`, drop `ForceSignIn` from the `pub use connector_app::{...}` list.

- [ ] **Step 4: Grep for stragglers**

Run: `rg -n "needs_sign_in|force_sign_in|retry_tick|ForceSignIn" crates/ui/src`
Expected: no matches (or only in comments you then remove).

- [ ] **Step 5: Build + clippy + reducer tests**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Run: `nix develop --command cargo test -p pentest-ui --lib auth_flow`
Expected: both clean.

- [ ] **Step 6: Manual regression pass**

Run desktop AND (via the Mac VM) rebuild+run iOS. Verify on both: fresh no-creds sign-in (single tap), relaunch with valid token, logout→sign-in, mode toggle mid-flow. On iOS confirm the native OAuth still presents from the button gesture.

- [ ] **Step 7: Commit**

```bash
git add crates/ui/src/connector_app.rs crates/ui/src/components/easy_mode.rs crates/ui/src/lib.rs
git commit -m "refactor(easy-mode): remove legacy auth signals; AuthFlow is sole writer"
```

---

## Notes for the implementer

- Dioxus signal borrow rule: never hold a `.read()`/`.peek()` guard across an `.await` (see the `AlreadyBorrowed` fix already in `on_logout`/`on_disconnect`). In `dispatch` and the effects, `flow.peek().clone()` then drop the guard before any await.
- `dispatch` captures signals (all `Copy`) and `easy_mode`/`settings` signals; if you need it in multiple closures, wrap in `Rc` once and clone the `Rc`.
- Effects that both read and write a signal re-run — the exact bug being fixed. The launch effect (Task 3) reads `flow` and writes only `launched_*` guard signals, never `flow`, so it does not self-trigger.
- Keep `status`/`connecting_step` as the connector's own lifecycle signals; `flow` is derived from them via the Task 4 bridge, not a replacement for them.
