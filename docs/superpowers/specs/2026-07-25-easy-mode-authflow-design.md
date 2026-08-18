# Easy-Mode AuthFlow State Machine — Design

**Status:** Approved for planning
**Date:** 2026-07-25
**Scope:** `crates/ui` (easy-mode login/connection flow only)

## Problem

Easy-mode sign-in state is spread across many independent Dioxus signals —
`needs_sign_in`, `force_sign_in`, `retry_tick` (plus the routing-relevant
`status`, `connecting_step`, `matrix_auth_token`) — with **six writers of
`needs_sign_in` across three files** and no single source of truth. The
combinations are not all legal, and two structural defects produce a
**double-sign-in** (the user must sign in twice; the UI briefly shows the
logged-in state, then a second sign-in completes quickly):

1. **Self-triggering effect.** The auto-connect `use_effect` (keyed on
   `retry_tick`, `connector_app.rs:783`) *reads* `force_sign_in()` and then
   *writes* `force_sign_in.set(false)` (`:819`). The write re-runs the effect.
   The early-return guard `if !initial_auto_connect && !force_sign_in()`
   (`:790`) does not protect the second run when `initial_auto_connect` is
   `true` — which it is in easy mode with a baked env host and no saved config
   (`:349-350`). So one "Sign in" tap runs the effect body twice: run 1 opens
   the browser (`PlgConnectStep::SignIn`), run 2 falls through to
   `plg_connect_decision` → often `Silent` → a second connect.

2. **Restored-dead-token race.** On relaunch `restore_matrix_token`
   (`:421-431`) seeds a non-empty `matrix_auth_token` (which may be
   server-dead), so `EasyModeShell` renders the logged-in shell *while*
   `needs_sign_in` is also true (set by `easy_mode.rs:113` or the disconnected
   effect) → the overlay shows too → tapping it triggers a *fresh* sign-in.
   There is no single predicate meaning "already authenticated / sign-in in
   flight" to dedupe against.

## Goal

Replace `needs_sign_in` + `force_sign_in` + `retry_tick` with one explicit
`AuthFlow` enum and a pure `reduce()` reducer that is the **sole writer** of
easy-mode auth/connection state. This makes the double-sign-in structurally
impossible and collapses the flag soup into one testable transition table.

**Easy mode only.** Expert mode keeps its current `compute_screen` /
`ConfigForm` / lazy-browser-auth path untouched.

## Architecture

New pure module `crates/ui/src/auth_flow.rs` — no Dioxus dependencies, fully
unit-testable:

```rust
pub enum AuthFlow {
    Restoring,                          // startup, deciding
    Disconnected,                       // easy: nothing to show yet (transient)
    AwaitingGesture,                    // sign-in overlay shown, waiting for the tap
    SigningIn,                          // browser / native OAuth in flight
    Registering(ConnectingStep),        // connector connect_and_run, post-token
    Connected { chat_ready: bool },     // Registered; chat_ready folds agents-loaded
    Failed { reason: String, reauth: bool }, // reauth=true => dead chat token, offer sign-in
}

pub enum AuthEvent {
    Restored { have_token: bool },
    CredsFound,
    CredsAbsent,
    SignInRequested,                    // the single event the button emits
    TokenObtained,
    TokenFailed(String),
    ConnectorStep(ConnectingStep),
    ConnectorRegistered,
    ChatReady,
    ChatAuthDead,
    LoggedOut,
    Disconnected,
}

/// Pure. `easy` and `auto` are the resolved easy-mode flag and the persisted
/// auto_connect setting; they parameterize startup transitions.
pub fn reduce(state: AuthFlow, event: AuthEvent, easy: bool, auto: bool) -> AuthFlow;
```

`connector_app` holds one `let mut flow = use_signal(|| AuthFlow::Restoring);`
and a `dispatch(event)` closure:

```rust
let dispatch = move |ev: AuthEvent| {
    flow.set(reduce(flow.peek().clone(), ev, easy_mode(), settings.peek().auto_connect));
};
```

`dispatch` is the only thing that writes `flow`. Every current
`needs_sign_in.set(...)`, the `force_sign_in` write, and the `retry_tick` bump
become a `dispatch(...)` with a specific event.

## Key transitions (the bug fixes)

**Double-sign-in fix (cause 1).** `SigningIn` is reachable only via
`SignInRequested`, and `reduce` honors it only from `AwaitingGesture`:

- `AwaitingGesture + SignInRequested → SigningIn` — the transition handler
  launches `plg_sign_in_and_connect` exactly once.
- `SigningIn + SignInRequested → SigningIn` — **no-op**; a second dispatch
  does nothing.
- any-other-state `+ SignInRequested → unchanged`.

The `retry_tick` edge counter and the read-and-write-`force_sign_in` effect are
deleted. One tap = one `SignInRequested` = one launch. Double-fire is
structurally impossible.

**Restored-dead-token fix (cause 2), optimistic → downgrade:**

- Startup `Restored { have_token: true } → Connected { chat_ready: false }`.
  The shell renders; **no overlay**, because the overlay is driven by
  `matches!(flow, AwaitingGesture | Failed { reauth: true })`, never by token
  emptiness.
- `Connected { .. } + ChatAuthDead → Failed { reason, reauth: true }` → overlay
  shows. The app is never in "logged-in shell + overlay" at once.
- `Restored { have_token: false }` → `CredsFound → Registering` (silent
  auto-connect) or `CredsAbsent → AwaitingGesture` (show the button), per
  `plg_connect_decision(easy, creds)` semantics, gated by `auto`.

**Other transitions:**

- `SigningIn + TokenObtained → Registering(SigningIn)` (token in hand, connector
  connects); `+ TokenFailed(e) → Failed { reason: e, reauth: true }`.
- `Registering(_) + ConnectorStep(s) → Registering(s)`;
  `+ ConnectorRegistered → Connected { chat_ready: false }`.
- `Connected { .. } + ChatReady → Connected { chat_ready: true }`.
- `* + LoggedOut → AwaitingGesture`.
- `* + Disconnected → Disconnected` (transient; startup logic decides next).

## Render / component wiring (easy mode only)

In `connector_app`'s render, when `easy_mode()` is true, route on `flow()`:

- `Restoring | Disconnected | AwaitingGesture | Failed { reauth: true }`
  → `EasyModeShell`; overlay shown iff `AwaitingGesture | Failed { reauth: true }`.
- `SigningIn | Registering(step)` → `ConnectingScreen` (the existing
  `ConnectingStep::SigningIn` copy: "Complete your sign-in in the browser").
- `Connected { .. }` → `EasyModeShell` (normal shell).

Expert mode (`!easy_mode()`) is unchanged: existing `compute_screen` match,
`ConfigForm`, and ChatPanel lazy-browser-auth.

`EasyModeShell` (`easy_mode.rs`): drop the `needs_sign_in` / `force_sign_in` /
`retry_tick` contexts and the token-emptiness effect; read `flow` from context;
the sign-in overlay button emits a single `dispatch(AuthEvent::SignInRequested)`.
Its `auth_token` signal + `watch_auth_token` future **stay** — they are the
legitimate async delivery of the chat token, not control state.

`ChatPanel` (`chat_panel/mod.rs`): keeps its local view flags (`agents_loaded`,
`fetch_started`, `awaiting_auth`, `browser_auth_attempted` — expert-only). Its
auth-failure recovery (`:594-617`) emits `dispatch(AuthEvent::ChatAuthDead)`
instead of poking `needs_sign_in`/`retry_tick`. When agents load it emits
`ChatReady`.

Handlers / SDK event loop: `on_logout → LoggedOut`, `on_disconnect →
Disconnected`, the connector event loop's status/step → `ConnectorRegistered` /
`ConnectorStep(_)`, the browser/token handlers → `TokenObtained` /
`TokenFailed`.

## Migration (incremental — every commit compiles and runs)

1. Add `auth_flow.rs` with `AuthFlow`, `AuthEvent`, `reduce`, and a
   transition-table unit test (mirror the style of
   `config.rs` `plg_connect_decision_matrix`). No wiring yet.
2. Add the `flow` signal + `dispatch` in `connector_app`; seed `flow` from the
   existing startup inputs (`resolved_easy`, `initial_auto_connect`,
   `restore_matrix_token`, `credentials_present`). `dispatch` also **mirrors**
   into the old `needs_sign_in`/`force_sign_in` signals so nothing breaks yet.
3. Route `plg_sign_in_and_connect` off the `AwaitingGesture → SigningIn`
   transition instead of the `retry_tick` effect; make `SignInRequested`
   idempotent (no-op unless `AwaitingGesture`).
4. Point the connector event loop + connect/logout/disconnect handlers at
   `dispatch(...)`.
5. Convert the easy-mode render branch to match on `flow()`; delete the
   easy-mode `needs_sign_in`-based short-circuit.
6. Convert `EasyModeShell` to read `flow` from context; drop its overlay-driving
   effect and the button's three-signal fan-out.
7. Convert `ChatPanel` recovery to emit `ChatAuthDead` / `ChatReady`.
8. Delete `needs_sign_in`, `retry_tick`, and the `ForceSignIn` newtype (and
   their context providers / exports) once `reduce` is the sole writer.

Steps 1–2 land behind the existing signals; the old signals are removed only in
step 8, so the app works per-commit.

## Testing

- **Unit:** `reduce` transition-table test covering every `(state, event)` pair
  that matters, especially: `SigningIn + SignInRequested` = no-op;
  `Restored{have_token:true} → Connected{chat_ready:false}`;
  `Connected + ChatAuthDead → Failed{reauth:true}`;
  `AwaitingGesture + SignInRequested → SigningIn`.
- **Manual matrix** (dev cluster, easy mode): fresh no-creds sign-in fires
  exactly one browser sign-in; relaunch with (a) valid restored token → straight
  to shell, (b) expired token dropped by `restore_matrix_token` → overlay, (c)
  server-dead token → shell then downgrade to overlay on `ChatAuthDead`;
  logout → overlay → single sign-in; mode toggle mid-flow doesn't strand state.

## Out of scope

- Expert-mode routing (`compute_screen`, `ConfigForm`, expert lazy-browser-auth).
- OAuth transport (`crates/core/src/matrix/auth.rs`).
- Persistence (`crates/ui/src/session.rs`, `crates/core/src/config.rs`).
- The `AlreadyBorrowed` connector-borrow-across-await mitigations in
  `on_disconnect`/`on_logout` (already fixed; leave intact).
