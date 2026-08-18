# Graceful Offline State + Easy-Mode Endpoint Swap Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace easy mode's bare sign-in overlay with a graceful, branded offline screen (Sign in / Change server / Retry), and let easy-mode users point the app at a different Strike48 endpoint by entering a URL, persisted across restarts.

**Architecture:** No `AuthFlow` state-machine change — the existing `Disconnected`, `Failed{reason, reauth}`, and `AwaitingGesture` states already ARE "offline"; we swap the surface they render. New `OfflineScreen` and `EndpointEntry` Dioxus components in `crates/ui`. Endpoint swap reuses `ConnectorConfig::normalize_host` and persists to `AppSettings.last_config` (which already wins over the baked default at startup — verified: `connector_app.rs:455-459`).

**Tech Stack:** Rust, Dioxus (component macro, signals, `EventHandler`), `pentest_core::config::{ConnectorConfig, AppSettings, NormalizedHost}`, `pentest_core::settings::{load_settings, save_settings}`.

## Global Constraints

- Rust stable 1.92+. Copied verbatim from CLAUDE.md.
- CI clippy runs with `-D warnings` — zero warnings.
- `cargo fmt --all -- --check` must pass.
- Conventional-commit messages. No Claude attribution, no customer/tenant names, no emojis or em-dashes.
- Dioxus-liveview form-data converter PANICS on `<input type=checkbox>` `onchange`; use `<button>` `onclick` for toggles (existing easy-mode pattern, `easy_mode.rs:396-398`).
- `crates/ui` has NO Dioxus component unit-test harness (consistent across the crate). Component tasks verify via `cargo check`/`clippy`; pure logic gets real unit tests.
- Build/test on this host requires `nix develop --command <cmd>`; prefix `DISABLE_SANDBOX=true` if a command hangs on sandbox/proot. The `pentest-ui` feature set for easy mode is `--features "desktop,connector,shell-ws"` (confirmed in prior work).

## Verified Current-State Facts (do not re-derive)

- `AuthFlow` enum + `reduce()`: `crates/ui/src/auth_flow.rs` (states at 14-31; transitions 65-123; `(_, Disconnected) => Disconnected` at 118; `Disconnected/AwaitingGesture/Failed{reauth} + SignInRequested => SigningIn` at 84-86).
- Bare sign-in overlay to replace: `crates/ui/src/components/easy_mode.rs:480-494` (renders for `AwaitingGesture | Failed{reauth:true} | Disconnected`).
- Easy-mode settings overlay: `easy_mode.rs:377-479` (button-style toggle rows).
- `EasyModeShell` props: `easy_mode.rs:35-68`. Render call site: `connector_app.rs:1267-1300+`.
- `EasyModeShell` gets `on_sign_in: move |_| d1(AuthEvent::SignInRequested)` (`connector_app.rs:1275`).
- Config seeding precedence (settings win over baked): `connector_app.rs:449-467`.
- `config` signal: `connector_app.rs:472`. `matrix_api_url` signal: `connector_app.rs:529-533`.
- `matrix_api_url` persistence pattern (write to in-memory settings + save): `connector_app.rs:877-889`.
- `AppSettings.last_config: Option<ConnectorConfig>` (`config.rs:737`), `AppSettings.matrix_api_url: String` (`config.rs:771`).
- `ConnectorConfig::normalize_host(&str) -> Result<NormalizedHost, String>` (`config.rs:292`). `NormalizedHost { value: String, .. }` (`config.rs:147-149`); `NormalizedHost::hint() -> Option<String>` (`config.rs:156+`), used by `config_form.rs:57-59`.
- `load_settings()` / `save_settings(&AppSettings)`: `pentest_core::settings`.

---

## Task 1: Confirm endpoint-change persistence precedence (spike + guard test)

**Goal:** Lock down the one design unknown before building UI on it: does a `ConnectorConfig` written to `AppSettings.last_config` actually override the baked `STRIKE48_HOST` on next launch? Produce a regression test that pins the precedence.

**Files:**
- Test: `crates/ui/src/connector_app.rs` is not unit-testable (Dioxus). Instead test the pure precedence in `crates/core/src/config.rs` if a helper exists; otherwise document the finding and add the guard where the logic lives.

**Interfaces:**
- Consumes: `ConnectorConfig::from_baked_or_env()`, `AppSettings::last_config`.
- Produces: a documented, tested guarantee that `settings.last_config` is preferred over `from_baked_or_env()` (relied on by Task 5's persistence).

- [ ] **Step 1: Read the seeding logic and confirm precedence**

Read `crates/ui/src/connector_app.rs:449-467`. Confirm the chain is
`settings.peek().last_config.clone().or_else(|| easy_mode_env_config.clone())`
— i.e. a present `last_config` wins over the baked/env config. Note the exact
line in your report.

- [ ] **Step 2: Determine where a pure test can live**

The precedence lives in the Dioxus component (`connector_app.rs`), which has no
unit harness. Check whether the `or_else` precedence can be extracted into a
tiny pure helper in `pentest_core::config` — e.g.

```rust
/// The config easy mode should start from: a persisted `last_config` always
/// wins over the build-time baked/env default, so a user who changed their
/// endpoint keeps it across restarts.
pub fn resolve_initial_config(
    last_config: Option<ConnectorConfig>,
    baked_or_env: Option<ConnectorConfig>,
) -> Option<ConnectorConfig> {
    last_config.or(baked_or_env)
}
```

If extracting is low-risk (the call site becomes
`resolve_initial_config(settings.peek().last_config.clone(), easy_mode_env_config.clone())`),
do it. If it would tangle other logic, SKIP extraction and instead just add the
test against `AppSettings` round-trip (Step 3 covers both cases).

- [ ] **Step 3: Write the guard test**

If you extracted the helper, add to `crates/core/src/config.rs` tests:

```rust
#[test]
fn persisted_last_config_wins_over_baked_default() {
    let baked = Some(ConnectorConfig { host: "wss://baked.example".into(), ..Default::default() });
    let saved = Some(ConnectorConfig { host: "wss://user-chosen.example".into(), ..Default::default() });
    let chosen = resolve_initial_config(saved.clone(), baked.clone()).unwrap();
    assert_eq!(chosen.host, "wss://user-chosen.example", "a persisted endpoint must survive restart");
    // With no saved config, fall back to baked.
    assert_eq!(resolve_initial_config(None, baked).unwrap().host, "wss://baked.example");
}
```

If you did NOT extract, instead add a round-trip test proving an `AppSettings`
with a `last_config` serializes and deserializes that host intact (this is the
part Task 5 depends on):

```rust
#[test]
fn app_settings_roundtrips_last_config_host() {
    let mut s = AppSettings::default();
    s.last_config = Some(ConnectorConfig { host: "wss://user-chosen.example".into(), ..Default::default() });
    let json = serde_json::to_string(&s).unwrap();
    let back: AppSettings = serde_json::from_str(&json).unwrap();
    assert_eq!(back.last_config.unwrap().host, "wss://user-chosen.example");
}
```

- [ ] **Step 4: Run the test**

Run: `nix develop --command cargo test -p pentest-core --lib config 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/config.rs crates/ui/src/connector_app.rs
git commit -m "test(config): pin that a persisted last_config overrides the baked default"
```

Report which path you took (extracted helper vs round-trip test) so Task 5 knows
whether `resolve_initial_config` exists.

---

## Task 2: `OfflineScreen` component

**Goal:** A branded offline screen that replaces the bare sign-in overlay. Renders for the three offline `AuthFlow` states; shows a failure reason when present; offers Sign in, Change server, Retry.

**Files:**
- Create: `crates/ui/src/components/offline_screen.rs`
- Modify: `crates/ui/src/components/mod.rs` (register + re-export)

**Interfaces:**
- Consumes: nothing from other tasks.
- Produces: `OfflineScreen` component with

```rust
#[derive(Props, Clone, PartialEq)]
pub struct OfflineScreenProps {
    /// The failure reason to surface, when the offline state came from a failure
    /// (AuthFlow::Failed). `None` for a plain disconnect/cancel.
    #[props(default)]
    pub reason: Option<String>,
    /// Start the OAuth sign-in flow.
    pub on_sign_in: EventHandler<()>,
    /// Open the change-server URL entry.
    pub on_change_server: EventHandler<()>,
    /// Retry sign-in (same as on_sign_in today, but a distinct affordance so the
    /// screen can emphasize "Try again" when a failure reason is shown).
    pub on_retry: EventHandler<()>,
}
```

- [ ] **Step 1: Create the component**

Create `crates/ui/src/components/offline_screen.rs`:

```rust
//! Graceful offline / auth-unavailable screen for easy mode.
//!
//! Replaces the bare sign-in overlay. The easy-mode `AuthFlow` states
//! `AwaitingGesture`, `Disconnected`, and `Failed { reauth: true, .. }` all
//! render this: a branded panel that explains the state and offers Sign in,
//! Change server, and (on failure) Retry — never a blank or dead screen.

use dioxus::prelude::*;

/// Props for [`OfflineScreen`].
#[derive(Props, Clone, PartialEq)]
pub struct OfflineScreenProps {
    #[props(default)]
    pub reason: Option<String>,
    pub on_sign_in: EventHandler<()>,
    pub on_change_server: EventHandler<()>,
    pub on_retry: EventHandler<()>,
}

/// The graceful offline screen. When `reason` is `Some`, the state came from a
/// connection/auth failure: show the reason and emphasize "Try again". When
/// `None` (a plain disconnect or a cancelled sign-in), show a neutral prompt and
/// emphasize "Sign in". "Change server" is always offered as a secondary action.
#[component]
pub fn OfflineScreen(props: OfflineScreenProps) -> Element {
    let failed = props.reason.is_some();
    rsx! {
        div { class: "easy-doc-screen easy-overlay",
            div { class: "easy-signin",
                if let Some(reason) = props.reason.clone() {
                    p { class: "easy-signin-title", "Couldn't connect to Strike48" }
                    p { class: "easy-signin-sub", "{reason}" }
                } else {
                    p { class: "easy-signin-title", "You're not connected" }
                    p { class: "easy-signin-sub", "Sign in to register this connector and start scanning. We'll open your browser to complete sign-in." }
                }
                // Primary action: Retry when we failed, Sign in otherwise.
                button {
                    class: "action-card",
                    onclick: move |_| {
                        if failed {
                            props.on_retry.call(());
                        } else {
                            props.on_sign_in.call(());
                        }
                    },
                    span { class: "action-card-label",
                        if failed { "Try again" } else { "Sign in" }
                    }
                }
                // Secondary action: change the Strike48 endpoint.
                button {
                    class: "easy-signin-secondary",
                    onclick: move |_| props.on_change_server.call(()),
                    "Change server"
                }
            }
        }
    }
}
```

- [ ] **Step 2: Register and re-export the module**

In `crates/ui/src/components/mod.rs`, add (alphabetically near the other
component modules — check the file for the exact style):

```rust
pub mod offline_screen;
```

and, matching how sibling components are re-exported (find e.g.
`pub use documents_panel::` in that file), add:

```rust
pub use offline_screen::OfflineScreen;
```

- [ ] **Step 3: Verify build + clippy**

Run:
```bash
nix develop --command cargo check -p pentest-ui --features "desktop,connector,shell-ws" 2>&1 | tail -10
nix develop --command cargo clippy -p pentest-ui --features "desktop,connector,shell-ws" -- -D warnings 2>&1 | tail -10
```
Expected: clean. (The component is unused so far; clippy may warn `OfflineScreen`
is never used — if so, that resolves in Task 4 when it's wired in. If clippy
`-D warnings` fails ONLY on dead-code for the new pub item, note it and proceed;
a `pub` component re-exported from `mod.rs` is part of the crate's public surface
and should not trip dead_code. If it does, do NOT add `#[allow(dead_code)]` —
it will be consumed in Task 4.)

- [ ] **Step 4: Add the CSS for the secondary action**

Find the stylesheet that defines `.easy-signin` / `.action-card` (search:
`rg -l "easy-signin" crates/ui`). Add a `.easy-signin-secondary` rule styled as a
quiet text/link button consistent with the existing easy-mode buttons (borrowing
padding/color from `.easy-drawer-item` or similar). Keep it minimal — one rule.

- [ ] **Step 5: Commit**

```bash
git add crates/ui/src/components/offline_screen.rs crates/ui/src/components/mod.rs
git add <the stylesheet you edited>
git commit -m "feat(ui): add graceful OfflineScreen component for easy mode"
```

---

## Task 3: `EndpointEntry` component

**Goal:** A modal that asks for a new Strike48 URL, previews what it resolves to (via `normalize_host`), validates, and hands the raw URL back to the parent on save.

**Files:**
- Create: `crates/ui/src/components/endpoint_entry.rs`
- Modify: `crates/ui/src/components/mod.rs` (register + re-export)

**Interfaces:**
- Consumes: `pentest_core::config::ConnectorConfig::normalize_host` (`config.rs:292`), `NormalizedHost::hint()`.
- Produces: `EndpointEntry` component with

```rust
#[derive(Props, Clone, PartialEq)]
pub struct EndpointEntryProps {
    /// The current host, pre-filled into the field.
    pub initial: String,
    /// Fired with the raw (un-normalized) URL string the user entered, once it
    /// passes `normalize_host` validation. The parent normalizes + persists.
    pub on_save: EventHandler<String>,
    /// Close without changing anything.
    pub on_cancel: EventHandler<()>,
}
```

- [ ] **Step 1: Create the component**

Create `crates/ui/src/components/endpoint_entry.rs`:

```rust
//! Easy-mode "Change server" URL entry.
//!
//! Ed's ask: even in easy mode, let the user point Pick at a different Strike48
//! endpoint than the compile-time baked one — "just ask for a new URL". One
//! field; the API + WS URLs are derived by `normalize_host`, and the tenant is
//! resolved server-side by the OAuth-first pre-approve flow, so we do not ask
//! for it here.

use dioxus::prelude::*;

use pentest_core::config::ConnectorConfig;

/// Props for [`EndpointEntry`].
#[derive(Props, Clone, PartialEq)]
pub struct EndpointEntryProps {
    pub initial: String,
    pub on_save: EventHandler<String>,
    pub on_cancel: EventHandler<()>,
}

/// Modal URL entry for changing the Strike48 endpoint. Validates via
/// `normalize_host`: a valid URL enables Save and shows a "Will connect to: …"
/// preview; an empty or malformed URL shows an inline error and disables Save.
#[component]
pub fn EndpointEntry(props: EndpointEntryProps) -> Element {
    let mut url = use_signal(|| props.initial.clone());

    // Validation + preview, recomputed on every keystroke.
    let value = url.read().clone();
    let trimmed = value.trim().to_string();
    let (hint, error): (Option<String>, Option<String>) = if trimmed.is_empty() {
        (None, None)
    } else {
        match ConnectorConfig::normalize_host(&trimmed) {
            Ok(n) => (n.hint().or_else(|| Some(format!("Will connect to: {}", n.value))), None),
            Err(e) => (None, Some(e)),
        }
    };
    let can_save = !trimmed.is_empty() && error.is_none();

    rsx! {
        div { class: "easy-doc-screen easy-overlay",
            div { class: "easy-signin",
                p { class: "easy-signin-title", "Change Strike48 server" }
                p { class: "easy-signin-sub", "Enter the URL of the Strike48 server to connect to." }
                div { class: "input-group",
                    input {
                        r#type: "text",
                        placeholder: "wss://strike48.example.com:443",
                        value: "{url}",
                        oninput: move |e| url.set(e.value()),
                    }
                    if let Some(hint) = hint {
                        span { class: "form-hint", "{hint}" }
                    }
                    if let Some(err) = error {
                        span { class: "error-banner", "{err}" }
                    }
                }
                button {
                    class: "action-card",
                    disabled: !can_save,
                    onclick: move |_| {
                        let v = url.read().trim().to_string();
                        if !v.is_empty() {
                            props.on_save.call(v);
                        }
                    },
                    span { class: "action-card-label", "Save" }
                }
                button {
                    class: "easy-signin-secondary",
                    onclick: move |_| props.on_cancel.call(()),
                    "Cancel"
                }
            }
        }
    }
}
```

- [ ] **Step 2: Register and re-export**

In `crates/ui/src/components/mod.rs` add:

```rust
pub mod endpoint_entry;
```
and:
```rust
pub use endpoint_entry::EndpointEntry;
```

- [ ] **Step 3: Verify build + clippy**

Run:
```bash
nix develop --command cargo check -p pentest-ui --features "desktop,connector,shell-ws" 2>&1 | tail -10
nix develop --command cargo clippy -p pentest-ui --features "desktop,connector,shell-ws" -- -D warnings 2>&1 | tail -10
```
Expected: clean (same dead-code caveat as Task 2 Step 3 — consumed in Task 4/5).

- [ ] **Step 4: Commit**

```bash
git add crates/ui/src/components/endpoint_entry.rs crates/ui/src/components/mod.rs
git commit -m "feat(ui): add EndpointEntry URL modal for easy-mode server change"
```

---

## Task 4: Wire `OfflineScreen` + `EndpointEntry` into `EasyModeShell`

**Goal:** Replace the bare sign-in overlay with `OfflineScreen`, add `on_change_server`/`on_retry`/`on_endpoint_save` props, add a "Change server" row to the settings overlay, and render `EndpointEntry` when its local toggle is set.

**Files:**
- Modify: `crates/ui/src/components/easy_mode.rs` (props 35-68; overlay 480-494; settings 377-479)

**Interfaces:**
- Consumes: `OfflineScreen` (Task 2), `EndpointEntry` (Task 3), the `flow` context (`easy_mode.rs:80`).
- Produces: three new `EasyModeShellProps` fields:
  - `pub on_change_server: EventHandler<()>` — REMOVE (handled locally; see note). Actually the shell owns the show/hide of `EndpointEntry` locally, so it needs only:
  - `pub on_endpoint_save: EventHandler<String>` — fired with the raw URL when the user saves a new endpoint.
  - `pub current_host: String` — the current host, to prefill `EndpointEntry`.

- [ ] **Step 1: Add the new props**

In `crates/ui/src/components/easy_mode.rs`, add to `EasyModeShellProps` (after
`on_sign_in`, ~line 51):

```rust
    /// The current Strike48 host, prefilled into the "Change server" entry.
    #[props(default)]
    pub current_host: String,
    /// Fired with the raw URL when the user saves a new endpoint in "Change
    /// server". The parent normalizes, updates config, and persists.
    pub on_endpoint_save: EventHandler<String>,
```

- [ ] **Step 2: Add local state for the endpoint-entry modal**

Near the other `use_signal` declarations in `EasyModeShell` (e.g. by `show_docs`
at ~line 98), add:

```rust
    // Whether the "Change server" URL entry modal is open.
    let mut show_endpoint_entry = use_signal(|| false);
```

- [ ] **Step 3: Replace the bare sign-in overlay with OfflineScreen**

Replace the block at `easy_mode.rs:480-494` (the
`if matches!(flow(), ...AwaitingGesture | Failed{reauth:true} | Disconnected)`
overlay) with:

```rust
        if matches!(
            flow(),
            crate::auth_flow::AuthFlow::AwaitingGesture
                | crate::auth_flow::AuthFlow::Failed { reauth: true, .. }
                | crate::auth_flow::AuthFlow::Disconnected
        ) {
            {
                // Surface the failure reason when the offline state came from a
                // Failed transition; a plain Disconnected/AwaitingGesture has none.
                let reason = match flow() {
                    crate::auth_flow::AuthFlow::Failed { reason, .. } => Some(reason),
                    _ => None,
                };
                rsx! {
                    crate::components::OfflineScreen {
                        reason,
                        on_sign_in: move |_| props.on_sign_in.call(()),
                        on_retry: move |_| props.on_sign_in.call(()),
                        on_change_server: move |_| show_endpoint_entry.set(true),
                    }
                }
            }
        }
        // "Change server" URL entry, above the offline screen when open.
        if show_endpoint_entry() {
            crate::components::EndpointEntry {
                initial: props.current_host.clone(),
                on_save: move |raw: String| {
                    show_endpoint_entry.set(false);
                    props.on_endpoint_save.call(raw);
                },
                on_cancel: move |_| show_endpoint_entry.set(false),
            }
        }
```

Note: `on_sign_in` and `on_retry` both call `props.on_sign_in` — the parent maps
both to `AuthEvent::SignInRequested` (which advances from all three offline
states, per `auth_flow.rs:84-86`). Two props are kept so `OfflineScreen` can
label the button contextually.

- [ ] **Step 4: Add a "Change server" row to the settings overlay**

In the settings overlay body (`easy_mode.rs:388-477`, inside
`div { class: "easy-settings-body" }`, after the sandbox row's closing), add a
row that opens the same modal:

```rust
                    // Change the Strike48 endpoint (URL only; tenant is resolved
                    // server-side by the OAuth pre-approve flow).
                    div { class: "easy-settings-row",
                        div { class: "easy-settings-text",
                            div { class: "easy-settings-label", "Strike48 server" }
                            div { class: "easy-settings-desc", "{props.current_host}" }
                        }
                        button {
                            class: "easy-toggle",
                            "aria-label": "Change Strike48 server",
                            onclick: move |_| {
                                show_settings.set(false);
                                show_endpoint_entry.set(true);
                            },
                            span { class: "easy-settings-action-label", "Change" }
                        }
                    }
```

(If `.easy-settings-action-label` doesn't exist, either reuse an existing label
class from a settings row or add a one-line CSS rule in the stylesheet Task 2
touched. Prefer reuse.)

- [ ] **Step 5: Verify build + clippy**

Run:
```bash
nix develop --command cargo check -p pentest-ui --features "desktop,connector,shell-ws" 2>&1 | tail -15
nix develop --command cargo clippy -p pentest-ui --features "desktop,connector,shell-ws" -- -D warnings 2>&1 | tail -15
```
Expected: clean. `OfflineScreen` / `EndpointEntry` are now consumed, resolving
any earlier dead-code concern. The call site at `connector_app.rs:1267` will now
FAIL to compile because `on_endpoint_save`/`current_host` are required props not
yet passed — that is expected and fixed in Task 5. To check THIS task in
isolation, it is acceptable that the workspace check fails only at the
`connector_app.rs` EasyModeShell call site; confirm the error is ONLY the two
missing props there and nothing inside `easy_mode.rs` itself.

- [ ] **Step 6: Commit**

```bash
git add crates/ui/src/components/easy_mode.rs
git commit -m "feat(ui): render OfflineScreen + EndpointEntry in easy-mode shell"
```

---

## Task 5: Wire the endpoint-save handler in `connector_app`

**Goal:** Pass `current_host` + `on_endpoint_save` to `EasyModeShell`; on save, normalize the URL, update the `config` and `matrix_api_url` signals, and persist to `AppSettings` so it survives restart.

**Files:**
- Modify: `crates/ui/src/connector_app.rs` (EasyModeShell call site ~1267; reuse the `matrix_api_url` persist pattern at 877-889; `normalize_host`/`derive_api_url` already imported per 600/291)

**Interfaces:**
- Consumes: `EasyModeShell`'s new `current_host: String` + `on_endpoint_save: EventHandler<String>` (Task 4); `config` signal (472), `matrix_api_url` signal (529), `settings` signal, `ConnectorConfig::normalize_host` (`config.rs:292`), `derive_api_url` (`connector_registration.rs`), `save_settings`.
- Produces: nothing downstream.

- [ ] **Step 1: Add the two props at the EasyModeShell call site**

In `crates/ui/src/connector_app.rs`, in the `EasyModeShell { ... }` block
(~1267-1300), add these props (alongside `on_sign_in` at 1275):

```rust
                                    current_host: config.read().host.clone(),
                                    on_endpoint_save: move |raw: String| {
                                        // Normalize the typed URL the same way the
                                        // expert connect form does. On failure, log
                                        // and keep the old endpoint (the modal already
                                        // validated, so this should not fire).
                                        let normalized = match ConnectorConfig::normalize_host(&raw) {
                                            Ok(n) => n.value,
                                            Err(e) => {
                                                tracing::warn!("change-server: rejected URL {raw:?}: {e}");
                                                return;
                                            }
                                        };
                                        // Derive the chat API URL from the new host.
                                        let api = pentest_core::connector_registration::derive_api_url(
                                            &normalized,
                                            config.peek().use_tls,
                                        );
                                        // Update in-memory config + chat URL signals.
                                        {
                                            let mut c = config.write();
                                            c.host = normalized.clone();
                                        }
                                        {
                                            let mut u = matrix_api_url;
                                            u.set(api.clone());
                                        }
                                        // Persist so the new endpoint survives restart
                                        // (last_config wins over the baked default at
                                        // startup — see connector_app.rs:455).
                                        {
                                            let mut s = settings.write();
                                            s.last_config = Some(config.peek().clone());
                                            s.matrix_api_url = api;
                                            let _ = save_settings(&s);
                                        }
                                    },
```

Adapt the exact signal-write idiom to the surrounding code: if `matrix_api_url`
is already `mut` in scope (it is declared `let mut matrix_api_url` at 529, but a
closure may need `let mut u = matrix_api_url;` to rebind — match the pattern used
at 877). Confirm `ConnectorConfig` and `save_settings` are already imported in
this file (they are used at 594/1285); if `derive_api_url`'s full path differs,
use the crate path `pentest_core::connector_registration::derive_api_url`.

- [ ] **Step 2: Verify the whole workspace compiles**

Run:
```bash
nix develop --command cargo check -p pentest-ui --features "desktop,connector,shell-ws" 2>&1 | tail -15
```
Expected: clean — the missing-props error from Task 4 is now resolved.

- [ ] **Step 3: Clippy the crate**

Run:
```bash
nix develop --command cargo clippy -p pentest-ui --features "desktop,connector,shell-ws" -- -D warnings 2>&1 | tail -15
```
Expected: zero warnings.

- [ ] **Step 4: Commit**

```bash
git add crates/ui/src/connector_app.rs
git commit -m "feat(ui): persist easy-mode endpoint change from OfflineScreen"
```

---

## Task 6: Verify end-to-end + full gate

**Goal:** Confirm the feature works in the running desktop app and passes the mandatory gate.

**Files:** none (verification only).

- [ ] **Step 1: Run fmt + the mandatory gate**

Run in order:
```bash
nix develop --command cargo fmt --all
nix develop --command cargo fmt --all -- --check
DISABLE_SANDBOX=true nix develop --command cargo check -p pentest-ui --features "desktop,connector,shell-ws"
DISABLE_SANDBOX=true nix develop --command cargo clippy -p pentest-ui --features "desktop,connector,shell-ws" -- -D warnings
DISABLE_SANDBOX=true nix develop --command cargo test -p pentest-core --lib config
git status
```
Expected: fmt clean, check clean, clippy zero warnings, config tests pass, no
stray uncommitted changes (only fmt edits, which you then commit).

- [ ] **Step 2: Drive the app to verify the offline screen and endpoint swap**

Use the `verify` skill / `run` skill to launch the desktop app. Confirm:
1. On a fresh/disconnected start, the OfflineScreen renders (not a blank overlay)
   with "You're not connected", a Sign in button, and a "Change server" link.
2. Tapping "Change server" opens EndpointEntry; typing a bare host shows a
   "Will connect to: …" hint; an empty field disables Save.
3. Saving a URL closes the modal and returns to the OfflineScreen.
4. (If reachable) cancelling a sign-in returns to the OfflineScreen, not a blank
   screen.

If the desktop app can't reach a real Strike48 to complete sign-in, verify at
minimum items 1-3 (they need no server). Record what you observed.

- [ ] **Step 3: Commit any fmt changes**

```bash
git add -A
git commit -m "style: cargo fmt" 2>/dev/null || echo "nothing to format-commit"
```

---

## Self-Review

**Spec coverage:**
- Graceful offline screen (Sign in / Change server / Retry, reason surfaced) → Tasks 2, 4.
- Endpoint swap, URL-only, derive the rest → Tasks 3, 5 (`normalize_host` + `derive_api_url`, no tenant field).
- Reachable from offline screen AND settings overlay → Task 4 (Steps 3, 4).
- Persist across restart → Tasks 1 (precedence guard), 5 (writes `last_config` + `matrix_api_url`).
- Cancel returns to a nice offline state → Task 4 Step 3 (Disconnected renders OfflineScreen).
- Reuse existing AuthFlow states, no new variant → confirmed; no `auth_flow.rs` change.
- No offline app functionality / no tenant field / no presets → honored (out of scope).

**Placeholder scan:** No TBD/"handle errors"/"similar to Task N". Every code step
has full code. Task 1 branches on a spike outcome (extract helper vs round-trip
test) with complete code for both. Task 2/3 Step 3 name the dead-code caveat
explicitly with the resolution task. CSS steps say "reuse existing class or add
one rule" — concrete, since exact class names must be read from the stylesheet.

**Type consistency:** `OfflineScreenProps { reason: Option<String>, on_sign_in,
on_change_server, on_retry }` defined in Task 2, consumed in Task 4 Step 3.
`EndpointEntryProps { initial: String, on_save: EventHandler<String>, on_cancel }`
defined in Task 3, consumed in Task 4 Step 3. `EasyModeShellProps` gains
`current_host: String` + `on_endpoint_save: EventHandler<String>` in Task 4,
passed in Task 5 Step 1. `normalize_host -> Result<NormalizedHost,String>` with
`.value` / `.hint()` used consistently in Tasks 3 and 5. `resolve_initial_config`
(Task 1) is optional and self-contained.
