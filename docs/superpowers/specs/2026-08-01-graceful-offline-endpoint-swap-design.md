# Graceful Offline State + Easy-Mode Endpoint Swap Design

**Date:** 2026-08-01
**Requested by:** Ed — "Graceful state when offline / auth unavailable." Plus: even in easy mode, allow swapping to a different endpoint than the baked one (just ask for a new URL), and make hitting Cancel return to a nice offline state.
**Target:** `crates/ui` (primary) + `crates/core/src/config.rs` (persistence)

---

## Problem

Today, easy mode has no offline concept. When the user cancels sign-in or auth
fails, `AuthFlow` transitions to `Disconnected` (cancel) or `Failed { reason,
reauth }` (failure), and both — along with `AwaitingGesture` — render the same
**bare sign-in overlay** (`easy_mode.rs:480-494`): no "you're offline" framing,
no failure context, no way to change the server. It is not broken, but it is
undignified, and there is no way in easy mode to point the app at a different
Strike48 endpoint than the compile-time baked `STRIKE48_HOST`
(`config.rs:450`) — you must toggle to expert mode, edit `ConfigForm`, and
toggle back.

## Current-State Map (verified)

- **Easy-mode shell:** `crates/ui/src/components/easy_mode.rs` — `EasyModeShell`
  (72-690). Sign-in overlay at 480-494; settings overlay at 377-479 (telemetry,
  easy-mode, sandbox toggles — no host field).
- **Auth state machine:** `crates/ui/src/auth_flow.rs` — `AuthFlow` enum (14-31:
  `Restoring`, `Disconnected`, `AwaitingGesture`, `SigningIn`,
  `Registering(..)`, `Connected{..}`, `Failed{reason, reauth}`); pure `reduce()`
  (65-123). `(_, Disconnected) => Disconnected` (118); `(Disconnected,
  SignInRequested) => SigningIn` (85); `(SigningIn, TokenFailed) => Failed{..}`
  (91-94).
- **Baked endpoint:** `crates/core/src/config.rs` —
  `ConnectorConfig::from_baked_or_env()` (448-477) reads `option_env!` at
  compile time. Runtime-mutable via `config` signal
  (`connector_app.rs:472`) and `matrix_api_url` signal (`connector_app.rs:529`).
  Persisted in `AppSettings` (`config.rs:732-784`): `last_config` (737),
  `matrix_api_url` (771).
- **Sign-in trigger:** `easy_mode.rs:485-491` button → `props.on_sign_in` →
  `connector_app.rs:1275` dispatches `AuthEvent::SignInRequested` → effect at
  937-971 launches `plg_sign_in_and_connect` (822-935) → OAuth backend
  `crates/core/src/matrix/auth.rs`.
- **Cancel:** `connecting_screen.rs:114-119` → `on_disconnect`
  (`connector_app.rs:1025-1054`) → shuts connector, sets status Disconnected,
  dispatches `AuthEvent::Disconnected` → renders the bare overlay.
- **Offline concept:** NONE app-wide. (`subscription.rs:41-49` `ConnectionState`
  is chat-WebSocket-internal only.)
- **Endpoint entry UI:** expert mode only — `config_form.rs` (host/tenant/token,
  inference hint 50-60). `normalize_host` at `connector_app.rs:600`;
  `derive_api_url` at `connector_registration.rs:21-44`.

## Decisions (from brainstorming)

- **Offline scope:** Informational only. A branded screen with Sign in / Change
  server / Retry. No offline app functionality; cached view-only reports are a
  possible follow-up, explicitly out of scope here.
- **Endpoint swap input:** URL only — one field; derive API + WS URLs via
  `normalize_host`/`derive_api_url`; tenant stays PLG-default (pre-approve
  resolves the authoritative tenant server-side).
- **Entry point + persistence:** reachable from the offline screen ("Change
  server") AND the easy-mode settings overlay; a successful change persists to
  `AppSettings` so it survives restart.
- **State model:** reuse the existing `AuthFlow` states — no new variant. Replace
  the bare overlay that `Disconnected` / `Failed{..}` / `AwaitingGesture` render
  with the new graceful screen. Lowest risk; these states already are "offline".

## Architecture

### New components

- **`crates/ui/src/components/offline_screen.rs` — `OfflineScreen`**
  - Props: `reason: Option<String>`, `on_sign_in: EventHandler<()>`,
    `on_change_server: EventHandler<()>`, `on_retry: EventHandler<()>`.
  - Branded (Sage) layout mirroring the existing hero/sign-in styling in
    `easy_mode.rs`. `reason: Some(msg)` → calm error note ("Couldn't connect:
    {msg}") + Retry emphasized. `reason: None` (plain cancel) → neutral "You're
    not connected" + Sign in emphasized. Always offers "Change server" as a
    secondary action.

- **`crates/ui/src/components/endpoint_entry.rs` — `EndpointEntry`**
  - A modal/overlay (rendered above the offline screen and reachable from
    settings). Props: `initial: String` (current host), `on_save:
    EventHandler<String>`, `on_cancel: EventHandler<()>`.
  - One URL text field + an inference hint reusing the `ConfigForm` pattern
    ("Will connect to: {derived}" via `normalize_host`). Save + Cancel buttons.
  - Validation: reject empty/malformed; accept bare host, scheme-prefixed, and
    trailing-slash forms (the same shapes `normalize_host`/`derive_api_url`
    already handle).

### Modified

- **`easy_mode.rs`** — replace the sign-in overlay block (480-494) with
  `OfflineScreen`; add a "Change server" row to the settings overlay (377-479)
  that opens `EndpointEntry`.
- **`connector_app.rs`** — wire `on_change_server` (open entry),
  `on_retry` (→ `AuthEvent::SignInRequested`), and the save handler (update
  `config` + `matrix_api_url` signals, persist `AppSettings`). Thread the
  `Failed { reason }` string into `OfflineScreen`'s `reason` prop.
- **`crates/core/src/config.rs`** — ensure the endpoint change writes
  `matrix_api_url` / `last_config` to `AppSettings`, and confirm load precedence:
  persisted settings win over the baked default on next launch.

## Data Flow

1. Cancel / failure → `AuthEvent::Disconnected` / `TokenFailed(reason)` →
   `AuthFlow::Disconnected` / `Failed{reason}` → `OfflineScreen` (with `reason`
   when present).
2. **Retry** → `on_retry` → `AuthEvent::SignInRequested` → existing
   `plg_sign_in_and_connect`.
3. **Change server** → open `EndpointEntry` → type URL → validate +
   `normalize_host` → Save: update `config`/`matrix_api_url` signals, write
   `AppSettings`, close entry, remain on offline screen (now targeting the new
   endpoint).
4. **Sign in** → `AuthEvent::SignInRequested` against the (possibly new)
   endpoint.
5. Next launch: persisted `AppSettings.matrix_api_url`/`last_config` override the
   baked default (precedence verified during implementation).

## Error Handling

- Endpoint entry: empty/malformed URL → inline field error, no state change.
- The offline screen never shows a blank/dead state: every `AuthFlow` offline
  state maps to a populated screen with at least Sign in + Change server.
- A failed sign-in against a newly-entered endpoint returns to the offline
  screen with the new `reason`, endpoint change preserved.

## Testing

- **Unit (pure):** URL validation/derivation for the entry field — extend
  `derive_api_url` tests; accept bare/scheme/trailing-slash, reject
  empty/malformed.
- **State machine:** guard the three offline-rendering states' transitions in
  `auth_flow.rs` tests (Disconnected↔SigningIn, Failed→SigningIn on retry). No
  new variants.
- **Persistence:** round-trip test — an endpoint change writes and reloads from
  `AppSettings` (mirrors existing settings/OTT tests).
- **Component rendering:** no Dioxus component unit harness exists in this crate
  (consistent with the rest of `crates/ui`); verified via `cargo check`/`clippy`
  and manual/`verify` on desktop. This gap is stated, not hidden.

## Out of Scope

- Offline app functionality (cached/view-only reports) — possible follow-up.
- Tenant entry in easy mode (PLG resolves it server-side).
- Endpoint presets/known-cluster list.
- Any change to expert-mode `ConfigForm`.
- New `AuthFlow` variant.
