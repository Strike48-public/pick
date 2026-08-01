# Android Interactive Shell Restoration — Design

**Date:** 2026-08-01
**Branch:** `josh/catching-up`
**Status:** Design (pre-implementation)

## Problem

The interactive Shell tab (reachable on mobile via Settings → turn off easy mode →
non-easy workspace layout) renders `InteractiveShell`
(`crates/ui/src/components/shell.rs`), whose `shell_init.js` connects a WebSocket
to `ws://127.0.0.1:3030/ws/shell`. On the current `josh/catching-up` branch this
is broken in two ways:

1. **No TCP listener.** `crates/ui/src/liveview_server.rs` binds only an
   `IpcListener` (unix socket / named pipe). There is no `127.0.0.1:3030` TCP
   listener on any platform. The WebView cannot open a unix socket, so
   `ws://127.0.0.1:3030/ws/shell` has nothing to connect to.
2. **Fatal unix bind on Android.** The standalone branch does
   `IpcListener::bind(&addr)?` on `/tmp/pentest-agent-<pid>.sock`
   (`crates/ui/src/ipc.rs:29`). `/tmp` is not writable in the Android app
   sandbox, so the `?` returns `Err` and aborts the entire
   `start_liveview_server` — surfacing as `LiveView server failed: Permission
   denied (os error 13)` at `connector_app.rs:721`. The server never starts.

The shell **did** work previously, via commit `63475b7` ("feat: enable shell
terminal on Android") on the unmerged `origin/feat/android-update` branch. That
commit added a TCP:3030 listener, WebView cross-origin settings in a static
`apps/mobile/android/MainActivity.kt`, and a `restty.js` asset copy. It is not
an ancestor of the current HEAD (`git merge-base --is-ancestor 63475b7 HEAD` →
false).

The proot PTY backend itself is fully implemented and functional on Android
(`crates/platform/src/android/pty_shell.rs` — `spawn_proot` runs bundled
`libproot.so` against a BlackArch rootfs and execs `/bin/bash -l -i`). Only the
transport and WebView glue are missing.

`63475b7` cannot be cherry-picked verbatim because the branch has drifted:

- **Ordering drift:** `63475b7` placed the TCP block *after* the
  `IpcListener::bind(&addr)?`. On the current Android sandbox that `?` aborts
  first, so a verbatim port would never reach the TCP listener.
- **MainActivity drift:** `apps/mobile/android/MainActivity.kt` no longer
  exists; `apps/mobile` now uses a **dx-generated** `MainActivity.kt`
  (`dev/dioxus/main/MainActivity.kt`) regenerated on every `dx build`.

## Goals

- Restore a working interactive shell on the Android build (non-easy-mode Shell
  tab), verified on both the local x86_64 emulator and the arm64 Pixel.
- Do it in a way that survives dx regeneration (durable, like
  `_inject-android-lib`).
- Add a per-session token gate to `/ws/shell` so the localhost root-shell port
  is not open to every app on the device (also hardens the desktop shell).

## Non-goals

- Linking the Shell tab into the easy-mode sidebar. The shell remains reachable
  only via Settings → non-easy mode. (Explicit user decision.)
- Changing the proot PTY backend (already works).
- iOS shell (separate concern; iOS is cfg-gated out alongside Android in the
  shell-ws UI code and is not addressed here).

## Global Constraints

- Rust stable 1.92+; `cargo fmt` + `cargo clippy -- -D warnings` clean.
- No secrets/tenant names/emojis/em-dashes in commits.
- Mobile has no runtime env; build-time bakes only where already used.
- The token is generated with `uuid::Uuid::new_v4()` (the repo's existing random
  primitive; no new crypto dependency).

## Architecture

Four components.

### 1. `liveview_server.rs` — Android TCP transport (TCP-only)

On Android, bind **only** `127.0.0.1:3030` via `tokio::net::TcpListener` and
`axum::serve` the same router, honoring the existing `shutdown` `AtomicBool`.
Skip the unix-socket path entirely on Android (it is both unreachable by the
WebView and unwritable in the sandbox). Concretely, in the standalone section of
`start_liveview_server`:

- `#[cfg(target_os = "android")]`: bind TCP, spawn the serve task, and return a
  `LiveViewHandle` with `ipc_addr: None` and the TCP `port`.
- `#[cfg(not(target_os = "android"))]`: the existing `IpcListener::bind(&addr)?`
  standalone path, unchanged.

This removes the fatal `?` on Android and the misleading EPERM log line, and
gives the WebView a reachable endpoint. Desktop/StrikeHub paths are untouched.

### 2. `shell_ws.rs` — per-session token gate

- Add a process-global token: `static SHELL_TOKEN: OnceLock<String>`, with a
  `pub fn shell_token() -> &'static str` that initializes it once via
  `Uuid::new_v4()` on first read. (Mirrors the `WORKSPACE_PATH` `OnceLock`
  pattern already in `liveview_server.rs`.)
- Add `token: Option<String>` to `ShellParams`.
- In `ws_handler`, before `ws.on_upgrade(...)`: if
  `params.token.as_deref() != Some(shell_token())`, return
  `StatusCode::UNAUTHORIZED` and do not upgrade. Otherwise proceed as today.

This applies on every platform, so the desktop shell endpoint is hardened too
(same `/ws/shell` handler).

### 3. `shell.rs` + `shell_init.js` — token propagation

- Add a `__SHELL_TOKEN__` placeholder to `shell_init.js`. When building `wsUrl`
  in every branch, append `&token=<token>`.
- In `shell.rs`, substitute `__SHELL_TOKEN__` with `shell_token()` alongside the
  existing `__LIVEVIEW_BASE__` / `__SHELL_MODE__` replacements. No new props or
  context; the component reads the process-global directly.

### 4. `justfile` — two post-`dx build` injections

Both are added **inside the existing `_inject-android-lib` recipe**, which
already takes the generated-project path as `proj` and is already invoked after
`dx build` by all three artifact recipes (`build-android:381`,
`build-android-release:432`, `bundle-android:502`). Placing them there means
every Android artifact path gets them with no additional call sites. They mirror
the recipe's existing conventions (idempotent, self-verifying, abort loudly on a
missing anchor).

- **WebView settings injection** into
  `target/dx/pentest-mobile/<profile>/android/app/app/src/main/kotlin/dev/dioxus/main/MainActivity.kt`:
  after the `super.onWebViewCreate(webView)` call, insert:
  ```kotlin
  webView.settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
  @Suppress("DEPRECATION")
  webView.settings.allowUniversalAccessFromFileURLs = true
  webView.settings.allowContentAccess = true
  webView.settings.allowFileAccess = true
  ```
  plus the `import android.webkit.WebSettings` if absent. Grep-guard so it is
  only inserted once; abort with a clear error if the `onWebViewCreate` anchor
  is not found (dx template changed).
- **restty.js asset copy**: `cp crates/ui/src/assets/restty.js` into
  `<proj>/app/src/main/assets/assets/restty.js`, creating the dir.

## Data Flow

1. App start: `shell_token()` lazily initializes the token before the server
   starts.
2. Android `start_liveview_server`: binds `127.0.0.1:3030`, serves the router
   (shell routes merged via `extra_routes`), logs the TCP bind.
3. User opens Shell tab: `InteractiveShell` runs `shell_init.js` with
   `__LIVEVIEW_BASE__=http://127.0.0.1:3030` and `__SHELL_TOKEN__=<token>`.
4. JS loads `http://127.0.0.1:3030/assets/restty.js`, then opens
   `ws://127.0.0.1:3030/ws/shell?cols=80&rows=24&token=<token>`. The WebView
   permits the cross-origin call due to the injected `MainActivity` settings.
5. `ws_handler` validates the token → `on_upgrade` → `handle_socket` →
   `PtyShell::spawn(ShellMode::Proot)` → `android/pty_shell.rs` spawns proot
   bash.
6. Bytes flow both ways over WS ↔ PTY via the existing `handle_socket` loop.

## Error Handling

- **TCP bind fails (port in use):** log the error; the shell tab stays at
  "Starting shell...". Non-fatal to the app. Only cause on a phone is a second
  connector instance.
- **Token mismatch/absent:** `ws_handler` returns 401 before upgrade; JS
  surfaces connection-closed. Blocks other local apps.
- **proot rootfs not present:** existing `ensure_rootfs` progress path;
  unchanged.
- **MainActivity injection anchor missing:** the justfile step aborts the build
  loudly rather than shipping a shell that cannot connect.

## Security

`/ws/shell` upgrades to an interactive root shell inside the proot BlackArch
sandbox. On Android, any installed app can reach `127.0.0.1` TCP, so an
unauthenticated 3030 port would let a malicious local app open that shell. The
per-session token (component 2) closes this: only the app's own WebView, which
received the token via `shell_init.js` substitution, can connect. The token is
process-scoped and regenerated each launch. This also hardens the desktop shell,
which shares the endpoint. The token is not a secret at rest (it lives only in
process memory and the in-page JS), which is the correct scope for a
same-device, same-process localhost gate.

## Testing

- **Unit (`shell_ws.rs`):** token gate accept/reject/absent; `ShellParams`
  deserialize with and without `token`.
- **Build-time (justfile):** injection idempotency and anchor-present assertion
  (recipe self-verifies, like `_inject-android-lib`).
- **Integration (manual, both devices):**
  - Local x86_64 emulator first (fast KVM loop): confirm `127.0.0.1:3030` binds,
    Shell tab spawns proot bash, `nmap -sT` runs in the terminal.
  - Pixel 9 Pro Fold (arm64) next: same checks on real hardware.
  - Capture via logcat using the committed `[shell_ws]` / `ws-bridge` tracing.
- **Regression:** desktop shell (Linux, running on this box) still works with
  the token gate.

## Files

- Modify: `crates/ui/src/liveview_server.rs` (Android TCP branch)
- Modify: `crates/ui/src/shell_ws.rs` (token global + gate + `ShellParams.token`)
- Modify: `crates/ui/src/components/shell.rs` (token substitution)
- Modify: `crates/ui/src/assets/shell_init.js` (`__SHELL_TOKEN__` + `&token=`)
- Modify: `justfile` `_inject-android-lib` recipe (MainActivity WebView-settings
  injection + restty.js asset copy — inherited by `build-android`,
  `build-android-release`, `bundle-android`, which already call it)
