# Android Interactive Shell Restoration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the working interactive Shell tab on the Android build (reachable via Settings → non-easy mode), token-gated for safety.

**Architecture:** On Android, bind the LiveView server to `127.0.0.1:3030` TCP (the only transport the WebView can reach) instead of the unwritable/unreachable unix socket. Gate `/ws/shell` with a per-session token generated at startup and propagated into `shell_init.js`. Inject the WebView cross-origin settings and `restty.js` asset into the dx-generated Android project via the existing `_inject-android-lib` recipe so they survive dx regeneration.

**Tech Stack:** Rust (axum, tokio, uuid), Dioxus/wry (dx 0.7.9), Android (Kotlin, Gradle), justfile, proot.

## Global Constraints

- Rust stable 1.92+; `cargo fmt --all` + `cargo clippy -- -D warnings` clean before commit.
- No secrets, tenant names, emojis, or em-dashes in commit messages.
- Token generated with `uuid::Uuid::new_v4()` — no new crypto dependency (`uuid` is already a workspace dependency).
- Mobile has no runtime env; do not add runtime-env reads for Android.
- Non-Android (desktop/StrikeHub) behavior must be unchanged except for the shared token gate.
- The Shell tab is NOT added to the easy-mode sidebar; it stays reachable only via Settings → non-easy mode.

---

## File Structure

- `crates/ui/src/shell_ws.rs` — shared `/ws/shell` handler. Add the process-global session token, add `token` to `ShellParams`, gate `ws_handler`. Owns the token's canonical accessor.
- `crates/ui/src/components/shell.rs` — Dioxus `InteractiveShell`. Substitute a new `__SHELL_TOKEN__` placeholder using the token accessor.
- `crates/ui/src/assets/shell_init.js` — terminal bootstrap JS. Add `__SHELL_TOKEN__` and append `&token=` to every `wsUrl` branch.
- `crates/ui/src/liveview_server.rs` — server bind. Add an Android-only TCP bind branch; keep the unix path for non-Android.
- `justfile` — `_inject-android-lib` recipe. Add WebView cross-origin settings injection into the generated `RustWebView.kt` and copy `restty.js` into APK assets.

---

## Task 1: Session token + `/ws/shell` gate

**Files:**
- Modify: `crates/ui/src/shell_ws.rs:22-58`

**Interfaces:**
- Produces: `pub fn shell_token() -> &'static str` — returns the process-global session token, initializing it once via `Uuid::new_v4()`. Consumed by Task 2.
- Produces: `/ws/shell` now requires a `token` query param matching `shell_token()`; a mismatch/absent token yields HTTP 401 and no upgrade.

- [ ] **Step 1: Write the failing test**

Add to the bottom of `crates/ui/src/shell_ws.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_token_is_stable_and_nonempty() {
        let a = shell_token();
        let b = shell_token();
        assert!(!a.is_empty(), "token must be non-empty");
        assert_eq!(a, b, "token must be stable across calls");
    }

    #[test]
    fn token_matches_only_exact_value() {
        let t = shell_token();
        // Accept path: exact match.
        assert!(token_ok(Some(t)));
        // Reject paths: absent or wrong.
        assert!(!token_ok(None));
        assert!(!token_ok(Some("not-the-token")));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-ui --features "connector,shell-ws,desktop" shell_ws 2>&1 | tail -20`
Expected: FAIL — `cannot find function shell_token` / `token_ok` not defined.

- [ ] **Step 3: Write minimal implementation**

In `crates/ui/src/shell_ws.rs`, add imports near the top (after line 25):

```rust
use std::sync::OnceLock;
```

Add the token accessor and gate helper after the `ShellParams` struct (replace lines 27-31 with):

```rust
#[derive(Deserialize)]
struct ShellParams {
    cols: Option<u16>,
    rows: Option<u16>,
    /// Per-session token gating access to the shell. The page's shell_init.js
    /// is served the token via placeholder substitution; other local processes
    /// (which matters on Android, where any app can reach 127.0.0.1 TCP) do not
    /// have it and are rejected before the PTY is spawned.
    token: Option<String>,
}

/// Process-global per-session shell token. Generated once on first read with
/// `Uuid::new_v4()` and stable for the process lifetime. Mirrors the
/// `WORKSPACE_PATH` OnceLock pattern in liveview_server.rs — a value any thread
/// can read without threading it through the Dioxus component tree.
pub fn shell_token() -> &'static str {
    static SHELL_TOKEN: OnceLock<String> = OnceLock::new();
    SHELL_TOKEN.get_or_init(|| uuid::Uuid::new_v4().to_string())
}

/// True when the supplied token exactly matches the session token.
fn token_ok(supplied: Option<&str>) -> bool {
    supplied == Some(shell_token())
}
```

Then gate `ws_handler` — replace its body (lines 41-58) with:

```rust
async fn ws_handler(ws: WebSocketUpgrade, Query(params): Query<ShellParams>) -> impl IntoResponse {
    // Reject before upgrading if the token is missing or wrong. On Android the
    // shell WS is served over a localhost TCP port reachable by any app, so this
    // gate is what keeps a root proot shell from being opened by another process.
    if !token_ok(params.token.as_deref()) {
        tracing::warn!("[shell_ws] rejecting /ws/shell: missing or invalid token");
        return axum::http::StatusCode::UNAUTHORIZED.into_response();
    }

    let cols = params.cols.unwrap_or(80);
    let rows = params.rows.unwrap_or(24);

    // Always read the authoritative shell mode from the persisted settings
    // rather than relying on the client to pass it (the workspace_app's
    // settings signal can be stale).
    let shell_mode = load_settings().shell_mode;

    let workspace = crate::liveview_server::get_workspace_path();
    let cwd = if workspace.is_empty() {
        None
    } else {
        Some(PathBuf::from(workspace))
    };

    ws.on_upgrade(move |socket| handle_socket(socket, cols, rows, cwd, shell_mode))
        .into_response()
}
```

Note: `ws_handler` now returns `axum::response::Response` on both arms; the `.into_response()` on the upgrade arm unifies the type. The `use axum::response::IntoResponse;` import already exists (line 14).

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo test -p pentest-ui --features "connector,shell-ws,desktop" shell_ws 2>&1 | tail -20`
Expected: PASS — both tests green.

- [ ] **Step 5: Clippy + fmt**

Run: `nix develop --command cargo clippy -p pentest-ui --features "connector,shell-ws,desktop" -- -D warnings 2>&1 | tail -15`
Expected: no warnings. Then `nix develop --command cargo fmt --all`.

- [ ] **Step 6: Commit**

```bash
git add crates/ui/src/shell_ws.rs
git commit -m "feat(shell): token-gate /ws/shell with a per-session token

Add a process-global session token (Uuid::new_v4, OnceLock) and require it
as a ?token= query param on /ws/shell. Rejects with 401 before upgrade when
absent/wrong. Matters on Android, where the shell WS is served over a
localhost TCP port any app can reach; also hardens the desktop endpoint."
```

---

## Task 2: Propagate the token into shell_init.js

**Files:**
- Modify: `crates/ui/src/components/shell.rs:62-67`
- Modify: `crates/ui/src/assets/shell_init.js:174-191`

**Interfaces:**
- Consumes: `crate::shell_ws::shell_token()` (Task 1).
- Produces: every `wsUrl` the terminal builds now carries `&token=<token>`, so the gate from Task 1 accepts the app's own WebView.

- [ ] **Step 1: Add the placeholder to the JS wsUrl branches**

In `crates/ui/src/assets/shell_init.js`, add a token variable just after the `var shellMode = '__SHELL_MODE__';` line (line 174):

```javascript
    var shellMode = '__SHELL_MODE__';
    var shellToken = '__SHELL_TOKEN__';
```

Then append `&token=` to all three `wsUrl` assignments (lines 185, 188, 190). They become:

```javascript
        wsUrl = wsBridgeBase + '/ws/' + connectorId + '/ws/shell?cols=80&rows=24&mode=' + shellMode + '&token=' + shellToken;
```
```javascript
        wsUrl = wsProto + '//' + location.host + '/ws/shell?cols=80&rows=24&mode=' + shellMode + '&token=' + shellToken;
```
```javascript
        wsUrl = BASE.replace('http', 'ws') + '/ws/shell?cols=80&rows=24&mode=' + shellMode + '&token=' + shellToken;
```

- [ ] **Step 2: Substitute the placeholder in shell.rs**

In `crates/ui/src/components/shell.rs`, extend the `.replace(...)` chain (lines 65-66). It becomes:

```rust
        let js = format!(
            "{teardown}\n{init}",
            init = SHELL_INIT_JS
                .replace("__LIVEVIEW_BASE__", LIVEVIEW_BASE)
                .replace("__SHELL_MODE__", &current_mode)
                .replace("__SHELL_TOKEN__", crate::shell_ws::shell_token())
        );
```

- [ ] **Step 3: Verify it compiles**

Run: `nix develop --command cargo check -p pentest-ui --features "connector,shell-ws,desktop" 2>&1 | tail -15`
Expected: `Finished` with no errors.

- [ ] **Step 4: Grep-verify no placeholder is left unsubstituted**

Run: `grep -c "__SHELL_TOKEN__" crates/ui/src/assets/shell_init.js && grep -c "__SHELL_TOKEN__" crates/ui/src/components/shell.rs`
Expected: `1` (the JS placeholder) and `1` (the shell.rs `.replace` line). Both present means the placeholder is defined in the asset and substituted in Rust.

- [ ] **Step 5: fmt + Commit**

```bash
nix develop --command cargo fmt --all
git add crates/ui/src/components/shell.rs crates/ui/src/assets/shell_init.js
git commit -m "feat(shell): pass the session token from shell_init.js to /ws/shell

Substitute __SHELL_TOKEN__ (from shell_token()) into the terminal bootstrap
JS and append &token= to every wsUrl branch so the app's own WebView passes
the Task 1 gate."
```

---

## Task 3: Android TCP listener for the LiveView server

**Files:**
- Modify: `crates/ui/src/liveview_server.rs:418-456`

**Interfaces:**
- Consumes: nothing new.
- Produces: on Android, `start_liveview_server` binds `127.0.0.1:3030` TCP and serves the router; returns `LiveViewHandle { ipc_addr: None }`. Non-Android keeps the existing unix-socket path unchanged.

- [ ] **Step 1: Replace the standalone bind section with a cfg split**

In `crates/ui/src/liveview_server.rs`, replace the standalone section (lines 418-456, from the `// Standalone mode:` comment through the closing `}` of the function) with:

```rust
    // Standalone mode. Android and non-Android diverge: the Android WebView
    // cannot reach a unix domain socket (and /tmp is not writable in the app
    // sandbox), so on Android we bind a localhost TCP port the WebView CAN
    // reach. On desktop we keep the PID-based unix socket / named pipe, which
    // avoids port collisions when multiple connectors run on one host.
    #[cfg(target_os = "android")]
    {
        let bind_addr = format!("127.0.0.1:{}", port);
        let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
        tracing::info!("LiveView TCP server listening on {}", bind_addr);

        tokio::spawn(async move {
            tracing::info!("LiveView server task started (Android TCP mode)");
            let server = axum::serve(listener, router.into_make_service());
            tokio::select! {
                result = server => {
                    tracing::warn!("LiveView server exited: {:?}", result);
                    if let Err(e) = result {
                        tracing::error!("LiveView server error: {}", e);
                    }
                }
                _ = async {
                    while !shutdown_clone.load(Ordering::SeqCst) {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                } => {
                    tracing::info!("LiveView server shutting down");
                }
            }
            tracing::warn!("LiveView server task ending");
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        return Ok(LiveViewHandle {
            shutdown,
            port,
            ipc_addr: None,
        });
    }

    #[cfg(not(target_os = "android"))]
    {
        // PID-based IPC address (Unix socket or named pipe) to avoid conflicts
        // when multiple connectors run simultaneously.
        let addr = IpcAddr::for_agent(std::process::id());
        let listener = IpcListener::bind(&addr)?;
        tracing::info!("LiveView server listening on {}", addr);

        let addr_clone = addr.clone();
        tokio::spawn(async move {
            tracing::info!("LiveView server task started");
            let server = axum::serve(listener, router.into_make_service());

            tokio::select! {
                result = server => {
                    tracing::warn!("LiveView server exited: {:?}", result);
                    if let Err(e) = result {
                        tracing::error!("LiveView server error: {}", e);
                    }
                }
                _ = async {
                    while !shutdown_clone.load(Ordering::SeqCst) {
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                } => {
                    tracing::info!("LiveView server shutting down");
                }
            }
            addr_clone.cleanup();
            tracing::warn!("LiveView server task ending");
        });

        // Wait a moment for the server to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        Ok(LiveViewHandle {
            shutdown,
            port,
            ipc_addr: Some(addr),
        })
    }
}
```

Note: this preserves the exact non-Android behavior (same `addr`, `IpcListener::bind`, `cleanup()`, `ipc_addr: Some(addr)`), only wrapping it in `#[cfg(not(target_os = "android"))]`. The Android arm has no `addr_clone.cleanup()` because TCP needs no socket-file cleanup.

- [ ] **Step 2: Verify desktop still compiles + no behavior drift**

Run: `nix develop --command cargo check -p pentest-ui --features "connector,shell-ws,desktop" 2>&1 | tail -15`
Expected: `Finished` with no errors.

- [ ] **Step 3: Verify the Android target compiles**

Run: `nix develop --command bash -c 'unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH; NDK_BIN=$(just _android-ndk-bin); export CC_aarch64_linux_android="$NDK_BIN/aarch64-linux-android28-clang" CXX_aarch64_linux_android="$NDK_BIN/aarch64-linux-android28-clang++" AR_aarch64_linux_android="$NDK_BIN/llvm-ar"; cargo check -p pentest-ui --features "connector,shell-ws,desktop" --target aarch64-linux-android 2>&1 | tail -15'`
Expected: `Finished`. (This proves the `#[cfg(target_os = "android")]` arm typechecks — `tokio::net::TcpListener` is available under the mobile feature set.)

- [ ] **Step 4: Commit**

```bash
git add crates/ui/src/liveview_server.rs
git commit -m "fix(android): serve LiveView over 127.0.0.1:3030 TCP, not a unix socket

The Android WebView cannot reach a unix domain socket and /tmp is not
writable in the app sandbox, so the standalone unix bind failed with EPERM
and aborted the whole server (LiveView server failed: Permission denied).
On Android, bind a localhost TCP port the WebView can reach instead. Desktop
keeps the PID-based unix socket / named pipe unchanged."
```

---

## Task 4: Inject WebView cross-origin settings + restty.js asset

**Files:**
- Modify: `justfile:225-280` (the `_inject-android-lib` recipe)

**Interfaces:**
- Consumes: the dx-generated project at `{{proj}}` containing `app/src/main/kotlin/dev/dioxus/main/RustWebView.kt` (whose `init {}` block sets `settings.*`, imports `android.webkit.*`) and `crates/ui/src/assets/restty.js`.
- Produces: the built APK's WebView allows cross-origin requests to `http://127.0.0.1:3030`, and `restty.js` is available as an APK asset. Inherited by `build-android`, `build-android-release`, `bundle-android` (all call `_inject-android-lib`).

- [ ] **Step 1: Add the two injection blocks to `_inject-android-lib`**

In `justfile`, inside the `_inject-android-lib` recipe, insert the following AFTER the jniLibs copy loop (after line 280, the `done` of the `for arch in android-jniLibs/*/` loop), still inside the recipe:

```bash
    # Allow the dx WebView to reach the localhost TCP LiveView server
    # (http://127.0.0.1:3030). The Dioxus WebView renders under a custom scheme;
    # without these cross-origin settings the shell's fetch/WebSocket to
    # 127.0.0.1:3030 is blocked. dx regenerates RustWebView.kt every build, so
    # (like the android-lib injection) this must run after dx and be idempotent.
    # android.webkit.* is already imported in the generated file, so
    # WebSettings.MIXED_CONTENT_ALWAYS_ALLOW resolves without a new import.
    webview_file="{{proj}}/app/src/main/kotlin/dev/dioxus/main/RustWebView.kt"
    anchor="settings.javaScriptCanOpenWindowsAutomatically = true"
    if [ ! -f "$webview_file" ]; then
        echo "ERROR: generated RustWebView.kt not found at $webview_file" >&2
        exit 1
    fi
    if ! grep -q "MIXED_CONTENT_ALWAYS_ALLOW" "$webview_file"; then
        if ! grep -qF "$anchor" "$webview_file"; then
            echo "ERROR: RustWebView.kt anchor not found ('$anchor'); dx template changed." >&2
            exit 1
        fi
        # Insert the four settings immediately after the anchor line.
        python3 - "$webview_file" "$anchor" <<'PY'
import sys
path, anchor = sys.argv[1], sys.argv[2]
inject = (
    "        settings.mixedContentMode = android.webkit.WebSettings.MIXED_CONTENT_ALWAYS_ALLOW\n"
    "        @Suppress(\"DEPRECATION\")\n"
    "        settings.allowUniversalAccessFromFileURLs = true\n"
    "        settings.allowContentAccess = true\n"
    "        settings.allowFileAccess = true\n"
)
lines = open(path).read().splitlines(keepends=True)
out = []
for ln in lines:
    out.append(ln)
    if anchor in ln:
        out.append(inject)
open(path, "w").write("".join(out))
PY
    fi
    if ! grep -q "MIXED_CONTENT_ALWAYS_ALLOW" "$webview_file"; then
        echo "ERROR: failed to inject WebView cross-origin settings into $webview_file" >&2
        exit 1
    fi

    # Copy restty.js into the APK assets so the WebView asset path can serve it
    # (the LiveView server also serves it over HTTP, this is the belt-and-braces
    # asset copy the original Android shell shipped).
    assets_dir="{{proj}}/app/src/main/assets/assets"
    mkdir -p "$assets_dir"
    cp crates/ui/src/assets/restty.js "$assets_dir/restty.js"
```

- [ ] **Step 2: Build a debug APK (x86_64) to exercise the injection**

Run: `nix develop --command bash -c 'ANDROID_TARGETS="x86_64-linux-android" just build-android' 2>&1 | tail -15`
Expected: `BUILD SUCCESSFUL` and `OK: ConnectorBridge present in APK` (the injection ran without hitting the anchor-missing error).

- [ ] **Step 3: Verify the settings actually landed in the generated file**

Run: `grep -c "MIXED_CONTENT_ALWAYS_ALLOW" target/dx/pick/debug/android/app/app/src/main/kotlin/dev/dioxus/main/RustWebView.kt && ls -la target/dx/pick/debug/android/app/app/src/main/assets/assets/restty.js`
Expected: `1` and the `restty.js` file listed with non-zero size.

- [ ] **Step 4: Commit**

```bash
git add justfile
git commit -m "build(android): inject WebView cross-origin settings + restty.js asset

Extend _inject-android-lib (already run after every dx build) to add the
four WebView settings (mixedContentMode ALWAYS_ALLOW, allowUniversalAccess/
Content/File) into the regenerated RustWebView.kt, and copy restty.js into
APK assets. Lets the WebView reach the localhost TCP LiveView server so the
Android shell terminal connects. Aborts loudly if the dx anchor is missing."
```

---

## Task 5: End-to-end verification on emulator then device

**Files:** none (verification only).

**Interfaces:**
- Consumes: Tasks 1-4 (token gate, JS token, Android TCP, WebView injection).

- [ ] **Step 1: Build + install on the local x86_64 emulator**

The emulator `PentestDev` should be booted (`emulator-5554`). Build the x86_64 debug APK and install:

```bash
nix develop --command bash -c '
  ANDROID_TARGETS="x86_64-linux-android" just build-android
  ADB="$ANDROID_HOME/platform-tools/adb"
  "$ADB" -s emulator-5554 uninstall com.strike48.pentest_connector 2>/dev/null || true
  "$ADB" -s emulator-5554 install target/dx/pick/debug/android/app/app/build/outputs/apk/debug/app-debug.apk
  "$ADB" -s emulator-5554 shell monkey -p com.strike48.pentest_connector -c android.intent.category.LAUNCHER 1
'
```
Expected: `Success`, app launches.

- [ ] **Step 2: Confirm the TCP server bound and no EPERM abort**

Run: `nix develop --command bash -c '"$ANDROID_HOME/platform-tools/adb" -s emulator-5554 logcat -d 2>/dev/null | grep -iE "LiveView TCP server listening|Permission denied|LiveView server failed" | tail -5'`
Expected: a `LiveView TCP server listening on 127.0.0.1:3030` line, and NO `Permission denied` / `LiveView server failed` line.

- [ ] **Step 3: Open the Shell tab and confirm it connects (manual)**

In the app: Settings → turn OFF easy mode → navigate to the Shell tab. Then capture:

```bash
nix develop --command bash -c '"$ANDROID_HOME/platform-tools/adb" -s emulator-5554 logcat -d 2>/dev/null | grep -iE "shell_ws|PtyShell|reader loop started|rejecting /ws/shell" | tail -20'
```
Expected: `[shell_ws] handle_socket` / `PtyShell::spawn` / `PTY reader loop started` present, and NO `rejecting /ws/shell` (the token matched). The terminal shows a prompt (not stuck on "Starting shell...").

- [ ] **Step 4: Run a command in the terminal (manual)**

In the Shell tab, type `nmap -sT 127.0.0.1 -p 22` (or `whoami`), confirm output renders. This proves the WS↔PTY byte flow works end to end.

- [ ] **Step 5: Build arm64 + install on the Pixel**

```bash
nix develop --command bash -c '
  ANDROID_TARGETS="aarch64-linux-android" just build-android
  ADB="$ANDROID_HOME/platform-tools/adb"
  D="192.168.1.128:46133"
  "$ADB" connect "$D" || true
  "$ADB" -s "$D" uninstall com.strike48.pentest_connector 2>/dev/null || true
  "$ADB" -s "$D" install target/dx/pick/debug/android/app/app/build/outputs/apk/debug/app-debug.apk
  "$ADB" -s "$D" shell monkey -p com.strike48.pentest_connector -c android.intent.category.LAUNCHER 1
'
```
Expected: `Success`. Repeat Steps 2-4 with `-s 192.168.1.128:46133` (wireless adb may need re-pairing if it dropped).

- [ ] **Step 6: Regression — desktop shell still works with the token gate**

Launch the Linux desktop build (`/tmp/run-pick-x11.sh`), open the Shell tab, confirm it still connects (the token substitution + gate work on desktop too). Check the log for `rejecting /ws/shell` — it must NOT appear.

- [ ] **Step 7: No commit** (verification task). If any step fails, return to the owning task (transport→Task 3, gate→Task 1/2, WebView→Task 4) and fix.

---

## Notes for the implementer

- The `#[cfg(target_os = "android")]` arm in Task 3 is only compiled when cross-building for Android; desktop `cargo check` will not catch a typo there. Task 3 Step 3 (the `--target aarch64-linux-android` check) is the guard — do not skip it.
- `uuid` is already a direct dependency of `pentest-ui` (`crates/ui/Cargo.toml:69` — `uuid = { workspace = true }`, workspace version `1` with `v4`) and already used as `uuid::Uuid::new_v4()` in `crates/ui/src/liveview_connector/llm_proxy.rs:301`. No Cargo.toml change is needed for Task 1.
- Wireless adb to the Pixel (`192.168.1.128:46133`) has dropped mid-session before; if `adb connect` fails, re-pair via the phone's Wireless debugging screen (pair code + connect port).
- The committed `[shell_ws]` / `ws-bridge` tracing (commit `3ecca11`) is what Steps 2-3 rely on; it is already present.
