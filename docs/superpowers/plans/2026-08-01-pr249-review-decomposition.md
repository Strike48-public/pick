# PR #249 Review Decomposition & Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Shrink PR #249's review surface by extracting the crux and run_js work onto their own parked branches, then fix every remaining finding that stays on #249 so it passes CI and closes its security holes.

**Architecture:** Snapshot-then-delete split (no history rewrite): cut two new branches from the current tip, then remove those paths from #249 in one cleanup commit + lockfile regen. Then apply the staying findings as TDD-style fixes, running `cargo fmt` last.

**Tech Stack:** Rust (workspace, 1.92+), Cargo, git, `serde_json`, `reqwest::Url`, `sentry` 0.48, `wiremock` (test), `std::os::unix::fs`.

## Global Constraints

- Rust stable 1.92+ (egui dependency floor). Copied verbatim from CLAUDE.md.
- CI runs clippy with `-D warnings` — zero warnings tolerated.
- `cargo fmt --all -- --check` must pass — it parses every target agnostically (this is why finding 9 slipped past Check/Clippy).
- Conventional-commit messages. No Claude attribution, no customer/tenant names, no emojis or em-dashes.
- Maintainer push policy: feature branches to `origin` directly; `main` is protected.
- The mandatory pre-ready gate (CLAUDE.md): `cargo fmt --all -- --check` → `cargo check --all-targets` → `cargo test --workspace` → `cargo clippy --all-targets -- -D warnings` → `git status` clean.
- `browser-auth` is a non-default feature of `pentest-core` (`crates/core/Cargo.toml:10`), enabled by `apps/web`, `apps/mobile`, `apps/desktop`. The OAuth code and its tests are all `#[cfg(feature = "browser-auth")]`.

---

## Finding-to-Task Map

| Finding | Home | Task |
|---|---|---|
| F1, F3, F4, F5, F6, F7 + crux-only should-fix | leaves with `feat/pick-crux` | Task 1 (extract only) |
| F8 (run_js SSRF) | leaves with `feat/run-js-tool` | Task 1 (extract only) |
| F2 core half (OAuth state) | stays #249 | Task 3 |
| OTT 0600 atomic + umask test | stays #249 | Task 4 |
| derive_api_url https downgrade | stays #249 | Task 5 |
| telemetry is_enabled + flush | stays #249 | Task 6 |
| documents_panel error surfacing | stays #249 | Task 7 |
| param_bool coercion + test | stays #249 | Task 8 |
| mdns/ssdp probe-skipped + set_read_timeout | stays #249 | Task 9 |
| service_banner batch tests | stays #249 | Task 10 |
| OAuth tests feature-gating (CI) | stays #249 | Task 11 |
| F9 (cargo fmt) + final gate | stays #249 | Task 12 |

> Reclassified during design: the `Event::Logout`/`NewChat` `tool_calls`-clear item lives in `crux-core/src/update.rs` and leaves with crux — NOT fixed here.

> Severity corrections from reading current code (line numbers had drifted from the review's base):
> - `documents_panel` main loader already has a proper `Err` arm (`crates/ui/src/components/documents_panel.rs:130`). The only silent-drop is the best-effort per-doc metadata fetch (`:156`). Task 7 is scoped to that, and begins by verifying the current behavior.
> - `service_banner` batch `unwrap_or("")` on host is immediately followed by an emptiness check that returns `InvalidParams` (`crates/tools/src/service_banner.rs:168`), so it is not a crash. Task 10 is test-coverage only, no code change.

---

## Task 1: Snapshot the two carve-out branches

**Files:** none modified (git branch creation only).

**Interfaces:**
- Produces: two local branches `feat/pick-crux` and `feat/run-js-tool`, both pointing at the current `josh/catching-up` tip, preserving full history via shared ancestry.

- [ ] **Step 1: Confirm working tree is clean and on the right branch**

Run:
```bash
cd /home/jadams/src/github.com/Strike48-public/pick
git status --porcelain && git branch --show-current
```
Expected: no output from `--porcelain` (clean); branch is `josh/catching-up`.

- [ ] **Step 2: Create both snapshot branches from the current tip**

Run:
```bash
git branch feat/pick-crux
git branch feat/run-js-tool
git branch --list 'feat/pick-crux' 'feat/run-js-tool'
```
Expected: both branches listed. No checkout — we stay on `josh/catching-up`.

- [ ] **Step 3: Verify the snapshots contain the code to be extracted**

Run:
```bash
git ls-tree feat/pick-crux --name-only -- crates/crux-core crates/crux-ffi crates/crux-middleware apps/android-crux apps/ios-crux
git ls-tree feat/run-js-tool --name-only -- crates/tools/src/run_js.rs
```
Expected: all five crux paths present on `feat/pick-crux`; `run_js.rs` present on `feat/run-js-tool`.

No commit — branch creation is the deliverable. Deferred findings (F1,3,4,5,6,7 on `feat/pick-crux`; F8 on `feat/run-js-tool`) are tracked by the team out-of-band; do NOT open GitHub issues.

---

## Task 2: Delete crux + run_js from #249 and verify green

**Files:**
- Delete: `crates/crux-core/`, `crates/crux-ffi/`, `crates/crux-middleware/`, `apps/android-crux/`, `apps/ios-crux/`, `crates/tools/src/run_js.rs`
- Modify: `Cargo.toml` (remove 3 crux `members` entries + the crux-ffi release profile comment block if it references removed crates), `crates/tools/src/lib.rs:25,83,247`
- Regenerate: `Cargo.lock`

**Interfaces:**
- Consumes: nothing (crux crates referenced only by workspace `members`, each other, and `Cargo.lock`; `run_js`/`RunJsTool` has zero refs outside `crates/tools/src` — both verified during design).
- Produces: a #249 tree with no crux/run_js code that still builds/tests/lints clean.

- [ ] **Step 1: Remove the run_js registration from the tools crate**

Edit `crates/tools/src/lib.rs` — delete these three lines:
- Line 25: `pub mod run_js; // Sandboxed JavaScript (QuickJS) tool runner`
- Line 83: `pub use run_js::RunJsTool;`
- Line 247: `registry.register(RunJsTool); // Sandboxed JavaScript payload runner (iOS-capable)`

- [ ] **Step 2: Delete the source files and directories**

Run:
```bash
git rm crates/tools/src/run_js.rs
git rm -r crates/crux-core crates/crux-ffi crates/crux-middleware apps/android-crux apps/ios-crux
```
Expected: git stages the deletions.

- [ ] **Step 3: Remove the crux workspace members**

Edit `Cargo.toml` — delete these three lines from the `members` array (lines 9-11):
```toml
    "crates/crux-core",
    "crates/crux-ffi",
    "crates/crux-middleware",
```
Also check `Cargo.toml:113` — the `release-ffi` profile comment block exists for crux-ffi's `#[no_mangle]` symbols. If a `[profile.release-ffi]` section is now orphaned (no crate uses it), remove it too. Run `rg -n "release-ffi" Cargo.toml crates apps` first; only remove if there are no remaining consumers.

- [ ] **Step 4: Regenerate the lockfile and confirm crux entries are gone**

Run:
```bash
cargo update -w 2>&1 | tail -5 || cargo generate-lockfile
rg -n "pick-crux-core|pick-crux-ffi|pick-crux-middleware" Cargo.lock
```
Expected: the `rg` returns nothing (crux packages removed from the lockfile).

- [ ] **Step 5: Confirm no dangling references remain**

Run:
```bash
rg -n "crux|RunJsTool|run_js" --type rust crates apps | rg -v "^Binary"
rg -n "crux" Cargo.toml
```
Expected: no matches (or only unrelated substrings — inspect any hit).

- [ ] **Step 6: Run the full workspace build + tests to confirm green BEFORE any fixes**

Run:
```bash
cargo check --all-targets 2>&1 | tail -20
cargo test --workspace --locked --features pentest-platform/desktop-pcap 2>&1 | tail -20
cargo clippy --all-targets -- -D warnings 2>&1 | tail -20
```
Expected: check + tests + clippy all succeed. This proves the extraction is clean independent of the later fixes.

- [ ] **Step 7: Commit the extraction**

```bash
git add -A
git commit -m "refactor: extract crux and run_js onto parked branches

Move crates/crux-{core,ffi,middleware}, apps/{android,ios}-crux, and
crates/tools/src/run_js.rs out of this PR onto feat/pick-crux and
feat/run-js-tool respectively, to shrink the review surface. No behavior
change to the remaining Dioxus shells."
```

---

## Task 3: F2 — OAuth `state` parameter generation + validation (core)

**Files:**
- Modify: `crates/core/src/matrix/auth.rs` (the `#[cfg(feature = "browser-auth")]` OAuth block: `try_native_android_oauth` ~443, `try_native_web_auth_session` ~354, `deliver_native_oauth_callback` ~317)
- Test: same file's `#[cfg(all(test, feature = "browser-auth"))]` module

**Interfaces:**
- Consumes: existing `NATIVE_OAUTH_TX` (`auth.rs:215`), `token_from_callback_url` (`auth.rs:409`), `NATIVE_OAUTH_SCHEME` (`auth.rs:272`).
- Produces:
  - `fn generate_oauth_state() -> String` — 32 hex chars from a CSPRNG.
  - `static NATIVE_OAUTH_STATE: std::sync::Mutex<Option<String>>` — the state expected for the in-flight login.
  - `fn state_from_callback_url(url: &str) -> Option<String>` — pulls the `state` query/fragment param (mirrors `token_from_callback_url`).
  - Changed contract: `deliver_native_oauth_callback` returns `false` when there is no in-flight login OR the callback's `state` does not match `NATIVE_OAUTH_STATE`.

- [ ] **Step 1: Write failing tests for state validation**

Add to the test module in `crates/core/src/matrix/auth.rs` (gate `#[cfg(all(test, feature = "browser-auth"))]`):
```rust
#[test]
fn deliver_rejects_callback_with_no_inflight_login() {
    // No login armed: even a well-formed token+state callback must be rejected.
    clear_oauth_state_for_test();
    let url = "com.strike48.pentest://oauth/callback?access_token=abc&state=deadbeef";
    assert!(!deliver_native_oauth_callback(url), "no in-flight login must reject");
}

#[test]
fn deliver_rejects_state_mismatch() {
    // Arm a login expecting one state, deliver a different state -> rejected.
    let (tx, _rx) = tokio::sync::oneshot::channel::<String>();
    arm_oauth_for_test(tx, "expected-state");
    let url = "com.strike48.pentest://oauth/callback?access_token=abc&state=attacker";
    assert!(!deliver_native_oauth_callback(url), "state mismatch must reject");
}

#[test]
fn deliver_accepts_matching_state() {
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    arm_oauth_for_test(tx, "good-state");
    let url = "com.strike48.pentest://oauth/callback?access_token=tok123&state=good-state";
    assert!(deliver_native_oauth_callback(url), "matching state must deliver");
    assert_eq!(rx.blocking_recv().unwrap(), "tok123");
}

#[test]
fn generate_oauth_state_is_random_and_hex() {
    let a = generate_oauth_state();
    let b = generate_oauth_state();
    assert_ne!(a, b, "two states must differ");
    assert_eq!(a.len(), 32);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
}
```
Add these test-only helpers in the same module (they poke the statics directly):
```rust
#[cfg(test)]
fn clear_oauth_state_for_test() {
    *NATIVE_OAUTH_TX.lock().unwrap() = None;
    *NATIVE_OAUTH_STATE.lock().unwrap() = None;
}
#[cfg(test)]
fn arm_oauth_for_test(tx: tokio::sync::oneshot::Sender<String>, state: &str) {
    *NATIVE_OAUTH_TX.lock().unwrap() = Some(tx);
    *NATIVE_OAUTH_STATE.lock().unwrap() = Some(state.to_string());
}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run:
```bash
cargo test -p pentest-core --features browser-auth --lib matrix::auth 2>&1 | tail -25
```
Expected: FAIL — `generate_oauth_state`, `NATIVE_OAUTH_STATE`, `state_from_callback_url`, and the new behavior don't exist yet (compile error / assertion failure).

- [ ] **Step 3: Add the state static, generator, and extractor**

In `crates/core/src/matrix/auth.rs`, next to `NATIVE_OAUTH_TX` (~line 215):
```rust
/// The `state` value expected for the in-flight native-OAuth login. Set before
/// the browser opens; checked in `deliver_native_oauth_callback` so a forged
/// custom-scheme callback (any zero-permission app can `startActivity` one)
/// cannot inject a token for a login this process never initiated.
#[cfg(feature = "browser-auth")]
static NATIVE_OAUTH_STATE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Generate an unguessable OAuth `state` (128 bits, hex). Uses `getrandom` (a
/// transitive dep via reqwest/rustls) so no new crate is added.
#[cfg(feature = "browser-auth")]
fn generate_oauth_state() -> String {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).expect("CSPRNG available");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Extract the `state` parameter from a callback URL (query or fragment),
/// mirroring `token_from_callback_url`.
#[cfg(feature = "browser-auth")]
fn state_from_callback_url(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    if let Some((_, v)) = parsed.query_pairs().find(|(k, _)| k == "state") {
        if !v.is_empty() {
            return Some(v.into_owned());
        }
    }
    if let Some(frag) = parsed.fragment() {
        for (k, v) in reqwest::Url::parse(&format!("{NATIVE_OAUTH_SCHEME}://x/?{frag}"))
            .ok()?
            .query_pairs()
        {
            if k == "state" && !v.is_empty() {
                return Some(v.into_owned());
            }
        }
    }
    None
}
```
Confirm `getrandom` is already resolvable: run `rg -n "getrandom" Cargo.lock | head`. If absent, add `getrandom = "0.2"` under `[dependencies]` in `crates/core/Cargo.toml` instead (it is almost certainly already transitive via rustls).

- [ ] **Step 4: Enforce state in `deliver_native_oauth_callback`**

Replace the body of `deliver_native_oauth_callback` (`auth.rs:317`) so it (a) takes the waiting sender FIRST and rejects when there is none, and (b) validates state before caching/sending:
```rust
#[cfg(feature = "browser-auth")]
pub fn deliver_native_oauth_callback(callback_url: &str) -> bool {
    // Reject unless a login is actually in flight. A forged callback from any
    // other app must not be adopted.
    let sender = match NATIVE_OAUTH_TX.lock() {
        Ok(mut guard) => guard.take(),
        Err(_) => {
            tracing::error!("[BROWSER_AUTH] native OAuth sender lock poisoned");
            return false;
        }
    };
    let Some(tx) = sender else {
        tracing::warn!("[BROWSER_AUTH] native OAuth callback with no login in flight; rejected");
        return false;
    };

    // Validate the state parameter against the value we generated for this login.
    let expected = NATIVE_OAUTH_STATE.lock().ok().and_then(|mut g| g.take());
    let got = state_from_callback_url(callback_url);
    if expected.is_none() || got.is_none() || expected != got {
        tracing::warn!("[BROWSER_AUTH] native OAuth state mismatch; rejected");
        return false;
    }

    let Some(token) = token_from_callback_url(callback_url) else {
        tracing::warn!("[BROWSER_AUTH] native OAuth callback URL contained no access_token");
        return false;
    };
    // Cache only AFTER state validation succeeds.
    if let Ok(mut cache) = BROWSER_TOKEN_CACHE.lock() {
        *cache = Some(token.clone());
    }
    tx.send(token).is_ok()
}
```
Note: this deliberately drops the old "cache a late callback with no login in flight" path — that path was the vulnerability (a token adopted with no sign-in). A timed-out login now requires a fresh, state-matched sign-in.

- [ ] **Step 5: Generate + append state, and store it, in the request builders**

In `try_native_android_oauth` (`auth.rs:443`): after building `login_url` but before `append_pair("redirect", ...)`, add a state and store it. Change the query-building block to:
```rust
    let redirect = format!("{NATIVE_OAUTH_SCHEME}://oauth/callback");
    let state = generate_oauth_state();
    let mut login_url = reqwest::Url::parse(base)
        .map_err(|e| crate::error::Error::Matrix(format!("invalid Matrix base URL: {e}")))?;
    login_url.set_path("/auth/login");
    login_url
        .query_pairs_mut()
        .append_pair("redirect", &redirect)
        .append_pair("state", &state);
    let login_url = login_url.to_string();
```
Then, right where the code registers the oneshot (`match NATIVE_OAUTH_TX.lock()`), also store the state:
```rust
    match NATIVE_OAUTH_TX.lock() {
        Ok(mut guard) => *guard = Some(tx),
        Err(_) => return Err(crate::error::Error::Matrix("native OAuth sender lock poisoned".to_string())),
    }
    if let Ok(mut g) = NATIVE_OAUTH_STATE.lock() {
        *g = Some(state);
    }
```
Apply the same `state` generation + `append_pair("state", &state)` in `try_native_web_auth_session` (`auth.rs:354`) for the iOS path. iOS validates in-process (the session returns the callback URL directly), so after it returns, validate with `state_from_callback_url(&callback_url)` against the generated `state` before extracting the token; return `Error::Matrix("iOS web auth state mismatch")` on mismatch.

- [ ] **Step 6: Run tests to confirm they pass**

Run:
```bash
cargo test -p pentest-core --features browser-auth --lib matrix::auth 2>&1 | tail -25
```
Expected: PASS (all four new tests + existing OAuth tests).

- [ ] **Step 7: Commit**

```bash
git add crates/core/src/matrix/auth.rs crates/core/Cargo.toml Cargo.lock
git commit -m "fix(auth): validate OAuth state and require in-flight login on native callback

A forged custom-scheme callback could previously inject a token with no
sign-in in flight (the None arm returned true and cached unconditionally).
Generate an unguessable state per login, require it to match on delivery,
and reject callbacks with no waiting login."
```

---

## Task 4: OTT — atomic 0600 write + 0700 dir + umask test

**Files:**
- Modify: `crates/core/src/matrix/pre_approval.rs:61-83` (`stage_ott_for_sdk`)
- Test: same file's `#[cfg(test)]` module

**Interfaces:**
- Consumes: `staged_ott_path()` (`pre_approval.rs:51`), `OttData` (`pre_approval.rs:13`).
- Produces: `stage_ott_for_sdk` writes the OTT file at mode 0600 atomically (never briefly world/group-readable) and the `.strike48` dir at 0700.

- [ ] **Step 1: Write a failing test that sets a permissive umask**

Add to the tests module in `crates/core/src/matrix/pre_approval.rs`:
```rust
#[cfg(unix)]
#[test]
fn stage_writes_0600_even_under_permissive_umask() {
    use std::os::unix::fs::PermissionsExt;
    // A permissive umask is the real-world hazard: std::fs::write creates the
    // file honoring umask, so a later chmod leaves a window at 0644/0664.
    let old = unsafe { libc_umask(0o002) };
    let ott = OttData {
        token: "ott_perm".into(),
        matrix_url: "https://api.test".into(),
        keycloak_url: "https://auth/realms/x".into(),
        tenant_id: "tid".into(),
    };
    let tmp = std::env::temp_dir().join(format!("pick-ott-umask-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let prev_home = std::env::var("HOME").ok();
    std::env::set_var("HOME", &tmp);

    let path = stage_ott_for_sdk(&ott).expect("stage");
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "OTT file must be 0600 regardless of umask");
    let dir_mode = std::fs::metadata(path.parent().unwrap()).unwrap().permissions().mode();
    assert_eq!(dir_mode & 0o777, 0o700, "OTT dir must be 0700");

    unsafe { libc_umask(old); }
    match prev_home { Some(h) => std::env::set_var("HOME", h), None => std::env::remove_var("HOME") }
    let _ = std::fs::remove_dir_all(&tmp);
}

#[cfg(unix)]
extern "C" { fn umask(mask: u32) -> u32; }
#[cfg(unix)]
unsafe fn libc_umask(mask: u32) -> u32 { umask(mask) }
```

- [ ] **Step 2: Run test to confirm it fails**

Run:
```bash
cargo test -p pentest-core --lib matrix::pre_approval 2>&1 | tail -20
```
Expected: FAIL — file mode is `0664`/`0644` (write-then-chmod leaves a window and the dir is default-mode), or dir assertion fails.

- [ ] **Step 3: Rewrite the write to create-mode 0600 and set dir 0700**

Replace the body of `stage_ott_for_sdk` (`pre_approval.rs:61`):
```rust
pub fn stage_ott_for_sdk(ott: &OttData) -> Result<PathBuf> {
    let path = staged_ott_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Matrix(format!("cannot create OTT dir: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }
    }
    let json = serde_json::json!({
        "token": ott.token,
        "matrix_url": ott.matrix_url,
        "keycloak_url": ott.keycloak_url,
    })
    .to_string();

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600) // create AT 0600 — never a permissive window
            .open(&path)
            .map_err(|e| Error::Matrix(format!("cannot open OTT file: {e}")))?;
        f.write_all(json.as_bytes())
            .map_err(|e| Error::Matrix(format!("cannot write OTT file: {e}")))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&path, json)
            .map_err(|e| Error::Matrix(format!("cannot write OTT file: {e}")))?;
    }

    Ok(path)
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run:
```bash
cargo test -p pentest-core --lib matrix::pre_approval 2>&1 | tail -20
```
Expected: PASS — new umask test + the existing `stage_writes_sdk_shaped_json_and_roundtrips`.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/matrix/pre_approval.rs
git commit -m "fix(plg): create staged OTT at mode 0600 atomically

std::fs::write honored umask then chmod'd, leaving the single-use
registration token briefly group/world-readable. Open with mode(0o600)
so it is never permissive, and lock the .strike48 dir to 0700."
```

---

## Task 5: derive_api_url must not downgrade explicit https

**Files:**
- Modify: `crates/core/src/connector_registration.rs:22-38`
- Test: same file's `#[cfg(test)]` module

**Interfaces:**
- Consumes: none new.
- Produces: `derive_api_url` keeps `https` when the input scheme is explicitly `https://`/`wss://`/`grpcs://`, regardless of `use_tls`.

- [ ] **Step 1: Write a failing test**

Add to the tests module in `crates/core/src/connector_registration.rs`:
```rust
#[test]
fn explicit_https_is_not_downgraded_to_http() {
    // A user who typed https must never have their bearer JWT sent over http.
    assert_eq!(derive_api_url("https://host.example", false), "https://host.example");
    assert_eq!(derive_api_url("wss://host.example", false), "https://host.example");
}

#[test]
fn explicit_insecure_scheme_still_honors_use_tls_false() {
    // ws:// / http:// with use_tls=false stays http (localhost dev).
    assert_eq!(derive_api_url("ws://localhost:3030/", false), "http://localhost:3030");
}
```

- [ ] **Step 2: Run test to confirm it fails**

Run:
```bash
cargo test -p pentest-core --lib connector_registration 2>&1 | tail -15
```
Expected: FAIL — `explicit_https_is_not_downgraded_to_http` returns `http://host.example`.

- [ ] **Step 3: Detect a secure input scheme and force https**

Replace the scheme selection in `derive_api_url` (`connector_registration.rs:22`):
```rust
pub fn derive_api_url(host: &str, use_tls: bool) -> String {
    let host_lower = host.to_lowercase();
    let secure_schemes = ["https://", "wss://", "grpcs://"];
    let input_is_secure = secure_schemes.iter().any(|p| host_lower.starts_with(p));
    // An explicit secure input is never downgraded, even when use_tls is false.
    let scheme = if use_tls || input_is_secure { "https" } else { "http" };
    let schemes = [
        "grpc://", "grpcs://", "http://", "https://", "ws://", "wss://",
    ];
    let mut bare_host = host;
    for prefix in &schemes {
        if host_lower.starts_with(prefix) {
            bare_host = &host[prefix.len()..];
            break;
        }
    }
    let api_host = bare_host.strip_prefix("connectors-").unwrap_or(bare_host);
    let api_host = api_host.trim_end_matches('/');
    format!("{scheme}://{api_host}")
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run:
```bash
cargo test -p pentest-core --lib connector_registration 2>&1 | tail -15
```
Expected: PASS — the two new tests plus the four existing ones (verify `no_tls_uses_http_and_trims_trailing_slash` still passes: `ws://` is not in `secure_schemes`, so it stays http).

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/connector_registration.rs
git commit -m "fix(plg): never downgrade an explicit https connector host to http

derive_api_url applied use_tls as the scheme unconditionally, so an
explicit https/wss input with use_tls=false would send the user bearer
JWT over http. Honor a secure input scheme regardless of use_tls."
```

---

## Task 6: telemetry — check `is_enabled()` guard + wire `flush()` caller

**Files:**
- Modify: `crates/core/src/telemetry.rs:170-212` (init) — only set `ENABLED` when the guard is actually enabled.
- Modify: the staying shell's suspend/background hook to call `telemetry::flush()` (locate in `apps/mobile` and/or `apps/desktop`).
- Test: `crates/core/src/telemetry.rs` `#[cfg(test)]` module.

**Interfaces:**
- Consumes: `ENABLED` (`telemetry.rs:25`), `GUARD` (`:32`), `flush()` (`:218`).
- Produces: `ENABLED` is true only when `sentry::init` returned an enabled client; `flush()` is called on app background.

- [ ] **Step 1: Write a failing test for the enabled-gate helper**

The init path calls `sentry::init` which needs a DSN; unit-testing it directly is awkward. Instead extract the gate decision into a testable pure helper. Add to `telemetry.rs`:
```rust
/// Whether telemetry should mark itself enabled given the init guard's own
/// report. A rejected/invalid DSN yields a *disabled* client rather than an
/// error, so trusting `sentry::init` returning is wrong — ask the guard.
fn guard_reports_enabled(guard: &sentry::ClientInitGuard) -> bool {
    guard.is_enabled()
}
```
Add a test:
```rust
#[test]
fn disabled_guard_does_not_enable_telemetry() {
    // A guard built from an empty client is not enabled.
    let guard = sentry::ClientInitGuard::from(sentry::Client::from_config(()));
    assert!(!guard_reports_enabled(&guard), "empty-config client must report disabled");
}
```
If `ClientInitGuard::from` / `Client::from_config(())` does not compile against sentry 0.48, fall back to asserting on `sentry::Hub::new_from_top`'s client being `None`; the key requirement is a test that fails when `ENABLED` is set without consulting `is_enabled()`.

- [ ] **Step 2: Run test to confirm it fails/compiles-red**

Run:
```bash
cargo test -p pentest-core --lib telemetry 2>&1 | tail -15
```
Expected: FAIL — `guard_reports_enabled` does not exist yet.

- [ ] **Step 3: Gate ENABLED on the guard and add the helper**

In `telemetry.rs`, replace the tail of the init fn (`:203-211`):
```rust
    let enabled = guard_reports_enabled(&guard);
    if let Ok(mut g) = GUARD.lock() {
        *g = Some(guard);
    }
    ENABLED.store(enabled, Ordering::Relaxed);
    if enabled {
        tracing::info!(
            "telemetry initialized (env={}, channel={})",
            environment(),
            channel(easy_mode)
        );
    } else {
        tracing::warn!("telemetry DSN rejected; client disabled, no events will be sent");
    }
```

- [ ] **Step 4: Run test to confirm it passes**

Run:
```bash
cargo test -p pentest-core --lib telemetry 2>&1 | tail -15
```
Expected: PASS.

- [ ] **Step 5: Wire `flush()` into the staying shell's background hook**

Locate the app lifecycle hook that fires on suspend/background in the remaining shells:
```bash
rg -n "did_enter_background|applicationDidEnterBackground|on_suspend|WindowEvent::Focused|suspend|background" apps/mobile apps/desktop --type rust
```
Add a `pentest_core::telemetry::flush();` call in that handler (it is a no-op when disabled). If NO suitable hook exists in the staying shells (the mobile background hook may have lived in the crux shell that just left), add a `tracing::debug!` note and call `flush()` from the app's shutdown/exit path instead. Do not invent a lifecycle system — wire into an existing one.

- [ ] **Step 6: Verify build + commit**

Run:
```bash
cargo check -p pentest-core --all-features 2>&1 | tail -10
```
Then:
```bash
git add crates/core/src/telemetry.rs apps/
git commit -m "fix(telemetry): only mark enabled when the client is, and flush on background

sentry::init returns a disabled client (not an error) for a rejected DSN,
yet ENABLED was set true unconditionally and success was logged. Gate
ENABLED on guard.is_enabled() and call flush() on app background so
batched events survive process termination."
```

---

## Task 7: documents_panel — surface per-doc metadata-fetch errors

**Files:**
- Modify: `crates/ui/src/components/documents_panel.rs:154-165`

**Interfaces:**
- Consumes: `MatrixChatClient`, `ReportMeta::parse`, `meta_map` signal.
- Produces: metadata-fetch failures no longer vanish silently; a failed fetch is memoized so it does not re-fetch every poll (matching the existing memoization intent).

- [ ] **Step 1: Verify current behavior first**

Read `crates/ui/src/components/documents_panel.rs:117-167`. Confirm: the main list loader (`:123-131`) already has an `Err` arm that sets `error` ("Couldn't load reports"). The only silent drop is the per-doc metadata `if let Ok(content) = ...` at `:156` — a network failure there is dropped and the doc is retried on every `docs()` change because it was never inserted into `meta_map`. This is the actual (lower-severity) gap.

- [ ] **Step 2: Log the metadata error and memoize the failure**

Replace the metadata-fetch closure body (`:154-164`):
```rust
                spawn(async move {
                    let client = MatrixChatClient::new(api_url).with_auth_token(auth_token);
                    match client
                        .get_document_content(&doc.conversation_id, &doc.id)
                        .await
                    {
                        Ok(content) => {
                            meta_map
                                .write()
                                .insert(doc.id.clone(), ReportMeta::parse(&content));
                        }
                        Err(e) => {
                            // Memoize as "fetched, no metadata" so a transient
                            // failure doesn't re-fan-out every poll, and surface
                            // it in the log rather than dropping it silently.
                            tracing::warn!("report metadata fetch failed for {}: {e}", doc.id);
                            meta_map.write().insert(doc.id.clone(), None);
                        }
                    }
                });
```

- [ ] **Step 3: Verify build (UI crate has no unit test harness for components)**

Run:
```bash
cargo check -p pentest-ui --features "desktop,connector" 2>&1 | tail -10
cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings 2>&1 | tail -10
```
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/ui/src/components/documents_panel.rs
git commit -m "fix(ui): surface and memoize report-metadata fetch failures

A failed per-doc metadata fetch was dropped by if-let-Ok and, never
memoized, re-fetched on every 5s poll. Log the error and memoize the
failure as no-metadata so it does not retry forever."
```

---

## Task 8: param_bool — accept string/int forms + test

**Files:**
- Modify: `crates/tools/src/util.rs:56-59`
- Test: `crates/tools/src/util.rs` tests module

**Interfaces:**
- Consumes: `serde_json::Value`.
- Produces: `param_bool` coerces `true`/`false` (bool), `"true"`/`"false"`/`"1"`/`"0"`/`"yes"`/`"no"` (string, case-insensitive), and `0`/`1` (int) — matching how `param_u64`/`param_u16_opt` coerce, since LLM tool callers send loose types.

- [ ] **Step 1: Write failing tests**

Add to the tests module in `crates/tools/src/util.rs`:
```rust
#[test]
fn param_bool_coerces_bool_string_and_int() {
    assert!(param_bool(&json!({"append": true}), "append", false));
    assert!(param_bool(&json!({"append": "true"}), "append", false));
    assert!(param_bool(&json!({"append": "TRUE"}), "append", false));
    assert!(param_bool(&json!({"recursive": 1}), "recursive", false));
    assert!(param_bool(&json!({"recursive": "yes"}), "recursive", false));
    assert!(!param_bool(&json!({"append": "false"}), "append", true));
    assert!(!param_bool(&json!({"append": "0"}), "append", true));
    assert!(!param_bool(&json!({"append": 0}), "append", true));
}

#[test]
fn param_bool_falls_back_to_default_when_missing_or_unparseable() {
    assert!(param_bool(&json!({}), "append", true));
    assert!(!param_bool(&json!({}), "append", false));
    assert!(param_bool(&json!({"append": "maybe"}), "append", true));
}
```

- [ ] **Step 2: Run tests to confirm they fail**

Run:
```bash
cargo test -p pentest-tools --lib util 2>&1 | tail -20
```
Expected: FAIL — string/int forms currently return the default.

- [ ] **Step 3: Implement coercion**

Replace `param_bool` (`util.rs:56-59`):
```rust
/// Extract a `bool` parameter with a default value.
///
/// Accepts real JSON booleans, plus the string forms LLM tool callers emit
/// (`"true"`/`"false"`/`"yes"`/`"no"`/`"1"`/`"0"`, case-insensitive) and the
/// integers `1`/`0` — mirroring the loose coercion `param_u64` does for numbers.
/// Unparseable or missing values yield `default`.
pub fn param_bool(params: &Value, key: &str, default: bool) -> bool {
    match params.get(key) {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => true,
            "false" | "no" | "0" => false,
            _ => default,
        },
        Some(Value::Number(n)) => match n.as_i64() {
            Some(0) => false,
            Some(_) => true,
            None => default,
        },
        _ => default,
    }
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run:
```bash
cargo test -p pentest-tools --lib util 2>&1 | tail -20
```
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/tools/src/util.rs
git commit -m "fix(tools): param_bool accepts string and int forms

LLM tool callers send booleans as \"true\"/1, which as_bool() rejected,
silently falling back to the default across 20+ call sites. Coerce the
same loose forms param_u64 already handles."
```

---

## Task 9: mdns/ssdp — distinguish "probe skipped" + honor set_read_timeout

**Files:**
- Modify: `crates/platform/src/common/mdns.rs:35-84`, `crates/platform/src/common/ssdp.rs:32-87`
- Test: both files' `#[cfg(test)]` modules

**Interfaces:**
- Consumes: `MdnsService`, `SsdpDevice` (`crates/platform/src/traits.rs`).
- Produces: a `ProbeOutcome` reason type so callers can tell "probe could not run" (bind/send/setsockopt failed) from "ran, found nothing". Keeps the existing `discover` signatures returning `Result<Vec<_>>` to avoid churn at the four call sites (`ios/network.rs:21,26`, `android/network.rs:64`); adds a sibling `discover_with_outcome` that returns the reason. Honors `set_read_timeout`: if it fails, abort the probe as skipped rather than looping on a blocking socket.

- [ ] **Step 1: Add the ProbeOutcome type (shared)**

Create `crates/platform/src/common/probe.rs`:
```rust
//! Shared outcome type for best-effort network discovery probes.
//!
//! For a pentest report, "the probe could not run" (sandbox blocked bind/send,
//! or the recv timeout could not be set so a blocking socket would hang) must be
//! distinguishable from "the probe ran and found nothing on the network".

/// Why a discovery probe produced no results, or that it ran normally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The probe ran to completion (results may still be empty).
    Ran,
    /// The probe could not run; the string is a short, non-PII reason.
    Skipped(String),
}
```
Register it: add `pub mod probe;` to `crates/platform/src/common/mod.rs`.

- [ ] **Step 2: Write failing tests**

Add to `crates/platform/src/common/ssdp.rs` tests:
```rust
#[tokio::test]
async fn zero_timeout_reports_skipped_not_empty_ran() {
    let (devices, outcome) = discover_with_outcome(0).await;
    assert!(devices.is_empty());
    assert!(matches!(outcome, crate::common::probe::ProbeOutcome::Skipped(_)),
        "a zero-timeout probe did not run; must be Skipped, not Ran");
}
```
Add the analogous test to `crates/platform/src/common/mdns.rs`:
```rust
#[tokio::test]
async fn zero_timeout_reports_skipped() {
    let (svcs, outcome) = discover_with_outcome("_http._tcp.local.", 0).await;
    assert!(svcs.is_empty());
    assert!(matches!(outcome, crate::common::probe::ProbeOutcome::Skipped(_)));
}
```

- [ ] **Step 3: Run tests to confirm they fail**

Run:
```bash
cargo test -p pentest-platform --lib common::ssdp common::mdns 2>&1 | tail -20
```
Expected: FAIL — `discover_with_outcome` does not exist.

- [ ] **Step 4: Implement discover_with_outcome for ssdp**

In `crates/platform/src/common/ssdp.rs`, add above `discover`:
```rust
use crate::common::probe::ProbeOutcome;

/// Like [`discover`] but also reports whether the probe actually ran. `discover`
/// delegates to this and discards the outcome for call sites that only want the
/// device list.
pub async fn discover_with_outcome(timeout_ms: u64) -> (Vec<SsdpDevice>, ProbeOutcome) {
    if timeout_ms == 0 {
        return (Vec::new(), ProbeOutcome::Skipped("zero timeout".into()));
    }
    tokio::task::spawn_blocking(move || {
        let socket = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(e) => return (Vec::new(), ProbeOutcome::Skipped(format!("bind failed: {e}"))),
        };
        if let Err(e) = socket.set_read_timeout(Some(Duration::from_millis(RECV_TIMEOUT_MS))) {
            // Without a read timeout the recv loop would block past the deadline.
            return (Vec::new(), ProbeOutcome::Skipped(format!("set_read_timeout failed: {e}")));
        }
        let _ = socket.set_broadcast(true);
        let search_request = "M-SEARCH * HTTP/1.1\r\n\
            HOST: 239.255.255.250:1900\r\n\
            MAN: \"ssdp:discover\"\r\n\
            MX: 2\r\n\
            ST: ssdp:all\r\n\r\n";
        if let Err(e) = socket.send_to(search_request.as_bytes(), SSDP_MULTICAST_ADDR) {
            return (Vec::new(), ProbeOutcome::Skipped(format!("send failed: {e}")));
        }
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        let mut devices = Vec::new();
        let mut buf = [0u8; 2048];
        while Instant::now() < deadline {
            match socket.recv_from(&mut buf) {
                Ok((len, _)) => {
                    let response = String::from_utf8_lossy(&buf[..len]);
                    if let Some(device) = parse_ssdp_response(&response) {
                        devices.push(device);
                    }
                }
                Err(_) => continue,
            }
        }
        (devices, ProbeOutcome::Ran)
    })
    .await
    .unwrap_or_else(|_| (Vec::new(), ProbeOutcome::Skipped("probe task panicked".into())))
}
```
Then reduce `discover` to a thin delegator:
```rust
pub async fn discover(timeout_ms: u64) -> Result<Vec<SsdpDevice>> {
    Ok(discover_with_outcome(timeout_ms).await.0)
}
```

- [ ] **Step 5: Implement discover_with_outcome for mdns**

Apply the same pattern in `crates/platform/src/common/mdns.rs`: add `use crate::common::probe::ProbeOutcome;`, add `discover_with_outcome(service_type: &str, timeout_ms: u64) -> (Vec<MdnsService>, ProbeOutcome)` returning `Skipped` on the zero-timeout, bind failure, `set_read_timeout` failure, and send failure paths (the existing code already early-returns `Vec::new()` at each of those — replace each with the matching `Skipped` reason), and `Ran` after the loop. Reduce `discover` to `Ok(discover_with_outcome(service_type, timeout_ms).await.0)`.

- [ ] **Step 6: Run tests to confirm they pass**

Run:
```bash
cargo test -p pentest-platform --lib common::ssdp common::mdns common::probe 2>&1 | tail -20
```
Expected: PASS (new outcome tests + existing parser tests).

- [ ] **Step 7: Verify the four call sites still compile**

Run:
```bash
cargo check -p pentest-platform --all-targets 2>&1 | tail -10
```
Expected: clean — `ios/network.rs:21,26` and `android/network.rs:64` still call `discover(...)`.

- [ ] **Step 8: Commit**

```bash
git add crates/platform/src/common/
git commit -m "feat(discovery): distinguish skipped probe from empty result

mdns/ssdp returned Ok(vec![]) for both 'sandbox blocked the probe' and
'nothing on the network' — indistinguishable in a pentest report. Add
ProbeOutcome and discover_with_outcome, and abort as Skipped when
set_read_timeout fails instead of looping on a blocking socket."
```

---

## Task 10: service_banner — batch-mode tests

**Files:**
- Test only: `crates/tools/src/service_banner.rs` (add a `#[cfg(test)]` module; currently has none)

**Interfaces:**
- Consumes: `ServiceBannerTool`, `ToolContext`, `Tool::execute`.
- Produces: coverage for the batch path's input validation and the identified-count accounting. No production code change.

- [ ] **Step 1: Confirm there are no existing tests**

Run:
```bash
rg -n "#\[test\]|#\[tokio::test\]|mod tests" crates/tools/src/service_banner.rs
```
Expected: no output.

- [ ] **Step 2: Write batch-mode validation tests**

Add at the end of `crates/tools/src/service_banner.rs`. Check the exact `ToolContext` constructor first (`rg -n "impl ToolContext|fn (new|default|for_test)" crates/tools/src/lib.rs crates/tools/src/context.rs 2>/dev/null`) and use whatever the crate exposes; the shape below assumes a `ToolContext::default()`-style constructor:
```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx() -> ToolContext { ToolContext::default() }

    #[tokio::test]
    async fn batch_rejects_target_with_empty_host() {
        let tool = ServiceBannerTool;
        let params = json!({ "targets": [ { "host": "", "port": 22 } ] });
        let res = tool.execute(params, &ctx()).await;
        assert!(res.is_err(), "empty host must be InvalidParams");
    }

    #[tokio::test]
    async fn batch_rejects_target_with_missing_port() {
        let tool = ServiceBannerTool;
        let params = json!({ "targets": [ { "host": "10.0.0.1" } ] });
        let res = tool.execute(params, &ctx()).await;
        assert!(res.is_err(), "missing port must be InvalidParams");
    }

    #[tokio::test]
    async fn empty_targets_array_falls_through_to_single_mode_error() {
        // An empty targets array is not batch mode; single mode then requires a
        // host and errors without one.
        let tool = ServiceBannerTool;
        let params = json!({ "targets": [] });
        let res = tool.execute(params, &ctx()).await;
        assert!(res.is_err(), "no host in single mode must error");
    }
}
```

- [ ] **Step 3: Run tests**

Run:
```bash
cargo test -p pentest-tools --lib service_banner 2>&1 | tail -20
```
Expected: PASS. If `ToolContext::default()` does not exist, adapt to the real constructor found in Step 2 and re-run.

- [ ] **Step 4: Commit**

```bash
git add crates/tools/src/service_banner.rs
git commit -m "test(tools): cover service_banner batch-mode input validation"
```

---

## Task 11: CI — run the browser-auth OAuth tests on the macOS lane

**Files:**
- Modify: `.github/workflows/ci.yml:102` (and `:86` if appropriate)

**Interfaces:**
- Consumes: the `browser-auth` feature of `pentest-core`.
- Produces: the OAuth tests (including Task 3's new ones) run explicitly rather than only via incidental Linux feature unification.

- [ ] **Step 1: Confirm the tests are feature-gated and not run today**

Run:
```bash
rg -n "cargo test" .github/workflows/ci.yml
rg -n "browser-auth" .github/workflows/ci.yml
```
Expected: the macOS lane (`:102`) runs `cargo test --package pentest-platform --package pentest-core --lib` with NO `browser-auth` feature; no `browser-auth` in the file.

- [ ] **Step 2: Add the feature to the macOS test invocation**

Edit `.github/workflows/ci.yml:102`, appending the feature:
```yaml
      - run: cargo test --package pentest-platform --package pentest-core --lib --locked --features pentest-platform/desktop-pcap,pentest-core/browser-auth
```

- [ ] **Step 3: Verify the invocation locally**

Run (mirrors the CI command):
```bash
cargo test --package pentest-platform --package pentest-core --lib --locked --features pentest-platform/desktop-pcap,pentest-core/browser-auth 2>&1 | tail -25
```
Expected: PASS — the `matrix::auth` OAuth tests are now included and green.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: run browser-auth OAuth tests explicitly on the macOS lane

The eight OAuth tests are cfg(browser-auth) and ran only via incidental
feature unification on Linux. Enable the feature so the auth-flow tests
(including OAuth state validation) are a real gate."
```

---

## Task 12: F9 — cargo fmt + final verification gate

**Files:**
- Modify: any files `cargo fmt` reformats (expected: `crates/platform/src/ios/oauth.rs:77,113,134` plus anything the earlier tasks touched).

**Interfaces:** none — this is the closing gate.

- [ ] **Step 1: Confirm the pre-fmt failure (finding 9)**

Run:
```bash
cargo fmt --all -- --check 2>&1 | tail -30
```
Expected: FAIL — diffs in `crates/platform/src/ios/oauth.rs` (and possibly files from Tasks 3-11).

- [ ] **Step 2: Apply formatting**

Run:
```bash
cargo fmt --all
git diff --stat
```

- [ ] **Step 3: Run the full mandatory gate (CLAUDE.md)**

Run in order:
```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo test --workspace --locked --features pentest-platform/desktop-pcap
cargo clippy --all-targets -- -D warnings
git status
```
Expected: fmt clean, check clean, tests pass, clippy zero warnings, no unexpected uncommitted changes (only the fmt edits staged next).

- [ ] **Step 4: Commit the formatting**

```bash
git add -A
git commit -m "style: cargo fmt --all

Fixes the ios/oauth.rs formatting the CI Format gate flagged (target-agnostic
fmt parses the cfg(target_os = ios) module that Check/Clippy never compile)."
```

- [ ] **Step 5: Push #249 and re-run the CI gates**

```bash
git push origin josh/catching-up
gh pr checks 249 --watch || gh pr view 249
```
Expected: the Format lane (and the rest) go green.

---

## Self-Review

**Spec coverage:** Every finding in the spec's "Finding-to-Home Mapping" maps to a task (see the table at top). Crux/run_js findings → Task 1 (extract only, deferred by decision). F2-core → Task 3, OTT → Task 4, derive_api_url → Task 5, telemetry → Task 6, documents_panel → Task 7, param_bool → Task 8, mdns/ssdp → Task 9, service_banner → Task 10, OAuth CI gating → Task 11, F9 + gate → Task 12. The reclassified `tool_calls`-clear item is explicitly excluded (leaves with crux).

**Placeholder scan:** No "TBD"/"handle edge cases"/"similar to Task N". Two tasks (6 flush-hook, 10 ToolContext constructor) contain explicit `rg` discovery steps because the exact hook/constructor name must be read from the tree — each gives the concrete fallback if the assumed shape is absent. Task 2's orphaned-profile removal is conditional on an `rg` check, stated explicitly.

**Type consistency:** `ProbeOutcome` (Ran/Skipped(String)) used identically in Tasks 9 mdns+ssdp. `discover_with_outcome` signatures match their call in tests. `generate_oauth_state`/`state_from_callback_url`/`NATIVE_OAUTH_STATE` defined in Task 3 Step 3 and used in Steps 4-5. `param_bool` signature unchanged (`&Value, &str, bool -> bool`). `guard_reports_enabled(&sentry::ClientInitGuard) -> bool` defined and used in Task 6.
