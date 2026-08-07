# PLG Connector OAuth-First Registration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** In PLG/easy mode, register Pick's connector approved under the user's personal tenant via the pre-approval OTT flow, instead of the tokenless registration that lands pending under tenant `default`.

**Architecture:** Add a testable `pre_approve` HTTP client and an OTT-file bridge in `pentest-core`, plus a pure `plg_connect_decision` helper. Wire a new PLG pre-connect orchestration step into `connector_app.rs` (easy mode only): if no SDK connector credentials exist on disk, run the existing in-app OAuth flow, exchange the JWT for an OTT, stage the OTT into the file the SDK already reads, then connect — the SDK's built-in `has_ott()` → `register_with_ott` path lands the connector approved. On any failure, show a friendly retry state; never fall back to tokenless registration.

**Tech Stack:** Rust, Dioxus 0.7, `reqwest`, `serde`, `strike48-connector` 0.4.x SDK (unchanged), iOS `ASWebAuthenticationSession` (existing).

## Global Constraints

- Easy/PLG mode only (`cfg.easy_mode`); expert mode and the saved-config auto-connect path are unchanged.
- OAuth-first: in PLG mode with no existing connector credentials, present the in-app OAuth session before connecting.
- Sign in once: if the SDK already has saved connector credentials on disk, skip OAuth and connect silently.
- Never fall back to tokenless registration; on failure show a friendly retry state.
- No SDK changes and no SDK version bump; feature works against pinned `strike48-connector = "0.4.1"`.
- SDK reads OTT from `STRIKE48_REGISTRATION_TOKEN_FILE` (path) and persists connector creds to `~/.strike48/credentials/<connector_type>_<instance_id>.json`.
- OTT JSON shape the SDK expects: `{"token": ..., "matrix_url": ..., "keycloak_url": ...}`.
- Pre-approve endpoint: `POST {api_url}/api/connectors/pre-approve`, `Authorization: Bearer <jwt>`, body `{"connector_type": <type>, "notes": <optional>}`, returns 201 with `{token, tenant_id, keycloak_url, matrix_wss_url, matrix_grpc_url, connector_type, expires_at}`.
- Reuse the existing `MATRIX_TLS_INSECURE`/`MATRIX_INSECURE` handling for the reqwest client (see `crates/core/src/matrix/client.rs:20-28`).
- Error type: `pentest_core::error::{Error, Result}`; `Error::Matrix(String)` for HTTP/parse failures.
- Commit messages (project rule): conventional commits; no attribution lines, no customer/tenant names, no emojis or em-dashes.

---

## File Structure

- `crates/core/src/matrix/pre_approval.rs` (new) — `OttData`, `pre_approve`, `stage_ott_for_sdk`, `clear_staged_ott`, and staged-file path helper. One responsibility: obtaining and staging an OTT for the SDK.
- `crates/core/src/matrix/mod.rs` (modify) — declare and re-export the new module.
- `crates/core/src/config.rs` (modify) — add pure `plg_connect_decision` + `PlgConnectStep` (near `read_credentials_tenant_id`, which it complements). Also add `credentials_present(connector_name, instance_id) -> bool`.
- `crates/ui/src/components/connecting_screen.rs` (modify) — add `ConnectingStep::SigningIn` variant + its label/mapping.
- `crates/ui/src/connector_app.rs` (modify) — PLG pre-connect orchestration + `needs_sign_in` signal wiring.
- `crates/ui/src/components/easy_mode.rs` (modify) — render a `NeedsSignIn` retry overlay when the signal is set.

---

### Task 1: `OttData` type and pre-approve response parsing

**Files:**
- Create: `crates/core/src/matrix/pre_approval.rs`
- Modify: `crates/core/src/matrix/mod.rs`

**Interfaces:**
- Consumes: `pentest_core::error::{Error, Result}`.
- Produces:
  - `pub struct OttData { pub token: String, pub matrix_url: String, pub keycloak_url: String, pub tenant_id: String }`
  - `pub(crate) fn parse_pre_approve_response(body: &str) -> Result<OttData>`

Notes on mapping: the endpoint returns `matrix_wss_url` (and `matrix_grpc_url`) but the SDK's OTT file expects a field named `matrix_url`. `parse_pre_approve_response` maps `matrix_wss_url` → `OttData.matrix_url`.

- [ ] **Step 1: Write the failing test**

Add to the bottom of `crates/core/src/matrix/pre_approval.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_201: &str = r#"{
        "token": "ott_8Ucs8wG8RRMX-YEm2un24D4MrOiiF7tGaj5cArlwSN0",
        "tenant_id": "019f86b4-d2bf-7f56-89cf-30485d8a956b",
        "keycloak_url": "https://auth.strike48.test/realms/personal-f668ca45dbb0",
        "connector_type": "pentest-connector",
        "expires_at": "2026-07-21T22:32:42Z",
        "matrix_grpc_url": "grpc://localhost:50061",
        "matrix_wss_url": "wss://localhost:4000/socket/connector"
    }"#;

    #[test]
    fn parses_all_fields_and_maps_wss_to_matrix_url() {
        let ott = parse_pre_approve_response(SAMPLE_201).expect("should parse");
        assert_eq!(ott.token, "ott_8Ucs8wG8RRMX-YEm2un24D4MrOiiF7tGaj5cArlwSN0");
        assert_eq!(ott.tenant_id, "019f86b4-d2bf-7f56-89cf-30485d8a956b");
        assert_eq!(
            ott.keycloak_url,
            "https://auth.strike48.test/realms/personal-f668ca45dbb0"
        );
        assert_eq!(ott.matrix_url, "wss://localhost:4000/socket/connector");
    }

    #[test]
    fn parse_error_on_missing_token() {
        let body = r#"{"tenant_id":"t","keycloak_url":"k","matrix_wss_url":"w"}"#;
        assert!(parse_pre_approve_response(body).is_err());
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-core pre_approval 2>&1 | tail -20`
Expected: FAIL to compile — `parse_pre_approve_response` / `OttData` not defined.

- [ ] **Step 3: Write minimal implementation**

At the top of `crates/core/src/matrix/pre_approval.rs`:

```rust
//! PLG connector pre-approval: exchange a user OAuth JWT for a tenant-scoped
//! one-time registration token (OTT) and stage it for the SDK to register with.

use serde::Deserialize;

use crate::error::{Error, Result};

/// A pre-approval OTT scoped to the user's personal tenant. `matrix_url` is the
/// SDK-facing field name; the endpoint returns it as `matrix_wss_url`.
#[derive(Debug, Clone, PartialEq)]
pub struct OttData {
    pub token: String,
    pub matrix_url: String,
    pub keycloak_url: String,
    pub tenant_id: String,
}

/// Wire shape of the `POST /api/connectors/pre-approve` 201 response.
#[derive(Debug, Deserialize)]
struct PreApproveResponse {
    token: String,
    tenant_id: String,
    keycloak_url: String,
    matrix_wss_url: String,
}

pub(crate) fn parse_pre_approve_response(body: &str) -> Result<OttData> {
    let raw: PreApproveResponse = serde_json::from_str(body)
        .map_err(|e| Error::Matrix(format!("pre-approve response parse error: {e}")))?;
    Ok(OttData {
        token: raw.token,
        matrix_url: raw.matrix_wss_url,
        keycloak_url: raw.keycloak_url,
        tenant_id: raw.tenant_id,
    })
}
```

Add to `crates/core/src/matrix/mod.rs` after the other `pub mod` lines (e.g. after `pub mod documents;`):

```rust
pub mod pre_approval;
```

And add to the re-export block:

```rust
pub use pre_approval::{pre_approve, stage_ott_for_sdk, clear_staged_ott, OttData};
```

NOTE: `pre_approve`, `stage_ott_for_sdk`, and `clear_staged_ott` are added in Tasks 2 and 3. To keep this task compiling on its own, for now re-export only what exists:

```rust
pub use pre_approval::OttData;
```

(Task 2 and Task 3 extend this re-export line.)

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo test -p pentest-core pre_approval 2>&1 | tail -20`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/matrix/pre_approval.rs crates/core/src/matrix/mod.rs
git commit -m "feat(easy-mode): add OttData + pre-approve response parsing"
```

---

### Task 2: `pre_approve` HTTP client

**Files:**
- Modify: `crates/core/src/matrix/pre_approval.rs`
- Modify: `crates/core/src/matrix/mod.rs`
- Test: `crates/core/src/matrix/pre_approval.rs` (async test with a mock server)

**Interfaces:**
- Consumes: `parse_pre_approve_response` (Task 1), `super::normalize_url`.
- Produces: `pub async fn pre_approve(api_url: &str, jwt: &str, connector_type: &str) -> Result<OttData>`

This task needs an HTTP mock. The repo already depends on `reqwest`; add `wiremock` as a dev-dependency for `pentest-core` if not present.

- [ ] **Step 1: Add the dev-dependency (if missing)**

Check: `grep -n "wiremock" crates/core/Cargo.toml`
If absent, add under `[dev-dependencies]` in `crates/core/Cargo.toml`:

```toml
wiremock = "0.6"
```

Verify it resolves: `nix develop --command cargo fetch 2>&1 | tail -3`

- [ ] **Step 2: Write the failing test**

Add to the `tests` module in `crates/core/src/matrix/pre_approval.rs`:

```rust
    #[tokio::test]
    async fn pre_approve_posts_bearer_and_parses_ott() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/pre-approve"))
            .and(header("authorization", "Bearer jwt-abc"))
            .respond_with(ResponseTemplate::new(201).set_body_raw(SAMPLE_201, "application/json"))
            .mount(&server)
            .await;

        let ott = pre_approve(&server.uri(), "jwt-abc", "pentest-connector")
            .await
            .expect("pre_approve should succeed");
        assert_eq!(ott.tenant_id, "019f86b4-d2bf-7f56-89cf-30485d8a956b");
        assert_eq!(ott.matrix_url, "wss://localhost:4000/socket/connector");
    }

    #[tokio::test]
    async fn pre_approve_maps_non_201_to_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/connectors/pre-approve"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&server)
            .await;

        let err = pre_approve(&server.uri(), "jwt-abc", "pentest-connector")
            .await
            .expect_err("403 should be an error");
        match err {
            Error::Matrix(msg) => assert!(msg.contains("403"), "msg should mention status: {msg}"),
            other => panic!("expected Error::Matrix, got {other:?}"),
        }
    }
```

- [ ] **Step 3: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-core pre_approve 2>&1 | tail -20`
Expected: FAIL to compile — `pre_approve` not defined.

- [ ] **Step 4: Write minimal implementation**

Add to `crates/core/src/matrix/pre_approval.rs` (below `parse_pre_approve_response`):

```rust
/// Exchange a user OAuth JWT for a tenant-scoped OTT via the PLG pre-approval
/// endpoint. The endpoint recovers the PLG session server-side to determine the
/// authoritative personal tenant, so the JWT need not carry a tenant claim.
pub async fn pre_approve(api_url: &str, jwt: &str, connector_type: &str) -> Result<OttData> {
    let base = super::normalize_url(api_url);
    let url = format!("{}/api/connectors/pre-approve", base);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(
            std::env::var("MATRIX_TLS_INSECURE")
                .or_else(|_| std::env::var("MATRIX_INSECURE"))
                .map(|v| v == "1" || v == "true")
                .unwrap_or(false),
        )
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {jwt}"))
        .json(&serde_json::json!({ "connector_type": connector_type }))
        .send()
        .await
        .map_err(|e| Error::Matrix(format!("pre-approve request failed: {e}")))?;

    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| Error::Matrix(format!("pre-approve body read failed: {e}")))?;

    if !status.is_success() {
        return Err(Error::Matrix(format!(
            "pre-approve returned HTTP {}: {}",
            status.as_u16(),
            body
        )));
    }

    parse_pre_approve_response(&body)
}
```

`super::normalize_url` is `pub(crate) fn normalize_url(url: &str) -> &str` in
`crates/core/src/matrix/mod.rs` — reachable here because this code lives in the
same crate. It strips scheme/trailing-slash noise; `format!("{}/api/...", base)`
is correct.

- [ ] **Step 5: Extend the re-export**

In `crates/core/src/matrix/mod.rs`, change the pre_approval re-export line to:

```rust
pub use pre_approval::{pre_approve, OttData};
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `nix develop --command cargo test -p pentest-core pre_approve 2>&1 | tail -20`
Expected: PASS (both async tests plus the Task 1 tests).

- [ ] **Step 7: Commit**

```bash
git add crates/core/src/matrix/pre_approval.rs crates/core/src/matrix/mod.rs crates/core/Cargo.toml
git commit -m "feat(easy-mode): add pre_approve HTTP client for PLG OTT exchange"
```

---

### Task 3: OTT-file staging bridge

**Files:**
- Modify: `crates/core/src/matrix/pre_approval.rs`
- Modify: `crates/core/src/matrix/mod.rs`
- Test: `crates/core/src/matrix/pre_approval.rs`

**Interfaces:**
- Consumes: `OttData` (Task 1).
- Produces:
  - `pub fn staged_ott_path() -> std::path::PathBuf` (`~/.strike48/registration_token.json`)
  - `pub fn stage_ott_for_sdk(ott: &OttData) -> Result<std::path::PathBuf>`
  - `pub fn clear_staged_ott()`

The staged file must match the SDK's expected `{token, matrix_url, keycloak_url}` shape so `OttProvider::parse_ott` loads it.

- [ ] **Step 1: Write the failing test**

Add to the `tests` module in `crates/core/src/matrix/pre_approval.rs`:

```rust
    #[test]
    fn stage_writes_sdk_shaped_json_and_roundtrips() {
        let ott = OttData {
            token: "ott_xyz".to_string(),
            matrix_url: "wss://host:4000/socket/connector".to_string(),
            keycloak_url: "https://auth/realms/personal-abc".to_string(),
            tenant_id: "tid".to_string(),
        };

        // Redirect HOME to a temp dir so the test does not touch the real ~/.strike48.
        let tmp = std::env::temp_dir().join(format!("pick-ott-test-{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let prev_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", &tmp);

        let path = stage_ott_for_sdk(&ott).expect("stage should succeed");
        assert!(path.exists(), "staged file should exist");

        let written = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&written).unwrap();
        assert_eq!(v["token"], "ott_xyz");
        assert_eq!(v["matrix_url"], "wss://host:4000/socket/connector");
        assert_eq!(v["keycloak_url"], "https://auth/realms/personal-abc");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "staged OTT must be 0600");
        }

        clear_staged_ott();
        assert!(!path.exists(), "clear_staged_ott should remove the file");

        // Restore HOME.
        match prev_home {
            Some(h) => std::env::set_var("HOME", h),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-core stage_writes 2>&1 | tail -20`
Expected: FAIL to compile — `stage_ott_for_sdk` / `clear_staged_ott` not defined.

- [ ] **Step 3: Write minimal implementation**

Add to `crates/core/src/matrix/pre_approval.rs`:

```rust
use std::path::PathBuf;

/// Path Pick writes the staged OTT to. `$HOME` is the app sandbox container on
/// iOS, so this lands in Pick's private, persisted storage.
pub fn staged_ott_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".strike48").join("registration_token.json")
}

/// Write `ott` to [`staged_ott_path`] in the SDK's `{token, matrix_url,
/// keycloak_url}` shape (mode 0600 on Unix). Returns the path so the caller can
/// point `STRIKE48_REGISTRATION_TOKEN_FILE` at it.
pub fn stage_ott_for_sdk(ott: &OttData) -> Result<PathBuf> {
    let path = staged_ott_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Matrix(format!("cannot create OTT dir: {e}")))?;
    }
    let json = serde_json::json!({
        "token": ott.token,
        "matrix_url": ott.matrix_url,
        "keycloak_url": ott.keycloak_url,
    })
    .to_string();
    std::fs::write(&path, json).map_err(|e| Error::Matrix(format!("cannot write OTT file: {e}")))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(path)
}

/// Remove the staged OTT file. OTTs are single-use, so this is called after a
/// successful registration and on failure to avoid reusing a stale token.
pub fn clear_staged_ott() {
    let _ = std::fs::remove_file(staged_ott_path());
}
```

- [ ] **Step 4: Extend the re-export**

In `crates/core/src/matrix/mod.rs`, change the pre_approval re-export line to:

```rust
pub use pre_approval::{clear_staged_ott, pre_approve, stage_ott_for_sdk, staged_ott_path, OttData};
```

- [ ] **Step 5: Run test to verify it passes**

Run: `nix develop --command cargo test -p pentest-core stage_writes 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/core/src/matrix/pre_approval.rs crates/core/src/matrix/mod.rs
git commit -m "feat(easy-mode): stage pre-approval OTT to the SDK-read file"
```

---

### Task 4: Pure PLG connect decision + credentials-present check

**Files:**
- Modify: `crates/core/src/config.rs`
- Test: `crates/core/src/config.rs` (existing `#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: existing `ConnectorConfig::read_credentials_tenant_id(connector_name: &str, instance_id: &str) -> Option<String>` (config.rs:466).
- Produces:
  - `pub enum PlgConnectStep { Silent, SignIn }`
  - `pub fn plg_connect_decision(easy_mode: bool, creds_present: bool) -> PlgConnectStep`
  - `impl ConnectorConfig { pub fn credentials_present(connector_name: &str, instance_id: &str) -> bool }`

- [ ] **Step 1: Write the failing test**

Add to the existing `#[cfg(test)] mod tests` in `crates/core/src/config.rs`:

```rust
    #[test]
    fn plg_connect_decision_matrix() {
        use crate::config::{plg_connect_decision, PlgConnectStep};
        assert_eq!(plg_connect_decision(true, true), PlgConnectStep::Silent);
        assert_eq!(plg_connect_decision(true, false), PlgConnectStep::SignIn);
        // Expert mode is handled by the existing path; decision is Silent.
        assert_eq!(plg_connect_decision(false, false), PlgConnectStep::Silent);
        assert_eq!(plg_connect_decision(false, true), PlgConnectStep::Silent);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-core plg_connect_decision 2>&1 | tail -20`
Expected: FAIL to compile — `plg_connect_decision` / `PlgConnectStep` not defined.

- [ ] **Step 3: Write minimal implementation**

Add near `read_credentials_tenant_id` in `crates/core/src/config.rs` (module level, outside `impl`):

```rust
/// Whether the PLG easy-mode connect should sign in first or connect silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlgConnectStep {
    /// Connect straight away (expert mode, or easy mode with saved creds).
    Silent,
    /// Run OAuth-first, then exchange for an OTT before connecting.
    SignIn,
}

/// Decide the easy-mode connect path. Only easy mode with no saved connector
/// credentials needs the OAuth-first flow; every other case connects silently
/// (expert mode's own path is unaffected).
pub fn plg_connect_decision(easy_mode: bool, creds_present: bool) -> PlgConnectStep {
    if easy_mode && !creds_present {
        PlgConnectStep::SignIn
    } else {
        PlgConnectStep::Silent
    }
}
```

Add inside `impl ConnectorConfig` (next to `read_credentials_tenant_id`):

```rust
    /// True when the SDK has already persisted connector credentials for this
    /// identity (i.e. a prior OTT registration succeeded), so we can connect
    /// without signing in again.
    pub fn credentials_present(connector_name: &str, instance_id: &str) -> bool {
        let home = match std::env::var("HOME") {
            Ok(h) => h,
            Err(_) => return false,
        };
        std::path::PathBuf::from(home)
            .join(".strike48")
            .join("credentials")
            .join(format!("{connector_name}_{instance_id}.json"))
            .exists()
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo test -p pentest-core plg_connect_decision 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/config.rs
git commit -m "feat(easy-mode): add plg_connect_decision and credentials_present"
```

---

### Task 5: `SigningIn` connecting-screen step

**Files:**
- Modify: `crates/ui/src/components/connecting_screen.rs`

**Interfaces:**
- Produces: `ConnectingStep::SigningIn` variant, mapped to display index 0 with label "Signing in to Strike48...".

- [ ] **Step 1: Write the failing test**

Add a test at the bottom of `crates/ui/src/components/connecting_screen.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_in_maps_to_first_display_step() {
        assert_eq!(display_index(ConnectingStep::SigningIn), 0);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-ui --features "desktop,connector" signing_in_maps 2>&1 | tail -20`
Expected: FAIL to compile — no `SigningIn` variant.

- [ ] **Step 3: Write minimal implementation**

In `crates/ui/src/components/connecting_screen.rs`, add `SigningIn` as the first variant of the enum:

```rust
pub enum ConnectingStep {
    SigningIn,
    Connecting,
    Registering,
    WaitingForApproval,
    ExchangingToken,
    Finalizing,
}
```

Update `display_index` to map it to 0:

```rust
fn display_index(step: ConnectingStep) -> u8 {
    match step {
        ConnectingStep::SigningIn | ConnectingStep::Connecting | ConnectingStep::Registering => 0,
        ConnectingStep::WaitingForApproval => 1,
        ConnectingStep::ExchangingToken | ConnectingStep::Finalizing => 2,
    }
}
```

Add its label in the `status_text` match in `ConnectingScreen`:

```rust
    let status_text = match step {
        ConnectingStep::SigningIn => "Signing in to Strike48...",
        ConnectingStep::Connecting => "Opening connection...",
        ConnectingStep::Registering => "Registering connector...",
        ConnectingStep::WaitingForApproval => "Awaiting approval",
        ConnectingStep::ExchangingToken => "Exchanging credentials...",
        ConnectingStep::Finalizing => "Finalizing session...",
    };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo test -p pentest-ui --features "desktop,connector" signing_in_maps 2>&1 | tail -20`
Expected: PASS.

Then check the whole workspace still compiles (other `match ConnectingStep` sites may need the arm):
Run: `nix develop --command cargo check -p pentest-ui --features "desktop,connector" 2>&1 | tail -20`
Expected: no errors. If a non-exhaustive-match error appears in `liveview_connector` or elsewhere, add a `ConnectingStep::SigningIn => ...` arm mirroring the `Connecting` arm at that site.

- [ ] **Step 5: Commit**

```bash
git add crates/ui/src/components/connecting_screen.rs
git commit -m "feat(easy-mode): add SigningIn connecting step"
```

---

### Task 6: PLG pre-connect orchestration + NeedsSignIn state

**Files:**
- Modify: `crates/ui/src/connector_app.rs`
- Modify: `crates/ui/src/components/easy_mode.rs`

**Interfaces:**
- Consumes:
  - `pentest_core::matrix::{pre_approve, stage_ott_for_sdk, clear_staged_ott, OttData}` (Tasks 1-3)
  - `pentest_core::config::{plg_connect_decision, PlgConnectStep}` and `ConnectorConfig::credentials_present` (Task 4)
  - `pentest_core::matrix::fetch_matrix_token_browser(matrix_url: &str) -> Result<String>` (existing, feature `browser-auth`)
  - `ConnectingStep::SigningIn` (Task 5)
  - Existing `on_connect((ConnectorConfig, bool))` closure, `config` signal, `connecting_step` signal, `status` signal, `chat_api_url` derivation.
- Produces: a `needs_sign_in: Signal<bool>` provided via context so `EasyModeShell` renders a retry overlay.

This is the integration task. It has no new unit test (the pure decision is tested in Task 4; the HTTP/file pieces in Tasks 1-3). It is verified by compilation + the manual iOS checklist in Task 7.

- [ ] **Step 1: Add the `needs_sign_in` signal and provide it via context**

In `crates/ui/src/connector_app.rs`, near the other signals (after `connect_error` around line 332), add:

```rust
    // PLG easy mode: set when OAuth-first / OTT exchange fails so EasyModeShell
    // can show a friendly "sign in to continue" retry overlay. Never triggers a
    // tokenless connect.
    let needs_sign_in = use_context_provider(|| Signal::new(false));
```

- [ ] **Step 1b: Extract a reusable `derive_api_url` helper**

The existing `chat_api_url` block (connector_app.rs ~801-826) derives an HTTPS
API URL from the connector host (strips `grpc://`/`ws://`/etc. scheme prefixes,
strips a leading `connectors-`, applies `use_tls` to pick `https`/`http`). Lift
that logic into a module-level free function in `crates/ui/src/connector_app.rs`
so both the chat derivation and the PLG flow use one implementation:

```rust
/// Derive the HTTPS(S) Matrix API URL from a connector host string.
/// Strips transport scheme prefixes and a leading `connectors-` host label,
/// then applies the TLS choice.
fn derive_api_url(host: &str, use_tls: bool) -> String {
    let scheme = if use_tls { "https" } else { "http" };
    let schemes = ["grpc://", "grpcs://", "http://", "https://", "ws://", "wss://"];
    let host_lower = host.to_lowercase();
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

Then update the existing `chat_api_url` block to call `derive_api_url(&host, config.read().use_tls)` in its non-empty-host branch instead of the inline logic, so there is a single source of truth. Confirm the workspace still compiles after this refactor:
Run: `nix develop --command cargo check -p pentest-ui --features "desktop,connector" 2>&1 | tail -10`

- [ ] **Step 2: Add the PLG pre-connect helper closure**

In `crates/ui/src/connector_app.rs`, immediately BEFORE the `// ---- auto-connect ----` block (around line 614), add a closure that performs the OAuth-first exchange then calls `on_connect`. It captures `on_connect`, `config`, `connecting_step`, `status`, `terminal_lines`, `needs_sign_in`, and calls `derive_api_url` from Step 1b.

```rust
    // PLG easy-mode OAuth-first connect: obtain the user JWT, exchange it for a
    // tenant-scoped OTT, stage the OTT for the SDK, then connect. On any failure
    // set needs_sign_in and stop — never fall back to a tokenless connect.
    let plg_sign_in_and_connect = {
        let mut on_connect = on_connect;
        move |base_config: ConnectorConfig| {
            let mut connecting_step = connecting_step;
            let mut status = status;
            let mut terminal_lines = terminal_lines;
            let mut needs_sign_in = needs_sign_in;
            let mut config = config;
            spawn(async move {
                needs_sign_in.set(false);
                status.set(ConnectorStatus::Connecting);
                connecting_step.set(Some(ConnectingStep::SigningIn));

                // Derive the HTTPS API URL from the connector host using the
                // same logic as the chat_api_url derivation below (connector_app.rs
                // ~801-826). `matrix::normalize_url` is pub(crate) and not
                // reachable from this crate, so use the shared helper added in
                // Step 1b instead.
                let api_url = derive_api_url(&base_config.host, base_config.use_tls);

                let jwt = match pentest_core::matrix::fetch_matrix_token_browser(&api_url).await {
                    Ok(t) => t,
                    Err(e) => {
                        terminal_lines
                            .write()
                            .push(TerminalLine::error(format!("Sign-in failed: {e}")));
                        status.set(ConnectorStatus::Disconnected);
                        connecting_step.set(None);
                        needs_sign_in.set(true);
                        return;
                    }
                };

                let ott = match pentest_core::matrix::pre_approve(
                    &api_url,
                    &jwt,
                    &base_config.connector_name,
                )
                .await
                {
                    Ok(o) => o,
                    Err(e) => {
                        terminal_lines
                            .write()
                            .push(TerminalLine::error(format!("Pre-approval failed: {e}")));
                        status.set(ConnectorStatus::Disconnected);
                        connecting_step.set(None);
                        needs_sign_in.set(true);
                        return;
                    }
                };

                let staged = match pentest_core::matrix::stage_ott_for_sdk(&ott) {
                    Ok(p) => p,
                    Err(e) => {
                        terminal_lines
                            .write()
                            .push(TerminalLine::error(format!("Could not stage OTT: {e}")));
                        status.set(ConnectorStatus::Disconnected);
                        connecting_step.set(None);
                        needs_sign_in.set(true);
                        return;
                    }
                };

                // Point the SDK at the staged OTT and adopt the authoritative
                // tenant so the connector registers under the personal tenant.
                std::env::set_var("STRIKE48_REGISTRATION_TOKEN_FILE", &staged);
                let mut c = base_config;
                c.tenant_id = ott.tenant_id.clone();
                config.set(c.clone());

                terminal_lines.write().push(TerminalLine::info(
                    "Signed in. Registering connector for your workspace...",
                ));
                connecting_step.set(Some(ConnectingStep::Connecting));
                on_connect((c, true));
            });
        }
    };
```

If `pentest_core::matrix::normalize_url` is not public, use the same host→api-url derivation already present for `chat_api_url` (connector_app.rs:801-826); extract it into a small local `fn derive_api_url(host: &str, use_tls: bool) -> String` and call it here and there. Confirm with:
Run: `grep -rn "pub fn normalize_url" crates/core/src/matrix/`

- [ ] **Step 3: Route the auto-connect through the PLG decision**

In `crates/ui/src/connector_app.rs`, modify the `// ---- auto-connect ----` `use_effect` (currently connector_app.rs:614-636). Replace the body so easy mode consults `plg_connect_decision`:

```rust
    // ---- auto-connect ----
    let easy_mode_autoconnect_config = easy_mode_env_config.clone();
    let easy_mode_flag = cfg.easy_mode;
    use_effect(move || {
        if !initial_auto_connect {
            return;
        }
        // Pick the config we would connect with (saved config wins, else PLG env).
        let candidate = settings
            .read()
            .last_config
            .clone()
            .or_else(|| {
                easy_mode_autoconnect_config.clone().map(|mut c| {
                    c.instance_id = device_id.clone();
                    c
                })
            });
        let Some(candidate) = candidate else { return };

        let creds = ConnectorConfig::credentials_present(
            &candidate.connector_name,
            &candidate.instance_id,
        );
        match pentest_core::config::plg_connect_decision(easy_mode_flag, creds) {
            pentest_core::config::PlgConnectStep::SignIn => {
                terminal_lines.write().push(TerminalLine::info(
                    "Easy mode: signing in to your Strike48 workspace...",
                ));
                plg_sign_in_and_connect(candidate);
            }
            pentest_core::config::PlgConnectStep::Silent => {
                terminal_lines
                    .write()
                    .push(TerminalLine::info("Auto-connecting..."));
                // remember=true when it came from saved config, false for a
                // build-time PLG env default (mirrors prior behaviour).
                let remember = settings.read().last_config.is_some();
                on_connect((candidate, remember));
            }
        }
    });
```

- [ ] **Step 4: Render the NeedsSignIn overlay in EasyModeShell**

In `crates/ui/src/components/easy_mode.rs`, consume the `needs_sign_in` context and render a retry overlay when set. Near the top of `EasyModeShell` (after the other `use_context`/signal setup, e.g. after `chat_header_ctx`), add:

```rust
    let needs_sign_in = use_context::<Signal<bool>>();
```

Then, in the render, BEFORE the normal `rsx!` return (after the `show_docs` early-return block, around easy_mode.rs:119), add:

```rust
    if needs_sign_in() {
        let mut needs_sign_in = needs_sign_in;
        return rsx! {
            div { class: "easy-doc-screen",
                div { class: "easy-signin",
                    p { class: "easy-signin-title", "Sign in to connect to Strike48" }
                    p { class: "easy-signin-sub", "We could not complete sign-in. Tap retry to try again." }
                    button {
                        class: "action-card",
                        onclick: move |_| needs_sign_in.set(false),
                        span { class: "action-card-label", "Retry sign-in" }
                    }
                }
            }
        };
    }
```

NOTE: setting `needs_sign_in` to false alone does not re-trigger the auto-connect effect. To make Retry actually re-run the flow, expose a retry mechanism: add a `retry_tick: Signal<u32>` context in `connector_app.rs` alongside `needs_sign_in`, have the auto-connect `use_effect` read `retry_tick()` so it re-runs when it changes, and have the Retry button increment it. Wire it as follows:

In `connector_app.rs` (with the `needs_sign_in` declaration):

```rust
    let retry_tick = use_context_provider(|| Signal::new(0u32));
```

Add `let _ = retry_tick();` as the first line inside the auto-connect `use_effect` closure so the effect subscribes to it.

In `easy_mode.rs`, change the Retry button to bump the tick (and clear the flag):

```rust
    let needs_sign_in = use_context::<Signal<bool>>();
    let retry_tick = use_context::<Signal<u32>>();
```

```rust
                    button {
                        class: "action-card",
                        onclick: move |_| {
                            let mut needs_sign_in = needs_sign_in;
                            let mut retry_tick = retry_tick;
                            needs_sign_in.set(false);
                            retry_tick.set(retry_tick() + 1);
                        },
                        span { class: "action-card-label", "Retry sign-in" }
                    }
```

- [ ] **Step 5: Add minimal CSS for the sign-in overlay**

In `crates/ui/src/styles/mobile.css`, add (near the `.easy-doc-screen` rules):

```css
.easy-signin {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: var(--em-space-3);
    padding: var(--em-space-4);
    text-align: center;
}
.easy-signin-title { font-size: 18px; font-weight: 600; color: var(--em-text); }
.easy-signin-sub { font-size: 14px; opacity: 0.7; color: var(--em-text); }
.easy-signin .action-card { max-width: 320px; }
```

- [ ] **Step 6: Compile the whole workspace**

Run: `nix develop --command cargo check -p pentest-ui --features "desktop,connector" 2>&1 | tail -20`
Expected: no errors. Resolve any missing-match-arm or borrow issues surfaced here (e.g. `Signal` copy semantics — add `let mut x = x;` rebinds inside closures as shown).

- [ ] **Step 7: Clippy**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings 2>&1 | tail -20`
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/ui/src/connector_app.rs crates/ui/src/components/easy_mode.rs crates/ui/src/styles/mobile.css
git commit -m "feat(easy-mode): OAuth-first PLG connector registration via OTT"
```

---

### Task 7: Clear staged OTT on successful registration + manual iOS verification

**Files:**
- Modify: `crates/ui/src/lib.rs` (event handling for successful registration)

**Interfaces:**
- Consumes: `pentest_core::matrix::clear_staged_ott` (Task 3); the existing connector event that signals successful registration (`ConnectorEvent::CredentialsUpdated` or `StatusChanged(Registered)` in `run_event_loop`).

- [ ] **Step 1: Find where successful registration is handled**

Run: `grep -n "CredentialsUpdated\|ConnectorStatus::Registered\|StatusChanged" crates/ui/src/lib.rs`
Identify the arm that fires once the connector is registered with credentials (`CredentialsUpdated` is emitted when the SDK persists connector creds).

- [ ] **Step 2: Clear the staged OTT there**

In `crates/ui/src/lib.rs`, in the `ConnectorEvent::CredentialsUpdated { .. }` arm (lib.rs:98), after the existing body that saves the connector JWT, add:

```rust
                    // The OTT is single-use; once the SDK has persisted
                    // connector credentials we no longer need the staged file.
                    pentest_core::matrix::clear_staged_ott();
```

- [ ] **Step 3: Compile**

Run: `nix develop --command cargo check -p pentest-ui --features "desktop,connector" 2>&1 | tail -10`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add crates/ui/src/lib.rs
git commit -m "feat(easy-mode): clear staged OTT after successful registration"
```

- [ ] **Step 5: Build and deploy to iOS (Mac VM)**

The iOS app builds on the Mac VM (engineering@10.10.0.8), checkout at `/Users/engineering/src/github.com/Strike48-public/pick`. Push the branch, pull on the VM, build, install, launch against the PLG host with NO tenant configured:

```bash
# On the dev host: push
git push origin HEAD

# On the VM: pull + build
ssh engineering@10.10.0.8 'cd /Users/engineering/src/github.com/Strike48-public/pick && git pull --ff-only && unset C_INCLUDE_PATH CPLUS_INCLUDE_PATH && nix develop --command dx build --platform ios --package pick 2>&1 | tail -5'

# On the VM: install + launch (plg host, NO tenant, insecure TLS for dev studio)
ssh engineering@10.10.0.8 '
APP="/Users/engineering/src/github.com/Strike48-public/pick/target/dx/pick/debug/ios/Pick.app"
xcrun simctl terminate booted com.strike48.pentest_connector 2>/dev/null
xcrun simctl install booted "$APP"
SIMCTL_CHILD_STRIKE48_HOST="wss://plg.strike48.test" \
SIMCTL_CHILD_MATRIX_API_URL="https://plg.strike48.test" \
SIMCTL_CHILD_MATRIX_TLS_INSECURE="true" SIMCTL_CHILD_MATRIX_INSECURE="1" \
SIMCTL_CHILD_STRIKE48_ACCEPT_INVALID_CERTS="true" \
SIMCTL_CHILD_RUST_LOG="info,pentest_core=debug" \
xcrun simctl launch booted com.strike48.pentest_connector'
```

- [ ] **Step 6: Manual verification checklist**

Sign in as `plgdemo@example.com` / `PlgDemo123!` (plg realm). Then verify each:

1. After sign-in, the connector is REGISTERED (not pending) under a `personal-*` tenant. Check via cluster RPC:
   ```bash
   POD=$(kubectl get pods -n default | grep local-dev-studio-app | awk '{print $1}')
   kubectl exec -n default $POD -c matrix-forge -- /app/bin/matrix_studio rpc '
   conns = MatrixConnectors.Registry.list_all()
   IO.puts("REGISTERED: #{length(conns)}")
   Enum.each(conns, fn {k,m} -> IO.puts("  #{k} status=#{inspect(m[:status])}") ; _ -> :ok end)
   pend = MatrixConnectors.ApprovalService.list_pending_registrations()
   IO.puts("PENDING: #{length(pend)}")'
   ```
   Expected: REGISTERED >= 1 with a key beginning `019f86b4-...` (or the plgdemo personal tenant id), PENDING: 0.
2. In the browser (plg.strike48.test/studio, logged in as plgdemo), Gateway Config for the personal tenant shows the connector.
3. Kill and relaunch the app WITHOUT re-entering credentials — it connects silently (no sign-in prompt), because saved creds exist.
4. Delete the app / reinstall, launch, cancel the sign-in prompt — the app shows the "Sign in to connect to Strike48" retry overlay and PENDING stays 0 (nothing registered tokenless).
5. Tap "Scan My Network" and confirm a scan runs end-to-end.

Record the outcomes. If step 1 shows PENDING instead of REGISTERED, capture the connector's `tenant_id` and the app terminal log; the likely cause is `STRIKE48_REGISTRATION_TOKEN_FILE` not being read before the SDK's `initialize_auth` runs (ordering) — the env var must be set before `connect_and_run`, which Task 6 Step 2 ensures by setting it prior to `on_connect`.

- [ ] **Step 7: Commit any fixes from verification**

If verification surfaces fixes, commit them with a `fix(easy-mode): ...` message describing the specific issue found.

---

## Notes for the implementer

- Run all Rust commands through `nix develop --command ...` (the toolchain lives in the flake devshell).
- `Signal<T>` in Dioxus is `Copy`; inside `move` closures you often need `let mut x = x;` rebinds before `.set(...)`. The code blocks above already do this.
- The `browser-auth` feature gates `fetch_matrix_token_browser`. It is enabled for the mobile/connector build; if a `cargo check` for a non-mobile target fails on that symbol, gate the PLG orchestration call behind `#[cfg(feature = "browser-auth")]` and provide a `Silent`-only fallback for builds without it. Confirm the feature set with: `grep -n "browser-auth" crates/ui/Cargo.toml`.
- Do not change expert-mode behaviour. Every new branch is gated on `cfg.easy_mode` or `easy_mode` decision inputs.
