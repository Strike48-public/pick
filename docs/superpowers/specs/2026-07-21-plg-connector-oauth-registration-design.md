# PLG Connector OAuth-First Registration — Design

**Status:** Approved for planning
**Date:** 2026-07-21
**Related:** PLG initiative (epic project-management#72); connector registration gap

## Goal

In PLG/easy mode, register Pick's connector *approved under the user's personal
tenant* via the pre-approval OTT flow, instead of the current tokenless
registration that lands in the pending queue under tenant `default` and never
appears in the user's tenant-scoped Gateway Config.

## Problem (confirmed live)

Pick does two disconnected things today:

- **Connector registration** runs **tokenless** → the matrix gateway forces it
  into the *pending* approval queue with a self-declared tenant (`default`, or
  `*` → global scope). It never auto-approves.
- **OAuth login JWT** is obtained (iOS `ASWebAuthenticationSession` via
  `fetch_matrix_token_browser`) but used for **chat/GraphQL only**
  (`crates/ui/src/lib.rs` `MatrixTokenObtained`: "chat only, not saving to
  config").

So login provisions the personal tenant correctly, but the connector sits
pending under `default` and is invisible in the user's Gateway Config.

**Why not just register with the user JWT?** The plg-realm `studio` user-login
JWT carries **no `tenant_id` claim** (verified: password grant →
`tenant_id=None`). The gateway's `issue_session_token` rejects a JWT without
that claim. The `tenant_id` protocol-mapper claim only exists on *connector*
clients created via the OTT flow.

**The fix — pre-approval OTT (verified working via curl):** exchange the user
login JWT at `POST /api/connectors/pre-approve` for an OTT scoped to the user's
personal tenant, then register the connector with that OTT. The endpoint
recovers the PLG session server-side to determine the authoritative tenant.
Verified: plgdemo login JWT (no tenant claim) → pre-approve returned
`tenant_id: 019f86b4-...`, `keycloak_url: .../realms/personal-f668ca45dbb0`, an
`ott_...` token, HTTP 201.

## Global Constraints

- **Easy/PLG mode only.** Expert mode and the existing saved-config
  auto-connect path are unchanged.
- **OAuth-first.** In PLG mode with no existing connector credentials, present
  the in-app OAuth session before the connector connects.
- **Sign in once.** If the SDK already has saved connector credentials on disk,
  skip OAuth and connect silently.
- **Never fall back to tokenless registration.** If auth/exchange fails,
  nothing registers; show a friendly retry state.
- **No SDK changes and no SDK version bump.** Use the SDK's existing file/env
  OTT ingestion (`STRIKE48_REGISTRATION_TOKEN_FILE`) and its built-in
  `has_ott()` → `register_with_ott` path. The feature works against the
  currently pinned `strike48-connector = "0.4.1"` — verified that both 0.4.x
  and the local `sdk-rs` 0.5.1 read OTT from env/file and persist connector
  creds to `~/.strike48/credentials/<type>_<instance>.json`, so the pin is not
  changed by this work.
- Commit-message rules (project): no attribution lines, no customer/tenant
  names, no emojis or em-dashes.
- Dev-only insecure-TLS flags (`MATRIX_TLS_INSECURE`) must never be defaulted
  in production paths.

## Background: how the SDK already works

- `strike48_connector`'s `OttProvider` implements the entire OTT flow: keypair
  generation, `register_with_ott`, `register_public_key_with_ott_data`,
  credential persistence, and token refresh.
- The connector's `run()` → `initialize_auth()` checks, in priority order:
  1. direct config (cert-manager), 2. `has_ott()` (pre-approval), 3. saved
  credentials.
- `has_ott()` → `load_ott()` reads, in order: `STRIKE48_REGISTRATION_TOKEN`
  (inline JSON), `STRIKE48_REGISTRATION_TOKEN_FILE` (path), then default
  `~/.strike48/...` paths.
- The OTT JSON shape is `{token, matrix_url, keycloak_url}` — exactly what
  `/api/connectors/pre-approve` returns.
- After a successful OTT registration the SDK writes
  `~/.strike48/credentials/<connector_type>_<instance_id>.json`, which it (and
  Pick's `read_credentials_tenant_id`) read on later launches.

### iOS path semantics

`$HOME` on iOS is the app's sandbox container
(`/var/mobile/Containers/Data/Application/<UUID>/`). All `~/.strike48/...`
paths land inside Pick's private, writable, persisted sandbox. This mechanism
already functions on the current iOS build — `read_credentials_tenant_id` reads
that exact path today, and settings persistence uses the same `dirs`/`$HOME`
resolution. The container UUID changes on reinstall (not on normal relaunch);
that correctly drops saved creds and re-enters the OAuth-first path, matching
the "exchange only when no valid creds" rule. The OAuth *user JWT* is stored
separately in the iOS Keychain (`io.strike48.pick.chat`).

## Architecture & Flow

```
Launch (easy mode)
  │
  ├─ SDK connector creds exist?  ──yes──► connect_and_run (silent, as today)
  │  (~/.strike48/credentials/<type>_<instance>.json)
  │
  └─no─► [SigningIn] fetch_matrix_token_browser()  → user JWT (Keychain-cached)
             │
             ├─ pre_approve(api_url, jwt, connector_type)  →  OttData
             │      (POST /api/connectors/pre-approve, Bearer jwt)
             │
             ├─ stage_ott_for_sdk(&ott)  →  write JSON, set STRIKE48_REGISTRATION_TOKEN_FILE
             │
             └─ connect_and_run()  →  SDK has_ott() → register_with_ott → APPROVED
                    (SDK persists creds → next launch takes the silent path)

  any step fails / user cancels ─► [NeedsSignIn] friendly retry (no tokenless fallback)
```

## Components

### 1. `pentest-core`: `matrix/pre_approval.rs` (new)

```rust
pub struct OttData {
    pub token: String,        // "ott_..."
    pub matrix_url: String,   // wss/grpc base the connector should dial
    pub keycloak_url: String, // realm URL, e.g. .../realms/personal-<hash>
    pub tenant_id: String,    // authoritative personal tenant
}

/// POST {api_url}/api/connectors/pre-approve with Bearer jwt.
/// Body: {"connector_type": <type>, "notes": <optional>}
/// Returns the minted OTT scoped to the JWT's PLG tenant.
pub async fn pre_approve(
    api_url: &str,
    jwt: &str,
    connector_type: &str,
) -> Result<OttData>;
```

Reuses the reqwest client conventions already in `crates/core/src/matrix/`
(including `MATRIX_TLS_INSECURE` handling). Deserializes the 201 body; maps
non-201/network/TLS errors to a descriptive `crate::error::Error`.

### 2. `pentest-core`: OTT-file bridge (in `pre_approval.rs`)

```rust
/// Serialize OttData to the SDK's expected {token, matrix_url, keycloak_url}
/// JSON and write it to a Pick-owned path (0600 on Unix); return the path so
/// the caller can set STRIKE48_REGISTRATION_TOKEN_FILE.
pub fn stage_ott_for_sdk(ott: &OttData) -> Result<PathBuf>;   // ~/.strike48/registration_token.json

/// Remove the staged OTT file (single-use token cleanup).
pub fn clear_staged_ott();
```

### 3. `pentest-core`: "already registered?" check

Reuse existing `ConnectorConfig::read_credentials_tenant_id(connector_name,
instance_id)`. `Some(_)` → creds exist → silent path. No new code.

### 4. `pentest-core`: pure connect decision (testable)

```rust
pub enum PlgConnectStep { Silent, SignIn }

/// easy_mode + creds_present → decision. Expert mode is handled by the
/// existing path and never reaches this.
pub fn plg_connect_decision(easy_mode: bool, creds_present: bool) -> PlgConnectStep;
```

- `(true,  true)  → Silent`
- `(true,  false) → SignIn`
- `(false, _)     → Silent` (expert path unchanged; caller ignores)

### 5. `connector_app.rs`: PLG pre-connect orchestration

A `spawn`ed async step, gated on `cfg.easy_mode`, invoked from the auto-connect
effect instead of calling `on_connect` directly when creds are absent:

```
match plg_connect_decision(cfg.easy_mode, creds_present) {
  Silent => on_connect(config, remember),          // silent or expert path
  SignIn => {
    connecting_step = SigningIn
    let jwt = fetch_matrix_token_browser(api_url).await?   // existing; NeedsSignIn on Err
    let ott = pre_approve(api_url, &jwt, connector_name).await?  // NeedsSignIn on Err
    let path = stage_ott_for_sdk(&ott)?                    // NeedsSignIn on Err
    std::env::set_var("STRIKE48_REGISTRATION_TOKEN_FILE", path)
    // adopt the OTT's authoritative tenant for the SDK config
    config.tenant_id = ott.tenant_id
    on_connect((config, /* remember */ true))
  }
}
```

### 6. UI state

- Add `ConnectingStep::SigningIn` (spinner copy: "Signing in to Strike48...").
- Add an easy-mode `NeedsSignIn` state: friendly copy ("Sign in to connect to
  Strike48") + a Retry action that re-enters at `SigningIn`.

## Error Handling & State Machine

```
              creds exist on disk?
              ┌──────┴───────┐
           yes│              │no
              ▼              ▼
        Connecting      SigningIn ──(user JWT)──► Exchanging
        (silent)             │                        │
              │              │                    pre_approve + stage OTT
              │         cancel/fail                    │
              │              ▼                    fail  │  ok
              │         NeedsSignIn ◄──────────────────┘  │
              │         (Retry btn)                        ▼
              │              ▲                        Connecting
              │              └──(retry)──► SigningIn   (has_ott→approved)
              ▼                                             │
          Connected ◄───────────────────────────────────────┘
```

| Failure point | Behavior |
|---|---|
| User cancels `ASWebAuthenticationSession` | → `NeedsSignIn` + Retry. No connect attempt. |
| `pre_approve` non-201 / network / TLS | → `NeedsSignIn`; log underlying error to terminal, show friendly copy. |
| `stage_ott_for_sdk` write/IO error | → `NeedsSignIn`; log path/IO error. |
| SDK `register_with_ott` fails after staging | Existing `connect_and_run` → `Err` mapped to `NeedsSignIn`; call `clear_staged_ott()` so a stale OTT is not reused. |
| OTT expired between stage and register | Same as above; retry re-runs `pre_approve` (fresh OTT). |

**Critical rule:** never fall back to a tokenless `on_connect`. If auth does
not complete, nothing registers.

**Idempotency / cleanup:**
- On successful register the SDK persists creds; call `clear_staged_ott()`
  (single-use, 15-min TTL token — no reason to keep it).
- Retry always re-mints a fresh OTT rather than reusing the staged file.
- `fetch_matrix_token_browser`'s process-global cache means a retry after a
  *pre_approve* failure reuses a still-valid JWT and does not necessarily
  re-prompt sign-in.

## Testing

### Unit tests (`pentest-core`, no network/device)

| Test | Asserts |
|---|---|
| `pre_approve` success | Mock server returns the real 201 body; parses `OttData` with all four fields. |
| `pre_approve` request shape | Mock captures `POST /api/connectors/pre-approve`, `Authorization: Bearer <jwt>`, body `{"connector_type": ...}`. |
| `pre_approve` non-201 → Err | 401/403/500 map to a descriptive `Error`, not a panic or empty `OttData`. |
| `stage_ott_for_sdk` writes SDK-shaped JSON | Written file parses back to `{token, matrix_url, keycloak_url}`; mode `0600` on Unix; returns the path. |
| `stage_ott_for_sdk` round-trip | Staged file is loadable by the same JSON contract the SDK's `parse_ott` expects (drift guard). |
| `plg_connect_decision` matrix | `(true,true)→Silent`, `(true,false)→SignIn`, `(false,_)→Silent`. |

### Manual/integration (iOS sim — the real proof)

1. Fresh install, PLG host, no tenant configured → sign-in prompt → after
   sign-in, cluster RPC shows connector **REGISTERED/active under `personal-*`**
   (not pending/`default`).
2. Browser Gateway Config for that personal tenant **shows the connector**.
3. Kill + relaunch → **no sign-in prompt**, connects silently (saved-creds
   path).
4. Cancel sign-in → **`NeedsSignIn`** with Retry; nothing registers
   (`PENDING: 0`).
5. Scan runs end-to-end under the personal tenant.

## Out of scope (YAGNI)

- No SDK changes; no new OAuth mechanism (reuses `fetch_matrix_token_browser`).
- No expert-mode changes.
- No Android-specific work in this spec (the same `$HOME` mechanism applies;
  the verification target here is iOS).

## Dev environment reference

- `plg_mode` feature flag enabled for hostnames `plg.strike48.test`,
  `studio.strike48.test`, `connectors-studio.strike48.test` (non-prod
  excluded). `external_connectors` globally on.
- PLG test user: `plgdemo@example.com` / `PlgDemo123!` in the `plg` realm →
  personal tenant `personal-f668ca45dbb0`
  (`019f86b4-d2bf-7f56-89cf-30485d8a956b`).
- Matrix source: `matrix_studio/.../controllers/connector_pre_approval_controller.ex`
  (route `/api/connectors/pre-approve`, pipeline `:webhook_receiver`),
  `matrix_connectors/.../pre_approval_service.ex`.
