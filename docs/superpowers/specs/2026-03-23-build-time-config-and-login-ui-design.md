# Build-Time Config & Login UI

## Problem

The Android app requires manual entry of host, tenant, and auth token to connect. There are no build-time defaults for dev vs prod environments, TLS insecure mode is hardcoded, and the auth flow launches raw Chrome instead of using a Chrome Custom Tab. The tenant field is unnecessary since it comes from the backend.

## Design

### 1. Build-Time Environment Defaults

Two mutually exclusive Cargo features in `pentest-core`: `dev-defaults` and `prod-defaults`. Each defines compile-time constants consumed by the app.

| Constant | `dev-defaults` | `prod-defaults` |
|---|---|---|
| `DEFAULT_CONNECTOR_HOST` | `grpcs://connectors-studio.strike48.test` | `grpcs://connectors-studio.strike48.com` |
| `DEFAULT_TLS_INSECURE` | `true` | `false` |
| `DEFAULT_ENV_LABEL` | `"Development"` | `"Production"` |

**Justfile wiring:**
- `just build-android` → `dx build --platform android --package pentest-mobile --features dev-defaults`
- `just build-android-release` → `dx build --platform android --package pentest-mobile --release --features prod-defaults`
- Desktop and headless recipes follow the same pattern

**Implementation:** A `build_defaults` module in `pentest-core` with `cfg`-gated constants. If neither feature is enabled, falls back to prod defaults (safe default). A `compile_error!` guard prevents both features from being enabled simultaneously.

**Feature forwarding:** Since the feature is defined on `pentest-core` but the build target is `pentest-mobile`, the mobile crate re-exports the features:

```toml
# apps/mobile/Cargo.toml
[features]
dev-defaults = ["pentest-core/dev-defaults"]
prod-defaults = ["pentest-core/prod-defaults"]
```

### 2. Login Screen

Replaces the current `ConfigForm` component. Clean, minimal design:

- Strike48 logo (styled icon)
- App name
- Environment badge: green pill for "Development", neutral/grey pill for "Production"
- **"Sign In" button** — primary action, triggers auth flow
- Host override label — **only visible** if the user has changed the server host from the compiled default. Otherwise omitted for a clean look.
- **"Advanced" link** at bottom — expands to show a single server host text field. Value persists in settings and overrides the compiled default.

No tenant field (comes from backend after registration). No auth token field (handled by auth flow). No "remember connection" checkbox (always persists automatically).

### 3. Auth Flow

The existing Matrix-mediated OAuth flow in `pentest_core::matrix::auth::fetch_matrix_token_browser` already works: it opens `{studio_host}/auth/login?redirect=...`, Keycloak handles the login, and the token comes back via the `com.strike48.pentest://oauth/callback` deep link.

The only change is **upgrading the browser opener from `Intent.ACTION_VIEW` to Chrome Custom Tab** for a native in-app feel:

**Kotlin changes (`android-lib`):**
1. Add `androidx.browser:browser` dependency to `android-lib/build.gradle.kts`
2. Update `ConnectorBridge.openBrowser()` to use `CustomTabsIntent.Builder().build().launchUrl(context, uri)` instead of `Intent.ACTION_VIEW`
3. Chrome Custom Tab provides: in-app browser overlay, shared Chrome cookies, back button returns to app

**Rust side:** No changes to the auth flow logic. The `open_browser` callback registered in `apps/mobile/src/main.rs` calls `ConnectorBridge.openBrowser()` via JNI — the upgrade is transparent.

**Auth sequence (unchanged):**
1. "Sign In" tapped → derive studio host from connector host (strip `connectors-` prefix)
2. Open Chrome Custom Tab to `https://{studio_host}/auth/login?redirect=com.strike48.pentest://oauth/callback`
3. User logs in via Keycloak
4. Redirect to deep link → app receives token
5. Connect to gRPC backend with the token
6. Tenant and connector identity come from the backend registration response

### 4. Settings Persistence

`AppSettings` changes:
- `last_config.host` is only saved when it differs from the compiled default
- `last_config.tenant_id` removed from user-facing config (still stored internally after backend provides it)
- `last_config.auth_token` managed by auth flow, not user input
- `auto_connect` removed (always auto-connects if valid tokens are present)

On subsequent launches, if valid tokens exist in storage, the app auto-connects without showing the login screen. If tokens are expired or missing, the login screen is shown.

### 5. Validation Changes

`ConnectorConfig::validate()` currently requires `tenant_id` to be non-empty. Since tenant now comes from the backend after registration, `validate()` must be updated to not require `tenant_id` upfront. The `normalize_host` function is kept as validation-only (it no longer strips schemes, just validates the format).

### 6. TLS Insecure Handling

The `DEFAULT_TLS_INSECURE` constant replaces the hardcoded `std::env::set_var("MATRIX_TLS_INSECURE", "true")` in `crates/platform/src/android/mod.rs`. The Android init will set both `MATRIX_TLS_INSECURE` and `MATRIX_INSECURE` env vars from this constant, since different parts of the codebase check different env var names (`matrix::auth` checks `MATRIX_INSECURE`, the SDK checks `MATRIX_TLS_INSECURE`).

### 7. What Gets Removed

- `ConfigForm` component — replaced by new login screen
- Tenant ID input field
- Auth token input field
- "Remember connection" checkbox
- Hardcoded `MATRIX_TLS_INSECURE` in Android init — replaced by build-time constant
- Manual host entry on the main screen (moved to Advanced)

### 8. Files Affected

**New:**
- `crates/core/src/build_defaults.rs` — compile-time environment constants

**Modified:**
- `crates/core/Cargo.toml` — add `dev-defaults` / `prod-defaults` features
- `crates/core/src/lib.rs` — declare `pub mod build_defaults`
- `crates/core/src/config.rs` — use build defaults for `ConnectorConfig::default()`, update `validate()` to not require tenant
- `crates/ui/src/components/config_form.rs` — rewrite as login screen
- `crates/ui/src/connector_app.rs` — simplify connect flow, remove tenant/token from UI
- `crates/platform/src/android/mod.rs` — set TLS env vars from `DEFAULT_TLS_INSECURE`
- `android-lib/build.gradle.kts` — add `androidx.browser:browser` dependency
- `android-lib/src/main/kotlin/.../ConnectorBridge.kt` — use `CustomTabsIntent` instead of `Intent.ACTION_VIEW`
- `apps/mobile/Cargo.toml` — add `dev-defaults` / `prod-defaults` feature forwarding
- `justfile` — pass `--features dev-defaults` / `--features prod-defaults` to build recipes

### 9. Out of Scope

- iOS equivalent (SFSafariViewController) — future work
- Token refresh / silent re-auth — existing refresh logic is sufficient
- Keycloak admin configuration — assumed already set up
- Desktop login UI changes — this spec targets Android mobile
