# Build-Time Config & Login UI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the manual config form with a clean login screen backed by build-time environment defaults and Chrome Custom Tab auth.

**Architecture:** Add `dev-defaults`/`prod-defaults` Cargo features to `pentest-core` that set compile-time constants for host, TLS, and environment label. Replace the `ConfigForm` component with a minimal login screen. Upgrade Android browser opener from `Intent.ACTION_VIEW` to Chrome Custom Tab.

**Tech Stack:** Rust/Dioxus, Cargo feature flags, Kotlin (Android Custom Tabs), Gradle

**Spec:** `docs/superpowers/specs/2026-03-23-build-time-config-and-login-ui-design.md`

---

### Task 1: Add build_defaults module to pentest-core

**Files:**
- Create: `crates/core/src/build_defaults.rs`
- Modify: `crates/core/Cargo.toml` (lines 8-10, features section)
- Modify: `crates/core/src/lib.rs` (line 17, add module declaration)

- [ ] **Step 1: Add feature flags to Cargo.toml**

In `crates/core/Cargo.toml`, replace the `[features]` section (lines 8-10):

```toml
[features]
default = []
browser-auth = ["dep:axum", "dep:open"]
dev-defaults = []
prod-defaults = []
```

- [ ] **Step 2: Create build_defaults.rs**

Create `crates/core/src/build_defaults.rs`:

```rust
//! Compile-time environment defaults selected via Cargo features.
//!
//! - `dev-defaults`: local k8s cluster (*.strike48.test), TLS insecure
//! - `prod-defaults`: production (*.strike48.com), TLS strict
//! - Neither feature: falls back to prod defaults (safe default)

#[cfg(all(feature = "dev-defaults", feature = "prod-defaults"))]
compile_error!("Features `dev-defaults` and `prod-defaults` are mutually exclusive");

#[cfg(feature = "dev-defaults")]
mod values {
    pub const DEFAULT_CONNECTOR_HOST: &str = "grpcs://connectors-studio.strike48.test";
    pub const DEFAULT_TLS_INSECURE: bool = true;
    pub const DEFAULT_ENV_LABEL: &str = "Development";
}

#[cfg(not(feature = "dev-defaults"))]
mod values {
    // Prod defaults: used for prod-defaults feature OR when no feature is specified (safe fallback)
    pub const DEFAULT_CONNECTOR_HOST: &str = "grpcs://connectors-studio.strike48.com";
    pub const DEFAULT_TLS_INSECURE: bool = false;
    pub const DEFAULT_ENV_LABEL: &str = "Production";
}

pub use values::*;
```

- [ ] **Step 3: Declare module in lib.rs**

In `crates/core/src/lib.rs`, add after line 17 (`pub mod workspace;`):

```rust
pub mod build_defaults;
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check -p pentest-core`
Expected: compiles with no errors (falls back to prod defaults)

Run: `cargo check -p pentest-core --features dev-defaults`
Expected: compiles with dev defaults

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/build_defaults.rs crates/core/src/lib.rs crates/core/Cargo.toml
git commit -m "feat: add build-time environment defaults (dev/prod feature flags)"
```

---

### Task 2: Wire build defaults into ConnectorConfig and validation

**Files:**
- Modify: `crates/core/src/config.rs` (lines 57-73 default impl, lines 96-105 validate)

- [ ] **Step 1: Update ConnectorConfig::default() to use build defaults**

In `crates/core/src/config.rs`, replace the `impl Default for ConnectorConfig` block (lines 57-73):

```rust
impl Default for ConnectorConfig {
    fn default() -> Self {
        Self {
            host: crate::build_defaults::DEFAULT_CONNECTOR_HOST.to_string(),
            tenant_id: "default".to_string(),
            auth_token: String::new(),
            instance_id: Uuid::new_v4().to_string(),
            connector_name: default_connector_name(),
            display_name: None,
            tags: vec![],
            use_tls: true,
            reconnect_enabled: true,
            reconnect_delay_ms: 5000,
            max_backoff_delay_ms: 60000,
        }
    }
}
```

- [ ] **Step 2: Relax validate() to not require tenant_id**

In `crates/core/src/config.rs`, replace the `validate` method (lines 96-105):

```rust
/// Validate the configuration
pub fn validate(&self) -> Result<(), String> {
    if self.host.is_empty() {
        return Err("Strike48 host is required".to_string());
    }
    Ok(())
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p pentest-core`
Expected: compiles, default host is now the prod default

- [ ] **Step 4: Commit**

```bash
git add crates/core/src/config.rs
git commit -m "feat: use build-time defaults for ConnectorConfig, relax tenant validation"
```

---

### Task 3: Wire feature forwarding in mobile app, platform crate, and justfile

**Files:**
- Modify: `apps/mobile/Cargo.toml` (add feature forwarding)
- Modify: `crates/platform/Cargo.toml` (add feature forwarding)
- Modify: `justfile` (lines 242, 267 — add --features flag to dx build)

- [ ] **Step 1: Add feature forwarding in apps/mobile/Cargo.toml**

Add a `[features]` section to `apps/mobile/Cargo.toml` (after `[dependencies]`):

```toml
[features]
dev-defaults = ["pentest-core/dev-defaults"]
prod-defaults = ["pentest-core/prod-defaults"]
```

- [ ] **Step 1b: Add feature forwarding in crates/platform/Cargo.toml**

Add to the `[features]` section in `crates/platform/Cargo.toml` (it already has `desktop`, `android`, etc.):

```toml
dev-defaults = ["pentest-core/dev-defaults"]
prod-defaults = ["pentest-core/prod-defaults"]
```

- [ ] **Step 2: Update justfile build-android recipe**

In `justfile`, change the `dx build` line in `build-android` (line 242) from:

```
    {{dx}} build --platform android --package pentest-mobile
```

to:

```
    {{dx}} build --platform android --package pentest-mobile --features dev-defaults
```

- [ ] **Step 3: Update justfile build-android-release recipe**

In `justfile`, change the `dx build` line in `build-android-release` (line 267) from:

```
    {{dx}} build --platform android --package pentest-mobile --release
```

to:

```
    {{dx}} build --platform android --package pentest-mobile --release --features prod-defaults
```

- [ ] **Step 4: Verify debug build compiles with dev-defaults**

Run: `just build-android 2>&1 | tail -5`
Expected: BUILD SUCCESSFUL

- [ ] **Step 5: Commit**

```bash
git add apps/mobile/Cargo.toml crates/platform/Cargo.toml justfile
git commit -m "feat: wire dev-defaults/prod-defaults features through mobile app, platform, and justfile"
```

---

### Task 4: Update Android TLS init to use build defaults

**Files:**
- Modify: `crates/platform/src/android/mod.rs` (lines 38-42, TLS env var block)

- [ ] **Step 1: Replace hardcoded TLS insecure with build default**

In `crates/platform/src/android/mod.rs`, replace the TLS block (lines 38-42):

```rust
        // Accept self-signed TLS certs in dev/test environments.
        // The local k8s Cilium gateway uses a self-signed certificate.
        if std::env::var("MATRIX_TLS_INSECURE").is_err() {
            std::env::set_var("MATRIX_TLS_INSECURE", "true");
        }
```

with:

```rust
        // Set TLS insecure mode from build-time defaults.
        // Dev builds accept self-signed certs; prod builds require valid certs.
        if std::env::var("MATRIX_TLS_INSECURE").is_err() {
            let insecure = if pentest_core::build_defaults::DEFAULT_TLS_INSECURE {
                "true"
            } else {
                "false"
            };
            std::env::set_var("MATRIX_TLS_INSECURE", insecure);
            std::env::set_var("MATRIX_INSECURE", insecure);
        }
```

- [ ] **Step 2: Verify it compiles**

Run: `cargo check -p pentest-platform --features android`
Expected: compiles (pentest-platform depends on pentest-core)

- [ ] **Step 3: Commit**

```bash
git add crates/platform/src/android/mod.rs
git commit -m "feat: set TLS insecure from build-time defaults instead of hardcoding"
```

---

### Task 5: Replace ConfigForm with login screen

**Files:**
- Modify: `crates/ui/src/components/config_form.rs` (full rewrite)

- [ ] **Step 1: Rewrite config_form.rs as login screen**

Replace the entire contents of `crates/ui/src/components/config_form.rs`:

```rust
use dioxus::prelude::*;
use pentest_core::config::ConnectorConfig;
use pentest_core::build_defaults::{DEFAULT_CONNECTOR_HOST, DEFAULT_ENV_LABEL};

/// Props for the login screen.
#[derive(Props, Clone, PartialEq)]
pub struct LoginScreenProps {
    /// Current config (may have host override from settings).
    pub config: ConnectorConfig,
    /// Called with (config, remember=true) when user taps Sign In.
    pub on_connect: EventHandler<(ConnectorConfig, bool)>,
    /// Whether a connection attempt is in progress.
    #[props(default = false)]
    pub is_connecting: bool,
}

/// Minimal login screen with optional advanced host override.
#[component]
pub fn LoginScreen(props: LoginScreenProps) -> Element {
    let mut show_advanced = use_signal(|| false);
    let mut host_override = use_signal(|| {
        let h = &props.config.host;
        if h == DEFAULT_CONNECTOR_HOST || h.is_empty() {
            String::new()
        } else {
            h.clone()
        }
    });

    let has_override = !host_override.read().is_empty();

    let on_sign_in = move |_| {
        let mut config = props.config.clone();
        if has_override {
            config.host = host_override.read().clone();
        } else {
            config.host = DEFAULT_CONNECTOR_HOST.to_string();
        }
        props.on_connect.call((config, true));
    };

    rsx! {
        style { {include_str!("css/login_screen.css")} }

        div { class: "login-screen",
            // Logo
            div { class: "login-logo", "S48" }

            // App name
            div { class: "login-title", "Strike48" }

            // Environment badge
            div {
                class: if DEFAULT_ENV_LABEL == "Development" { "login-env-badge dev" } else { "login-env-badge prod" },
                "{DEFAULT_ENV_LABEL}"
            }

            // Host override label (only shown when overridden)
            if has_override {
                div { class: "login-host-label", "{host_override}" }
            }

            // Sign In button
            button {
                class: "login-button",
                disabled: props.is_connecting,
                onclick: on_sign_in,
                if props.is_connecting { "Connecting..." } else { "Sign In" }
            }

            // Advanced toggle
            div { class: "login-advanced-toggle",
                span {
                    onclick: move |_| show_advanced.toggle(),
                    if *show_advanced.read() { "Hide Advanced" } else { "Advanced" }
                }
            }

            // Advanced panel
            if *show_advanced.read() {
                div { class: "login-advanced-panel",
                    label { "Server Host" }
                    input {
                        r#type: "text",
                        placeholder: "{DEFAULT_CONNECTOR_HOST}",
                        value: "{host_override}",
                        oninput: move |e| host_override.set(e.value()),
                    }
                }
            }
        }
    }
}
```

- [ ] **Step 2: Create login screen CSS**

Create `crates/ui/src/components/css/login_screen.css`:

```css
.login-screen {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    min-height: 80vh;
    padding: 24px;
    gap: 12px;
}

.login-logo {
    width: 64px;
    height: 64px;
    background: linear-gradient(135deg, #22c55e, #16a34a);
    border-radius: 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 24px;
    font-weight: bold;
    color: white;
    margin-bottom: 8px;
}

.login-title {
    font-size: 22px;
    font-weight: 600;
}

.login-env-badge {
    font-size: 13px;
    padding: 4px 14px;
    border-radius: 12px;
    margin-bottom: 4px;
}

.login-env-badge.dev {
    color: #22c55e;
    background: rgba(34, 197, 94, 0.1);
}

.login-env-badge.prod {
    color: #888;
    background: rgba(136, 136, 136, 0.1);
}

.login-host-label {
    font-size: 12px;
    color: #888;
    margin-bottom: 4px;
}

.login-button {
    width: 100%;
    max-width: 280px;
    padding: 14px;
    background: #22c55e;
    color: white;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    margin-top: 24px;
}

.login-button:disabled {
    opacity: 0.6;
    cursor: not-allowed;
}

.login-button:hover:not(:disabled) {
    background: #16a34a;
}

.login-advanced-toggle {
    margin-top: 16px;
}

.login-advanced-toggle span {
    font-size: 13px;
    color: #888;
    cursor: pointer;
    border-bottom: 1px dashed #555;
}

.login-advanced-panel {
    width: 100%;
    max-width: 280px;
    margin-top: 12px;
}

.login-advanced-panel label {
    display: block;
    font-size: 12px;
    color: #888;
    margin-bottom: 4px;
}

.login-advanced-panel input {
    width: 100%;
    padding: 10px;
    border: 1px solid #ddd;
    border-radius: 6px;
    font-size: 14px;
    box-sizing: border-box;
}
```

- [ ] **Step 3: Verify it compiles**

Run: `cargo check -p pentest-ui --features connector`
Expected: may have unused import warnings from old ConfigForm references — that's expected, we fix those in the next task.

- [ ] **Step 4: Commit**

```bash
git add crates/ui/src/components/config_form.rs crates/ui/src/components/css/login_screen.css
git commit -m "feat: replace ConfigForm with clean login screen"
```

---

### Task 6: Update connector_app to use LoginScreen

**Files:**
- Modify: `crates/ui/src/connector_app.rs` (imports, auto-connect ~line 409-419, render ~line 530-542)
- Modify: `crates/ui/src/components/mod.rs` (export rename)

> **Note:** The config init (lines 244-255) and on_connect handler (line 311) need no changes — `ConnectorConfig::default()` now uses build defaults from Task 2, and `normalize_host` / `validate` are already relaxed.

- [ ] **Step 1: Update import in connector_app.rs**

In `crates/ui/src/connector_app.rs`, find the components import block (around line 21). Replace `ConfigForm` with `LoginScreen`:

```rust
use crate::components::{
    AppLayout, ChatPanel, LoginScreen, ConnectingScreen, ConnectingStep, Dashboard, FileBrowser,
    InteractiveShell, NavPage, SettingsPage, Terminal, ToolsPage, STRIKE48_SIDEBAR_LOGO_SVG,
};
```

Also remove `initial_auto_connect` (line 242) — it becomes unused. Delete:

```rust
    let initial_auto_connect = settings.peek().auto_connect;
```

- [ ] **Step 2: Update auto-connect to always auto-connect with valid tokens**

In `crates/ui/src/connector_app.rs`, replace the auto-connect block (lines 409-419):

```rust
    // ---- auto-connect ----
    use_effect(move || {
        if let Some(saved_config) = settings.read().last_config.clone() {
            if !saved_config.auth_token.is_empty() || settings.read().auto_connect {
                terminal_lines
                    .write()
                    .push(TerminalLine::info("Auto-connecting with saved settings..."));
                on_connect((saved_config, true));
            }
        }
    });
```

- [ ] **Step 3: Replace ConfigForm with LoginScreen in the render**

In `crates/ui/src/connector_app.rs`, find the `ConfigForm` usage in the render (around line 530-542). Replace:

```rust
                        ConfigForm {
                            config: config.read().clone(),
                            on_connect: on_connect,
                            is_connecting: false,
                            remember: settings.read().auto_connect,
                        }
```

with:

```rust
                        LoginScreen {
                            config: config.read().clone(),
                            on_connect: on_connect,
                            is_connecting: false,
                        }
```

- [ ] **Step 4: Update components/mod.rs export**

In `crates/ui/src/components/mod.rs`, the existing `pub use config_form::*;` will automatically export `LoginScreen` since we rewrote the file contents in Task 5. Verify that `config_form` is still declared as a module and the wildcard re-export picks up `LoginScreen`.

- [ ] **Step 6: Verify it compiles**

Run: `cargo check -p pentest-ui --features connector`
Expected: compiles with no errors

- [ ] **Step 7: Commit**

```bash
git add crates/ui/src/connector_app.rs crates/ui/src/components/mod.rs
git commit -m "feat: use LoginScreen in connector_app, simplify auto-connect"
```

---

### Task 7: Upgrade Android browser opener to Chrome Custom Tab

**Files:**
- Modify: `android-lib/build.gradle.kts` (add browser dependency)
- Modify: `android-lib/src/main/kotlin/com/strike48/pentest_connector/ConnectorBridge.kt` (lines 240-253, openBrowser method)

- [ ] **Step 1: Add androidx.browser dependency**

In `android-lib/build.gradle.kts`, update the `dependencies` block (around line 20). Note: this also bumps appcompat from 1.6.1 to 1.7.0:

```kotlin
dependencies {
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.browser:browser:1.8.0")
}
```

- [ ] **Step 2: Update openBrowser to use Chrome Custom Tab**

In `android-lib/src/main/kotlin/com/strike48/pentest_connector/ConnectorBridge.kt`, replace the `openBrowser` method (lines 240-253):

```kotlin
private fun openBrowser(context: Context, paramsJson: String): String {
    val params = JSONObject(paramsJson)
    val url = params.getString("url")

    return try {
        val customTabsIntent = androidx.browser.customtabs.CustomTabsIntent.Builder()
            .setShowTitle(true)
            .build()
        customTabsIntent.launchUrl(context, Uri.parse(url))
        """{"success":true}"""
    } catch (e: Exception) {
        // Fallback to regular browser if Custom Tabs unavailable
        try {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url)).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            context.startActivity(intent)
            """{"success":true}"""
        } catch (e2: Exception) {
            """{"error":"Failed to open browser: ${e2.message?.replace("\"", "\\\"")}"}"""
        }
    }
}
```

- [ ] **Step 3: Build and verify**

Run: `just build-android 2>&1 | tail -10`
Expected: BUILD SUCCESSFUL (Gradle resolves the new dependency)

- [ ] **Step 4: Commit**

```bash
git add android-lib/build.gradle.kts android-lib/src/main/kotlin/com/strike48/pentest_connector/ConnectorBridge.kt
git commit -m "feat: upgrade Android browser opener to Chrome Custom Tab"
```

---

### Task 8: End-to-end test on emulator

**Files:** None (testing only)

- [ ] **Step 1: Build and install**

```bash
just build-android
adb install -r target/dx/pentest-mobile/debug/android/app/app/build/outputs/apk/debug/app-debug.apk
```

- [ ] **Step 2: Clear old settings and launch**

```bash
adb shell am force-stop com.strike48.pentest_connector
adb shell "rm -f /data/data/com.strike48.pentest_connector/files/.config/pentest-connector/settings.json"
adb shell am start -n com.strike48.pentest_connector/dev.dioxus.main.MainActivity
```

- [ ] **Step 3: Verify login screen appears**

Take screenshot: `adb exec-out screencap -p > /tmp/pick-login-screen.png`

Expected: Clean login screen with Strike48 logo, "Development" green badge, "Sign In" button. No host/tenant/token fields visible.

- [ ] **Step 4: Verify Advanced toggle works**

Tap "Advanced" → should reveal a single server host field pre-filled with placeholder `grpcs://connectors-studio.strike48.test`.

- [ ] **Step 5: Verify Sign In opens Chrome Custom Tab**

Tap "Sign In" → Chrome Custom Tab should open (in-app browser overlay, not full Chrome). Should navigate to `https://studio.strike48.test/auth/login?redirect=com.strike48.pentest://oauth/callback`.

- [ ] **Step 6: Verify gRPC connection uses correct host**

Check logs: `adb logcat -d --pid=$(adb shell pidof com.strike48.pentest_connector) | grep "ConnectorClient init"`

Expected: `connectors-studio.strike48.test:443 (transport: Grpc, TLS: true)`

- [ ] **Step 7: Verify TLS insecure is set from build defaults**

Check logs: `adb logcat -d --pid=$(adb shell pidof com.strike48.pentest_connector) | grep "INSECURE"`

Expected: `gRPC TLS certificate verification DISABLED (MATRIX_TLS_INSECURE=true)`

- [ ] **Step 8: Verify desktop still compiles**

Run: `cargo check --workspace --features pentest-platform/desktop-pcap`
Expected: compiles (uses prod defaults since no dev/prod feature specified)
