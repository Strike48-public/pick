# Easy Mode — Phase 1 (Shell + Scan + Chat) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a simplified "Easy Mode" app shell to Pick — one screen with a network-scan button and a full-page chat — enabled by default on mobile, with no backend dependency.

**Architecture:** Add an `easy_mode` flag to `ConnectorAppConfig`. When set, the shared `connector_app()` renders a new `EasyModeShell` (scan action-card + reused `ChatPanel { full_page: true }`) instead of the standard `AppLayout` + `ConnectorPages`. The scan button seeds a canned prompt into the existing chat mailbox; the server-side agent runs Pick's existing scan tools. No new scan code, no new chat backend, no `matrix_share`/#1390 dependency (that is Phase 2).

**Tech Stack:** Rust (stable ≥1.92 via the nix devshell), Dioxus 0.7. Build/test through `nix develop --command …`.

## Global Constraints

- Rust toolchain and all builds run inside the nix devshell: prefix commands with `nix develop --command …`.
- Conventional commit messages. **No** Claude attribution lines, emojis, or em-dashes (CLAUDE.md).
- `cargo clippy --all-targets -- -D warnings` must pass (CI treats warnings as errors).
- `ConnectorAppConfig` is a `#[derive(Clone, Copy)]` struct of `'static`/`Copy` fields; adding a field requires updating **every** construction site (there are exactly three: `apps/mobile/src/main.rs`, `apps/desktop/src/main.rs`, `apps/web/src/main.rs`).
- Reuse existing components and CSS (`ChatPanel`, `.action-card` / `.dashboard-card` in `crates/ui/src/styles/mobile.css`). Do not build new subsystems.
- Phase 1 must not change behavior when `easy_mode == false` (desktop/web unaffected).

## File Structure

- **Modify** `crates/ui/src/connector_app.rs` — add `easy_mode: bool` to `ConnectorAppConfig`; branch the `AppScreen::Connected` render on `cfg.easy_mode`.
- **Create** `crates/ui/src/components/easy_mode.rs` — `easy_mode_scan_prompt()` pure fn + `EasyModeShell` component.
- **Modify** `crates/ui/src/components/mod.rs` — declare the module and re-export `EasyModeShell`.
- **Modify** `apps/mobile/src/main.rs`, `apps/desktop/src/main.rs`, `apps/web/src/main.rs` — add the `easy_mode` field to each config literal.

---

### Task 1: Add `easy_mode` to `ConnectorAppConfig` and update all construction sites

**Files:**
- Modify: `crates/ui/src/connector_app.rs:38-58` (struct)
- Modify: `apps/mobile/src/main.rs:8-18`
- Modify: `apps/desktop/src/main.rs:10-20`
- Modify: `apps/web/src/main.rs` (WEB_CONFIG literal)

**Interfaces:**
- Produces: `ConnectorAppConfig.easy_mode: bool` — read by `connector_app()` in Task 4.

- [ ] **Step 1: Add the field to the struct**

In `crates/ui/src/connector_app.rs`, add to `ConnectorAppConfig` (after `set_sandbox`):

```rust
    /// Optional sandbox toggle. Desktop/Web pass `pentest_platform::set_use_sandbox`.
    pub set_sandbox: Option<fn(bool)>,
    /// When true, render the simplified "Easy Mode" shell (scan + chat) instead
    /// of the full dashboard/sidebar UI. Default target is mobile.
    pub easy_mode: bool,
}
```

- [ ] **Step 2: Set the field at all three construction sites**

`apps/mobile/src/main.rs` — add `easy_mode: true,` to `MOBILE_CONFIG` (after `set_sandbox: None,`):

```rust
    create_tools: pentest_tools::create_tool_registry,
    set_sandbox: None,
    easy_mode: true,
};
```

`apps/desktop/src/main.rs` — add `easy_mode: false,` to `DESKTOP_CONFIG` (after `set_sandbox: Some(...)`):

```rust
    create_tools: pentest_tools::create_tool_registry,
    set_sandbox: Some(pentest_platform::set_use_sandbox),
    easy_mode: false,
};
```

`apps/web/src/main.rs` — add `easy_mode: false,` to `WEB_CONFIG` in the same position (after the last existing field, before the closing `};`).

- [ ] **Step 3: Confirm there are no other construction sites**

Run: `grep -rn "ConnectorAppConfig {" apps crates | grep -v "pub struct"`
Expected: exactly the three lines in `apps/web/src/main.rs`, `apps/desktop/src/main.rs`, `apps/mobile/src/main.rs`. If any other site appears, add `easy_mode: false,` there too.

- [ ] **Step 4: Verify it compiles**

Run: `nix develop --command cargo check -p pentest-desktop -p pentest-mobile`
Expected: `Finished` with no errors. (A missing-field error here means a construction site was missed in Step 2/3.)

- [ ] **Step 5: Commit**

```bash
git add crates/ui/src/connector_app.rs apps/mobile/src/main.rs apps/desktop/src/main.rs apps/web/src/main.rs
git commit -m "feat(easy-mode): add easy_mode flag to ConnectorAppConfig"
```

---

### Task 2: Scan seed-prompt (pure function + unit test)

**Files:**
- Create: `crates/ui/src/components/easy_mode.rs`
- Modify: `crates/ui/src/components/mod.rs`

**Interfaces:**
- Produces: `pub fn easy_mode_scan_prompt() -> String` — used by `EasyModeShell` in Task 3.

- [ ] **Step 1: Create the module file with the failing test**

Create `crates/ui/src/components/easy_mode.rs`:

```rust
//! Easy Mode — a simplified shell (network scan + chat) for non-expert users.

/// The canned chat message the Easy Mode "Scan" button sends. It instructs the
/// server-side agent to enumerate local interfaces, scan the local subnet, and
/// write a report document of the findings. Kept as one place so the wording is
/// consistent and testable.
pub fn easy_mode_scan_prompt() -> String {
    "Discover the devices on my local network: enumerate my network interfaces, \
     scan the local subnet for reachable hosts and their open services, then write \
     a clear report document summarizing what you found."
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_prompt_mentions_network_and_report_document() {
        let p = easy_mode_scan_prompt().to_lowercase();
        assert!(p.contains("network"), "prompt should mention the network: {p}");
        assert!(
            p.contains("report document"),
            "prompt must ask the agent to write a report document: {p}"
        );
    }
}
```

- [ ] **Step 2: Declare the module so the test is compiled**

In `crates/ui/src/components/mod.rs`, add the module declaration (alongside the other `mod`/`pub mod` lines) and a re-export:

```rust
pub mod easy_mode;
pub use easy_mode::{easy_mode_scan_prompt, EasyModeShell};
```

(The `EasyModeShell` re-export will fail to resolve until Task 3 — do the module `pub mod easy_mode;` line now and add the `pub use` line in Task 3 Step 2. For this task, add only `pub mod easy_mode;`.)

- [ ] **Step 3: Run the test to verify it fails to compile / fails**

Run: `nix develop --command cargo test -p pentest-ui --features desktop,connector easy_mode::tests::scan_prompt_mentions_network_and_report_document`
Expected: PASS (this is a pure function with the assertion already satisfiable). If it fails, adjust the prompt wording so it contains both "network" and "report document".

- [ ] **Step 4: Commit**

```bash
git add crates/ui/src/components/easy_mode.rs crates/ui/src/components/mod.rs
git commit -m "feat(easy-mode): add scan seed-prompt builder"
```

---

### Task 3: `EasyModeShell` component

**Files:**
- Modify: `crates/ui/src/components/easy_mode.rs`
- Modify: `crates/ui/src/components/mod.rs`

**Interfaces:**
- Consumes: `easy_mode_scan_prompt()` (Task 2); `ChatPanel` / `ChatPanelProps` from `crate::components::chat_panel`.
- Produces: `EasyModeShell` component with props `api_url: String`, `auth_token: String`, `tenant_id: String`, `chat_mailbox: Signal<Option<String>>`, `conversation_mailbox: Signal<Option<String>>`. Used by `connector_app()` in Task 4.

- [ ] **Step 1: Add the component to `easy_mode.rs`**

Prepend the imports and append the component (keep the `easy_mode_scan_prompt` fn and its tests):

```rust
use dioxus::prelude::*;

use crate::components::icons::Network;
use crate::components::ChatPanel;

/// Props for [`EasyModeShell`]. Mirrors the inputs the standard chat path uses.
#[derive(Props, Clone, PartialEq)]
pub struct EasyModeShellProps {
    pub api_url: String,
    pub auth_token: String,
    pub tenant_id: String,
    /// Shared mailbox: writing Some(msg) makes the chat auto-send it.
    pub chat_mailbox: Signal<Option<String>>,
    /// Mailbox to open a specific conversation by ID.
    pub conversation_mailbox: Signal<Option<String>>,
}

/// The simplified Easy Mode screen: a scan action card above a full-page chat.
#[component]
pub fn EasyModeShell(props: EasyModeShellProps) -> Element {
    let mut chat_mailbox = props.chat_mailbox;
    rsx! {
        div { class: "easy-mode",
            div { class: "action-grid",
                div {
                    class: "action-card",
                    onclick: move |_| chat_mailbox.set(Some(easy_mode_scan_prompt())),
                    span { class: "action-card-icon", Network { size: 24 } }
                    span { class: "action-card-label", "Scan My Network" }
                }
            }
            div { class: "easy-mode-chat",
                ChatPanel {
                    visible: true,
                    api_url: props.api_url.clone(),
                    auth_token: props.auth_token.clone(),
                    tenant_id: props.tenant_id.clone(),
                    on_close: move |_| {},
                    send_mailbox: props.chat_mailbox,
                    full_page: true,
                    open_conversation_id: props.conversation_mailbox,
                }
            }
        }
    }
}
```

Note: `Network` is the icon used by the existing Dashboard "Network Scan" card (`crates/ui/src/components/dashboard.rs`). If the import path differs, mirror the `use crate::components::icons::…` line from `dashboard.rs`.

- [ ] **Step 2: Add the `EasyModeShell` re-export**

In `crates/ui/src/components/mod.rs`, ensure the re-export line is present:

```rust
pub use easy_mode::{easy_mode_scan_prompt, EasyModeShell};
```

- [ ] **Step 3: Verify it compiles and clippy is clean**

Run: `nix develop --command cargo clippy -p pentest-ui --features desktop,connector,shell-ws -- -D warnings`
Expected: `Finished` with no warnings/errors.

- [ ] **Step 4: Commit**

```bash
git add crates/ui/src/components/easy_mode.rs crates/ui/src/components/mod.rs
git commit -m "feat(easy-mode): add EasyModeShell (scan card + full-page chat)"
```

---

### Task 4: Render `EasyModeShell` from `connector_app()` when `easy_mode`

**Files:**
- Modify: `crates/ui/src/connector_app.rs:714-…` (the `AppScreen::Connected(page)` arm)

**Interfaces:**
- Consumes: `ConnectorAppConfig.easy_mode` (Task 1); `EasyModeShell` (Task 3). In-scope values in the Connected arm: `chat_api_url: String`, `matrix_auth_token: Signal<String>`, `config: Signal<ConnectorConfig>` (has `tenant_id`), `chat_mailbox: Signal<Option<String>>`, `conversation_mailbox: Signal<Option<String>>`.

- [ ] **Step 1: Wrap the existing Connected render in an `if cfg.easy_mode` branch**

In `crates/ui/src/connector_app.rs`, inside `AppScreen::Connected(page) => { … }`, after `chat_api_url` is computed (it is defined at ~line 725-750) and before the existing `let page_subtitle = …;`, insert an early return for easy mode:

```rust
                    if cfg.easy_mode {
                        return rsx! {
                            EasyModeShell {
                                api_url: chat_api_url.clone(),
                                auth_token: matrix_auth_token.read().clone(),
                                tenant_id: config.read().tenant_id.clone(),
                                chat_mailbox,
                                conversation_mailbox,
                            }
                        };
                    }
```

Note: this arm returns `rsx! { … }` (an `Element`), so `return rsx! { … };` matches the arm's type. Leave the entire existing `AppLayout { … ConnectorPages { … } }` block below untouched — it runs only when `easy_mode == false`.

- [ ] **Step 2: Import `EasyModeShell` in `connector_app.rs`**

Add `EasyModeShell` to the `use crate::components::{…}` list at the top of `crates/ui/src/connector_app.rs` (the block importing `AppLayout, ChatPanel, …`).

- [ ] **Step 3: Verify it compiles and clippy is clean**

Run: `nix develop --command cargo clippy -p pentest-desktop -p pentest-mobile --features pentest-ui/shell-ws -- -D warnings`
Expected: `Finished`, no warnings. If `--features` errors for the binary crates, fall back to `nix develop --command cargo clippy --workspace -- -D warnings`.

- [ ] **Step 4: Visually verify Easy Mode (desktop, fast loop)**

Temporarily flip `apps/desktop/src/main.rs` `DESKTOP_CONFIG.easy_mode` to `true`, then run:
`nix develop --command cargo run -p pentest-desktop`
Expected: after connecting, the window shows the "Scan My Network" card above a full-page chat (no sidebar/dashboard). Click the card → the scan prompt is sent in chat. Then revert `DESKTOP_CONFIG.easy_mode` back to `false`.

- [ ] **Step 5: Verify standard mode is unchanged**

With `DESKTOP_CONFIG.easy_mode = false` (reverted), run `nix develop --command cargo run -p pentest-desktop` again.
Expected: the normal dashboard + sidebar UI renders exactly as before.

- [ ] **Step 6: Commit**

```bash
git add crates/ui/src/connector_app.rs
git commit -m "feat(easy-mode): render EasyModeShell when config.easy_mode is set"
```

---

### Task 5: Easy-mode layout polish (CSS)

**Files:**
- Modify: `crates/ui/src/styles/mobile.css`

**Interfaces:**
- Consumes: the `.easy-mode`, `.easy-mode-chat` classes emitted by `EasyModeShell` (Task 3).

- [ ] **Step 1: Add minimal layout CSS**

Append to `crates/ui/src/styles/mobile.css`:

```css
/* Easy Mode: full-height column — scan card on top, chat fills the rest. */
.easy-mode {
    display: flex;
    flex-direction: column;
    height: 100%;
    min-height: 0;
}
.easy-mode .action-grid {
    padding: 12px;
    flex: 0 0 auto;
}
.easy-mode-chat {
    flex: 1 1 auto;
    min-height: 0;
    display: flex;
}
```

- [ ] **Step 2: Visually verify on mobile**

Run: `nix develop --command just build-android`
Then install/launch per the project run flow (`just run-android` with a device/emulator attached) and confirm the scan card sits above a chat that fills the screen, styled with the existing `.action-card` look.
Expected: a single clean screen; card tap sends the scan prompt.

- [ ] **Step 3: Commit**

```bash
git add crates/ui/src/styles/mobile.css
git commit -m "feat(easy-mode): full-height scan-card-over-chat layout"
```

---

## Self-Review

**Spec coverage (Phase 1 scope of `2026-07-18-easy-mode-design.md`):**
- §4.1 shell / `easy_mode` on `ConnectorAppConfig` / default true on mobile → Tasks 1, 4, 5. ✓
- §4.2 one-button scan via seed prompt (reusing existing tools/agent) → Tasks 2, 3. ✓
- §4.3 standalone chat via `ChatPanel { full_page: true }`, expert actions hidden → Task 3 (full_page already suppresses the header actions). ✓
- §6 platform coverage: mobile default (Task 1), desktop/web unaffected when false (Task 4 Step 5). ✓
- **Deferred (documented, not in this plan):** §4.1 runtime desktop/web settings toggle, and the entire §4.4 documents + share pillar → Phase 2 plan (gated on #1390 + risks R1/R2/R4).

**Placeholder scan:** No TBD/TODO; every code step shows complete code; commands have expected output. ✓

**Type consistency:** `easy_mode_scan_prompt() -> String` (Task 2) is consumed unchanged in Task 3; `EasyModeShellProps` fields (`api_url`, `auth_token`, `tenant_id`, `chat_mailbox`, `conversation_mailbox`) match the invocation in Task 4; `ChatPanel` props match the existing invocation copied from `workspace_app.rs:169`. ✓

## Notes for the implementer

- Dioxus components are not unit-testable for rendering here; UI verification is visual via the run steps (this mirrors how the rest of `crates/ui` is validated). The only pure unit test is the seed-prompt (Task 2).
- If `cargo test`/`clippy` feature flags differ from those shown, discover them from `crates/ui/Cargo.toml` `[features]` — the desktop app builds `pentest-ui` with `connector, shell-ws` and `pentest-platform/desktop-all`.
