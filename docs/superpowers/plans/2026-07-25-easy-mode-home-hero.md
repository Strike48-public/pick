# Easy Mode Home Hero + Resume Card Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the easy-mode empty-state "Scan My Network" tile with a template-style Home: a hero (badge + headline + subtitle + big scan pill) plus a "Pick up where you left off" card backed by the real most-recent conversation and its latest report, and a Reports count badge on the drawer.

**Architecture:** All UI in `crates/ui/src/components/easy_mode.rs` + a pure helper; styles in `crates/ui/src/styles/mobile.css`. No core/backend change. Recent conversation comes from the already-present `chat_header_ctx.conversations`; the latest report comes from `MatrixChatClient::list_documents` (same call `DocumentsPanel` uses), fetched in a `use_future` and reused for the drawer Reports count.

**Tech Stack:** Rust, Dioxus 0.7, CSS.

## Global Constraints

- Zero fabricated data. The "Last scan" stats card is OUT (no connector-side findings/host store). Only ship the hero + resume card + Reports badge.
- Keep the scan action's telemetry (`Activity::ScanStart`, `channel=easy`, `source=easy_mode_button`) and prompt (`easy_mode_scan_prompt()`) byte-identical — scan analytics and server-side agent behavior must not change.
- `format_relative_time(iso)` ALREADY returns a string ending in "ago" (e.g. `"1h ago"`, or `"now"`, or `"—"` on parse failure). Do NOT append another "ago".
- Home (hero + card) shows only when `!conversation_active() && matches!(flow(), AuthFlow::Connected { .. })` — same guard as today's scan tile. Once a conversation is active, chat takes over (no Home).
- The resume card renders only when a recent conversation exists; otherwise hero-only. `chat_header_ctx` is `None` until ChatPanel mounts — treat None/empty as "no card".
- `cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings` clean (run under `nix develop --command`). Expert mode unchanged.
- No Claude attribution, customer names, emojis, or em-dashes in commits. Conventional commits.

## Existing facts the implementer needs

- `easy_mode.rs` already imports: `Network`, `STRIKE48_S_BADGE_SVG`, `FileText` (from `super::icons`), `DocumentSummary` (from `pentest_core::matrix`), `ChatHeaderCtx` (from `super::chat_panel`), `save_settings`/`load_settings`.
- `chat_header_ctx: Signal<Option<ChatHeaderCtx>>` is in scope. `ChatHeaderCtx` has `conversations: Vec<ConversationInfo>`, `on_select_conversation: EventHandler<String>`, `on_new_chat: EventHandler<()>`. Conversations are already newest-first.
- `ConversationInfo { id: String, title: String, summary: Option<String>, updated_at: String }`.
- `DocumentSummary { id, title, doc_type, conversation_id: String, timestamp: String }`.
- Opening a report = `viewing.set(Some(doc))` (an existing `Signal<Option<DocumentSummary>>` in the component; the viewer overlay is already wired).
- Opening a conversation = `chat_header_ctx.peek().as_ref().map(|c| c.on_select_conversation.call(id))`.
- Client for documents: `MatrixChatClient::new(api_url).with_auth_token(token).list_documents(agent_id.as_deref()).await` returns `Result<Vec<DocumentSummary>>`.
- `agent_id: Signal<Option<String>>` and `auth_token: Signal<String>` and `props.api_url` are in scope.
- The block to REPLACE is the current scan tile (search for `class: "action-grid"` containing the `action-card` with `"Scan My Network"`), guarded by `if !conversation_active() && matches!(flow(), crate::auth_flow::AuthFlow::Connected { .. })`.

---

### Task 1: Pure helper for the resume-card sub-line

**Files:**
- Modify: `crates/ui/src/components/easy_mode.rs` (add a module-level `fn` + a `#[cfg(test)] mod` test)

**Interfaces:**
- Produces: `fn resume_sub_line(relative: &str, has_report: bool) -> String` — used by the resume card in Task 3.

- [ ] **Step 1: Write the failing test**

Add near the bottom of `easy_mode.rs` (there is already a `#[cfg(test)] mod tests` with `scan_prompt_requires_document_write` — add these to it; if the module import differs, use `use super::*;`):

```rust
#[test]
fn resume_sub_line_with_report() {
    assert_eq!(resume_sub_line("1h ago", true), "1h ago · report attached");
}

#[test]
fn resume_sub_line_without_report() {
    assert_eq!(resume_sub_line("3d ago", false), "3d ago");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-ui --features "desktop,connector" --lib resume_sub_line`
Expected: FAIL — `resume_sub_line` not found (won't compile).

- [ ] **Step 3: Implement the helper**

Add at module level in `easy_mode.rs` (near `easy_mode_scan_prompt`):

```rust
/// Build the resume-card sub-line. `relative` is an already-formatted
/// relative time (e.g. "1h ago") from `format_relative_time`, so we do NOT
/// append another "ago". Adds a report affordance hint when one exists.
fn resume_sub_line(relative: &str, has_report: bool) -> String {
    if has_report {
        format!("{relative} · report attached")
    } else {
        relative.to_string()
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo test -p pentest-ui --features "desktop,connector" --lib resume_sub_line`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add crates/ui/src/components/easy_mode.rs
git commit -m "feat(easy-mode): add resume-card sub-line helper"
```

---

### Task 2: Home hero + resume card + Reports badge (fetch + render together)

**Files:**
- Modify: `crates/ui/src/components/easy_mode.rs`

**Interfaces:**
- Consumes: `props.api_url`, `auth_token`/`agent_id`/`chat_header_ctx`/`viewing`/`chat_mailbox` signals, `MatrixChatClient::list_documents`, `resume_sub_line` (Task 1), `format_relative_time`.
- Produces: the Home region (hero + resume card) and the drawer Reports badge.

This task adds the `docs` fetch AND its two readers (resume card + Reports badge) in ONE commit, so the `docs` signal is never left unused (which `-D warnings` rejects).

- [ ] **Step 1: Add the relative-time import**

Ensure this `use` is present (add if missing):

```rust
use super::chat_panel::format_relative_time;
```

- [ ] **Step 2: Add the docs signal + fetch effect**

In `EasyModeShell`, near the other signals (after `let conversation_id = ...`), add:

```rust
// Reports for the current agent — powers the Home resume card's "Open report"
// affordance and the drawer Reports count. Same source as DocumentsPanel;
// fetched here so the Home screen has it without opening the reports overlay.
let mut docs = use_signal(Vec::<DocumentSummary>::new);
```

Then add a fetch effect after the `auth_token` watch `use_future` (mirrors `DocumentsPanel`):

```rust
{
    let api_url = props.api_url.clone();
    use_effect(move || {
        let api_url = api_url.clone();
        let token = auth_token();
        let aid = agent_id();
        if token.is_empty() || api_url.is_empty() {
            return;
        }
        spawn(async move {
            let client = pentest_core::matrix::MatrixChatClient::new(api_url)
                .with_auth_token(token);
            if let Ok(mut list) = client.list_documents(aid.as_deref()).await {
                // Newest first (timestamp is ISO-8601, lexical sort works).
                list.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
                docs.set(list);
            }
        });
    });
}
```

(`agent_id` and `auth_token` are `Copy` signals; the effect re-runs when they change because it reads them.)

- [ ] **Step 3: Replace the scan-tile block with the Home region**

Find the current block (guarded by `if !conversation_active() && matches!(flow(), crate::auth_flow::AuthFlow::Connected { .. })`) that renders `div { class: "action-grid", div { class: "action-card", ... "Scan My Network" } }`. Replace the ENTIRE `if` body with:

```rust
if !conversation_active() && matches!(flow(), crate::auth_flow::AuthFlow::Connected { .. }) {
    div { class: "easy-home",
        div { class: "easy-home-hero",
            span { class: "easy-hero-badge", dangerous_inner_html: STRIKE48_S_BADGE_SVG }
            h1 { class: "easy-hero-title", "What's on your network?" }
            p { class: "easy-hero-sub",
                "One click enumerates every live host, its open services, and the risk they carry."
            }
            button {
                class: "easy-hero-scan",
                onclick: move |_| {
                    pentest_core::telemetry::record(
                        pentest_core::telemetry::Activity::ScanStart,
                        &[("channel", "easy"), ("source", "easy_mode_button")],
                    );
                    chat_mailbox.set(Some(easy_mode_scan_prompt()));
                },
                span { class: "easy-hero-scan-icon", Network { size: 21 } }
                "Scan My Network"
            }
        }
        // Resume card — only when a recent conversation exists.
        {
            let recent = chat_header_ctx
                .read()
                .as_ref()
                .and_then(|c| c.conversations.first().cloned());
            if let Some(conv) = recent {
                let title = if conv.title.trim().is_empty() {
                    "Untitled chat".to_string()
                } else {
                    conv.title.clone()
                };
                let relative = format_relative_time(&conv.updated_at);
                // Latest report for THIS conversation, if any.
                let report = docs
                    .read()
                    .iter()
                    .find(|d| d.conversation_id == conv.id)
                    .cloned();
                let sub = resume_sub_line(&relative, report.is_some());
                let conv_id = conv.id.clone();
                rsx! {
                    div { class: "easy-home-cards",
                        div { class: "easy-home-card",
                            div { class: "easy-card-eye", "Pick up where you left off" }
                            div { class: "easy-home-card-title", "{title}" }
                            div { class: "easy-home-card-sub", "{sub}" }
                            if let Some(doc) = report {
                                button {
                                    class: "easy-home-card-btn",
                                    onclick: move |_| viewing.set(Some(doc.clone())),
                                    "Open report"
                                }
                            } else {
                                button {
                                    class: "easy-home-card-btn",
                                    onclick: move |_| {
                                        if let Some(c) = chat_header_ctx.peek().as_ref() {
                                            c.on_select_conversation.call(conv_id.clone());
                                        }
                                    },
                                    "Resume chat"
                                }
                            }
                        }
                    }
                }
            } else {
                rsx! {}
            }
        }
    }
}
```

(`viewing` and `chat_mailbox` are mutable signals already in scope; if the borrow checker complains that `viewing`/`chat_mailbox` are moved into two closures, remember Signals are `Copy` — re-`let` them inside each closure if needed, e.g. `let mut viewing = viewing;`.)

- [ ] **Step 4: Add the Reports count badge to the drawer**

Find the drawer Reports item (search `"Reports"` with `FileText` icon in the drawer `easy-drawer-item` list). Add a count tag when `docs` is non-empty. Locate the Reports `div { class: "easy-drawer-item", ... span { ... "Reports" } }` and append, after the label span:

```rust
{
    let n = docs.read().len();
    if n > 0 {
        rsx! { span { class: "easy-drawer-badge", "{n}" } }
    } else {
        rsx! {}
    }
}
```

- [ ] **Step 5: Verify compilation + clippy**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: clean (the readers consume `docs`, so no unused warning).

- [ ] **Step 6: Commit**

```bash
git add crates/ui/src/components/easy_mode.rs
git commit -m "feat(easy-mode): template-style Home hero, resume card, Reports badge"
```

---

### Task 3: Style the Home hero + resume card + drawer badge

**Files:**
- Modify: `crates/ui/src/styles/mobile.css`

**Interfaces:**
- Consumes: existing `--em-*` tokens (`--em-brand`, `--em-on-primary`/`--em-on-scan`, `--em-scan-bg`, `--em-surface`, `--em-text`, `--em-border`, `--em-radius-card`, `--em-radius-pill`, `--font-mono`, `--em-space-*`) defined in the `.easy-mode` block.

- [ ] **Step 1: Add the CSS**

Append to `crates/ui/src/styles/mobile.css` (after the existing `.easy-*` rules). Use the Sage tokens already defined for `.easy-mode`:

```css
/* Easy Mode Home — hero + contextual cards (template Home screen). */
.easy-home {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 24px;
    width: 100%;
    max-width: 660px;
    margin: 0 auto;
    padding: 48px 20px 24px;
}
.easy-home-hero {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 18px;
    text-align: center;
    width: 100%;
}
.easy-hero-badge {
    width: 54px;
    height: 54px;
    border-radius: 15px;
    background: var(--em-brand);
    color: var(--em-on-primary);
    display: grid;
    place-items: center;
}
.easy-hero-badge svg {
    width: 32px;
    height: 32px;
}
.easy-hero-title {
    font-size: 28px;
    font-weight: 700;
    color: var(--em-text);
    margin: 0;
}
.easy-hero-sub {
    font-size: 14px;
    color: var(--em-text);
    opacity: 0.7;
    line-height: 1.5;
    text-wrap: pretty;
    margin: 0;
    max-width: 46ch;
}
.easy-hero-scan {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    width: 100%;
    height: 62px;
    border: none;
    border-radius: 999px;
    background: var(--em-scan-bg);
    color: var(--em-on-scan);
    font-size: 17px;
    font-weight: 600;
    cursor: pointer;
    transition: filter 0.15s;
}
.easy-hero-scan:hover {
    filter: brightness(1.06);
}
.easy-hero-scan-icon {
    display: inline-flex;
    align-items: center;
}
.easy-home-cards {
    display: grid;
    grid-template-columns: 1fr;
    gap: 12px;
    width: 100%;
}
.easy-home-card {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 16px 18px;
    background: var(--em-surface);
    border: 1px solid var(--em-border);
    border-radius: var(--em-radius-card);
}
.easy-card-eye {
    font-family: var(--font-mono);
    font-size: 10.5px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--em-text);
    opacity: 0.5;
    margin-bottom: 5px;
}
.easy-home-card-title {
    font-size: 14px;
    font-weight: 600;
    color: var(--em-text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
}
.easy-home-card-sub {
    font-size: 12px;
    color: var(--em-text);
    opacity: 0.6;
}
.easy-home-card-btn {
    align-self: flex-start;
    margin-top: 10px;
    height: 32px;
    padding: 0 16px;
    border-radius: var(--em-radius-pill);
    border: 1px solid var(--em-border-strong);
    background: transparent;
    color: var(--em-text);
    font-size: 12.5px;
    font-weight: 600;
    cursor: pointer;
    transition: background-color 0.15s;
}
.easy-home-card-btn:hover {
    background: var(--em-surface-soft);
}
/* Drawer Reports count tag. */
.easy-drawer-badge {
    margin-left: auto;
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--em-on-primary);
    background: var(--em-brand);
    border-radius: var(--em-radius-pill);
    padding: 1px 8px;
}
```

VERIFY these token names exist in the `.easy-mode` block of `mobile.css` before using them (grep `--em-border-strong`, `--em-surface-soft`, `--em-scan-bg`, `--em-on-scan`, `--em-radius-card`, `--em-radius-pill`). If any is missing, substitute the closest existing token (e.g. `--em-border` for `--em-border-strong`) rather than inventing one.

- [ ] **Step 2: Verify token names**

Run: `nix develop --command bash -c "grep -oE '\-\-em-[a-z-]+' crates/ui/src/styles/mobile.css | sort -u"`
Confirm every `var(--em-*)` used above appears. Fix substitutions as noted.

- [ ] **Step 3: Clippy (CSS is include_str!'d; just confirm build)**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/ui/src/styles/mobile.css
git commit -m "style(easy-mode): Home hero, resume card, and drawer Reports badge"
```

---

### Task 4: Verification

**Files:** none (verification only)

- [ ] **Step 1: Full clippy**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: clean.

- [ ] **Step 2: Unit tests**

Run: `nix develop --command cargo test -p pentest-ui --features "desktop,connector" --lib resume_sub_line`
Expected: 2 pass. Also run the existing easy-mode test: `nix develop --command cargo test -p pentest-ui --features "desktop,connector" --lib scan_prompt` (should still pass).

- [ ] **Step 3: Confirm the scan tile is gone and hero replaced it**

Run: `grep -n "action-grid\|easy-home-hero\|Scan My Network" crates/ui/src/components/easy_mode.rs`
Expected: no `action-grid` in the Home region (the drawer/sign-in `action-card` uses, if any, are separate); `easy-home-hero` present; "Scan My Network" now inside `.easy-hero-scan`.

---

## Notes for the implementer

- Do not touch the sign-in `action-card` (the "Sign in" button in the sign-in overlay) — only the Home/empty-state scan tile is replaced.
- `viewing`, `chat_mailbox`, `docs`, `agent_id`, `auth_token` are all `Copy` Dioxus signals; re-`let` them inside `move` closures if the borrow checker complains about capture.
- The hero must render even when `docs`/conversations are empty (hero-only); the card is conditional.
- Keep expert mode and the ChatPanel untouched.
