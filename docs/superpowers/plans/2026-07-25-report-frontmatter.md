# Report Frontmatter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Adopt report-document YAML frontmatter end-to-end in Pick: the easy-mode scan prompt tells the agent to emit it, Pick's renderer strips it, and Pick parses + surfaces the metadata (scope, hosts/services, severity badge) on the Reports list rows and the Home resume card.

**Architecture:** `split_frontmatter` in `rendering.rs` isolates the YAML; `ReportMeta` (in a new `crates/core/src/matrix/report_meta.rs`) deserializes it via `serde_yml` with graceful fallback to empty on any error; the DocumentViewer renders body-only; DocumentsPanel fetches each visible report's content (capped + memoized) to show per-row metadata; the easy-mode resume card parses the one report it already selects. The easy-mode scan prompt gains frontmatter authoring guidance.

**Tech Stack:** Rust, Dioxus 0.7, serde/serde_yml, CSS.

## Global Constraints

- Every frontmatter field is optional; malformed or absent frontmatter must NEVER break rendering or panic — it degrades to a legacy report (title + date + body). `ReportMeta::parse` returns `Default`; `split_frontmatter` returns the body regardless.
- Content with NO frontmatter renders byte-for-byte as today (renderer change is transparent for legacy docs).
- Severity vocabulary is exactly: `critical`, `high`, `medium`, `low`, `info` (lowercase).
- Derived values match the source spec: row badge = highest non-zero severity bucket ("2 high"/"3 medium"/.../"clean"); high-risk = critical>0 || high>0; finding count = findings.len() else sum of severity counts.
- Reports-list per-row content fetch is CAPPED at 20 and memoized per doc id (no re-fetch); rows render immediately with title+date and fill in metadata async. Rows beyond 20 stay title+date (same as legacy).
- Out of scope: expert Report Agent prompt (server-side/Matrix), StrikeHub web dashboard.
- `cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings` AND `cargo clippy -p pentest-core -- -D warnings` clean (run under `nix develop --command`).
- No Claude attribution, customer names, emojis, or em-dashes in commits. Conventional commits.

## Existing facts the implementer needs

- `render_markdown_raw(content: &str) -> String` is in `crates/core/src/rendering.rs` (uses pulldown-cmark). It is `pub`. The DocumentViewer calls it at `documents_panel.rs` ~line 277: `html.set(render_markdown_raw(&md));`.
- `MatrixChatClient::get_document_content(&self, conversation_id: &str, document_id: &str) -> Result<String>` returns the full markdown content.
- `DocumentSummary { id, title, doc_type, conversation_id, timestamp }` (all String) — carries `conversation_id`, so per-row content fetch is possible.
- `crates/core/src/matrix/mod.rs` declares submodules and re-exports; add `pub mod report_meta;` + a `pub use report_meta::{...};`.
- Workspace deps live in root `Cargo.toml` `[workspace.dependencies]` (~line 25); `serde`/`serde_json` are there. `crates/core/Cargo.toml` `[dependencies]` uses `serde = { workspace = true }`.
- `easy_mode_scan_prompt() -> String` is in `crates/core/src/lib.rs`.
- Sage color tokens available in the `.easy-mode` block of `crates/ui/src/styles/mobile.css`: `--em-error` (#d99a9a), `--warning` (#d9b07c), `--em-toast-fg` (#8fc4ab), `--em-text`, `--em-radius-pill`, `--font-mono`.
- DocumentsPanel row loop is at `documents_panel.rs` ~line 121 (`for doc in items { ... span.easy-docs-title ... }`). The resume card is in `easy_mode.rs` (the `if let Some(conv) = recent` block; it already computes `report: Option<DocumentSummary>`).

---

### Task 1: `serde_yml` dependency + `split_frontmatter`

**Files:**
- Modify: `Cargo.toml` (workspace deps), `crates/core/Cargo.toml`
- Modify: `crates/core/src/rendering.rs` (+ tests)

**Interfaces:**
- Produces: `pub fn split_frontmatter(content: &str) -> (Option<&str>, &str)` in `rendering.rs`.

- [ ] **Step 1: Write the failing test**

Add a `#[cfg(test)] mod frontmatter_tests` (or extend an existing test mod) in `rendering.rs`:

```rust
#[cfg(test)]
mod frontmatter_tests {
    use super::split_frontmatter;

    #[test]
    fn splits_leading_frontmatter() {
        let c = "---\nscope: \"x\"\n---\n# Body\ntext";
        let (fm, body) = split_frontmatter(c);
        assert_eq!(fm, Some("scope: \"x\""));
        assert_eq!(body, "# Body\ntext");
    }

    #[test]
    fn no_frontmatter_returns_content() {
        let c = "# Just markdown\ntext";
        let (fm, body) = split_frontmatter(c);
        assert_eq!(fm, None);
        assert_eq!(body, c);
    }

    #[test]
    fn hr_not_at_start_is_not_frontmatter() {
        let c = "intro\n---\nnot fm\n---\n";
        let (fm, body) = split_frontmatter(c);
        assert_eq!(fm, None);
        assert_eq!(body, c);
    }

    #[test]
    fn unterminated_block_is_not_frontmatter() {
        let c = "---\nscope: x\nno closing fence";
        let (fm, body) = split_frontmatter(c);
        assert_eq!(fm, None);
        assert_eq!(body, c);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-core split_frontmatter`
Expected: FAIL — `split_frontmatter` not found (won't compile).

- [ ] **Step 3: Implement `split_frontmatter`**

Add to `crates/core/src/rendering.rs`:

```rust
/// Split a leading YAML frontmatter block from markdown content.
///
/// Returns `(Some(yaml), body)` when `content` begins with a `---` line,
/// contains a later `---` line on its own, and thus forms a frontmatter block;
/// the returned `yaml` excludes both fence lines. Returns `(None, content)`
/// otherwise (no frontmatter, `---` not at the very start, or no closing fence).
/// The opening fence must be the first line — no leading blank lines — matching
/// the report frontmatter format.
pub fn split_frontmatter(content: &str) -> (Option<&str>, &str) {
    // Opening fence must be the very first line.
    let rest = match content.strip_prefix("---\n") {
        Some(r) => r,
        None => return (None, content),
    };
    // Find a closing fence line: "\n---\n" (block, body follows) or a trailing
    // "\n---" at end of input (empty body).
    if let Some(idx) = rest.find("\n---\n") {
        let yaml = &rest[..idx];
        let body = &rest[idx + "\n---\n".len()..];
        (Some(yaml.trim_matches('\n')), body)
    } else if let Some(yaml) = rest.strip_suffix("\n---") {
        (Some(yaml.trim_matches('\n')), "")
    } else {
        (None, content)
    }
}
```

(Note the tests: the yaml is trimmed of surrounding newlines; `Some("scope: \"x\"")` for the first test. Adjust the trim so the first test's expected `Some("scope: \"x\"")` holds — `rest[..idx]` for `"scope: \"x\""` has no surrounding newlines here, so trim is a no-op; keep `trim_matches('\n')` for robustness.)

- [ ] **Step 4: Add serde_yml dependency**

In root `Cargo.toml` under `[workspace.dependencies]` add:

```toml
serde_yml = "0.0.12"
```

In `crates/core/Cargo.toml` under `[dependencies]` add:

```toml
serde_yml = { workspace = true }
```

(This isn't used until Task 2, but adding it here keeps Task 2 focused. If `cargo` warns about an unused dependency, ignore — unused-crate is not a clippy `-D warnings` failure by default. Verify with Step 5.)

- [ ] **Step 5: Run test to verify it passes + clippy**

Run: `nix develop --command cargo test -p pentest-core split_frontmatter`
Expected: PASS (4 tests).
Run: `nix develop --command cargo clippy -p pentest-core -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/core/Cargo.toml crates/core/src/rendering.rs
git commit -m "feat(core): add split_frontmatter and serde_yml dependency"
```

---

### Task 2: `ReportMeta` parser + derived helpers

**Files:**
- Create: `crates/core/src/matrix/report_meta.rs`
- Modify: `crates/core/src/matrix/mod.rs` (declare + re-export)

**Interfaces:**
- Consumes: `split_frontmatter` (Task 1), `serde_yml`.
- Produces: `ReportMeta`, `SeverityCounts`, `ReportFinding`, `SeverityBadge`, `BadgeKind`, and `ReportMeta::{parse, badge, is_high_risk, finding_count}`.

- [ ] **Step 1: Write the failing test**

Create `crates/core/src/matrix/report_meta.rs` with the types + tests below (tests first is fine to write alongside the impl in the same file; run to confirm behavior):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const FULL: &str = "---\nscope: \"192.168.1.0/24\"\nsource: \"mbp\"\nhosts: 8\nservices: 21\nseverity:\n  high: 2\n  medium: 3\n  low: 1\nfindings:\n  - severity: high\n    title: \"PG exposed\"\n    body: \"fix it\"\n---\n# Body\n";

    #[test]
    fn parses_full_frontmatter() {
        let m = ReportMeta::parse(FULL);
        assert_eq!(m.scope.as_deref(), Some("192.168.1.0/24"));
        assert_eq!(m.source.as_deref(), Some("mbp"));
        assert_eq!(m.hosts, Some(8));
        assert_eq!(m.services, Some(21));
        assert_eq!(m.severity.high, Some(2));
        assert_eq!(m.findings.len(), 1);
    }

    #[test]
    fn no_frontmatter_is_default() {
        let m = ReportMeta::parse("# just markdown");
        assert!(m.scope.is_none() && m.hosts.is_none() && m.findings.is_empty());
    }

    #[test]
    fn malformed_yaml_is_default() {
        let m = ReportMeta::parse("---\n: : : not yaml\n\t- broken\n---\nbody");
        assert!(m.scope.is_none() && m.findings.is_empty());
    }

    #[test]
    fn badge_picks_highest_bucket() {
        let m = ReportMeta::parse("---\nseverity:\n  high: 2\n  medium: 3\n---\nx");
        let b = m.badge();
        assert_eq!(b.label, "2 high");
        assert!(matches!(b.kind, BadgeKind::High));
        assert!(m.is_high_risk());
    }

    #[test]
    fn badge_clean_when_no_severity() {
        let m = ReportMeta::parse("---\nscope: x\n---\ny");
        assert_eq!(m.badge().label, "clean");
        assert!(matches!(m.badge().kind, BadgeKind::Clean));
        assert!(!m.is_high_risk());
    }

    #[test]
    fn finding_count_prefers_findings_then_severity_sum() {
        let with_findings = ReportMeta::parse("---\nseverity:\n  high: 5\nfindings:\n  - title: a\n  - title: b\n---\nx");
        assert_eq!(with_findings.finding_count(), 2);
        let sev_only = ReportMeta::parse("---\nseverity:\n  high: 2\n  low: 1\n---\nx");
        assert_eq!(sev_only.finding_count(), 3);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-core report_meta`
Expected: FAIL — types not defined (won't compile).

- [ ] **Step 3: Implement the module**

Full `report_meta.rs` (above the test mod):

```rust
//! Parser for the optional YAML frontmatter Pick's easy-mode reports carry.
//! Every field is optional and malformed input degrades to `Default` — the
//! renderer/UI must never break on a bad or absent block.

use serde::Deserialize;

use crate::rendering::split_frontmatter;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct SeverityCounts {
    pub critical: Option<u32>,
    pub high: Option<u32>,
    pub medium: Option<u32>,
    pub low: Option<u32>,
    pub info: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReportFinding {
    pub severity: Option<String>,
    pub title: Option<String>,
    pub body: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ReportMeta {
    pub title: Option<String>,
    pub scope: Option<String>,
    pub source: Option<String>,
    pub hosts: Option<u32>,
    pub services: Option<u32>,
    #[serde(default)]
    pub severity: SeverityCounts,
    #[serde(default)]
    pub findings: Vec<ReportFinding>,
}

/// Which color bucket a report's severity badge falls into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadgeKind {
    Critical,
    High,
    Medium,
    Low,
    Info,
    Clean,
}

/// A rendered severity badge: a short label and its color bucket.
#[derive(Debug, Clone)]
pub struct SeverityBadge {
    pub label: String,
    pub kind: BadgeKind,
}

impl ReportMeta {
    /// Parse from a document's full markdown content. Returns `Default`
    /// (all-None/empty) when there is no frontmatter or the YAML is malformed.
    pub fn parse(content: &str) -> ReportMeta {
        match split_frontmatter(content) {
            (Some(yaml), _) => serde_yml::from_str(yaml).unwrap_or_default(),
            (None, _) => ReportMeta::default(),
        }
    }

    /// Highest non-zero severity bucket as a badge, or "clean" when none.
    pub fn badge(&self) -> SeverityBadge {
        let s = &self.severity;
        // critical folds into "high"-red per the spec badge colors, but keep a
        // distinct kind so callers could style it; label uses the bucket name.
        for (n, kind, name) in [
            (s.critical, BadgeKind::Critical, "critical"),
            (s.high, BadgeKind::High, "high"),
            (s.medium, BadgeKind::Medium, "medium"),
            (s.low, BadgeKind::Low, "low"),
            (s.info, BadgeKind::Info, "info"),
        ] {
            if let Some(count) = n {
                if count > 0 {
                    return SeverityBadge { label: format!("{count} {name}"), kind };
                }
            }
        }
        SeverityBadge { label: "clean".to_string(), kind: BadgeKind::Clean }
    }

    /// True when the report has any critical or high findings.
    pub fn is_high_risk(&self) -> bool {
        self.severity.critical.unwrap_or(0) > 0 || self.severity.high.unwrap_or(0) > 0
    }

    /// Number of findings: `findings.len()` when present, else the sum of the
    /// severity counts.
    pub fn finding_count(&self) -> u32 {
        if !self.findings.is_empty() {
            return self.findings.len() as u32;
        }
        let s = &self.severity;
        s.critical.unwrap_or(0)
            + s.high.unwrap_or(0)
            + s.medium.unwrap_or(0)
            + s.low.unwrap_or(0)
            + s.info.unwrap_or(0)
    }
}
```

In `crates/core/src/matrix/mod.rs`, add `pub mod report_meta;` with the other module decls and:

```rust
pub use report_meta::{BadgeKind, ReportFinding, ReportMeta, SeverityBadge, SeverityCounts};
```

- [ ] **Step 4: Run test to verify it passes + clippy**

Run: `nix develop --command cargo test -p pentest-core report_meta`
Expected: PASS (6 tests).
Run: `nix develop --command cargo clippy -p pentest-core -- -D warnings`
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/matrix/report_meta.rs crates/core/src/matrix/mod.rs
git commit -m "feat(core): parse report frontmatter into ReportMeta"
```

---

### Task 3: Strip frontmatter in the DocumentViewer

**Files:**
- Modify: `crates/ui/src/components/documents_panel.rs`

**Interfaces:**
- Consumes: `split_frontmatter` (Task 1), `render_markdown_raw`.

- [ ] **Step 1: Render body-only in the viewer**

In `DocumentViewer`'s fetch effect (`documents_panel.rs` ~line 277), change:

```rust
html.set(render_markdown_raw(&md));
```

to strip the frontmatter first:

```rust
let (_fm, body) = pentest_core::rendering::split_frontmatter(&md);
html.set(render_markdown_raw(body));
```

(Import path: `split_frontmatter` is `pub` in `pentest_core::rendering`. Use the full path or add a `use`.)

- [ ] **Step 2: Verify compilation + clippy**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add crates/ui/src/components/documents_panel.rs
git commit -m "fix(ui): strip report frontmatter before rendering the viewer body"
```

---

### Task 4: Severity badge CSS (CSS-only)

**Files:**
- Modify: `crates/ui/src/styles/mobile.css`

**Interfaces:**
- Produces: `.easy-sev-badge` + `.sev-err`/`.sev-warn`/`.sev-muted`/`.sev-ok` CSS classes, consumed by Task 5's rendering. (The `sev_badge_class` Rust helper lands in Task 5, alongside its first use, to avoid an unused-fn `-D warnings` failure.)

- [ ] **Step 1: Add the CSS**

Append to `crates/ui/src/styles/mobile.css` (after the `.easy-docs-*` rules):

```css
/* Report severity badge (parsed from frontmatter). Tinted pill matching the
   template's b-err / b-warn chips; colors from Sage tokens. */
.easy-sev-badge {
    display: inline-flex;
    align-items: center;
    height: 22px;
    padding: 0 9px;
    border-radius: var(--em-radius-pill);
    font-family: var(--font-mono);
    font-size: 11px;
    font-weight: 600;
    white-space: nowrap;
}
.easy-sev-badge.sev-err {
    background: color-mix(in srgb, var(--em-error) 18%, transparent);
    color: var(--em-error);
}
.easy-sev-badge.sev-warn {
    background: color-mix(in srgb, var(--warning) 18%, transparent);
    color: var(--warning);
}
.easy-sev-badge.sev-muted {
    background: color-mix(in srgb, var(--em-text) 10%, transparent);
    color: var(--em-text);
    opacity: 0.75;
}
.easy-sev-badge.sev-ok {
    background: color-mix(in srgb, var(--em-toast-fg) 16%, transparent);
    color: var(--em-toast-fg);
}
```

- [ ] **Step 2: Verify build (CSS is include_str!'d)**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: clean (CSS-only change; no Rust yet).

- [ ] **Step 3: Commit**

```bash
git add crates/ui/src/styles/mobile.css
git commit -m "style(ui): severity badge pill for report metadata"
```

---

### Task 5: Reports list + resume card metadata rendering

**Files:**
- Modify: `crates/ui/src/components/documents_panel.rs` (per-row meta fetch + row render + `sev_badge_class` helper)
- Modify: `crates/ui/src/components/easy_mode.rs` (resume card badge)

**Interfaces:**
- Consumes: `ReportMeta` (Task 2), `sev_badge_class` (add here per Task 4 note), `get_document_content`, `docs` list.

- [ ] **Step 1: Add the `sev_badge_class` helper**

Add at module level in `documents_panel.rs`, and import the types:

```rust
use pentest_core::matrix::{BadgeKind, ReportMeta};

/// Map a severity badge bucket to its CSS modifier class. `pub(crate)` so the
/// easy-mode resume card can reuse it.
pub(crate) fn sev_badge_class(kind: BadgeKind) -> &'static str {
    match kind {
        BadgeKind::Critical | BadgeKind::High => "sev-err",
        BadgeKind::Medium => "sev-warn",
        BadgeKind::Low | BadgeKind::Info => "sev-muted",
        BadgeKind::Clean => "sev-ok",
    }
}
```

- [ ] **Step 2: Add a per-doc metadata map + capped fetch in DocumentsPanel**

In `DocumentsPanel`, after the `docs` signal, add:

```rust
// Parsed frontmatter per document id (filled async after the summary list
// loads; capped so a large report set doesn't fan out unbounded).
let mut meta_map = use_signal(std::collections::HashMap::<String, ReportMeta>::new);
```

Add an effect that, whenever `docs` changes, fetches content for up to 20 docs not already in `meta_map` and parses `ReportMeta`:

```rust
{
    let api_url = api_url.clone();
    let auth_token = auth_token.clone();
    use_effect(move || {
        let list = docs();
        if auth_token.is_empty() || api_url.is_empty() {
            return;
        }
        for doc in list.into_iter().take(20) {
            if meta_map.peek().contains_key(&doc.id) {
                continue;
            }
            let api_url = api_url.clone();
            let auth_token = auth_token.clone();
            spawn(async move {
                let client = MatrixChatClient::new(api_url).with_auth_token(auth_token);
                if let Ok(content) =
                    client.get_document_content(&doc.conversation_id, &doc.id).await
                {
                    meta_map.write().insert(doc.id.clone(), ReportMeta::parse(&content));
                }
            });
        }
    });
}
```

- [ ] **Step 3: Render metadata in each row**

In the `for doc in items` loop (~line 121), read the parsed meta and render scope / counts / badge when present:

```rust
for doc in items {
    {
        let title = doc.title.clone();
        let open_doc = doc.clone();
        let meta = meta_map.read().get(&doc.id).cloned();
        rsx! {
            div {
                class: "easy-docs-row easy-docs-row-tappable",
                onclick: move |_| props.on_open.call(open_doc.clone()),
                div { class: "easy-docs-row-main",
                    span { class: "easy-docs-title", "{title}" }
                    if let Some(m) = meta.as_ref() {
                        div { class: "easy-docs-meta",
                            if let Some(scope) = m.scope.as_ref() {
                                span { class: "easy-docs-scope", "{scope}" }
                            }
                            if let (Some(h), Some(s)) = (m.hosts, m.services) {
                                span { class: "easy-docs-counts", "{h} hosts · {s} services" }
                            }
                        }
                    }
                }
                if let Some(m) = meta.as_ref() {
                    {
                        let b = m.badge();
                        rsx! {
                            span { class: "easy-sev-badge {sev_badge_class(b.kind)}", "{b.label}" }
                        }
                    }
                }
                span { class: "easy-docs-chevron", "›" }
            }
        }
    }
}
```

Add minimal layout CSS for the new row sub-elements to `mobile.css` (in this task's commit): `.easy-docs-row-main { display:flex; flex-direction:column; gap:2px; flex:1; min-width:0; }`, `.easy-docs-meta { display:flex; gap:8px; font-size:12px; color:var(--em-text); opacity:0.6; }`, `.easy-docs-scope`/`.easy-docs-counts { white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }`. Ensure `.easy-docs-row` is `display:flex; align-items:center; gap:10px;` (check existing rule; extend, don't duplicate).

- [ ] **Step 4: Resume card badge in easy_mode.rs**

In the resume card block (`easy_mode.rs`, the `if let Some(conv) = recent` region), the code already selects `report: Option<DocumentSummary>`. When a report exists, fetch+parse its content to show a badge. Since the card already knows `report.conversation_id`/`report.id`, add a small `use_effect`/state or reuse: simplest is a `meta: Signal<Option<ReportMeta>>` fetched when `report` changes:

```rust
// (near the resume-card state, once) parse the selected report's frontmatter
// for a severity badge; None until it loads or when there is no report.
```

Given the card is rendered inside a match/closure, add a `report_meta` signal at the component top level (next to `docs`) and an effect keyed on the selected report id that fetches `get_document_content` + `ReportMeta::parse`. Then in the card, when `report_meta()` is `Some(m)`, render `span.easy-sev-badge` (using the same `sev_badge_class` — re-export or duplicate the tiny mapping in `easy_mode.rs`, or make `sev_badge_class` `pub(crate)` in `documents_panel.rs` and import it). Prefer making `sev_badge_class` `pub(crate)` and importing it into `easy_mode.rs`.

Keep the existing `resume_sub_line` text; the badge is additive (shown alongside, e.g. to the right of the sub line).

- [ ] **Step 5: Verify compilation + clippy**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add crates/ui/src/components/documents_panel.rs crates/ui/src/components/easy_mode.rs crates/ui/src/styles/mobile.css
git commit -m "feat(easy-mode): show report metadata (scope, counts, severity) in Reports list and resume card"
```

---

### Task 6: Teach the easy-mode scan prompt to emit frontmatter

**Files:**
- Modify: `crates/core/src/lib.rs` (`easy_mode_scan_prompt`)

**Interfaces:**
- Consumes: nothing new; edits the prompt string.

- [ ] **Step 1: Update existing prompt test (if any) then extend the prompt**

Check for an existing test asserting the prompt content (`scan_prompt_requires_document_write` in `easy_mode.rs` asserts the prompt requires `document_write`). It must still pass. Add a new assertion in that test (or a core-side test in `lib.rs`) that the prompt mentions frontmatter:

```rust
// in crates/core/src/lib.rs tests (add a #[cfg(test)] mod if none)
#[test]
fn scan_prompt_requests_frontmatter() {
    let p = crate::easy_mode_scan_prompt();
    assert!(p.contains("frontmatter"));
    assert!(p.contains("scope"));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `nix develop --command cargo test -p pentest-core scan_prompt_requests_frontmatter`
Expected: FAIL (prompt doesn't mention frontmatter yet).

- [ ] **Step 3: Extend `easy_mode_scan_prompt`**

Append to the `document_write` guidance in the prompt string (keep the existing "you MUST call document_write" text intact). Add a paragraph like:

```
At the very top of the document content, before the markdown body, include a \
YAML frontmatter block fenced with lines of three dashes (---). Put optional \
metadata there so the app can render a richer report card: \
scope (the subnet or target you scanned, e.g. \"10.10.0.0/24\"), \
source (this device's hostname), hosts (integer count that responded), \
services (integer count enumerated), severity (a map with integer counts for \
any of critical/high/medium/low/info), and findings (a short list, ideally 8 \
or fewer, of items each with severity, title, and a one-to-two sentence body). \
Use those exact lowercase severity words. Every field is optional — include \
what you know. After the closing --- line, write the normal Markdown summary \
(GFM tables are great for host/service breakdowns).
```

(Match the existing string's escaping/continuation style. Keep it one coherent addition to the returned string.)

- [ ] **Step 4: Run to verify it passes**

Run: `nix develop --command cargo test -p pentest-core scan_prompt`
Expected: PASS (both the existing document_write assertion and the new frontmatter one).

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/lib.rs
git commit -m "feat(easy-mode): instruct the scan agent to emit report frontmatter"
```

---

### Task 7: Verification

**Files:** none.

- [ ] **Step 1: Full clippy (both crates)**

Run: `nix develop --command cargo clippy -p pentest-core -- -D warnings`
Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
Expected: both clean.

- [ ] **Step 2: Full test run for the feature**

Run: `nix develop --command cargo test -p pentest-core split_frontmatter report_meta scan_prompt`
Expected: all pass (4 + 6 + prompt tests).

- [ ] **Step 3: Legacy-safety check**

Confirm `split_frontmatter("# no fm\nbody")` path: a report with no frontmatter still renders (covered by unit test `no_frontmatter_returns_content` + `no_frontmatter_is_default`). No manual step needed beyond confirming those pass.

- [ ] **Step 4: Commit (if any fixups)**

```bash
git add -A && git commit -m "test(report-frontmatter): verify parse, strip, and legacy safety"
```

(Skip if nothing changed.)

---

## Notes for the implementer

- `serde_yml` deserializes `Option<u32>` and `Vec<T>` with `#[serde(default)]` cleanly; unknown/extra YAML keys are ignored by default (good — forward-compatible).
- The Reports-list per-row fetch is the only real cost: cap 20, memoize by id, render title+date immediately. Do NOT block the list on metadata.
- All Dioxus signals (`docs`, `meta_map`, `report_meta`) are `Copy`; re-`let` inside spawned closures if the borrow checker complains.
- Keep `resume_sub_line` and the scan telemetry/prompt-send behavior unchanged; the badge and frontmatter guidance are additive.
- Never let a bad frontmatter block break rendering — `parse` and `split_frontmatter` both degrade to body/Default.
