# Report Frontmatter — Emit, Strip, and Use in Pick

**Status:** Approved design, pending spec review
**Date:** 2026-07-25
**Source spec:** `/tmp/pick-report-frontmatter.md` (Pick/StrikeHub report frontmatter format)

## Goal

Adopt the report-document YAML frontmatter format end-to-end within the Pick
repo, across three coordinated pieces:

1. **Emit** — the easy-mode scan flow instructs the agent to prepend a YAML
   frontmatter block (scope/source/hosts/services/severity/findings, all
   optional) to the report it saves via `document_write`.
2. **Strip** — Pick's in-app markdown renderer detects and removes a leading
   frontmatter block so it never shows as literal `---` text in the report
   viewer.
3. **Use** — Pick parses the frontmatter and surfaces it in its OWN UI: the
   Reports list rows (scope, hosts/services, severity badge) and the Home
   resume card (scope + severity badge).

## Scope boundary

- **In scope (Pick repo):** the easy-mode scan prompt (`easy_mode_scan_prompt`),
  Pick's markdown renderer, a metadata parser, and Pick's Reports list + resume
  card rendering.
- **Out of scope:** the expert-pipeline **Report Agent** prompt — it lives
  server-side (Matrix), not in Pick (`agent_defaults.rs` only defines Pick's
  red-team/pentester persona + the easy scan prompt). Emitting frontmatter from
  the expert Report Agent is a separate Matrix-side change. The frontmatter
  feature targets the easy-mode console, whose reports come from
  `easy_mode_scan_prompt`, so this boundary is natural.
- The StrikeHub **web** console's dashboard (stat tiles, filterable table) is a
  separate app (the desktop template) — not built here. Pick renders its own
  console; this design enriches THAT.

## Architecture

### Piece 1 — Emit (crates/core/src/lib.rs: `easy_mode_scan_prompt`)

Extend the existing scan prompt's `document_write` instruction to require a YAML
frontmatter block at the very top of the document `content`, before the markdown
body. The added guidance (verbatim intent, wording may be tightened):

- Prepend a fenced YAML block: a `---` line, the YAML, a closing `---` line, then
  the markdown body. No blank line before the opening `---`.
- Fields (all optional): `scope` (subnet/target string), `source` (host that ran
  the scan), `hosts` (int), `services` (int), `severity` (map with
  `critical`/`high`/`medium`/`low`/`info` int counts), `findings` (list of
  `{severity, title, body}`, severity from the same vocabulary, keep to the
  material items ~<=8).
- `severity` counts and `findings` should agree where both present.
- Body stays normal markdown (GFM tables encouraged for host/service breakdowns).

The prompt keeps the existing "you MUST call document_write" requirement; the
frontmatter is additive.

### Piece 2 — Strip (crates/core/src/rendering.rs)

Add:

```rust
/// Split a leading YAML frontmatter block from markdown content.
/// Returns (Some(yaml_without_fences), body) when `content` starts with a
/// `---\n ... \n---` block, else (None, content). The opening `---` must be the
/// very first line (no leading blank lines), matching the frontmatter spec.
pub fn split_frontmatter(content: &str) -> (Option<&str>, &str);
```

`render_markdown_raw` (or its callers in `DocumentViewer`) uses
`split_frontmatter` and renders only the body. Behavior for content with no
frontmatter is byte-for-byte unchanged (returns `(None, content)`).

### Piece 3a — Parse (crates/core/src/matrix/ new module e.g. `report_meta.rs`)

```rust
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

impl ReportMeta {
    /// Parse from a document's full content. Returns Default (all-None) if
    /// there is no frontmatter or the YAML is malformed — never panics/errs
    /// (spec: console never crashes on bad frontmatter).
    pub fn parse(content: &str) -> ReportMeta;
    /// Highest non-zero severity bucket -> ("2 high"|"3 medium"|...|"clean").
    pub fn badge(&self) -> SeverityBadge;
    /// severity.critical > 0 || severity.high > 0.
    pub fn is_high_risk(&self) -> bool;
    /// findings.len(), else sum of severity counts.
    pub fn finding_count(&self) -> u32;
}
```

Parsing uses **serde_yml** (maintained serde_yaml fork), added to
`[workspace.dependencies]` and `crates/core/Cargo.toml`. `ReportMeta::parse`
calls `split_frontmatter`; if `Some(yaml)`, `serde_yml::from_str` with a
`.unwrap_or_default()` fallback so malformed YAML degrades to empty.

`SeverityBadge { label: String, kind: BadgeKind }` where `BadgeKind` is
`Critical|High|Medium|Low|Info|Clean` (drives color: crit/high=err,
medium=warn, low/info=muted, clean=ok).

### Piece 3b — Use in Pick UI (crates/ui/src/components/documents_panel.rs + easy_mode.rs)

**Reports list (`DocumentsPanel`):** for each listed document, fetch its content
(`get_document_content(conversation_id, document_id)`) and parse `ReportMeta`.
- Fetches are **capped** (only the first N=20 rows on screen) and run
  concurrently after the summary list loads; rows render immediately with
  title+date and fill in scope/counts/badge as metadata arrives (a
  `HashMap<doc_id, ReportMeta>` signal).
- Row shows: title, `scope` (if any), `"{hosts} hosts · {services} services"`
  (when both present), and the severity badge. Missing fields render nothing
  extra (graceful — no `—` noise beyond what the row already shows).
- Guard the N+1 cost: cap at 20, skip re-fetch for docs already in the map,
  `log()` nothing (silent, it's a view enhancement).

**Home resume card (`easy_mode.rs`):** the card already fetches/selects one
report; parse its `ReportMeta` and show `scope` + severity badge under the
title, replacing the plain "report attached" hint when metadata exists.

**Severity badge component/CSS:** a small `.easy-sev-badge` pill with modifier
classes per `BadgeKind`. Color mapping uses existing Sage tokens: critical/high
→ `--em-error` (#d99a9a); medium → `--warning` (#d9b07c, already defined in the
`.easy-mode` block); low/info → muted (`--em-text` at reduced opacity); clean →
`--em-toast-fg` (#8fc4ab, the sage "ok" color). No new base tokens needed;
badges use tinted backgrounds (`color-mix`) matching the template's `b-err`/
`b-warn` chips.

## Testing

- **`split_frontmatter`:** (a) content with frontmatter → yaml + body split
  correctly; (b) no frontmatter → `(None, content)`; (c) `---` not at start (blank
  line first) → `(None, content)`; (d) unterminated block → `(None, content)`;
  (e) `---` used as a markdown HR mid-body → not treated as frontmatter.
- **`ReportMeta::parse`:** full example from the source spec → all fields;
  minimal (`scope`+`source`+`severity.high`) → those set, rest None/empty;
  malformed YAML → `Default`; no frontmatter → `Default`.
- **`badge` / `is_high_risk` / `finding_count`:** `{high:2,medium:3}`→"2 high",
  high_risk true; `{medium:3}`→"3 medium", high_risk false; all-zero/absent→
  "clean"; finding_count from findings len, else severity sum.
- **`render_markdown_raw`/viewer:** frontmatter content renders body only (no
  literal `---`); no-frontmatter content unchanged.
- **Manual/visual:** run an easy-mode scan → report gains frontmatter → viewer
  clean → Reports list rows show scope+counts+badge → resume card shows badge.
- **Regression:** `cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings`
  and `cargo clippy -p pentest-core` clean; existing reports without frontmatter
  still render (title+date+body, no badge).

## Non-goals

- Expert Report Agent frontmatter (Matrix-side).
- StrikeHub web dashboard (separate app).
- Enforcing severity/findings agreement (spec says console doesn't enforce).
- Persisting parsed metadata (re-parsed from content on demand; the backend may
  later expose it in `list_documents` to remove the per-row fetch — a future
  optimization, noted).

## Risks / notes

- **N+1 fetch on the Reports list:** capped at 20 concurrent + memoized per
  doc_id. If it proves heavy, the fallback is resume-card-only parsing (already
  cheap) until the backend exposes metadata in the list. The cap must be
  surfaced (a "showing metadata for first 20" is overkill; instead just cap
  silently — rows beyond 20 show title+date, same as a legacy report).
- **serde_yml maintenance:** it is the maintained fork of the now-archived
  serde_yaml; acceptable. If a dep is undesirable, `ReportMeta::parse` is the
  only YAML boundary and could be swapped for a hand parser later.
- **Malformed frontmatter must never break rendering** — `parse` returns
  `Default` and `split_frontmatter` returns the body regardless, so a bad block
  degrades to "legacy report."
- `get_document_content` needs `conversation_id`; `DocumentSummary` carries it,
  so per-row fetch is possible.
