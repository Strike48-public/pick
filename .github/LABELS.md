# Label Schema

Canonical labels for this repo. Every issue carries **exactly one** label from each required family, plus any optional families that apply. Priority and size live on labels, not board fields.

## Required - exactly one of each

| Family | Values |
|---|---|
| `product/` | `product/pick` (this repo) · `product/strikekit` (StrikeKit work in matrix) · `product/matrix` (platform work outside the Strike Kit slice) |
| `type/` | `type/bug` · `type/feature` · `type/enhancement` · `type/epic` · `type/docs` · `type/chore` · `type/refactor` · `type/research` · `type/technical-debt` · `type/test` |
| `priority/` | `priority/P0` (critical) → `priority/P4` (deferred) |
| `size/` | `size/XS` · `size/S` · `size/M` · `size/L` · `size/XL` |

### Size guide

| Size | Meaning |
|---|---|
| `XS` | one-liner / config tweak |
| `S` | localized single-module fix, ~1 day or less |
| `M` | feature or fix spanning 2 modules with tests, 1-3 days |
| `L` | cross-cutting or multi-module feature, ~1 week |
| `XL` | epic / multi-week |

## Optional

- `area/*`: `frontend`, `orchestrator`, `recon-agent`, `report-agent`, `infrastructure`, `database`, `agent-schema`, `integration`, `c2`
- `feature/*`: `security`, `evidence-chains`, `pick-integration`, `ai-foundation`, `autopwn`, `post-exploit`, `knowledge-graph`
- `mvp/strike-kit`, `persona/ciso`, `persona/pentester`
- pick only: `source/clearwing`, `source/specialist-gap`, `platform/macos`, `platform/windows`, `platform/android`, `platform/linux-desktop`, `platform/linux-headless`
- `status/triage` and `status/backlog` are **matrix-only** (canonical schema: `status_matrix_only`) - do not apply them in this repo. The five legacy `status/*` labels this repo already carries (`status/in-progress`, `status/needs-review`, `status/needs-testing`, `status/blocked`, `status/needs-design`) predate the schema; treat them as deprecated and do not add them to new issues.

## Rules

1. **Never use bare legacy labels** (`bug`, `enhancement`, `epic`, `documentation`, `status_triage`) - always the namespaced form.
2. **Epics** get `type/epic` + `size/XL`; never stack a second type on an epic. Track children as native sub-issues.
3. **The label is the source of truth for priority.** If the issue body states a different priority than its label, the label wins - fix the body, not the label.
4. Issues on [Project 42 (Strike Kit slice)](https://github.com/orgs/Strike48/projects/42) should be fully labeled at triage: product, type, priority, size, plus area/feature as applicable.
## Global issue types (org standard - required)

In addition to labels, every issue must carry a GitHub **issue type** (org-wide standard): `Bug`, `Feature`, `Epic`, `Task`, `Spike`, `Initiative`, `Infrastructure` / `Compliance`. The type is a coarse roll-up that mirrors the `type/*` label:

| `type/*` label (source of truth) | Global issue type |
|---|---|
| `type/bug` | `Bug` |
| `type/feature`, `type/enhancement` | `Feature` |
| `type/epic` | `Epic` |
| `type/research` | `Spike` |
| `type/docs`, `type/chore`, `type/refactor`, `type/test`, `type/technical-debt` | `Task` |
| initiative records (`[INIT]` in project-management) | `Initiative` |

Labels remain mandatory: `product/*`, `priority/*`, `size/*`, `area/*`, and `feature/*` have no global-type equivalent. Keep the type in sync when the `type/*` label changes.

Two repo caveats (verified 2026-09-24):

1. **This repo enables only `Bug`, `Feature` and `Task`.** Every other type is rejected by the API until enabled in repo Settings → General → Issues. Pick epics carry the `type/epic` label until `Epic` is enabled.
2. **Nothing sets the type automatically here.** This repo has no issue templates (see pick#480, still open), so set the type manually when filing (`gh issue create --type` or the type picker) - do not assume template auto-selection.