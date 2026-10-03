# Label Schema

Canonical labels for this repo. Every issue carries **exactly one** label from each of the four required families (`product/`, `type/`, `priority/`, `size/`). The other families below are optional but encouraged wherever they apply. Priority and size live on labels, not board fields.

Every one of the repo's 77 labels (as of 2026-10-01, `gh label list --limit 300`) is classified below as Required, Optional, or Outside the schema.

## Required - exactly one of each

| Family | Values |
|---|---|
| `product/` | `product/pick` (Pick open-source connector) · `product/strikekit` (StrikeKit enterprise platform) · `product/matrix` (Matrix protocol integration) |
| `type/` | `type/bug` · `type/feature` · `type/enhancement` · `type/epic` · `type/docs` · `type/chore` · `type/refactor` · `type/research` · `type/technical-debt` · `type/test` |
| `priority/` | `priority/P0` (critical) · `priority/P1` · `priority/P2` · `priority/P3` · `priority/P4` (deferred) |
| `size/` | `size/XS` · `size/S` · `size/M` · `size/L` · `size/XL` |

### Size guide

| Size | Meaning |
|---|---|
| `XS` | one-liner / config tweak |
| `S` | localized single-module fix, <= 1 day |
| `M` | feature or fix spanning 2 modules with tests, 1-3 days |
| `L` | cross-cutting or multi-module feature, ~1 week |
| `XL` | epic / multi-week |

## Optional - encouraged where they apply

Not required and not checked by the label guard, but add them whenever they fit; they drive board slicing and search.

- `area/*`: `area/frontend`, `area/orchestrator`, `area/recon-agent`, `area/report-agent`, `area/infrastructure`, `area/database`, `area/agent-schema`, `area/integration`, `area/c2`
- `feature/*`: `feature/security`, `feature/evidence-chains`, `feature/pick-integration`, `feature/ai-foundation`, `feature/autopwn`, `feature/post-exploit`, `feature/knowledge-graph`
- `source/*`: `source/clearwing`, `source/specialist-gap`
- `platform/*`: `platform/macos`, `platform/windows`, `platform/android`, `platform/linux-desktop`, `platform/linux-headless`
- `mvp/strike-kit`, `persona/ciso`, `persona/pentester`

`status/triage` and `status/backlog` are **matrix-only** (canonical schema: `status_matrix_only`) and do not exist in this repo.

## Outside the schema

These labels exist in the repo but are not part of the schema. Do not add the legacy ones to new issues; existing issues may still carry them until they are relabeled.

- **Legacy, use the namespaced form instead:** `bug` (use `type/bug`), `enhancement` (use `type/enhancement` or `type/feature`), `documentation` (use `type/docs`), `security` (use `feature/security`), `quality` (use `type/technical-debt` or `type/refactor`)
- **Legacy, no replacement:** `type/roadmap` (not in the canonical `type/` list; the label guard flags it), `credibility`, `team/integration`, `team/pick-integration`, `milestone/60-day-mvp`, `milestone/competitive-parity`, `milestone/xbow-mastery`, `milestone/enterprise-polish`, `roadmap/phase-1`, `roadmap/phase-2`, `roadmap/phase-3`
- **Legacy status:** `status/in-progress`, `status/needs-review`, `status/needs-testing`, `status/blocked`, `status/needs-design`. They predate the schema; board status lives on Project 42, not labels.
- **PR-only:** `build-apk` gates the Android artifact steps in `.github/workflows/ci.yml`; apply it to pull requests, never to issues.
- **GitHub defaults, allowed for triage outcomes:** `duplicate`, `invalid`, `question`, `wontfix`, `good first issue`, `help wanted`. They do not replace any required family.

## Rules

1. **Never use bare legacy labels** (see Outside the schema) - always the namespaced form. The same applies to `epic` and `status_triage`, which exist on other Strike48 boards but not in this repo.
2. **Epics** get `type/epic` + `size/XL`; never stack a second type on an epic. Track children as native sub-issues.
3. **The label is the source of truth for priority.** If the issue body states a different priority than its label, the label wins - fix the body, not the label.
4. Issues on [Project 42 (Strike Kit slice)](https://github.com/orgs/Strike48/projects/42) should be fully labeled at triage: product, type, priority, size, plus area/feature where they apply.

## Global issue types

In addition to labels, the org-wide standard is that every issue carries a GitHub **issue type**: `Bug`, `Feature`, `Epic`, `Task`, `Spike`, `Initiative`, `Infrastructure` / `Compliance`. The type is a coarse roll-up that mirrors the `type/*` label (see the repo caveats below for what applies here today):

| `type/*` label (source of truth) | Global issue type |
|---|---|
| `type/bug` | `Bug` |
| `type/feature`, `type/enhancement` | `Feature` |
| `type/epic` | `Epic` |
| `type/research` | `Spike` |
| `type/docs`, `type/chore`, `type/refactor`, `type/test`, `type/technical-debt` | `Task` |
| initiative records (`[INIT]` in project-management) | `Initiative` |

The issue type does not replace any label: `product/*`, `priority/*` and `size/*` stay required, and `area/*` and `feature/*` stay optional, because none of them has a global-type equivalent. Keep the type in sync when the `type/*` label changes.

Two repo caveats (verified 2026-10-01 with `gh api orgs/Strike48-public/issue-types`):

1. **Only `Bug`, `Feature` and `Task` exist here.** The Strike48-public org defines no other type, so the API rejects the rest. Every issue must carry the type its `type/*` label maps to when that type is `Bug`, `Feature` or `Task`. Issues labeled `type/epic` (maps to `Epic`) or `type/research` (maps to `Spike`) stay untyped until those types exist.
2. **Nothing sets the type automatically here.** The issue forms under `.github/ISSUE_TEMPLATE/` (added in pick#480) apply labels but do not set an issue type, so set the type manually when filing (`gh issue create --type` or the type picker) - do not assume template auto-selection.
