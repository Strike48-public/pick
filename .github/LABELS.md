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
- `status/triage`, `status/backlog` (slash spelling only)
- `mvp/strike-kit`, `persona/ciso`, `persona/pentester`
- pick only: `source/clearwing`, `source/specialist-gap`, `platform/macos`, `platform/windows`, `platform/android`, `platform/linux-desktop`, `platform/linux-headless`

## Rules

1. **Never use bare legacy labels** (`bug`, `enhancement`, `epic`, `documentation`, `status_triage`) - always the namespaced form.
2. **Epics** get `type/epic` + `size/XL`; never stack a second type on an epic. Track children as native sub-issues.
3. **The label is the source of truth for priority.** If the issue body states a different priority than its label, the label wins - fix the body, not the label.
4. Issues on [Project 42 (Strike Kit slice)](https://github.com/orgs/Strike48/projects/42) should be fully labeled at triage: product, type, priority, size, plus area/feature as applicable.
