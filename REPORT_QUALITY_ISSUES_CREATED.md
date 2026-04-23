# Report Quality Issues - Created in GitHub

All 8 report quality issues from the backlog document have been successfully created in the Strike48-public/pick repository.

## Issues Created

| # | Issue | Priority | URL |
|---|---|---|---|
| #51 | Post-validation report re-synthesis | P0-critical | https://github.com/Strike48-public/pick/issues/51 |
| #52 | Tool provenance & reproducible probe commands | P0-critical | https://github.com/Strike48-public/pick/issues/52 |
| #53 | Attack chain classification (3-state) | P1-high | https://github.com/Strike48-public/pick/issues/53 |
| #54 | Per-finding probe method & live evidence in appendix | P1-high | https://github.com/Strike48-public/pick/issues/54 |
| #58 | Severity-change audit trail + Summary of Changes box | P1-high | https://github.com/Strike48-public/pick/issues/58 |
| #57 | Infrastructure profile synthesis section | P2-medium | https://github.com/Strike48-public/pick/issues/57 |
| #56 | Controls In Place section | P2-medium | https://github.com/Strike48-public/pick/issues/56 |
| #55 | Stable finding IDs across re-synthesis | P2-medium | https://github.com/Strike48-public/pick/issues/55 |

## Labels Created

The following new labels were created on the upstream repository:

- `area:report-agent` - Report generation and synthesis
- `area:orchestrator` - Orchestrator and pipeline logic
- `area:agent-schema` - Agent output schemas and contracts
- `area:recon-agent` - Reconnaissance agent
- `persona:pentester` - Senior pentester/red team persona
- `persona:ciso` - CISO/buying committee persona
- `quality` - Code/output quality improvement
- `credibility` - Affects report credibility with target audience

## Priority Mapping

Document priorities were mapped to upstream labels:

- P0 → `P0-critical` (existing label)
- P1 → `P1-high` (existing label)
- P2 → `P2-medium` (existing label)

## Dependencies

Key dependencies between issues:

1. **Issue #2 (Tool provenance)** is a dependency for:
   - Issue #4 (Per-finding probe method & evidence appendix)
   - Issue #7 (Controls In Place section - for evidence references)

2. **Issue #1 (Post-validation re-synthesis)** should be implemented before:
   - Issue #5 (Severity-change audit trail)

3. **Issue #8 (Stable finding IDs)** is a dependency for:
   - Issue #4 (Per-finding probe method & evidence appendix)

## Recommended Implementation Order

Based on priorities and dependencies:

1. **Phase 1 (P0 blockers):**
   - #51: Post-validation report re-synthesis
   - #52: Tool provenance & reproducible probe commands

2. **Phase 2 (P1 high priority):**
   - #53: Attack chain classification
   - #54: Per-finding probe method & evidence appendix (depends on #52)
   - #58: Severity-change audit trail (benefits from #51)

3. **Phase 3 (P2 enhancements):**
   - #57: Infrastructure profile synthesis
   - #56: Controls In Place section (depends on #52 for evidence refs)
   - #55: Stable finding IDs

## Next Steps

1. Review issues with the team
2. Assign issues to appropriate team members
3. Add to project milestones if applicable
4. Begin implementation starting with P0 issues

---

**Created:** 2026-04-16
**Source Document:** Report Quality Issue Backlog v2
