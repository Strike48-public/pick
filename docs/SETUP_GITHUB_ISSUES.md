# Setup GitHub Issues - 60 Day MVP

Complete guide to setting up all GitHub issues with proper labels for the 60-day MVP roadmap.

## Prerequisites

- GitHub CLI (`gh`) installed and authenticated
- Access to Strike48/strikekit repository
- Bash shell

## Step-by-Step Setup

### 1. Create Labels

First, create all the label categories in the StrikeKit repository:

```bash
cd /home/jtomek/Code/pick/docs
./create-labels.sh
```

This creates:
- **Type labels**: feature, enhancement, bug, refactor, docs, test, chore
- **Priority labels**: P0 (critical), P1 (high), P2 (medium), P3 (low), P4 (backlog)
- **Feature labels**: evidence-chains, rag, ai-planning, integrations
- **Size labels**: XS (<1d), S (1-2d), M (3-5d), L (1-2w), XL (>2w)
- **Status labels**: blocked, in-progress, needs-review, needs-testing

### 2. Update Issue #94 (Already Created)

Issue #94 has already been created and updated with:
- Title changed: "Design and Implement Evidence Chain Database Schema" (Team prefix removed)
- Labels need to be added:

```bash
cd /home/jtomek/Code/strikekit
gh issue edit 94 --add-label "type: feature,priority: P1,feature: evidence-chains,size: M"
```

### 3. Create All Remaining Issues

Run the script to create all 20 remaining issues:

```bash
cd /home/jtomek/Code/pick/docs
./create-all-issues.sh
```

This will create:
- 5 Team A issues (Evidence Chains)
- 4 Team B issues (RAG)
- 4 Team C issues (AI Planning)
- 4 Team D issues (Integrations)
- 3 Cross-team issues (Integration, Docs, Demo)

All issues will be created with proper labels automatically.

### 4. Verify Issues

Check that all issues were created correctly:

```bash
cd /home/jtomek/Code/strikekit
gh issue list --limit 25
```

Expected output: Issues #94-#113 (21 total issues)

### 5. (Optional) Bulk Label Update

If you need to update labels after creation, use the helper script:

```bash
cd /home/jtomek/Code/pick/docs
# Edit add-labels-to-issues.sh to match actual issue numbers
./add-labels-to-issues.sh
```

## Label System Reference

### Type Labels

| Label | Description | Usage |
|-------|-------------|-------|
| `type: feature` | New feature or capability | New functionality being added |
| `type: enhancement` | Enhancement to existing feature | Improvements to existing code |
| `type: bug` | Bug or defect | Fixing broken functionality |
| `type: refactor` | Code refactoring | Restructuring code without changing behavior |
| `type: docs` | Documentation changes | Writing or updating documentation |
| `type: test` | Test additions or updates | Adding or improving tests |
| `type: chore` | Maintenance or tooling | Build, CI/CD, tooling updates |

### Priority Labels

| Label | Description | SLA |
|-------|-------------|-----|
| `priority: P0` | Critical - Immediate attention | Same day |
| `priority: P1` | High - Important | This week |
| `priority: P2` | Medium - Normal priority | This sprint |
| `priority: P3` | Low - Nice to have | Backlog |
| `priority: P4` | Backlog - Future consideration | No timeline |

### Feature Labels

| Label | Focus Area |
|-------|------------|
| `feature: evidence-chains` | Evidence chain infrastructure, knowledge graph |
| `feature: rag` | RAG knowledge base, Qdrant, ExploitDB |
| `feature: ai-planning` | AI planning, Reflector agent, LLM integration |
| `feature: integrations` | Nessus, reports, manual target workflows |

### Size Labels

| Label | Time Estimate | Description |
|-------|---------------|-------------|
| `size: XS` | < 1 day | Very small task |
| `size: S` | 1-2 days | Small task |
| `size: M` | 3-5 days | Medium task |
| `size: L` | 1-2 weeks | Large task |
| `size: XL` | > 2 weeks | Extra large task (consider breaking down) |

## Issue Dependencies

Some issues depend on others being completed first:

**Critical Path** (blocks other work):
1. Issue #94 (Evidence Chain Schema) → Issue A2 (Tracking API) → Issue A3 (Confidence) → Issue A4 (Knowledge Graph UI)

**RAG Path**:
1. Issue B1 (Qdrant Setup) → Issue B2 (PATT Ingestion) → Issue B3 (Semantic Search) → Issue B4 (Optimization)

**AI Planning Path**:
1. Issue C1 (Reflector Agent) + Issue B3 (Semantic Search) → Issue C2 (AI Task Generation) → Issue C3 (Replanning)

**Integrations Path**:
1. Issue D1 (Nessus Parser) → Issue D2 (Nessus Import Workflow)
2. Issue C2 (AI Task Generation) → Issue D4 (Manual Target Workflow)

## Troubleshooting

### Labels Not Found

If you get "label not found" errors, run `create-labels.sh` first.

### Wrong Issue Numbers

If issue numbers don't match expected sequence, edit `add-labels-to-issues.sh` and update the issue number variables at the top.

### Permission Denied

Ensure you have write access to the Strike48/strikekit repository:

```bash
gh auth status
gh repo view Strike48/strikekit
```

## Next Steps

After creating all issues:

1. **Assign team members** to issues
2. **Set up project board** (optional) for better visualization
3. **Review dependencies** and adjust priorities if needed
4. **Kick off Week 1** on Monday, April 7

## Files Reference

- `create-labels.sh` - Creates all label categories
- `create-all-issues.sh` - Creates all 20 issues with proper labels
- `add-labels-to-issues.sh` - Bulk update labels (if needed)
- `ISSUE_LABELS_MAPPING.md` - Complete label mapping reference
- `ISSUE_REPO_MAPPING.md` - Which issues go to which repo
- `GITHUB_ISSUES_60DAY_MVP.md` - Full issue descriptions (source)
- `60_DAY_MVP_ROADMAP.md` - Weekly milestone breakdown
- `WEEK1_DETAILED_CHECKLIST.md` - Day-by-day Week 1 tasks

---

**Ready to start!** Run the scripts in order: labels → update #94 → create all issues
