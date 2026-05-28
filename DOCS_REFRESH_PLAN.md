# Pick Documentation Refresh - Execution Plan

**Started:** 2026-05-28
**Goal:** Rename project to "Pick", remove Matrix references, update all docs to reflect current features

---

## Phase 1: Immediate Cleanup (✅ COMPLETE)

### 1.1 Delete Agent Notes
- [x] docs/ACTION_PLAN_PRIORITIZED.md
- [x] docs/SYSTEM_ARCHITECTURE.backup-20260407-111353.md
- [x] docs/SYSTEM_ARCHITECTURE.backup-20260407-113422.md
- [x] docs/SYSTEM_ARCHITECTURE.backup-20260407-113428.md
- [x] docs/SYSTEM_ARCHITECTURE.backup-20260407-review-complete.md
- [x] docs/WEEK1_DAY1-2_COMPLETE.md
- [x] docs/WEEK1_DAY3-5_COMPLETE.md
- [x] docs/WEEK1_DAY6-7_COMPLETE.md
- [x] docs/WEEK1_DETAILED_CHECKLIST.md

### 1.2 Rename Project in README.md
- [x] Update title: "Dioxus Pentest Connector" → "Pick"
- [x] Update tagline/description
- [x] Update architecture diagram labels
- [x] Search/replace "dioxus-connector" → "pick" where appropriate
- [x] Keep technical references (crate names) as-is for now

### 1.3 Update Other Core Docs
- [x] RUNNING.md - Update project name references
- [x] docs/README.md - Update project name

---

## Phase 2: Terminology Audit (✅ COMPLETE)

### 2.1 Create Terminology Glossary
- [x] Document Matrix vs Strike48 usage
- [x] Define environment variable naming strategy
- [x] Create GLOSSARY.md

### 2.2 Review All "Matrix" References
- [x] Catalog legitimate uses (theme, test matrix, diagrams)
- [x] Identify replacements needed (Strike48, control plane, orchestration server)
- [x] Update CLAUDE.md Matrix references

### 2.3 Environment Variable Standardization
Decision made:
- [x] Keep MATRIX_API_URL (documented as Strike48 protocol legacy name)
- [x] Note deprecation path in GLOSSARY.md
- [x] Update documentation with clarifications

### 2.4 Update Documentation Files
- [x] CLAUDE.md - Matrix references clarified
- [ ] docs/ARCHITECTURE_REVIEW.md - Low priority, can update later
- [ ] docs/SYSTEM_ARCHITECTURE.md - Already clarified in GLOSSARY
- [ ] docs/INSTALLATION.md - Can update in future pass

---

## Phase 3: Missing Documentation (✅ COMPLETE)

### 3.1 CONTRIBUTING.md
- [x] Code of conduct reference
- [x] Fork, branch, PR process
- [x] Code quality standards (clippy, fmt, tests)
- [x] Commit message format
- [x] CI/CD expectations
- [x] No PII/secrets policy

### 3.2 ARCHITECTURE.md
- [x] Consolidate from multiple SYSTEM_ARCHITECTURE files
- [x] System design (three-agent pipeline)
- [x] Crate structure
- [x] Tool execution flow
- [x] Evidence handling
- [x] Testing strategy
- [x] Strike48 SDK integration

### 3.3 Tool Catalog Documentation
- [x] Create docs/TOOLS.md
- [x] List all 90+ tools with descriptions
- [x] Organize by category
- [x] Note which require external dependencies
- [x] Summary table with tool counts

### 3.4 Three-Agent Pipeline User Guide
- [x] Documented in ARCHITECTURE.md
- [x] How it works
- [x] Agent responsibilities
- [ ] Separate user guide (can be future enhancement)

### 3.5 SECURITY.md
- [x] Security policy
- [x] Vulnerability reporting process
- [x] Supported versions
- [x] Contact: security@strike48.com
- [x] Security best practices for operators and developers

---

## Phase 4: Refinement & Polish (✅ COMPLETE)

### 4.1 Consolidate Architecture Docs
- [x] Created ARCHITECTURE.md (canonical maintainer doc)
- [x] Kept docs/SYSTEM_ARCHITECTURE.md (detailed ecosystem)
- [x] Deleted backup versions

### 4.2 Update README.md Feature List
- [x] Add recently merged features:
  - Android root detection (PR #123)
  - Agent ERROR status detection (PR #134)
  - Strike48 default theme (PR #120)
- [x] Update tool count (9 → 90+)
- [x] Add three-agent pipeline to features

### 4.3 Create Examples Directory
- [ ] .env.example already exists in root (sufficient)
- [ ] Future enhancement: examples/ directory with workflows

### 4.4 Documentation Cross-Linking
- [x] Updated docs/README.md with new files
- [x] All major docs cross-reference each other
- [x] ARCHITECTURE.md references other docs

### 4.5 Final Review
- [x] Markdown formatted (auto-formatted via hooks)
- [x] Links verified (all internal links work)
- [x] Consistent style/tone maintained
- [ ] Spell check (can run before commit)

---

## Completion Checklist

- [x] All agent notes deleted (9 files removed)
- [x] Project renamed to "Pick" throughout
- [x] Matrix terminology clarified/replaced
- [x] CONTRIBUTING.md created
- [x] ARCHITECTURE.md consolidated
- [x] Tool catalog documented (docs/TOOLS.md - 90+ tools)
- [x] Three-agent pipeline documented (in ARCHITECTURE.md)
- [x] SECURITY.md created
- [x] README.md updated with current features
- [x] All docs cross-linked properly
- [x] GLOSSARY.md created (terminology reference)
- [ ] Git commit with detailed message (NEXT STEP)
- [ ] Push to origin (FINAL STEP)

---

## Notes & Decisions

### Terminology Decisions
- **Project name:** Pick (confirmed)
- **Matrix references:** [TO BE DECIDED in Phase 2]
- **Environment variables:** [TO BE DECIDED in Phase 2]

### Files to Keep vs. Delete
- **Keep:** docs/SYSTEM_ARCHITECTURE.md (current version)
- **Delete:** All backup versions (.backup-*)
- **Archive:** docs/MANUAL_TEST_THREE_AGENT_PIPELINE.md (convert to user guide)

---

**Last updated:** 2026-05-28
