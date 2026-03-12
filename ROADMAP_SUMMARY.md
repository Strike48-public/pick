# Pick Roadmap Summary - Created 2026-03-12

## Overview

Created **19 beads issues** for the Pick lean connector roadmap:
- **4 Epics** (one per phase)
- **15 Features** (major capabilities)

All issues stored in `.beads/issues.jsonl`

## Epics

1. **pick-epic-1**: Phase 1: Data Pipeline & Tool Integration
2. **pick-epic-2**: Phase 2: Autonomous Execution & Intelligence
3. **pick-epic-3**: Phase 3: Advanced Capabilities & Performance
4. **pick-epic-4**: Phase 4: Platform & Multi-Connector Support

## Features by Priority

### P0 - CRITICAL (Month 1)
- **pick-001**: Structured Output Parser
- **pick-002**: StrikeKit Integration Protocol

### P1 - HIGH (Month 2)
- **pick-003**: BloodHound Integration
- **pick-004**: Kerberos Attack Tools

### P2 - HIGH/MEDIUM (Month 3-4)
- **pick-005**: Tool Recommendation Engine
- **pick-006**: Credential Reuse Testing
- **pick-007**: Evidence Collection
- **pick-008**: Progress Reporting

### P3 - MEDIUM (Month 5-6)
- **pick-009**: ADCS / Certipy Integration
- **pick-010**: Multi-Tool Orchestration
- **pick-014**: Multi-Connector Deconfliction

### P4 - LOW (Month 5-6)
- **pick-011**: UI Progress Visualization
- **pick-012**: Interactive Autonomy Modes
- **pick-013**: Tool Container Management
- **pick-015**: Hash Cracking Coordination

## Viewing Issues

Since the beads CLI requires a Dolt database (which needs CGO), you can view issues directly:

```bash
# List all epics
jq -r 'select(.type=="epic") | "\(.id) - \(.title)"' .beads/issues.jsonl

# List all features
jq -r 'select(.type=="feature") | "[\(.priority)] \(.id) - \(.title) (\(.labels | join(", ")))"' .beads/issues.jsonl

# View a specific issue
jq 'select(.id=="pick-001")' .beads/issues.jsonl | jq .

# List Month 1 features
jq -r 'select(.labels[]? == "month-1") | "\(.id) - \(.title)"' .beads/issues.jsonl
```

## Next Steps

1. **Month 1 Focus**: pick-001 (Structured Output Parser) + pick-002 (StrikeKit Integration Protocol)
2. **Coordinate with StrikeKit team**: Confirm message protocol and schema
3. **Start development**: Begin with parser architecture
4. **Set up crowdsourcing**: Document contribution guidelines

## Key Architectural Decisions

- **Pick = Thin Connector**: No credential storage, no long-term state
- **StrikeKit = Smart Platform**: Handles storage, analysis, visualization
- **Stateless Execution**: Pick queries StrikeKit for context each run
- **Structured Data First**: All tool outputs → JSON → StrikeKit
- **Fail Gracefully**: Tool failures don't crash Pick

## Resource Allocation

- **Team Size**: 2-3 core developers + crowdsource contributors
- **Timeline**: 3-6 months (parallel tracks)
- **Month 1-2**: Foundation (parsers, protocol, AD tools)
- **Month 3-4**: Intelligence (AI recommendations, cred reuse, evidence)
- **Month 5-6**: Advanced (orchestration, multi-connector, polish)

## Success Metrics

- **Data Quality**: 95%+ tool outputs successfully parsed
- **Message Delivery**: 99%+ messages reach StrikeKit
- **Tool Success Rate**: 90%+ tools execute without errors
- **Coverage**: 20+ tools with structured output parsers
- **Time to First Finding**: <5 minutes from AutoPwn start

---

**Files Created:**
- `ROADMAP_ANALYSIS.md` - Original comprehensive analysis (deferred features to StrikeKit)
- `ROADMAP_REVISED.md` - Lean connector-focused roadmap
- `ROADMAP_SUMMARY.md` - This summary
- `.beads/issues.jsonl` - 19 trackable issues

**Ready to start Month 1 work!** 🚀
