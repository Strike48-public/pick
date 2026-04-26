# Issue Repository Mapping

This document categorizes which GitHub issues should be created in which repository.

---

## StrikeKit Repository Issues

All Team A, B, C, and D issues go to StrikeKit since they involve the orchestration platform, database, RAG, AI planning, and integrations.

### Team A: Evidence Chain Infrastructure (StrikeKit)
- **A1:** [Team A] Design and Implement Evidence Chain Database Schema
- **A2:** [Team A] Implement Evidence Chain Tracking API
- **A3:** [Team A] Implement Confidence Scoring and Propagation
- **A4:** [Team A] Build Knowledge Graph Visualization UI
- **A5:** [Team A] Polish Knowledge Graph UI

### Team B: RAG Knowledge Base (StrikeKit)
- **B1:** [Team B] Setup Qdrant and Ingest ExploitDB
- **B2:** [Team B] Ingest PayloadsAllTheThings
- **B3:** [Team B] Build Semantic Search API
- **B4:** [Team B] Optimize RAG Performance

### Team C: AI Planning & Reflector (StrikeKit)
- **C1:** [Team C] Implement Reflector Agent
- **C2:** [Team C] Replace AutoPwn with AI Task Generation
- **C3:** [Team C] Implement Dynamic Replanning
- **C4:** [Team C] Add Cost Tracking and Budget Alerts

### Team D: Integrations & Polish (StrikeKit)
- **D1:** [Team D] Build Nessus XML Parser
- **D2:** [Team D] Build Nessus Import Workflow
- **D3:** [Team D] Build Report Generation Workflow
- **D4:** [Team D] Build Manual Target AI Planning Workflow

### Cross-Team Issues (StrikeKit)
- **X1:** [Integration] Integration Testing - Complete Workflows
- **X2:** [Documentation] Documentation - User Guide
- **X3:** [Demo] Demo Preparation

---

## Pick Repository Issues

Pick-specific issues for UI enhancements and StrikeKit integration.

### Pick Issues (4 total)

**Issue P1: Post-Exploitation Tool UI Enhancements** (Priority 1)
- Type: `type: enhancement`
- Priority: `priority: P1`
- Feature: `feature: post-exploit`
- Milestone: `milestone: week-3`
- Size: `size: L`

**Issue P2: Polish WiFi AutoPwn UI/UX** (Priority 2)
- Type: `type: enhancement`
- Priority: `priority: P2`
- Feature: `feature: autopwn`
- Milestone: `milestone: week-4`
- Size: `size: M`

**Issue P3: Integrate StrikeKit Evidence Chain APIs** (Priority 2)
- Type: `type: feature`
- Priority: `priority: P2`
- Feature: `feature: evidence-chains`
- Milestone: `milestone: week-5`
- Size: `size: L`
- Depends On: StrikeKit Issue A2

**Issue P4: Display Knowledge Graph from StrikeKit** (Priority 2)
- Type: `type: feature`
- Priority: `priority: P2`
- Feature: `feature: knowledge-graph`
- Milestone: `milestone: week-6`
- Size: `size: L`
- Depends On: StrikeKit Issue A4, Pick Issue P3

---

## Issues for External Tracking (Markdown File)

Some issues span both repos or involve infrastructure that's not directly in either codebase.

### Infrastructure Issues (Track in Markdown)
- Setup shared development environment
- Configure CI/CD for cross-repo testing
- Setup Qdrant infrastructure (local + production)
- Configure Prospector Studio integration
- Setup monitoring/observability for MVP

---

## Next Steps

1. Create labels in StrikeKit repo:
   - `team-a-evidence-chains`
   - `team-b-rag`
   - `team-c-ai-planning`
   - `team-d-integrations`
   - `milestone-week-1` through `milestone-week-8`
   - `priority-1-must-have`, `priority-2-should-have`, `priority-3-nice-to-have`

2. Create all Team A, B, C, D issues in StrikeKit repo

3. Define Pick-specific issues as integration work becomes clearer

4. Track infrastructure/cross-repo work in markdown file or separate project board

---

**Summary:**
- StrikeKit: 21 issues (all Feature A, B, C, D + cross-feature)
- Pick: 4 issues (UI enhancements + StrikeKit integration)
- External tracking: Infrastructure and cross-repo coordination
- **Total: 25 issues**
