# Issue Labels Mapping

This document defines the proper labels for each GitHub issue in the 60-day MVP.

## Label Scheme

### Type Labels
- `type: feature` - New feature or capability
- `type: enhancement` - Enhancement to existing feature
- `type: bug` - Bug or defect
- `type: refactor` - Code refactoring
- `type: docs` - Documentation changes
- `type: test` - Test additions or updates
- `type: chore` - Maintenance or tooling

### Priority Labels
- `priority: P0` - Critical - Immediate attention
- `priority: P1` - High - Important
- `priority: P2` - Medium - Normal priority
- `priority: P3` - Low - Nice to have
- `priority: P4` - Backlog - Future consideration

### Feature Labels
- `feature: evidence-chains` - Evidence Chain Infrastructure
- `feature: rag` - RAG Knowledge Base
- `feature: ai-planning` - AI Planning & Reflector
- `feature: integrations` - Integrations & Polish

### Size Labels
- `size: XS` - Extra small (< 1 day)
- `size: S` - Small (1-2 days)
- `size: M` - Medium (3-5 days)
- `size: L` - Large (1-2 weeks)
- `size: XL` - Extra large (> 2 weeks)

---

## Issue Label Assignments

### Team A: Evidence Chain Infrastructure

**Issue #94: Design and Implement Evidence Chain Database Schema**
- Type: `type: feature`
- Priority: `priority: P1`
- Feature: `feature: evidence-chains`
- Size: `size: M` (3-4 days)

**Issue A2: Implement Evidence Chain Tracking API**
- Type: `type: feature`
- Priority: `priority: P1`
- Feature: `feature: evidence-chains`
- Size: `size: L` (1 week)

**Issue A3: Implement Confidence Scoring and Propagation**
- Type: `type: feature`
- Priority: `priority: P1`
- Feature: `feature: evidence-chains`
- Size: `size: L` (1 week)

**Issue A4: Build Knowledge Graph Visualization UI**
- Type: `type: feature`
- Priority: `priority: P1`
- Feature: `feature: evidence-chains`
- Size: `size: L` (1.5 weeks)

**Issue A5: Polish Knowledge Graph UI**
- Type: `type: enhancement`
- Priority: `priority: P2`
- Feature: `feature: evidence-chains`
- Size: `size: L` (1 week)

Note: Issue titles do not include team prefixes. Feature area is indicated via the `feature:` label.

---

### Team B: RAG Knowledge Base

**Issue B1: Setup Qdrant and Ingest ExploitDB**
- Type: `type: feature`
- Priority: `priority: P1`
- Feature: `feature: rag`
- Size: `size: L` (1 week)

**Issue B2: Ingest PayloadsAllTheThings**
- Type: `type: feature`
- Priority: `priority: P1`
- Feature: `feature: rag`
- Size: `size: M` (3-4 days)

**Issue B3: Build Semantic Search API**
- Type: `type: feature`
- Priority: `priority: P1`
- Feature: `feature: rag`
- Size: `size: L` (1 week)

**Issue B4: Optimize RAG Performance**
- Type: `type: enhancement`
- Priority: `priority: P2`
- Feature: `feature: rag`
- Size: `size: L` (1 week)

---

### Team C: AI Planning & Reflector

**Issue C1: Implement Reflector Agent**
- Type: `type: feature`
- Priority: `priority: P1`
- Feature: `feature: ai-planning`
- Size: `size: L` (1 week)

**Issue C2: Replace AutoPwn with AI Task Generation**
- Type: `type: feature`
- Priority: `priority: P1`
- Feature: `feature: ai-planning`
- Size: `size: XL` (2 weeks)

**Issue C3: Implement Dynamic Replanning**
- Type: `type: feature`
- Priority: `priority: P1`
- Feature: `feature: ai-planning`
- Size: `size: L` (1.5 weeks)

**Issue C4: Add Cost Tracking and Budget Alerts**
- Type: `type: feature`
- Priority: `priority: P2`
- Feature: `feature: ai-planning`
- Size: `size: M` (3-4 days)

---

### Team D: Integrations & Polish

**Issue D1: Build Nessus XML Parser**
- Type: `type: feature`
- Priority: `priority: P2`
- Feature: `feature: integrations`
- Size: `size: M` (4-5 days)

**Issue D2: Build Nessus Import Workflow**
- Type: `type: feature`
- Priority: `priority: P2`
- Feature: `feature: integrations`
- Size: `size: M` (3-4 days)

**Issue D3: Build Report Generation Workflow**
- Type: `type: feature`
- Priority: `priority: P2`
- Feature: `feature: integrations`
- Size: `size: L` (1 week)

**Issue D4: Build Manual Target AI Planning Workflow**
- Type: `type: feature`
- Priority: `priority: P1`
- Feature: `feature: integrations`
- Size: `size: L` (1 week)

---

### Cross-Team Issues

**Issue X1: Integration Testing - Complete Workflows**
- Type: `type: test`
- Priority: `priority: P1`
- Feature: (no feature label - all features)
- Size: `size: L` (1 week)

**Issue X2: Documentation - User Guide**
- Type: `type: docs`
- Priority: `priority: P2`
- Feature: (no feature label - all features)
- Size: `size: L` (1 week)

**Issue X3: Demo Preparation**
- Type: `type: chore`
- Priority: `priority: P1`
- Feature: (no feature label - all features)
- Size: `size: L` (1 week)

---

## Quick Reference: gh command format

```bash
gh issue edit <issue-number> --add-label "type: feature,priority: P1,feature: evidence-chains,size: M"
```

**Note:** Labels must be created first using `create-labels.sh`
