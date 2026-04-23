# Architecture & PRD Review Guide

**Date:** 2026-04-07
**For:** Next Claude Code session
**Purpose:** Comprehensive review of architecture and competitive positioning documents

---

## Documents to Review

1. `/home/jtomek/Code/pick/docs/SYSTEM_ARCHITECTURE.md` (81KB, ~100 pages)
2. `/home/jtomek/Code/pick/docs/PRD_COMPETITIVE_POSITIONING.md` (59KB, ~90 pages)

**Backups available:**
- `SYSTEM_ARCHITECTURE.backup-20260407-113428.md`
- `PRD_COMPETITIVE_POSITIONING.backup-20260407-111353.md`

---

## Context Recovery

**Step 1:** Load recall context
```
Use mcp-recall to retrieve notes:
- recall_6b96964f (Architecture Decisions)
- recall_88c5e5df (Major Architecture Updates)
```

**Step 2:** Read both documents fully
```
Read SYSTEM_ARCHITECTURE.md (all sections)
Read PRD_COMPETITIVE_POSITIONING.md (all sections)
```

---

## Review Questions

### A. Architecture Validation

#### 1. Component Clarity
- **Q:** Is the distinction between StrikeKit (Prospector Studio) and Pick crystal clear?
- **Q:** Are the responsibilities well-defined with no overlap or confusion?
- **Q:** Does the "StrikeKit IS Prospector Studio" unification make sense throughout?

#### 2. Platform Support
- **Q:** Is iOS completely removed from all sections?
- **Q:** Are Desktop/Android/Web/TUI platforms consistently documented?
- **Q:** Is the Android mobile deployment clearly explained?

#### 3. Full Linux Environment
- **Q:** Is it clear that Pick provides a FULL Arch Linux environment, not just BlackArch tools?
- **Q:** Is the extensibility (Kali, Parrot, custom repos) well explained?
- **Q:** Are the 3000+ BlackArch tools positioned correctly as ONE of many capabilities?

#### 4. Connector SDK Integration
- **Q:** Is it clear that ALL C2 communication uses Strike48 Connector SDK (SDK-RS)?
- **Q:** Are there any references to generic "HTTPS" or "TLS" that should specify Connector SDK?
- **Q:** Is the security model (authenticated, secure connections) clear?

#### 5. Control Hierarchy
- **Q:** Is the StrikeKit → Mythic → Pick control flow clear?
- **Q:** Can StrikeKit controlling Mythic (which controls Pick) be easily understood?
- **Q:** Are the three deployment modes (standalone, Mythic agent, StrikeKit C2) well differentiated?

#### 6. Workflow Engine
- **Q:** Is the difference between Workflows (deterministic) and Task Graphs (AI-driven) clear?
- **Q:** Are the workflow capabilities (n8n-like, codeable) adequately explained?
- **Q:** Do the workflow examples make sense?
- **Q:** Is the "hybrid workflow" concept (deterministic + AI decision points) clear?

#### 7. Auditing & Scoping
- **Q:** Is the comprehensive auditing system (immutable, tamper-evident) well explained?
- **Q:** Are the legal protection features clear?
- **Q:** Is the real-time scoping enforcement understandable?
- **Q:** Are the compliance exports (SOC 2, ISO 27001, GDPR) adequately covered?
- **Q:** Is the scope violation workflow clear?

#### 8. Integrations
- **Q:** Is the GoPhish social engineering integration well explained?
- **Q:** Are Phase 1 (import) vs Phase 2 (real-time API) distinctions clear for all integrations?
- **Q:** Is the Nessus management capability (long-term engagements) clear?
- **Q:** Are all 10 integrations (Nessus, CS, Mythic, GoPhish, Metasploit, Burp, BloodHound, Shodan, Tenable, AWS) documented?

#### 9. Deployment Modes
- **Q:** Are the 4 deployment modes clearly differentiated?
  1. Standalone Pick
  2. Pick as Mythic Agent
  3. StrikeKit C2 Deployment
  4. Hybrid
- **Q:** Is the agent selection logic (full Pick vs lightweight agent) clear?
- **Q:** Are the use cases for each mode understandable?

#### 10. AI Orchestration
- **Q:** Is it clear that StrikeKit handles BOTH strategic AND tactical AI?
- **Q:** Is Pick's optional local AI (for offline mode) clear?
- **Q:** Is the evidence-based reasoning flow understandable?
- **Q:** Are the LLM integration points (OpenAI, Anthropic, Ollama) clear?

---

### B. PRD Validation

#### 11. Competitive Analysis
- **Q:** Are the 3 market segments (open source, commercial, Pick) clearly differentiated?
- **Q:** Is the competitive positioning compelling?
- **Q:** Are the open source competitors (LuaN1ao: 90.4% XBOW, Shannon: 96.15% XBOW) accurately described?
- **Q:** Are the commercial competitors (Horizon3, XBOW, Penligent, Maze) well analyzed?

#### 12. Unique Advantages
- **Q:** Is the "3000+ BlackArch tools" advantage clearly articulated?
- **Q:** Is the sandboxed/native toggle well explained as a differentiator?
- **Q:** Is the multi-platform advantage (Desktop/Android vs competitors' limitations) clear?
- **Q:** Is the enterprise integration (StrikeKit engagement management) positioned as unique?

#### 13. XBOW Benchmark Strategy
- **Q:** Is the path to 90%+ XBOW success clear?
- **Q:** Are the technical requirements (task graphs, evidence chains, LLM integration) well defined?
- **Q:** Is the 6-month timeline (70% → 85% → 90%) realistic?
- **Q:** Are the success metrics clear?

#### 14. Integration Roadmap
- **Q:** Is the Tier 1/2/3 prioritization clear?
- **Q:** Are the Nessus, Mythic, Cobalt Strike, GoPhish integrations adequately detailed?
- **Q:** Is the phasing (Phase 1: import, Phase 2: real-time) consistent?

#### 15. Pricing & Business Model
- **Q:** Is the "free vs $20k-100k/year commercial platforms" positioning clear?
- **Q:** Is the MIT (Pick) + AGPL (StrikeKit) licensing strategy explained?
- **Q:** Are the revenue opportunities (enterprise support, managed service) clear?

#### 16. Target Market
- **Q:** Are the user personas well defined?
- **Q:** Is the dual market (individual researchers + enterprises) strategy clear?
- **Q:** Are the value propositions differentiated by audience?

---

### C. Gap Analysis (Prepare for Next Docs)

#### 17. Missing Features Identification
- **Q:** Based on the architecture, what features are NOT yet implemented?
- **Q:** Which gaps are critical for the 60-day MVP?
- **Q:** Which gaps can be deferred post-funding?

#### 18. Component Boundaries
- **Q:** For each gap, is it clear whether it belongs in Pick or StrikeKit?
- **Q:** Are there any ambiguous features that could go in either?
- **Q:** Is the decision framework (tool execution = Pick, orchestration = StrikeKit) consistent?

#### 19. 60-Day MVP Scope
- **Q:** Based on the PRD, what are the MUST-HAVE features for the funding demo?
- **Q:** What's the minimum viable feature set to demonstrate:
  - Autonomous pentesting (XBOW 70%+)
  - Integration (Nessus → Pick → StrikeKit)
  - AI orchestration (task graphs, evidence chains)
- **Q:** What can be faked/mocked for the demo vs fully implemented?

---

### D. Consistency Checks

#### 20. Cross-Document Consistency
- **Q:** Do the architecture and PRD tell the same story?
- **Q:** Are feature claims in the PRD backed by architecture specs?
- **Q:** Are timelines consistent (60-day MVP, 6-month XBOW, 12-month full features)?

#### 21. Terminology Consistency
- **Q:** Is "StrikeKit (Prospector Studio)" used consistently?
- **Q:** Is "Connector SDK (SDK-RS)" used consistently for C2?
- **Q:** Are "workflows" (deterministic) vs "task graphs" (AI) clearly distinguished?
- **Q:** Is "full Linux environment" used instead of "BlackArch tools only"?

#### 22. Diagram Accuracy
- **Q:** Do all ASCII diagrams match the written descriptions?
- **Q:** Are control flows (StrikeKit → Mythic → Pick) consistent?
- **Q:** Do integration diagrams show correct data flows?

---

### E. Readability & Clarity

#### 23. Executive Summary
- **Q:** Can someone understand the system in 5 minutes from the executive summaries?
- **Q:** Are the key differentiators immediately clear?

#### 24. Technical Depth
- **Q:** Is there enough detail for developers to start implementing?
- **Q:** Are code examples helpful and accurate?
- **Q:** Are the pseudocode snippets understandable?

#### 25. Use Cases & Examples
- **Q:** Are there enough concrete examples?
- **Q:** Do the workflow examples (Nessus → exploitation) make sense?
- **Q:** Are the deployment scenarios realistic?

---

### F. Funding Pitch Validation

#### 26. Investor Appeal
- **Q:** Does the architecture demonstrate technical sophistication?
- **Q:** Is the competitive advantage compelling?
- **Q:** Does the 60-day MVP seem achievable?

#### 27. Team Size Estimation
- **Q:** Based on the 60-day scope, does "5-6 developers Month 1, 10-12 Month 2" seem right?
- **Q:** Are the parallel work streams (AI foundation, integrations, StrikeKit features) clear?

#### 28. Risk Assessment
- **Q:** Are technical risks identified?
- **Q:** Are there any impossible dependencies or blockers?
- **Q:** Is the XBOW 70% target realistic in 60 days?

---

## Specific Items to Verify

### ✅ Must Be Correct

1. **iOS is GONE** - No references anywhere
2. **StrikeKit IS Prospector Studio** - No separation
3. **Full Linux environment** - Not just BlackArch
4. **Connector SDK** - All C2 uses SDK-RS
5. **Workflows ≠ Task Graphs** - Deterministic vs AI
6. **Auditing is immutable** - Tamper-evident hash chain
7. **Scoping is real-time** - Block before execution, not after
8. **GoPhish integration** - Social engineering + technical unified
9. **Android deployment** - Mobile platform confirmed
10. **Nessus management** - Long-term scanner control

### ⚠️ Watch For

- Any mentions of "Prospector Studio" as separate from StrikeKit
- Generic "HTTPS listener" instead of "Connector SDK"
- "BlackArch tools" without mentioning full Linux environment
- iOS references (should be zero)
- Inconsistent deployment mode descriptions
- Missing auditing/scoping details

---

## Output Format

**Create a review document with:**

### 1. Executive Summary
- Overall assessment (Ready / Needs Minor Edits / Needs Major Revision)
- Top 3 strengths
- Top 3 concerns

### 2. Detailed Findings
- Section-by-section review
- Answer all questions above
- Flag inconsistencies, errors, unclear sections

### 3. Recommended Changes
- High priority (blocking issues)
- Medium priority (clarity improvements)
- Low priority (nice-to-haves)

### 4. Gap Analysis Preparation
- List of features mentioned but not implemented
- Categorize by component (Pick vs StrikeKit)
- Prioritize for 60-day MVP

### 5. Readiness Assessment
- Is this ready to show investors? (Yes/No + reasoning)
- What's missing before funding pitch?
- Confidence level in 60-day MVP plan (1-10)

---

## Commands for Next Agent

```bash
# Load context
mcp-recall retrieve recall_6b96964f
mcp-recall retrieve recall_88c5e5df

# Read documents
Read /home/jtomek/Code/pick/docs/SYSTEM_ARCHITECTURE.md
Read /home/jtomek/Code/pick/docs/PRD_COMPETITIVE_POSITIONING.md

# Create review
Write /home/jtomek/Code/pick/docs/ARCHITECTURE_REVIEW.md

# Search for specific items
Grep "iOS" /home/jtomek/Code/pick/docs/SYSTEM_ARCHITECTURE.md
Grep "Prospector Studio" /home/jtomek/Code/pick/docs/SYSTEM_ARCHITECTURE.md
Grep "BlackArch" /home/jtomek/Code/pick/docs/SYSTEM_ARCHITECTURE.md
```

---

## Success Criteria

The review is complete when:

1. ✅ All 28 question sections answered
2. ✅ All 10 "Must Be Correct" items verified
3. ✅ All "Watch For" items checked
4. ✅ Detailed findings document created
5. ✅ Readiness assessment provided
6. ✅ Gap analysis prep (list of unimplemented features)

---

## Notes for Reviewer

- **Be critical:** This is for funding - mistakes are costly
- **Check consistency:** Architecture must match PRD
- **Think like an investor:** Is this compelling and achievable?
- **Think like a developer:** Can this be built in 60 days?
- **Flag ambiguity:** If anything is unclear, call it out
- **Suggest improvements:** Don't just identify problems, propose solutions

---

**Estimated Review Time:** 2-3 hours for thorough analysis

**Priority:** HIGH - Funding depends on these documents

**Owner:** Next Claude Code session

---

**END OF REVIEW GUIDE**
