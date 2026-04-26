# Pick + StrikeKit: Prioritized Action Plan

**Date:** 2026-04-07
**Status:** Ready for Execution
**Based on:** Gap analysis of 25+ competitors

---

## Executive Summary

This action plan provides a week-by-week roadmap for the next 12 weeks (60-day MVP + 1 month buffer) to achieve 70%+ XBOW success and competitive parity with leading AI pentesting platforms.

**Critical Path:** Task Graphs → Evidence Chains → LLM Integration → XBOW Testing
**Team Size:** 5-6 developers Month 1, 10-12 developers Month 2
**Success Metric:** 70%+ XBOW benchmark success by Week 12

---

## Week-by-Week Breakdown

### Week 1-2: Foundation + XBOW Access

#### Week 1: Task Graph Foundation

**AI Foundation Team (2 devs):**
- [ ] Design task graph data structures (TaskNode, TaskGraph, TaskStatus)
- [ ] Implement DAG representation (nodes + edges)
- [ ] Build topological sorting for dependency resolution
- [ ] Create shared findings board (Arc<RwLock<FindingsBoard>>)

**StrikeKit Platform Team (2 devs):**
- [ ] Design C2 listener architecture (Connector SDK-based)
- [ ] Implement agent registration protocol
- [ ] Build command queue and task dispatch
- [ ] Set up PostgreSQL schema for engagements

**Pick Integration Team (1 dev):**
- [ ] Create evidence generation interface
- [ ] Build Connector SDK client
- [ ] Implement tool output parsing framework
- [ ] Set up test environment

**Infrastructure (part-time):**
- [ ] Set up CI/CD pipeline (GitHub Actions)
- [ ] Deploy PostgreSQL (development + staging)
- [ ] Configure development environment (Docker Compose)
- [ ] Set up monitoring (logs, metrics)

**CRITICAL DEADLINE:** Obtain XBOW benchmark suite by end of Week 2

---

#### Week 2: Task Graph Execution + XBOW Acquisition

**AI Foundation Team:**
- [ ] Implement parallel task execution (tokio async runtime)
- [ ] Build task scheduler (priority queue, dependency checking)
- [ ] Create task status tracking (Pending, Running, Success, Failed, Blocked)
- [ ] Add dynamic node insertion (discovered service → new tasks)

**StrikeKit Platform Team:**
- [ ] Implement file upload/download (C2 agent communication)
- [ ] Build session management (active sessions, heartbeat)
- [ ] Create health monitoring (agent status, last seen)
- [ ] Design engagement lifecycle API

**Pick Integration Team:**
- [ ] Integrate first 10 tools with task graph (nmap, rustscan, ffuf, gobuster, hydra, nikto, sqlmap, whatweb, subfinder, dnsrecon)
- [ ] Build evidence schema (PortOpen, ServiceBanner, VulnerabilityFound, etc.)
- [ ] Test tool execution with task graph

**Infrastructure:**
- [ ] Set up Qdrant vector database (for Phase 2 RAG)
- [ ] Configure secrets management (API keys, credentials)
- [ ] Deploy staging environment

**🚨 CRITICAL:** Acquire XBOW benchmark suite
- [ ] Contact XBOW maintainers
- [ ] Set up benchmark test environment
- [ ] Document benchmark scenarios
- [ ] Prepare baseline test (to run in Week 4)

---

### Week 3-4: Evidence Chains + Baseline XBOW Test

#### Week 3: Evidence-Based Reasoning

**AI Foundation Team:**
- [ ] Implement evidence chain data structures (Evidence, Hypothesis, Vulnerability, Exploit)
- [ ] Build confidence scoring system (0.0-1.0 scale)
- [ ] Create evidence → hypothesis → action pipeline
- [ ] Add confidence threshold enforcement (reject if < 0.7)

**StrikeKit Platform Team:**
- [ ] Build LLM client interface (trait definition)
- [ ] Implement OpenAI provider (GPT-4o, GPT-4o-mini)
- [ ] Implement Anthropic provider (Claude Sonnet 4.6, Haiku 4.5)
- [ ] Add cost tracking (tokens, estimated cost per engagement)

**Pick Integration Team:**
- [ ] Integrate next 15 tools (masscan, dirb, wfuzz, nuclei, wpscan, arjun, amass, assetfinder, httpx, httprobe, waybackurls, testssl, sslscan, enum4linux, ldapsearch)
- [ ] Build evidence confidence scoring per tool
- [ ] Create tool chaining logic (when to use tool Y after tool X)

**Integration Team (if onboarding early):**
- [ ] Research Nessus XML schema
- [ ] Design Nessus import workflow
- [ ] Build XML parser (quick-xml or similar)

---

#### Week 4: LLM Integration + XBOW Baseline Test

**AI Foundation Team:**
- [ ] Implement Ollama provider (local models: Llama 3.1, Qwen, Mistral)
- [ ] Build tool recommendation engine (LLM-powered)
- [ ] Add prompt templates (system prompts for Planner, Executor)
- [ ] Create LLM response parsing (structured output)

**StrikeKit Platform Team:**
- [ ] Implement budget alerts (configurable threshold)
- [ ] Build cost reporting UI (tokens used, cost per engagement)
- [ ] Add provider fallback logic (if OpenAI fails, try Anthropic)
- [ ] Create engagement basic UI (create, view, update)

**Pick Integration Team:**
- [ ] Test AI tool recommendations (LLM suggests next tool)
- [ ] Build tool failure handling (what to retry if tool fails)
- [ ] Integrate tool outputs with evidence chains

**Integration Team:**
- [ ] Implement Nessus XML import (parse hosts, services, vulnerabilities)
- [ ] Create Target entries in StrikeKit
- [ ] Create Finding entries (High/Critical vulns)
- [ ] Test Nessus → StrikeKit workflow

**🎯 MILESTONE: XBOW Baseline Test**
- [ ] Run XBOW benchmark with current AutoPwn + task graphs
- [ ] Document results (expected: 30-40% success)
- [ ] Analyze failure modes (categorize by type)
- [ ] Prioritize fixes based on impact
- [ ] Create improvement backlog

---

### Week 5-6: Multi-Agent Architecture + Nessus Integration

#### Week 5: Planner Agent

**AI Foundation Team:**
- [ ] Design Planner agent (strategic planning, task graph generation)
- [ ] Implement engagement context (target info, scope, findings)
- [ ] Build initial task graph generation (LLM-powered)
- [ ] Add adaptive planning (new findings → new tasks)

**StrikeKit Platform Team:**
- [ ] Build findings API (create, update, delete)
- [ ] Implement target tracking (IP, hostname, OS, services)
- [ ] Add credential storage (secure encryption)
- [ ] Create MITRE ATT&CK basic mapping

**Pick Integration Team:**
- [ ] Integrate next 15 tools (crackmapexec, evil-winrm, impacket suite, linpeas, bettercap, aircrack-ng, hashcat, john, cewl, crunch, changeme, exiftool, smbmap, onesixtyone, snmpwalk)
- [ ] Test multi-tool workflows (scan → enumerate → exploit)

**Integration Team:**
- [ ] Implement Mythic callback import (basic)
- [ ] Parse Mythic session data
- [ ] Create agent entries in StrikeKit
- [ ] Test Mythic → StrikeKit sync

**Frontend Team (if onboarded):**
- [ ] Design evidence chain visualization (web UI)
- [ ] Build task graph display (nodes + edges, real-time updates)
- [ ] Create engagement dashboard (targets, findings, tasks)

---

#### Week 6: Executor Agent + AI-Powered Exploitation

**AI Foundation Team:**
- [ ] Design Executor agent (tool execution, evidence collection)
- [ ] Integrate Executor with Pick tool registry
- [ ] Build evidence parsing (tool output → structured evidence)
- [ ] Test Planner → Executor workflow

**StrikeKit Platform Team:**
- [ ] Implement report generation (basic PDF templates)
- [ ] Build finding details (title, description, severity, evidence)
- [ ] Add scope validation logic (IP ranges, domains, timeframe)
- [ ] Create scope violation alerts

**Pick Integration Team:**
- [ ] Test AI-powered exploitation (Nessus vuln → AI selects exploit → Pick executes)
- [ ] Build exploit selection logic (evidence + RAG → best exploit)
- [ ] Add exploitation evidence (screenshots, shell access, data extracted)

**Integration Team:**
- [ ] Implement GoPhish campaign import (basic)
- [ ] Parse phishing results (clicks, credentials, emails)
- [ ] Create targets from clicked users
- [ ] Store harvested credentials

**Frontend Team:**
- [ ] Implement findings list view
- [ ] Build target details page
- [ ] Add evidence display (tool outputs, confidence scores)

---

### Week 7-8: Reflector Agent + Integration Testing

#### Week 7: Reflector Agent + Failure Analysis

**AI Foundation Team:**
- [ ] Design Reflector agent (failure analysis, learning)
- [ ] Implement L1-L4 failure categorization (like LuaN1ao)
  - L1: Tool execution failure (syntax error, missing tool)
  - L2: Tool output parsing failure (unexpected format)
  - L3: Logical failure (wrong tool for task)
  - L4: Strategic failure (wrong approach)
- [ ] Build failure analysis workflow (task failed → analyze → recommend fix)
- [ ] Test full P-E-R cycle (Planner → Executor → Reflector)

**StrikeKit Platform Team:**
- [ ] Implement audit log system (immutable, tamper-evident)
- [ ] Build timeline visualization (engagement activity over time)
- [ ] Add user attribution (all actions tied to user accounts)
- [ ] Create compliance export (SOC 2, ISO 27001 formats)

**Pick Integration Team:**
- [ ] Integrate remaining core tools (target: 100+ tools total)
- [ ] Optimize tool execution (parallel where possible)
- [ ] Add tool timeout handling (kill if running too long)

**Integration Team:**
- [ ] Test full integration workflow:
  - Nessus scan → Import to StrikeKit
  - AI analyzes findings → Generates task graph
  - Pick executes exploitation tasks
  - Results update StrikeKit findings
  - PDF report generated
- [ ] Fix integration bugs
- [ ] Document workflow

**QA/Documentation Team (if onboarded):**
- [ ] Write user documentation (getting started, tutorials)
- [ ] Create deployment guides (Docker, Kubernetes)
- [ ] Build API documentation (OpenAPI/Swagger)

---

#### Week 8: XBOW Improvement Test + Demo Prep

**AI Foundation Team:**
- [ ] Optimize AI prompts (improve task selection, exploit recommendations)
- [ ] Tune confidence thresholds (find optimal balance)
- [ ] Add prompt caching (reduce LLM costs)
- [ ] Improve error handling (graceful degradation)

**StrikeKit Platform Team:**
- [ ] Polish engagement UI (user-friendly, intuitive)
- [ ] Improve report formatting (professional appearance)
- [ ] Add report customization (logo, branding, template selection)
- [ ] Test full engagement lifecycle

**Pick Integration Team:**
- [ ] Optimize tool integration quality (better parsing, higher confidence)
- [ ] Add tool chaining optimizations (reduce redundant scans)
- [ ] Test edge cases (tool failures, network issues, timeout scenarios)

**Integration Team:**
- [ ] Polish Nessus integration (error handling, progress reporting)
- [ ] Add Mythic integration improvements (session management)
- [ ] Test GoPhish integration end-to-end

**🎯 MILESTONE: XBOW Improvement Test**
- [ ] Run XBOW benchmark with full AI orchestration
- [ ] Document results (target: 50-60% success)
- [ ] Compare to baseline (Week 4 results)
- [ ] Analyze improvement areas
- [ ] Create sprint plan for final push

---

### Week 9-10: XBOW Optimization Sprint

#### Week 9: Targeted XBOW Improvements

**AI Foundation Team:**
- [ ] Fix top 10 XBOW failure modes (based on Week 8 analysis)
- [ ] Improve task graph planning (better dependency detection)
- [ ] Enhance evidence reasoning (reduce false positives)
- [ ] Optimize LLM prompt engineering (better tool selection)

**StrikeKit Platform Team:**
- [ ] Add XBOW-specific features (if needed based on analysis)
- [ ] Improve C2 agent deployment (faster, more reliable)
- [ ] Optimize database queries (faster engagement loading)
- [ ] Add caching layers (reduce redundant work)

**Pick Integration Team:**
- [ ] Fix tool integration bugs identified in XBOW tests
- [ ] Add missing tool capabilities (discovered during testing)
- [ ] Improve evidence parsing (better structured output)

**All Teams:**
- [ ] Daily XBOW testing (rapid iteration cycle)
- [ ] Prioritize based on impact (focus on high-value improvements)
- [ ] Document what works and what doesn't

---

#### Week 10: Demo Preparation + Polish

**AI Foundation Team:**
- [ ] Final AI tuning (optimal prompts, thresholds, model selection)
- [ ] Add demo mode (skip time-consuming steps, highlight key features)
- [ ] Test demo scenarios (rehearse for investors)

**StrikeKit Platform Team:**
- [ ] Polish UI for demo (remove rough edges, fix visual bugs)
- [ ] Add demo data (sample engagements, findings, reports)
- [ ] Create demo script (step-by-step walkthrough)
- [ ] Test full demo flow

**Pick Integration Team:**
- [ ] Ensure demo tools work reliably (test repeatedly)
- [ ] Add fallback options (if demo tool fails, use backup)
- [ ] Test on demo environment (staging server)

**Integration Team:**
- [ ] Polish Nessus → exploitation workflow (key demo scenario)
- [ ] Ensure integrations work in demo environment
- [ ] Test all integration paths

**QA/Documentation Team:**
- [ ] Final testing (regression tests, integration tests)
- [ ] Complete documentation (user guides, API docs, deployment guides)
- [ ] Create demo video (if time permits)

---

### Week 11-12: Final XBOW Test + Launch Prep

#### Week 11: Final XBOW Validation

**🎯 MILESTONE: Final XBOW Test**
- [ ] Run XBOW benchmark (full suite, official test)
- [ ] Target: 70%+ success rate
- [ ] Document all test results (success, failures, edge cases)
- [ ] Create XBOW report (methodology, results, analysis)
- [ ] Compare to competitors (LuaN1ao 90.4%, Shannon 96.15%, PentestGPT 86.5%)

**If 70% not reached:**
- [ ] Emergency fix sprint (fix critical failures only)
- [ ] Re-test specific scenarios (don't re-run full suite)
- [ ] Document gap and mitigation plan (honest about shortfall)
- [ ] Prepare fallback demo (emphasize technical sophistication)

**If 70% reached:**
- [ ] Celebrate! 🎉
- [ ] Prepare announcement (blog post, social media)
- [ ] Create case studies (example scenarios Pick solved)
- [ ] Plan next iteration (path to 85%)

---

#### Week 12: MVP Launch + Investor Prep

**All Teams:**
- [ ] Final bug fixes (critical issues only)
- [ ] Performance optimization (if low-hanging fruit)
- [ ] Security review (basic security checklist)
- [ ] Deployment to production (or staging for investors)

**Documentation:**
- [ ] Finalize all documentation
- [ ] Create investor pitch deck (use architecture + PRD + gap analysis)
- [ ] Prepare demo script (15-minute presentation)
- [ ] Record demo video (backup if live demo fails)

**Testing:**
- [ ] End-to-end testing (full engagement workflow)
- [ ] Stress testing (multiple concurrent engagements)
- [ ] Security testing (basic pentesting of Pick itself)
- [ ] Usability testing (non-technical user can use it?)

**Launch Checklist:**
- [ ] XBOW benchmark result: 70%+ ✅
- [ ] Task graph execution working ✅
- [ ] Evidence chains tracked with confidence ✅
- [ ] Multi-agent (P-E-R) operational ✅
- [ ] LLM integration complete (OpenAI, Anthropic, Ollama) ✅
- [ ] Nessus → Pick → StrikeKit workflow functional ✅
- [ ] Basic C2 listener + agent deployment ✅
- [ ] PDF report generation working ✅
- [ ] Demo ready (rehearsed, tested, polished) ✅
- [ ] Documentation complete ✅

---

## Critical Success Factors

### 1. XBOW Benchmark Access (Week 2)
**Why Critical:** Cannot iterate without test suite
**Owner:** Technical Lead
**Deadline:** End of Week 2 (absolute latest)
**Fallback:** If cannot obtain, create proxy benchmark from public XBOW scenarios

### 2. Iterative Testing Cycle (Weeks 4, 8, 12)
**Why Critical:** Need data to guide development priorities
**Owner:** AI Foundation Team
**Cadence:** Week 4 (baseline), Week 8 (improvement), Week 12 (final)
**Output:** Test report with failure analysis and recommendations

### 3. LLM Integration Quality (Weeks 3-6)
**Why Critical:** AI orchestration depends on LLM quality
**Owner:** StrikeKit Platform Team
**Key Decisions:**
- Model selection (Sonnet vs Opus vs Haiku)
- Prompt engineering (system prompts, few-shot examples)
- Cost vs quality tradeoff (where to use expensive models)

### 4. Tool Integration Depth (Ongoing)
**Why Critical:** XBOW success depends on tool execution quality
**Owner:** Pick Integration Team
**Metric:** Not just "tool count" but "integration quality"
- Each tool needs: Schema, evidence parser, confidence scorer
- Tool chaining logic (when to use tool X after tool Y)
- Failure handling (what to try if tool fails)

### 5. Team Coordination (Daily)
**Why Critical:** 10-12 developers need to work in parallel without blocking
**Owner:** Technical Lead
**Cadence:** Daily standups (15 minutes)
**Output:** Blocker list, work assignments, progress updates

---

## Parallel Work Stream Coordination

### Month 1 (Weeks 1-4): Foundation

**Can work in parallel:**
- AI Foundation Team: Task graphs + evidence chains (no dependencies)
- StrikeKit Platform Team: C2 listener + LLM integration (independent)
- Pick Integration Team: Tool integration (independent)
- Infrastructure: CI/CD, databases, environments (independent)

**Sequential dependencies:**
- Task graphs MUST complete before evidence chains (data structure dependency)
- LLM integration MUST complete before tool recommendations (functional dependency)

---

### Month 2 (Weeks 5-8): AI Orchestration

**Can work in parallel:**
- AI Foundation Team: Multi-agent (P-E-R) (independent work)
- StrikeKit Platform Team: Engagement management, reporting (independent)
- Pick Integration Team: More tool integrations (independent)
- Integration Team: Nessus, Mythic, GoPhish imports (independent)
- Frontend Team: UI for evidence chains, task graphs (independent)

**Sequential dependencies:**
- Planner agent MUST complete before Executor (Executor consumes Planner output)
- Executor MUST complete before Reflector (Reflector analyzes Executor failures)

---

### Month 3 (Weeks 9-12): XBOW Optimization

**Can work in parallel:**
- All teams work on XBOW improvements based on test results
- No hard dependencies - prioritize based on impact
- Daily testing cycle allows rapid iteration

**Coordination needed:**
- Daily standups to share findings
- Shared XBOW results dashboard
- Prioritization meetings (focus on highest-impact fixes)

---

## Risk Mitigation Strategies

### Risk 1: XBOW 70% Not Achieved

**Mitigation:**
- Iterative testing (Weeks 4, 8, 12) allows course correction
- Fallback demo focuses on technical sophistication (task graphs, evidence chains)
- Honest messaging: "70% target, achieved X%, path to 85% by Month 6"

**Fallback Success Criteria:**
- 50% XBOW + compelling architecture = viable demo
- 60% XBOW + Nessus workflow = strong demo
- 70% XBOW + all features = excellent demo

---

### Risk 2: Team Capacity Insufficient

**Mitigation:**
- Ruthless prioritization (defer non-critical features)
- Contractor option (for integrations, UI polish)
- Extend timeline if needed (60 days → 75 days acceptable)

**Early Warning Signs:**
- Week 4: Task graphs not complete → scale back evidence chain scope
- Week 8: Multi-agent not working → simplify to 2 agents (defer Reflector)
- Week 10: XBOW <50% → focus on demo polish vs XBOW improvement

---

### Risk 3: LLM Costs Exceed Budget

**Mitigation:**
- Use Ollama for development (free local models)
- Cost tracking with alerts (warn before exceeding budget)
- Model selection optimization (Haiku for most tasks, Sonnet for critical)

**Budget Guidelines:**
- Development: <$500/month (use local Ollama)
- XBOW testing: <$200/test (estimate 5-10 tests = $1-2k)
- Demo: <$50/demo (pre-cache responses, use demo mode)

---

### Risk 4: Technical Complexity Underestimated

**Mitigation:**
- Start simple, iterate (don't build perfect system in one go)
- Use proven patterns (don't invent new architectures)
- Reference competitor implementations (learn from what works)
- Ask for help (community, forums, maintainers)

**Simplification Options:**
- Task graphs: Start with simple DAG, defer complex features
- Evidence chains: Start with basic confidence scoring, defer advanced reasoning
- Multi-agent: Start with 2 agents (Planner + Executor), defer Reflector
- Integrations: Start with import-only, defer real-time API sync

---

## Success Metrics

### Week 4 (End of Month 1)
- [ ] Task graph execution working (5+ parallel tasks)
- [ ] Evidence chains tracked (basic confidence scoring)
- [ ] LLM integration complete (OpenAI + Anthropic)
- [ ] XBOW baseline test complete (documented results)
- [ ] 25 tools integrated with AI orchestration

### Week 8 (End of Month 2)
- [ ] Multi-agent (P-E-R) operational
- [ ] Nessus integration functional (import → exploitation)
- [ ] C2 listener + lightweight agent working
- [ ] XBOW improvement test: 50-60% success
- [ ] 50+ tools integrated

### Week 12 (End of MVP)
- [ ] XBOW final test: 70%+ success ✅
- [ ] Full autonomous pentesting workflow operational
- [ ] PDF report generation working
- [ ] Demo ready and rehearsed
- [ ] 100+ tools integrated

---

## Next Steps

1. **Immediate (Today):**
   - Share this action plan with team
   - Assign team members to work streams
   - Schedule Week 2 XBOW acquisition review

2. **Week 1 Kickoff:**
   - Daily standups starting Monday
   - Set up development environments
   - Begin task graph implementation

3. **Week 2 Checkpoint:**
   - XBOW benchmark acquisition status
   - Task graph progress review
   - Adjust timeline if needed

4. **Week 4 Milestone:**
   - XBOW baseline test
   - Month 1 retrospective
   - Month 2 planning

---

**END OF ACTION PLAN**

**Total Duration:** 12 weeks (60 days + buffer)
**Team Size:** 5-6 developers → 10-12 developers
**Success Metric:** 70%+ XBOW benchmark success
**Confidence Level:** 8/10 (achievable with execution discipline)
