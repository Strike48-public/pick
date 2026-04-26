# 60-Day MVP Roadmap: Pick + StrikeKit

**Target:** Autonomous pentesting with transparent AI reasoning
**Team Size:** 4-6 developers
**Timeline:** 8 weeks (April 7 - June 7, 2026)

---

## Success Criteria

**Priority 1 (Must Demo):**
1. WiFi AutoPwn working end-to-end (already exists - polish)
2. Evidence chains visible in knowledge graph (Maltego/Neo4j style)

**Priority 2:**
3. Manual target with AI planning (user specifies target, AI plans attack)

**Priority 3:**
4. Nessus import with autonomous exploitation

**Priority 4:**
5. Multi-engagement management

---

## Feature Teams

### Team A: Evidence Chain Infrastructure (2 devs)
**Scope:** Build full causal chain system + knowledge graph UI

**Deliverables:**
- Database schema (Hypothesis, ExploitAttempt, Evidence Chain tables)
- Evidence chain tracking (Evidence -> Hypothesis -> Exploit -> Finding)
- Confidence scoring propagation
- Knowledge graph visualization (JS graph library integration)

### Team B: RAG Knowledge Base (1-2 devs)
**Scope:** ExploitDB/PayloadsAllTheThings indexing for AI recommendations

**Deliverables:**
- Qdrant vector database setup
- ExploitDB ingestion pipeline
- PayloadsAllTheThings ingestion
- Semantic search API
- LLM integration for exploit recommendation

### Team C: AI Planning & Reflector (1-2 devs)
**Scope:** LLM-powered task generation + failure analysis

**Deliverables:**
- Reflector agent implementation
- AI task generation (replace hardcoded AutoPwn logic)
- Replanning based on execution results
- Confidence scoring for recommendations

### Team D: Integrations & Polish (1 dev)
**Scope:** Nessus import + report generation + testing

**Deliverables:**
- Nessus XML import workflow
- Report generation (evidence -> findings -> PDF)
- Integration testing
- Bug fixes and polish

---

## Dependency Graph

```
Week 1-2: Foundation
├─ [A1] Evidence Chain Schema Design
├─ [B1] Qdrant Setup + ExploitDB Ingestion
├─ [C1] Reflector Agent Implementation
└─ [D1] Nessus XML Parser

Week 3-4: Core Implementation
├─ [A2] Evidence Chain Tracking (depends on A1)
├─ [A3] Confidence Scoring (depends on A2)
├─ [B2] PayloadsAllTheThings Ingestion (depends on B1)
├─ [B3] Semantic Search API (depends on B2)
├─ [C2] AI Task Generation (depends on C1, B3)
└─ [D2] Nessus Import Workflow (depends on D1)

Week 5-6: Integration
├─ [A4] Knowledge Graph UI (depends on A3)
├─ [C3] Replanning System (depends on C2)
├─ [D3] Report Generation (depends on A3, D2)
└─ Integration Testing (all teams)

Week 7-8: Polish & Demo Prep
├─ [A5] Knowledge Graph Polish
├─ Bug Fixes (all teams)
├─ Documentation
└─ Demo Preparation
```

**Critical Path:** A1 -> A2 -> A3 -> A4 (Evidence chains block knowledge graph UI)

**Parallel Work:**
- Team B (RAG) works independently until Week 3
- Team C (AI Planning) needs RAG semantic search (B3) by Week 3
- Team D (Integrations) works mostly independently

---

## Weekly Milestones

### Week 1 (April 7-13): Foundation & Schema Design

**Team A: Evidence Chains**
- Design database schema (Hypothesis, ExploitAttempt, EvidenceChain tables)
- Add migration scripts
- Create Rust structs and database access layer
- Write unit tests for schema

**Team B: RAG**
- Setup Qdrant vector database (local + Docker)
- Download ExploitDB archive
- Build ingestion pipeline (parse exploits, generate embeddings)
- Index first 1000 exploits as proof of concept

**Team C: AI Planning**
- Design Reflector agent interface
- Implement failure analysis logic (L1-L4 levels from architecture)
- Create Reflector agent node type in workflow engine
- Write tests for failure categorization

**Team D: Integrations**
- Build Nessus XML parser
- Extract hosts, services, vulnerabilities from .nessus files
- Create Target and Finding entries in StrikeKit
- Write parser tests

**Milestone:** Schema deployed, Qdrant running, Reflector agent interface complete, Nessus parser working

---

### Week 2 (April 14-20): Core Infrastructure

**Team A: Evidence Chains**
- Implement evidence chain tracking in StrikeKit
- Build API to create Evidence -> Hypothesis links
- Build API to create Hypothesis -> ExploitAttempt links
- Create ExploitAttempt -> Finding links
- Write integration tests

**Team B: RAG**
- Complete ExploitDB ingestion (all 50k+ exploits)
- Add PayloadsAllTheThings repository ingestion
- Implement semantic search query API
- Test search quality (precision/recall)
- Document API endpoints

**Team C: AI Planning**
- Implement Reflector agent in StrikeKit workflow engine
- Create system prompts for failure analysis
- Integrate with execution task results
- Test Reflector recommendations

**Team D: Integrations**
- Build Nessus import workflow in StrikeKit
- Create workflow definition for: Parse XML -> Create Targets -> Create Findings
- Test workflow execution
- Add error handling

**Milestone:** Evidence chain APIs working, RAG search operational, Reflector agent functional, Nessus import workflow complete

---

### Week 3 (April 21-27): AI Integration

**Team A: Evidence Chains**
- Implement confidence scoring logic
- Propagate confidence through evidence chains
- Add confidence thresholds for human approval gates
- Create confidence scoring tests

**Team B: RAG**
- Optimize semantic search performance (sub-100ms queries)
- Add CVE exact match search
- Add service/version fuzzy matching
- Build LLM integration for exploit recommendation
- Test recommendation quality

**Team C: AI Planning**
- Replace hardcoded AutoPwn logic with LLM task generation
- Create prompts for network attack planning
- Create prompts for WiFi attack planning
- Integrate RAG semantic search into task generation
- Test AI-generated plans against hardcoded plans

**Team D: Integrations**
- Build report generation workflow
- Create PDF template (findings, evidence, MITRE ATT&CK)
- Integrate evidence chains into reports
- Test report generation

**Milestone:** Confidence scoring working, LLM recommendations using RAG, AI task generation replacing AutoPwn, report generation functional

---

### Week 4 (April 28 - May 4): Advanced Features

**Team A: Evidence Chains**
- Evaluate JS graph libraries (Cytoscape.js, vis.js, D3.js)
- Choose library and integrate into StrikeKit UI
- Build basic graph rendering (nodes + edges)
- Test graph rendering performance

**Team B: RAG**
- Add custom playbook support (enterprise feature)
- Implement cache layer for frequent queries
- Add metrics tracking (query latency, hit rate)
- Performance optimization

**Team C: AI Planning**
- Implement dynamic replanning
- Add replanning triggers (phase complete, task failed, new findings)
- Build replanning prompt templates
- Test replanning with realistic scenarios

**Team D: Integrations**
- Connect Nessus import to AI planning
- Workflow: Nessus XML -> Targets/Findings -> AI generates exploit plan
- Test end-to-end: Nessus -> Plan -> Execution -> Report
- Bug fixes

**Milestone:** Graph UI rendering basic chains, RAG optimized, Replanning working, Nessus -> AI planning integrated

---

### Week 5 (May 5-11): Knowledge Graph Polish

**Team A: Evidence Chains**
- Implement interactive graph features (zoom, pan, click nodes)
- Add node styling by type (Evidence, Hypothesis, Exploit, Finding)
- Add confidence visualization (color-coded nodes/edges)
- Build timeline view (alternative to graph)
- Polish UI/UX

**Team B: RAG**
- Add more data sources (Metasploit modules, public CVE feeds)
- Improve embedding quality (experiment with models)
- Add filtering (by severity, platform, date)
- Documentation for adding custom sources

**Team C: AI Planning**
- Integrate replanning into StrikeKit workflow engine
- Add human approval gates for high-risk actions
- Implement cost tracking for LLM calls
- Add budget alerts

**Team D: Integrations**
- Build manual target AI planning workflow
- User input: target IP/CIDR -> AI generates recon plan
- Test with multiple target types (single host, network, web app)
- Polish error messages

**Milestone:** Knowledge graph fully interactive, RAG with multiple sources, Replanning integrated, Manual target planning working

---

### Week 6 (May 12-18): Integration Testing

**All Teams: Integration Testing**
- End-to-end testing of complete workflows
- Test: WiFi AutoPwn with evidence chains
- Test: Manual target -> AI plan -> execution -> evidence graph
- Test: Nessus import -> AI exploit -> evidence graph -> report
- Performance testing (load, latency, memory)
- Security testing (input validation, SQL injection, XSS)

**Team A: Evidence Chains**
- Fix bugs found in integration testing
- Performance optimization (graph rendering with 100+ nodes)
- Add graph export (PNG, SVG, JSON)

**Team B: RAG**
- Fix search quality issues
- Add relevance scoring improvements
- Cache optimization

**Team C: AI Planning**
- Fix AI planning bugs
- Improve prompt quality based on test results
- Add fallback logic for LLM failures

**Team D: Integrations**
- Fix workflow bugs
- Improve error handling
- Add retry logic

**Milestone:** All Priority 1 & 2 features tested end-to-end, major bugs fixed

---

### Week 7 (May 19-25): Polish & Documentation

**Team A: Evidence Chains**
- UI polish (tooltips, loading states, error messages)
- Add graph filters (show only high-confidence chains)
- Add search within graph
- User documentation

**Team B: RAG**
- API documentation
- Performance tuning
- Add monitoring/alerting
- Deployment guide

**Team C: AI Planning**
- Prompt optimization
- Cost optimization (use cheaper models where possible)
- Add AI reasoning explanations (why this plan?)
- User documentation

**Team D: Integrations**
- Report template improvements
- Add customization options
- Integration documentation
- Example workflows

**Milestone:** All features polished, documented, ready for demo

---

### Week 8 (May 26 - June 1): Demo Preparation

**All Teams: Demo Prep**
- Create demo script
- Setup demo environment
- Record demo video
- Prepare presentation slides
- Practice demo run-throughs

**Final Testing:**
- Smoke tests on all features
- Demo rehearsals
- Bug bash (find and fix remaining issues)
- Performance validation

**Documentation:**
- User guide
- Developer guide
- API documentation
- Deployment guide

**Milestone:** Demo ready, all Priority 1 & 2 features working, documentation complete

---

## Critical Risks

### Risk 1: Evidence Chain Schema Changes
**Probability:** Medium
**Impact:** High (blocks knowledge graph UI)
**Mitigation:** 
- Complete schema design in Week 1
- Get team buy-in before implementation
- Allow 2-3 days buffer for changes

### Risk 2: Knowledge Graph Performance
**Probability:** Medium
**Impact:** Medium (UI slowness affects demo)
**Mitigation:**
- Test with 100+ node graphs early (Week 4)
- Implement pagination/filtering if needed
- Have fallback timeline view

### Risk 3: RAG Search Quality
**Probability:** High
**Impact:** Medium (affects AI recommendations)
**Mitigation:**
- Start testing search quality in Week 2
- Iterate on embeddings and prompts
- Have fallback to keyword search

### Risk 4: LLM Cost Overruns
**Probability:** Medium
**Impact:** Low (development budget concern)
**Mitigation:**
- Use local Ollama for development
- Implement cost tracking early (Week 3)
- Set budget alerts

### Risk 5: Team Velocity Lower Than Expected
**Probability:** Medium
**Impact:** High (delays all features)
**Mitigation:**
- Cut Priority 3 & 4 features if needed
- Focus on Priority 1 (WiFi AutoPwn + Evidence Chains)
- Daily standups to catch blockers early

---

## Definition of Done

**For each feature:**
- [ ] Code implemented and reviewed
- [ ] Unit tests written (80%+ coverage)
- [ ] Integration tests written
- [ ] Documentation updated
- [ ] No critical bugs
- [ ] Passes CI/CD pipeline
- [ ] Demo-ready

**For 60-day MVP:**
- [ ] Priority 1 features working (WiFi AutoPwn + Evidence Chains)
- [ ] Priority 2 features working (Manual target AI planning)
- [ ] Knowledge graph visualization functional
- [ ] RAG-powered exploit recommendations
- [ ] End-to-end workflows tested
- [ ] Demo script prepared
- [ ] Documentation complete

---

## Next Steps

1. Review this roadmap with team
2. Assign developers to feature teams
3. Create GitHub issues from roadmap (see separate issues document)
4. Setup team communication (Slack channels, standups)
5. Kickoff Week 1 on Monday, April 7

---

**END OF ROADMAP**
