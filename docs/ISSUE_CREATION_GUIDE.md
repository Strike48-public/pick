# Issue Creation Guide: StrikeKit + Pick Gap Analysis

**Date:** 2026-04-07
**Based on:** Competitive gap analysis (25+ competitors, 17 gaps identified)

---

## Overview

This guide provides the complete plan for creating GitHub issues across StrikeKit and Pick repositories to close competitive gaps and achieve 70%+ XBOW benchmark success within 60 days.

**Total Issues:** 18 epics (5 critical, 6 high priority, 7 medium priority)
**Repositories:**
- StrikeKit: https://github.com/Strike48/strikekit
- Pick: https://github.com/Strike48-public/pick

---

## Label Setup (Do First)

### Priority Labels
- `P0-critical` - Blocks 70% XBOW, must complete in 60 days
- `P1-high` - Competitive parity, complete in 3-6 months
- `P2-medium` - Enhancements, complete in 6-12 months
- `P3-low` - Nice-to-have, defer beyond 12 months

### Component Labels
- `component:strikekit` - StrikeKit AI orchestration, engagement management
- `component:pick` - Pick tool execution, evidence generation
- `component:integration` - External integrations (Nessus, Mythic, GoPhish)
- `component:infrastructure` - CI/CD, deployment, monitoring
- `component:frontend` - UI, visualization, dashboards

### Team Labels
- `team:ai-foundation` - Task graphs, evidence chains, multi-agent
- `team:strikekit-platform` - Engagement management, C2, LLM integration
- `team:pick-integration` - Tool integration, evidence parsing
- `team:integration` - External integrations
- `team:frontend` - UI, visualization
- `team:qa-docs` - Testing, documentation

### Type Labels
- `type:epic` - Large feature (4+ weeks)
- `type:feature` - Medium feature (1-4 weeks)
- `type:bug` - Defect requiring fix
- `type:technical-debt` - Refactor, optimization
- `type:research` - Spike, investigation

### Milestone Labels
- `milestone:60-day-mvp` - Phase 1 (Weeks 1-12)
- `milestone:competitive-parity` - Phase 2 (Months 3-6)
- `milestone:xbow-mastery` - Phase 3 (Months 7-9)
- `milestone:enterprise-polish` - Phase 4 (Months 10-12)

### Status Labels
- `status:blocked` - Waiting on dependency
- `status:needs-review` - PR ready, needs approval
- `status:needs-testing` - Implementation done, needs XBOW test

---

## Milestone Setup (Do Second)

Create these milestones in both repositories:

### Milestone 1: 60-Day MVP
**Due Date:** Week 12 (2026-05-30)
**Description:** 70%+ XBOW success, functional autonomous pentesting with task graphs, evidence chains, and multi-agent coordination

### Milestone 2: Competitive Parity
**Due Date:** Month 6 (2026-09-30)
**Description:** 85%+ XBOW success, feature parity with leading open source platforms (PoC validation, browser automation, RAG)

### Milestone 3: XBOW Mastery
**Due Date:** Month 9 (2026-12-31)
**Description:** 90%+ XBOW success, public validation, knowledge graph, advanced multi-agent

### Milestone 4: Enterprise Polish
**Due Date:** Month 12 (2027-03-31)
**Description:** Production-ready, 5-10 pilot customers, advanced reporting, comprehensive documentation

---

## Issue Creation Strategy

### Phase 1: Week 1 (Critical Path)
Create **EPIC-000 through EPIC-004** (5 issues)
- All in StrikeKit repository
- P0 priority
- Milestone: 60-Day MVP
- Set up dependency chain

### Phase 2: Week 2 (Integration Requirements)
Create **EPIC-005 through EPIC-006** (2 issues)
- EPIC-005: Integration repo or StrikeKit
- EPIC-006: Pick repo
- P0/P1 priority
- Milestone: 60-Day MVP

### Phase 3: Week 4+ (After XBOW Baseline Test)
Create **EPIC-007 through EPIC-011** (5 issues)
- Based on XBOW failure modes
- P1 priority
- Milestone: Competitive Parity

### Phase 4: Month 3+ (Enhancements)
Create **EPIC-012 through EPIC-018** (7 issues)
- P2 priority
- Milestone: Enterprise Polish

---

## Epic Templates

### EPIC-000: XBOW Benchmark Acquisition 🚨

**Repository:** Strike48/strikekit
**Title:** `[Critical] Obtain XBOW benchmark suite for testing and iteration`

**Labels:** `P0-critical`, `component:infrastructure`, `team:ai-foundation`, `type:research`, `milestone:60-day-mvp`

**Description:**
```markdown
## Problem Statement
Without the XBOW benchmark suite, we cannot measure autonomous pentesting capability or iterate on improvements. Leading platforms achieve 86-96% XBOW success - we need this benchmark to validate our approach and reach 70%+ in 60 days.

## User Story
As a technical lead, I need access to the XBOW benchmark suite so that I can establish a baseline, measure progress, and validate that our AI orchestration achieves competitive success rates.

## Success Criteria
- [ ] Contact XBOW maintainers (Week 1)
- [ ] Obtain XBOW benchmark suite (Week 2 - ABSOLUTE DEADLINE)
- [ ] Set up test environment locally
- [ ] Document benchmark scenarios and requirements
- [ ] Run baseline test with current AutoPwn (Week 4)
- [ ] Establish testing cadence (Week 4, 8, 12)

## Technical Requirements
- Access to XBOW benchmark suite (tests, scenarios, validation criteria)
- Test environment setup (Docker, VMs, or cloud instances)
- Baseline test script (run all scenarios, collect results)
- Results documentation template (success rate, failure modes, analysis)

## XBOW Impact
**Current:** Unknown (never tested)
**Target:** Establish baseline in Week 4 (expected 30-40% with current AutoPwn)
**Justification:** Cannot achieve 70% XBOW goal without benchmark access

## Dependencies
None - this is the root dependency for all other epics

## Blocks
- #EPIC-001 (Task Graph Planning)
- #EPIC-002 (Evidence-Based Reasoning)
- #EPIC-003 (LLM Integration)
- #EPIC-004 (Multi-Agent Architecture)

## Effort Estimate
2 weeks (acquisition + setup)

## Priority Justification
🚨 CRITICAL - Entire 60-day MVP depends on this. Without XBOW access, we cannot validate progress or adjust approach based on data.

## Acceptance Criteria
- XBOW benchmark suite obtained and documented
- Test environment operational
- Baseline test completed (Week 4)
- Results analysis complete with failure categorization
```

---

### EPIC-001: Task Graph Planning with DAG Execution

**Repository:** Strike48/strikekit
**Title:** `[StrikeKit] Implement task graph planning with parallel DAG execution (Enable 5+ concurrent tasks)`

**Labels:** `P0-critical`, `component:strikekit`, `team:ai-foundation`, `type:epic`, `milestone:60-day-mvp`

**Description:**
```markdown
## Problem Statement
Current AutoPwn executes tools sequentially (one at a time), which is slow and inefficient. Leading platforms use directed acyclic graph (DAG) planning to execute 5-15 tasks in parallel, dramatically improving speed and enabling dynamic task insertion based on discoveries.

## User Story
As a pentester, I need parallel task execution so that reconnaissance, scanning, and enumeration run concurrently rather than sequentially, reducing engagement time from hours to minutes.

## Success Criteria
- [ ] Task graph data structures (TaskNode, TaskGraph, edges)
- [ ] DAG representation with dependency tracking
- [ ] Topological sorting for execution order
- [ ] Parallel task execution (5+ concurrent tasks via tokio)
- [ ] Dynamic node insertion (discovered service → new scan tasks)
- [ ] Shared findings board (Arc<RwLock<FindingsBoard>>)
- [ ] Task status tracking (Pending, Running, Success, Failed, Blocked)
- [ ] Real-time visualization in StrikeKit UI

## Technical Requirements

### Data Structures
```rust
pub struct TaskGraph {
    nodes: HashMap<TaskId, TaskNode>,
    edges: Vec<(TaskId, TaskId)>,
    shared_findings: Arc<RwLock<FindingsBoard>>,
}

pub struct TaskNode {
    id: TaskId,
    tool: ToolType,
    params: ToolParams,
    status: TaskStatus,
    evidence: Vec<Evidence>,
    confidence: f32,
    created_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}
```

### Features
- Topological sort for dependency resolution
- Async execution (tokio runtime)
- Dynamic task insertion (discovery-driven)
- Failure handling (retry, skip, or block dependent tasks)
- Progress tracking (X/Y tasks complete)

## XBOW Impact
**Current:** 30-40% baseline (sequential execution)
**Target:** 45-50% with parallel execution
**Justification:** Parallel execution enables faster discovery and reduces time to exploitation

## Dependencies
- Requires: #EPIC-000 (XBOW Benchmark - need baseline before implementing)

## Blocks
- #EPIC-002 (Evidence chains need task graph foundation)
- #EPIC-004 (Multi-agent needs task graph for coordination)

## Effort Estimate
4-6 weeks

### Week 1-2: Foundation
- [ ] Design data structures (TaskGraph, TaskNode)
- [ ] Implement DAG representation
- [ ] Build topological sorting
- [ ] Set up shared findings board

### Week 3-4: Execution Engine
- [ ] Implement async task scheduler
- [ ] Add parallel execution (tokio)
- [ ] Handle task dependencies
- [ ] Test with 5+ concurrent tasks

### Week 5-6: Dynamic Planning
- [ ] Dynamic node insertion
- [ ] Discovery-driven task generation
- [ ] Real-time UI updates
- [ ] Integration testing

## Priority Justification
P0 - Foundation for all AI orchestration. Evidence chains, multi-agent, and LLM integration all depend on task graph infrastructure.

## Acceptance Criteria
- Task graph executes 5+ tasks in parallel
- Dynamic task insertion working (discovered HTTP → launch web scans)
- Real-time visualization in StrikeKit shows progress
- XBOW improvement test shows 45-50% success (up from 30-40% baseline)
```

---

### EPIC-002: Evidence-Based Reasoning Framework

**Repository:** Strike48/strikekit
**Title:** `[StrikeKit] Implement evidence-based reasoning with confidence scoring (Prevent AI hallucinations)`

**Labels:** `P0-critical`, `component:strikekit`, `team:ai-foundation`, `type:epic`, `milestone:60-day-mvp`

**Description:**
```markdown
## Problem Statement
Without evidence-based reasoning, AI can hallucinate vulnerabilities that don't exist or recommend exploits without proof. Leading platforms use Evidence → Hypothesis → Vulnerability → Exploit chains with confidence scoring to prevent false positives and ensure trustworthy AI.

## User Story
As a security professional, I need evidence-based reasoning so that every finding is backed by actual tool output, reducing false positives and building trust in AI recommendations.

## Success Criteria
- [ ] Evidence chain data structures (Evidence, Hypothesis, Vulnerability, Exploit)
- [ ] Confidence scoring system (0.0-1.0 scale)
- [ ] Evidence → Hypothesis → Action pipeline
- [ ] Confidence threshold enforcement (reject if < 0.7)
- [ ] Human approval gates for high-risk actions
- [ ] Audit trail (evidence → finding with full chain)
- [ ] UI visualization of evidence chains

## Technical Requirements

### Data Structures
```rust
pub struct EvidenceChain {
    evidence: Vec<Evidence>,
    hypothesis: Hypothesis,
    vulnerability: Option<Vulnerability>,
    exploit: Option<Exploit>,
    confidence: f32,
}

pub struct Evidence {
    source: String, // Tool name
    output: String, // Raw tool output
    timestamp: DateTime<Utc>,
    evidence_type: EvidenceType,
}

pub enum EvidenceType {
    PortOpen { port: u16, service: Option<String> },
    ServiceBanner { service: String, version: Option<String> },
    VulnerabilityFound { cve_id: String, cvss: f32 },
    CredentialExtracted { username: String, hash: String },
    ExploitSuccess { technique: String, result: String },
}

pub struct Hypothesis {
    description: String,
    supporting_evidence: Vec<EvidenceId>,
    confidence: f32,
    generated_by: String, // AI model name
}
```

### Features
- Every hypothesis requires supporting evidence
- Confidence scoring propagates through chain
- Reject attacks with confidence < threshold (default 0.7)
- Human approval required for high-risk exploits
- Audit trail from evidence → finding

## XBOW Impact
**Current:** 45-50% with task graphs
**Target:** 55-60% with evidence-based reasoning
**Justification:** Reduces false positives and improves decision quality

## Dependencies
- Requires: #EPIC-001 (Task Graph Planning - evidence comes from tasks)

## Blocks
- #EPIC-004 (Multi-agent needs evidence chains for decision-making)

## Effort Estimate
4-6 weeks

### Week 1-2: Schema & Pipeline
- [ ] Design evidence chain data structures
- [ ] Implement confidence scoring system
- [ ] Build evidence → hypothesis pipeline
- [ ] Add confidence threshold enforcement

### Week 3-4: Integration
- [ ] Integrate with task graph (tasks generate evidence)
- [ ] Add human approval gates
- [ ] Build audit trail system
- [ ] Test evidence chain tracking

### Week 5-6: UI & Polish
- [ ] Evidence chain visualization
- [ ] Confidence score display
- [ ] Manual override capabilities
- [ ] Integration testing

## Priority Justification
P0 - Required for trustworthy AI and XBOW success. Without evidence chains, AI decisions lack credibility and increase false positive rate.

## Acceptance Criteria
- No exploit execution without evidence chain
- Confidence scores visible in UI
- Human can override low-confidence decisions
- Audit log shows evidence → hypothesis → action
- XBOW improvement test shows 55-60% success
```

---

### EPIC-003: LLM Integration with Multi-Provider Support

**Repository:** Strike48/strikekit
**Title:** `[StrikeKit] Implement LLM integration with multi-provider support and cost tracking (OpenAI, Anthropic, Ollama)`

**Labels:** `P0-critical`, `component:strikekit`, `team:strikekit-platform`, `type:epic`, `milestone:60-day-mvp`

**Description:**
```markdown
## Problem Statement
Current LLM integration is basic (single provider, no cost tracking, no optimization). Leading platforms support 15+ LLM providers with automatic fallback, cost optimization, and model selection per task type. Need full provider abstraction for competitive capability.

## User Story
As a pentester, I need flexible LLM options so that I can use local models (Ollama) for privacy/cost, cloud models (OpenAI, Anthropic) for quality, with automatic fallback if one provider fails.

## Success Criteria
- [ ] Provider abstraction layer (trait-based)
- [ ] OpenAI provider (GPT-4o, GPT-4o-mini)
- [ ] Anthropic provider (Claude Sonnet 4.6, Opus 4.6, Haiku 4.5)
- [ ] Ollama provider (local models: Llama 3.1, Qwen, Mistral)
- [ ] DeepSeek provider (DeepSeek-R1)
- [ ] Cost tracking (tokens used, estimated cost per engagement)
- [ ] Budget alerts (configurable threshold)
- [ ] Automatic provider fallback (if API fails)
- [ ] Model selection per task type (Planner vs Executor vs Reflector)

## Technical Requirements

### Provider Abstraction
```rust
pub trait LLMProvider: Send + Sync {
    async fn complete(&self, prompt: &str) -> Result<String>;
    async fn complete_with_tools(&self, prompt: &str, tools: &[ToolSchema]) -> Result<String>;
    fn cost_per_token(&self) -> (f64, f64); // (input, output)
}

pub struct LLMClient {
    provider: Box<dyn LLMProvider>,
    usage_tracker: Arc<UsageTracker>,
}
```

### Providers
- OpenAI: GPT-4o ($5/$15 per 1M tokens), GPT-4o-mini ($0.15/$0.60)
- Anthropic: Claude Sonnet 4.6 ($3/$15), Opus 4.6 ($15/$75), Haiku 4.5 ($1/$5)
- Ollama: Free (local), supports Llama 3.1, Qwen 32B, Mistral 7B
- DeepSeek: DeepSeek-R1 ($0.55/$2.19)

### Cost Tracking
- Tokens used (input/output per engagement)
- Estimated cost per engagement
- Budget alerts (e.g., warn at $50, block at $100)
- Cost reporting in StrikeKit dashboard

## XBOW Impact
**Parallel with EPIC-002** - LLM quality directly impacts decision quality
**Target:** Enable AI-powered tool selection and exploit recommendations
**Justification:** Multi-provider support prevents vendor lock-in and enables cost optimization

## Dependencies
None (parallel work stream)

## Blocks
- #EPIC-004 (Multi-agent needs LLM integration)

## Effort Estimate
3-4 weeks

### Week 1: Foundation
- [ ] Design provider trait
- [ ] Implement OpenAI provider
- [ ] Implement Anthropic provider
- [ ] Test basic completion

### Week 2: Expansion
- [ ] Implement Ollama provider
- [ ] Implement DeepSeek provider
- [ ] Add cost tracking
- [ ] Build usage tracker

### Week 3: Optimization
- [ ] Automatic provider fallback
- [ ] Model selection per task type
- [ ] Budget alerts
- [ ] Cost dashboard

### Week 4: Integration & Testing
- [ ] Integrate with task graph
- [ ] Test all providers
- [ ] Verify cost tracking accuracy
- [ ] Performance testing

## Priority Justification
P0 - Foundation for AI orchestration. Planner, Executor, and Reflector agents all require LLM access.

## Acceptance Criteria
- Support at least 4 providers (OpenAI, Anthropic, Ollama, DeepSeek)
- Cost tracking accurate within 5%
- Automatic fallback working (if OpenAI fails, try Anthropic)
- Budget alerts functional
- Model selection per agent type working
```

---

### EPIC-004: Multi-Agent Architecture (P-E-R Pattern)

**Repository:** Strike48/strikekit
**Title:** `[StrikeKit] Implement multi-agent architecture with Planner-Executor-Reflector pattern (Target: 50-60% XBOW)`

**Labels:** `P0-critical`, `component:strikekit`, `team:ai-foundation`, `type:epic`, `milestone:60-day-mvp`

**Description:**
```markdown
## Problem Statement
Current AutoPwn is a single-agent system with basic hardware detection and sequential tool execution. Leading platforms use multi-agent architectures (3-13 specialized agents) to achieve 86-96% XBOW success. Need Planner-Executor-Reflector (P-E-R) pattern for autonomous pentesting capability.

## User Story
As a security researcher, I need autonomous pentesting with intelligent planning and failure recovery so that I can achieve 70%+ XBOW benchmark success without manual intervention.

## Success Criteria
- [ ] Planner agent (strategic planning, task graph generation)
- [ ] Executor agent (tool execution, evidence collection)
- [ ] Reflector agent (failure analysis, learning from mistakes)
- [ ] Inter-agent communication (message passing)
- [ ] Full P-E-R cycle operational (Planner → Executor → Reflector → Planner)
- [ ] XBOW test: 50-60% success (up from 30-40% baseline)

## Technical Requirements

### Agent Interfaces
```rust
pub struct AIOrchestrator {
    planner: PlannerAgent,
    executor: ExecutorAgent,
    reflector: ReflectorAgent,
    task_graph: Arc<RwLock<TaskGraph>>,
}

pub struct PlannerAgent {
    llm: LLMClient,
    engagement_context: EngagementContext,
}

pub struct ExecutorAgent {
    tool_registry: ToolRegistry,
    sandbox: Sandbox,
}

pub struct ReflectorAgent {
    llm: LLMClient,
}
```

### Agent Responsibilities

**Planner Agent:**
- Generate initial task graph from engagement context
- Analyze evidence and adapt plan (dynamic replanning)
- Prioritize tasks based on findings
- Recommend next actions

**Executor Agent:**
- Execute tools in sandbox (Pick integration)
- Parse tool output into structured evidence
- Update task status (Success, Failed)
- Generate evidence with confidence scores

**Reflector Agent:**
- Analyze task failures (L1-L4 categorization)
  - L1: Tool execution failure (syntax error, missing tool)
  - L2: Tool output parsing failure (unexpected format)
  - L3: Logical failure (wrong tool for task)
  - L4: Strategic failure (wrong approach)
- Recommend fixes (retry with different params, try different tool)
- Learn from mistakes (update task selection logic)

## XBOW Impact
**Current:** 30-40% baseline (sequential AutoPwn)
**Target:** 50-60% with multi-agent coordination
**Justification:** P-E-R pattern is standard in leading platforms achieving 86-96% XBOW

## Dependencies
- Requires: #EPIC-001 (Task Graph Planning - foundation for coordination)
- Requires: #EPIC-002 (Evidence-Based Reasoning - agents use evidence)
- Requires: #EPIC-003 (LLM Integration - agents need LLM access)

## Effort Estimate
8-10 weeks (Weeks 1-10 of 60-day MVP)

### Week 1-4: Planner Agent
- [ ] Design Planner agent interface
- [ ] Implement engagement context
- [ ] Build initial task graph generation (LLM-powered)
- [ ] Add adaptive planning (new findings → new tasks)
- [ ] Test Planner in isolation

### Week 5-6: Executor Agent
- [ ] Design Executor agent interface
- [ ] Integrate with Pick tool registry
- [ ] Build evidence parsing (tool output → structured evidence)
- [ ] Test Planner → Executor workflow
- [ ] Integration testing

### Week 7-8: Reflector Agent
- [ ] Design Reflector agent interface
- [ ] Implement failure categorization (L1-L4)
- [ ] Build failure analysis workflow
- [ ] Test full P-E-R cycle
- [ ] Integration testing

### Week 9-10: Optimization & Testing
- [ ] Optimize inter-agent communication
- [ ] Improve decision quality
- [ ] XBOW improvement test (target: 50-60%)
- [ ] Fix top failure modes
- [ ] Performance tuning

## Priority Justification
P0 - Core autonomous pentesting capability. Required for 70% XBOW success and competitive positioning.

## Acceptance Criteria
- Planner generates task graphs from engagement context
- Executor executes tools and collects evidence
- Reflector analyzes failures and recommends fixes
- Full P-E-R cycle operational
- XBOW test: 50-60% success rate (demonstrable improvement from baseline)
- Inter-agent communication working (message passing, shared state)
```

---

### EPIC-005: Nessus Integration Workflow

**Repository:** Strike48/strikekit (or integration repo if exists)
**Title:** `[Integration] Implement Nessus XML import and AI-powered exploitation workflow (Demo requirement)`

**Labels:** `P0-critical`, `component:integration`, `team:integration`, `type:epic`, `milestone:60-day-mvp`

**Description:**
```markdown
## Problem Statement
Nessus is the industry-standard vulnerability scanner. For the investor demo, we need to show: Nessus scan → Import to StrikeKit → AI analyzes vulnerabilities → Pick exploits them → Results in professional report. This workflow demonstrates real-world value and integration capability.

## User Story
As a pentester, I need to import Nessus scan results so that AI can automatically prioritize and exploit the most critical vulnerabilities, reducing time from vulnerability discovery to exploitation.

## Success Criteria
- [ ] Nessus XML parser (extract hosts, services, vulnerabilities)
- [ ] Create Target entries in StrikeKit (IP, hostname, OS, services)
- [ ] Create Finding entries (High/Critical vulns → Findings)
- [ ] AI analysis (prioritize by exploitability)
- [ ] Generate exploitation task graph (Pick tools for each vuln)
- [ ] Execute exploitation via Pick
- [ ] Update findings with exploitation results
- [ ] Generate PDF report (Nessus found → Pick exploited → Evidence)

## Technical Requirements

### Nessus XML Schema
```rust
pub struct NessusReport {
    hosts: Vec<Host>,
    vulnerabilities: Vec<Vulnerability>,
}

pub struct Host {
    ip: IpAddr,
    hostname: Option<String>,
    os: Option<String>,
    services: Vec<Service>,
}

pub struct Vulnerability {
    plugin_id: String,
    severity: Severity, // Critical, High, Medium, Low, Info
    cve_id: Option<String>,
    cvss: Option<f32>,
    description: String,
    affected_hosts: Vec<IpAddr>,
}
```

### Workflow Steps
1. User uploads .nessus file to StrikeKit
2. Parse XML (extract hosts, services, vulnerabilities)
3. Create Target entries (IP, hostname, OS, services)
4. Create Finding entries (High/Critical vulns)
5. Send to AI for analysis (prioritize by exploitability)
6. Generate task graph (which Pick tools to use)
7. Present to user (HITL approval)
8. Execute via Pick (exploit vulnerabilities)
9. Update findings with results (success/failure + evidence)
10. Generate PDF report

## XBOW Impact
Not directly measured by XBOW, but critical for demo and real-world value proposition.

## Dependencies
- Requires: #EPIC-001 (Task Graph - AI generates tasks from vulns)
- Requires: #EPIC-004 (Multi-Agent - Planner analyzes Nessus results)

## Effort Estimate
2-3 weeks

### Week 1: Parser & Import
- [ ] Research Nessus XML schema
- [ ] Implement XML parser (quick-xml)
- [ ] Create Target entries
- [ ] Create Finding entries
- [ ] Test with sample .nessus files

### Week 2: AI Integration
- [ ] Send findings to Planner agent
- [ ] Generate exploitation task graph
- [ ] Integrate with Pick tool execution
- [ ] Test Nessus → Pick workflow

### Week 3: Reporting & Polish
- [ ] Update findings with exploitation results
- [ ] Generate PDF report (before/after)
- [ ] UI for Nessus import
- [ ] End-to-end testing

## Priority Justification
P0 - Required for investor demo. This workflow demonstrates: (1) Integration capability, (2) AI analysis, (3) Automated exploitation, (4) Professional reporting. Critical for funding.

## Acceptance Criteria
- Can import .nessus XML file
- Creates targets and findings in StrikeKit
- AI generates exploitation plan
- Pick executes exploitation tasks
- PDF report shows: Nessus finding → Pick exploitation → Evidence
- Full workflow completes in <10 minutes for demo
```

---

### EPIC-006: Pick Tool Count Expansion (80 → 100+)

**Repository:** Strike48-public/pick
**Title:** `[Pick] Expand integrated tool count from 80 to 100+ with AI orchestration (Quality over quantity)`

**Labels:** `P1-high`, `component:pick`, `team:pick-integration`, `type:epic`, `milestone:60-day-mvp`

**Description:**
```markdown
## Problem Statement
Pick currently has 80 tools integrated with AI orchestration. Competitors have 150-176+ tools. While we have 3000+ BlackArch tools available, only 80 are integrated with AI (schema, evidence parser, confidence scorer). Need to expand integration depth for competitive positioning.

## User Story
As a pentester, I need more tools integrated with AI orchestration so that the AI can select the best tool for each task, rather than falling back to manual tool selection.

## Success Criteria
- [ ] Integrate 20+ additional tools (target: 100+ total)
- [ ] Each tool has: Schema, evidence parser, confidence scorer
- [ ] Tool chaining logic (when to use tool X after tool Y)
- [ ] Failure handling (what to try if tool fails)
- [ ] Documentation (tool usage, parameters, examples)

## Tool Categories to Expand

### Network Scanning (Add 5)
- [ ] zmap (fast network scanner)
- [ ] masscan-fast (optimized masscan)
- [ ] shodan-cli (Shodan API integration)
- [ ] censys-cli (Censys API integration)
- [ ] legion (automated scanner framework)

### Web Application Testing (Add 5)
- [ ] nuclei (vulnerability scanner with templates)
- [ ] arjun (parameter discovery)
- [ ] commix (command injection testing)
- [ ] xsstrike (XSS detection)
- [ ] dalfox (XSS/SSRF scanner)

### Post-Exploitation (Add 5)
- [ ] mimikatz (credential extraction)
- [ ] rubeus (Kerberos attacks)
- [ ] bloodhound-python (AD enumeration)
- [ ] sharpup (Windows privilege escalation)
- [ ] winpeas (Windows enumeration)

### Active Directory (Add 3)
- [ ] ldapdomaindump (AD enumeration)
- [ ] GetUserSPNs (Kerberoasting)
- [ ] GetNPUsers (AS-REP roasting)

### Wireless (Add 2)
- [ ] kismet (wireless monitoring)
- [ ] reaver (WPS attacks)

## Technical Requirements

For each tool, implement:

```rust
pub struct ToolIntegration {
    schema: ToolSchema,
    parser: EvidenceParser,
    scorer: ConfidenceScorer,
    chaining_rules: Vec<ChainRule>,
}

pub struct ToolSchema {
    name: String,
    description: String,
    parameters: Vec<Parameter>,
    requires_root: bool,
    estimated_runtime: Duration,
}

pub struct EvidenceParser {
    parse_fn: Box<dyn Fn(&str) -> Result<Vec<Evidence>>>,
}

pub struct ConfidenceScorer {
    score_fn: Box<dyn Fn(&Evidence) -> f32>,
}
```

## XBOW Impact
**Indirect:** More tools = better coverage = higher XBOW success
**Target:** Each new tool improves specific XBOW scenarios
**Priority:** Quality over quantity - focus on high-impact tools

## Dependencies
None (parallel work stream)

## Effort Estimate
4-6 weeks (ongoing)

### Week 1-2: Network & Web Tools (10 tools)
- [ ] Integrate 5 network scanning tools
- [ ] Integrate 5 web testing tools
- [ ] Add evidence parsers
- [ ] Test with AI orchestration

### Week 3-4: Post-Exploitation & AD Tools (8 tools)
- [ ] Integrate 5 post-exploitation tools
- [ ] Integrate 3 AD tools
- [ ] Add confidence scorers
- [ ] Test exploitation workflows

### Week 5-6: Wireless & Polish (2 tools + optimization)
- [ ] Integrate 2 wireless tools
- [ ] Optimize tool chaining logic
- [ ] Add failure handling
- [ ] Documentation

## Priority Justification
P1 - Important for competitive positioning ("100+ tools integrated" sounds better than "80") but not blocking 70% XBOW. Quality of integration matters more than quantity.

## Acceptance Criteria
- 100+ tools integrated with AI orchestration
- Each new tool has schema, parser, scorer
- Tool chaining logic working (AI selects appropriate tools)
- Failure handling working (retry with different tool if first fails)
- Documentation complete (usage guide per tool)
```

---

## Commands to Create Issues

### Setup Labels (Run First)
```bash
# StrikeKit repo
gh label create "P0-critical" --color "d73a4a" --description "Blocks 70% XBOW, must complete in 60 days" --repo Strike48/strikekit
gh label create "P1-high" --color "fbca04" --description "Competitive parity, complete in 3-6 months" --repo Strike48/strikekit
gh label create "P2-medium" --color "0e8a16" --description "Enhancements, complete in 6-12 months" --repo Strike48/strikekit
gh label create "component:strikekit" --color "1d76db" --repo Strike48/strikekit
gh label create "team:ai-foundation" --color "bfd4f2" --repo Strike48/strikekit
gh label create "type:epic" --color "5319e7" --repo Strike48/strikekit
gh label create "milestone:60-day-mvp" --color "d4c5f9" --repo Strike48/strikekit

# Pick repo
gh label create "P0-critical" --color "d73a4a" --description "Blocks 70% XBOW, must complete in 60 days" --repo Strike48-public/pick
gh label create "P1-high" --color "fbca04" --description "Competitive parity, complete in 3-6 months" --repo Strike48-public/pick
gh label create "component:pick" --color "1d76db" --repo Strike48-public/pick
gh label create "team:pick-integration" --color "bfd4f2" --repo Strike48-public/pick
gh label create "type:epic" --color "5319e7" --repo Strike48-public/pick
gh label create "milestone:60-day-mvp" --color "d4c5f9" --repo Strike48-public/pick
```

### Create Milestones (Run Second)
```bash
# StrikeKit repo
gh milestone create --title "60-Day MVP" --due-date "2026-05-30" --description "70% XBOW success, functional autonomous pentesting" --repo Strike48/strikekit
gh milestone create --title "Competitive Parity" --due-date "2026-09-30" --description "85% XBOW success, feature parity with leading platforms" --repo Strike48/strikekit
gh milestone create --title "XBOW Mastery" --due-date "2026-12-31" --description "90% XBOW success, public validation" --repo Strike48/strikekit
gh milestone create --title "Enterprise Polish" --due-date "2027-03-31" --description "Production-ready, 5-10 pilot customers" --repo Strike48/strikekit

# Pick repo
gh milestone create --title "60-Day MVP" --due-date "2026-05-30" --description "70% XBOW success, functional autonomous pentesting" --repo Strike48-public/pick
gh milestone create --title "Competitive Parity" --due-date "2026-09-30" --description "85% XBOW success, feature parity with leading platforms" --repo Strike48-public/pick
gh milestone create --title "XBOW Mastery" --due-date "2026-12-31" --description "90% XBOW success, public validation" --repo Strike48-public/pick
gh milestone create --title "Enterprise Polish" --due-date "2027-03-31" --description "Production-ready, 5-10 pilot customers" --repo Strike48-public/pick
```

### Create Issues (Run Third)
See individual epic templates above for full issue bodies. Use:
```bash
gh issue create --title "TITLE" --body "BODY" --label "labels" --milestone "milestone" --repo "repo"
```

---

## Issue Creation Checklist

### Phase 1: Week 1 (Critical Path)
- [ ] Set up labels in both repos
- [ ] Create milestones in both repos
- [ ] Create EPIC-000: XBOW Benchmark Acquisition
- [ ] Create EPIC-001: Task Graph Planning
- [ ] Create EPIC-002: Evidence-Based Reasoning
- [ ] Create EPIC-003: LLM Integration
- [ ] Create EPIC-004: Multi-Agent Architecture
- [ ] Set up dependency chain (EPIC-001 depends on EPIC-000, etc.)

### Phase 2: Week 2 (Integration)
- [ ] Create EPIC-005: Nessus Integration
- [ ] Create EPIC-006: Pick Tool Expansion

### Phase 3: Week 4+ (After XBOW Baseline)
- [ ] Analyze XBOW failure modes
- [ ] Create high-priority epics based on results
- [ ] Prioritize fixes

---

## Success Metrics

### Week 2
- [ ] All labels created
- [ ] All milestones created
- [ ] 7 epics created (EPIC-000 through EPIC-006)
- [ ] Dependencies set up
- [ ] EPIC-000 in progress (XBOW acquisition)

### Week 4
- [ ] EPIC-000 complete (XBOW benchmark obtained)
- [ ] Baseline test complete (results documented)
- [ ] EPIC-001 in progress (task graphs)
- [ ] EPIC-002 in progress (evidence chains)
- [ ] EPIC-003 in progress (LLM integration)

### Week 12
- [ ] EPIC-001 through EPIC-004 complete
- [ ] EPIC-005 complete (Nessus workflow working)
- [ ] EPIC-006 substantial progress (90+ tools integrated)
- [ ] XBOW final test: 70%+ success

---

**END OF ISSUE CREATION GUIDE**
