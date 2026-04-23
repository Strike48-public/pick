# GitHub Issues: 60-Day MVP

Ready-to-paste GitHub issues for the 60-day MVP roadmap.

**Instructions:**
1. Copy each issue below
2. Create new issue in GitHub
3. Assign appropriate labels (team, milestone, priority)
4. Assign to team member

**Labels to create:**
- `team-a-evidence-chains`
- `team-b-rag`
- `team-c-ai-planning`
- `team-d-integrations`
- `milestone-week-1`, `milestone-week-2`, etc.
- `priority-1-must-have`, `priority-2-should-have`, `priority-3-nice-to-have`

---

## Team A: Evidence Chain Infrastructure

### Issue A1: Design and Implement Evidence Chain Database Schema

**Description:**

Design and implement the database schema for full causal evidence chains (Evidence -> Hypothesis -> Exploit Attempt -> Finding).

**Acceptance Criteria:**

- [ ] New tables created: `evidence`, `hypotheses`, `hypothesis_evidence`, `exploit_attempts`, `evidence_chains`
- [ ] Migration scripts written and tested
- [ ] Foreign key relationships established
- [ ] Indexes created for query performance
- [ ] Schema documented in README or schema.rs comments

**Technical Approach:**

Add the following tables to StrikeKit database:

```sql
-- Evidence: Raw observations from tools
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    source_tool TEXT NOT NULL,
    source_execution_id TEXT REFERENCES task_executions(id),
    evidence_type TEXT NOT NULL,
    target TEXT NOT NULL,
    raw_data TEXT NOT NULL,
    structured_data TEXT NOT NULL DEFAULT '{}',
    confidence REAL NOT NULL,
    timestamp TEXT NOT NULL,
    created_at TEXT NOT NULL
);

-- Hypotheses: AI interpretations of evidence
CREATE TABLE IF NOT EXISTS hypotheses (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    hypothesis_text TEXT NOT NULL,
    hypothesis_type TEXT NOT NULL,
    confidence REAL NOT NULL,
    generated_by TEXT NOT NULL,
    reasoning TEXT,
    created_at TEXT NOT NULL
);

-- Evidence-Hypothesis links
CREATE TABLE IF NOT EXISTS hypothesis_evidence (
    hypothesis_id TEXT NOT NULL REFERENCES hypotheses(id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL REFERENCES evidence(id) ON DELETE CASCADE,
    weight REAL NOT NULL DEFAULT 1.0,
    created_at TEXT NOT NULL,
    PRIMARY KEY (hypothesis_id, evidence_id)
);

-- Exploit attempts based on hypotheses
CREATE TABLE IF NOT EXISTS exploit_attempts (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    hypothesis_id TEXT REFERENCES hypotheses(id) ON DELETE SET NULL,
    task_execution_id TEXT REFERENCES task_executions(id),
    exploit_type TEXT NOT NULL,
    target TEXT NOT NULL,
    parameters TEXT NOT NULL DEFAULT '{}',
    result TEXT NOT NULL DEFAULT 'pending',
    confidence_before REAL NOT NULL,
    confidence_after REAL,
    created_at TEXT NOT NULL,
    completed_at TEXT
);

-- Complete chains for visualization
CREATE TABLE IF NOT EXISTS evidence_chains (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    finding_id TEXT REFERENCES findings(id) ON DELETE CASCADE,
    chain_json TEXT NOT NULL DEFAULT '{}',
    final_confidence REAL NOT NULL,
    created_at TEXT NOT NULL
);
```

**Files to Modify:**

- `crates/sk-db/src/schema.rs`
- `crates/sk-db/src/lib.rs`
- `crates/sk-core/src/types.rs` (add Rust structs)

**Testing:**

- Unit tests for schema creation
- Test foreign key constraints
- Test indexes improve query performance


**Labels:** `team-a-evidence-chains`, `milestone-week-1`, `priority-1-must-have`

---

### Issue A2: Implement Evidence Chain Tracking API

**Description:**

Build API layer to create and query evidence chains (Evidence -> Hypothesis -> Exploit -> Finding).

**Acceptance Criteria:**

- [ ] API to create Evidence entries from tool executions
- [ ] API to create Hypothesis entries with supporting evidence
- [ ] API to link Hypothesis to ExploitAttempt
- [ ] API to link ExploitAttempt to Finding
- [ ] API to query complete evidence chain for a Finding
- [ ] Integration tests for all APIs

**Technical Approach:**

In `crates/sk-db/src/evidence_chain.rs`:

```rust
impl StrikeKitDb {
    pub fn create_evidence(&self, evidence: Evidence) -> Result<()> {
        // Insert into evidence table
    }

    pub fn create_hypothesis(&self, hypothesis: Hypothesis, evidence_ids: Vec<Id>) -> Result<Id> {
        // Insert hypothesis
        // Insert hypothesis_evidence links
    }

    pub fn create_exploit_attempt(&self, attempt: ExploitAttempt) -> Result<Id> {
        // Insert exploit attempt
        // Link to hypothesis
    }

    pub fn get_evidence_chain(&self, finding_id: Id) -> Result<EvidenceChain> {
        // Query full chain: Evidence -> Hypothesis -> Exploit -> Finding
        // Return structured chain for visualization
    }
}
```

**Files to Create:**

- `crates/sk-db/src/evidence_chain.rs`

**Files to Modify:**

- `crates/sk-db/src/lib.rs`

**Testing:**

- Unit tests for each API method
- Integration test: create full chain end-to-end
- Test query performance with 100+ evidence entries


**Labels:** `team-a-evidence-chains`, `milestone-week-2`, `priority-1-must-have`

---

### Issue A3: Implement Confidence Scoring and Propagation

**Description:**

Implement confidence scoring logic that propagates through evidence chains.

**Acceptance Criteria:**

- [ ] Confidence calculation for Hypotheses (based on supporting evidence)
- [ ] Confidence propagation to ExploitAttempts
- [ ] Confidence thresholds for human approval gates
- [ ] API to recalculate confidence when evidence updates
- [ ] Unit tests for scoring logic

**Technical Approach:**

Confidence scoring algorithm:

```rust
fn calculate_hypothesis_confidence(
    evidence: &[Evidence],
    weights: &[f32]
) -> f32 {
    // Weighted average of evidence confidence
    let total_weight: f32 = weights.iter().sum();
    let weighted_sum: f32 = evidence.iter()
        .zip(weights)
        .map(|(e, w)| e.confidence * w)
        .sum();
    
    weighted_sum / total_weight
}

fn should_require_approval(confidence: f32, risk_level: RiskLevel) -> bool {
    match risk_level {
        RiskLevel::High => confidence < 0.9,
        RiskLevel::Medium => confidence < 0.7,
        RiskLevel::Low => confidence < 0.5,
    }
}
```

**Files to Create:**

- `crates/sk-core/src/confidence.rs`

**Testing:**

- Unit tests for confidence calculation
- Test edge cases (no evidence, conflicting evidence)
- Test threshold logic


**Labels:** `team-a-evidence-chains`, `milestone-week-3`, `priority-1-must-have`

---

### Issue A4: Build Knowledge Graph Visualization UI

**Description:**

Build interactive knowledge graph visualization (Maltego/Neo4j style) using JavaScript graph library.

**Acceptance Criteria:**

- [ ] JS graph library integrated (Cytoscape.js or vis.js)
- [ ] Graph renders evidence chains (nodes + edges)
- [ ] Nodes styled by type (Evidence, Hypothesis, Exploit, Finding)
- [ ] Edges show confidence (color-coded or thickness)
- [ ] Interactive features: zoom, pan, click nodes for details
- [ ] Performance tested with 100+ node graphs

**Technical Approach:**

Evaluate and integrate one of:
- Cytoscape.js (recommended - mature, good docs)
- vis.js (good force-directed layout)
- D3.js force graph (most flexible, more complex)

Integration approach:
1. Add JS library to StrikeKit UI assets
2. Create Dioxus component that renders container div
3. Use eval() or script injection to initialize graph
4. Fetch evidence chain data via API
5. Render graph on data load

**Files to Create:**

- `crates/sk-ui/src/components/evidence_graph.rs`
- `crates/sk-ui/assets/cytoscape.min.js` (or chosen library)

**Files to Modify:**

- `crates/sk-ui/src/app.rs` (add route)
- `crates/sk-ui/src/components/sidebar.rs` (add navigation link)

**Testing:**

- Manual testing with sample data
- Performance testing (100+ nodes)
- Cross-browser testing (Chrome, Firefox, Safari)


**Labels:** `team-a-evidence-chains`, `milestone-week-4`, `milestone-week-5`, `priority-1-must-have`

---

### Issue A5: Polish Knowledge Graph UI

**Description:**

Add polish and advanced features to knowledge graph visualization.

**Acceptance Criteria:**

- [ ] Tooltips on hover showing node details
- [ ] Loading states and error messages
- [ ] Graph filters (show only high-confidence chains)
- [ ] Search within graph
- [ ] Export graph (PNG, SVG, JSON)
- [ ] Timeline view (alternative visualization)

**Technical Approach:**

Add features incrementally:
1. Tooltips - use graph library's built-in tooltip support
2. Filters - add UI controls to filter nodes by confidence threshold
3. Search - highlight nodes matching search term
4. Export - use graph library's export methods or html2canvas
5. Timeline - build alternative linear view showing chain progression

**Files to Modify:**

- `crates/sk-ui/src/components/evidence_graph.rs`

**Testing:**

- User acceptance testing
- Accessibility testing (keyboard navigation, screen readers)


**Labels:** `team-a-evidence-chains`, `milestone-week-7`, `priority-2-should-have`

---

## Team B: RAG Knowledge Base

### Issue B1: Setup Qdrant and Ingest ExploitDB

**Description:**

Setup Qdrant vector database and build ingestion pipeline for ExploitDB archive.

**Acceptance Criteria:**

- [ ] Qdrant running (Docker or local)
- [ ] ExploitDB archive downloaded
- [ ] Ingestion script parses exploits and generates embeddings
- [ ] First 1000 exploits indexed successfully
- [ ] Basic search query works

**Technical Approach:**

1. Setup Qdrant:
```bash
docker run -p 6333:6333 qdrant/qdrant
```

2. Download ExploitDB:
```bash
git clone https://github.com/offensive-security/exploitdb.git
```

3. Build ingestion pipeline:
```rust
use qdrant_client::prelude::*;
use serde_json::json;

async fn ingest_exploitdb(client: &QdrantClient, exploits_path: &Path) -> Result<()> {
    // Parse exploit files
    // Generate embeddings (use sentence-transformers or OpenAI)
    // Insert into Qdrant collection
}
```

**Files to Create:**

- `crates/sk-rag/src/lib.rs`
- `crates/sk-rag/src/exploitdb.rs`
- `crates/sk-rag/src/embeddings.rs`

**Testing:**

- Test ingestion with sample exploits
- Verify embeddings are generated correctly
- Test search returns relevant results


**Labels:** `team-b-rag`, `milestone-week-1`, `milestone-week-2`, `priority-1-must-have`

---

### Issue B2: Ingest PayloadsAllTheThings

**Description:**

Add PayloadsAllTheThings repository to RAG knowledge base.

**Acceptance Criteria:**

- [ ] PayloadsAllTheThings cloned and parsed
- [ ] All payload files indexed
- [ ] Search includes PayloadsAllTheThings results
- [ ] Results labeled by source (ExploitDB vs PayloadsAllTheThings)

**Technical Approach:**

1. Clone repository:
```bash
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
```

2. Parse markdown files and extract payloads

3. Generate embeddings and index in Qdrant

**Files to Create:**

- `crates/sk-rag/src/payloads_all_the_things.rs`

**Testing:**

- Test parsing various payload file formats
- Verify search quality with mixed results


**Labels:** `team-b-rag`, `milestone-week-2`, `priority-1-must-have`

---

### Issue B3: Build Semantic Search API

**Description:**

Build API for semantic search over RAG knowledge base.

**Acceptance Criteria:**

- [ ] API endpoint for semantic search
- [ ] CVE exact match search
- [ ] Service/version fuzzy matching
- [ ] Results ranked by relevance
- [ ] Sub-100ms query latency
- [ ] API documentation

**Technical Approach:**

```rust
pub struct RagSearchClient {
    qdrant: QdrantClient,
}

impl RagSearchClient {
    pub async fn semantic_search(&self, query: &str, limit: usize) -> Result<Vec<ExploitDoc>> {
        // Generate query embedding
        // Search Qdrant
        // Return ranked results
    }

    pub async fn search_by_cve(&self, cve_id: &str) -> Result<Option<ExploitDoc>> {
        // Exact match on CVE ID
    }

    pub async fn search_by_service(&self, service: &str, version: Option<&str>) -> Result<Vec<ExploitDoc>> {
        // Fuzzy match on service name and version
    }
}
```

**Files to Create:**

- `crates/sk-rag/src/search.rs`
- `crates/sk-rag/src/api.rs`

**Testing:**

- Unit tests for each search method
- Performance tests (latency under 100ms)
- Test search quality (precision/recall)


**Labels:** `team-b-rag`, `milestone-week-2`, `milestone-week-3`, `priority-1-must-have`

---

### Issue B4: Optimize RAG Performance

**Description:**

Optimize RAG search performance and add advanced features.

**Acceptance Criteria:**

- [ ] Query latency under 50ms (p95)
- [ ] Cache layer for frequent queries
- [ ] Metrics tracking (query latency, hit rate, cache performance)
- [ ] Custom playbook support (enterprise feature)

**Technical Approach:**

1. Add caching:
```rust
use moka::future::Cache;

pub struct CachedRagClient {
    inner: RagSearchClient,
    cache: Cache<String, Vec<ExploitDoc>>,
}
```

2. Add metrics using `prometheus` crate

3. Custom playbooks: allow enterprises to add private exploit docs

**Files to Modify:**

- `crates/sk-rag/src/search.rs`

**Files to Create:**

- `crates/sk-rag/src/cache.rs`
- `crates/sk-rag/src/metrics.rs`

**Testing:**

- Load testing (1000 queries/sec)
- Cache hit rate validation


**Labels:** `team-b-rag`, `milestone-week-4`, `milestone-week-5`, `priority-2-should-have`

---

## Team C: AI Planning & Reflector

### Issue C1: Implement Reflector Agent

**Description:**

Implement Reflector agent for failure analysis (L1-L4 levels).

**Acceptance Criteria:**

- [ ] Reflector agent interface defined
- [ ] Failure categorization logic (L1: tool error, L2: network, L3: params, L4: target hardening)
- [ ] System prompts for LLM-based analysis
- [ ] Integration with task execution results
- [ ] Unit tests for failure categorization

**Technical Approach:**

```rust
pub struct ReflectorAgent {
    llm_client: LLMClient,
}

impl ReflectorAgent {
    pub async fn analyze_failure(&self, task: &TaskNode, error: &Error) -> Result<FailureAnalysis> {
        // Categorize failure level
        let level = self.categorize_failure(task, error)?;
        
        // Use LLM for deeper analysis if needed
        let analysis = match level {
            FailureLevel::L1 | FailureLevel::L2 => {
                // Simple categorization, no LLM needed
                FailureAnalysis::simple(level, error)
            }
            FailureLevel::L3 | FailureLevel::L4 => {
                // Complex analysis, use LLM
                self.llm_analysis(task, error, level).await?
            }
        };
        
        Ok(analysis)
    }
    
    fn categorize_failure(&self, task: &TaskNode, error: &Error) -> Result<FailureLevel> {
        // Rule-based categorization
    }
}
```

**Files to Create:**

- `crates/sk-workflow/src/reflector.rs`

**Files to Modify:**

- `crates/sk-workflow/src/agents.rs`

**Testing:**

- Unit tests for failure categorization
- Mock LLM responses for testing
- Integration test with real task failures


**Labels:** `team-c-ai-planning`, `milestone-week-1`, `milestone-week-2`, `priority-1-must-have`

---

### Issue C2: Replace AutoPwn with AI Task Generation

**Description:**

Replace hardcoded AutoPwn logic with LLM-powered task generation.

**Acceptance Criteria:**

- [ ] LLM prompts for network attack planning
- [ ] LLM prompts for WiFi attack planning
- [ ] Integration with RAG semantic search
- [ ] Generated plans match or exceed hardcoded AutoPwn quality
- [ ] Comparison tests (AI vs hardcoded)

**Technical Approach:**

Create LLM prompts that generate task graphs:

```
System: You are a penetration testing AI planner. Given target information, 
generate a task graph for autonomous exploitation.

Target: {target_info}
Available tools: {tools}
Known vulnerabilities: {rag_results}

Generate a JSON task graph with:
- Tasks: tool name, parameters, estimated duration
- Dependencies: task A must complete before task B
- Reasoning: why this sequence is optimal
```

**Files to Create:**

- `crates/sk-workflow/src/ai_planner.rs`

**Files to Modify:**

- `crates/tools/src/autopwn/orchestrator.rs` (replace logic)

**Testing:**

- Compare AI plans vs hardcoded plans
- Test with various target types
- Validate generated JSON is well-formed


**Labels:** `team-c-ai-planning`, `milestone-week-3`, `milestone-week-4`, `priority-1-must-have`

---

### Issue C3: Implement Dynamic Replanning

**Description:**

Implement adaptive replanning based on execution results.

**Acceptance Criteria:**

- [ ] Replanning triggers (phase complete, task failed, new findings)
- [ ] LLM prompts for replanning
- [ ] Integration with workflow engine
- [ ] Replanning preserves successful tasks, adapts failed ones
- [ ] Tests with realistic scenarios

**Technical Approach:**

Build on existing replanning foundation in `sk-executor/src/planning.rs`:

```rust
pub async fn replan(
    original_plan: &EngagementPlan,
    execution_results: &[ExecutionResult],
    trigger: ReplanTrigger
) -> Result<EngagementPlan> {
    // Build replanning prompt
    let prompt = build_replan_prompt(original_plan, execution_results, trigger);
    
    // Call LLM
    let llm_response = llm_client.complete(&prompt).await?;
    
    // Parse updated plan
    let new_plan = parse_plan(&llm_response)?;
    
    // Merge with original (preserve successful tasks)
    merge_plans(original_plan, new_plan)
}
```

**Files to Modify:**

- `crates/sk-executor/src/planning.rs`
- `crates/sk-workflow/src/engine.rs`

**Testing:**

- Test replanning on task failure
- Test replanning on new findings
- Verify original successful tasks preserved


**Labels:** `team-c-ai-planning`, `milestone-week-4`, `milestone-week-5`, `priority-2-should-have`

---

### Issue C4: Add Cost Tracking and Budget Alerts

**Description:**

Implement LLM cost tracking with budget alerts.

**Acceptance Criteria:**

- [ ] Track tokens used per LLM call
- [ ] Calculate estimated cost
- [ ] Budget thresholds configurable
- [ ] Alerts when approaching budget limit
- [ ] Hard stop when budget exceeded
- [ ] Cost reporting per engagement

**Technical Approach:**

```rust
pub struct LLMBudgetGuard {
    max_cost_per_engagement: f64,
    warn_threshold: f64,
    current_spend: Arc<Mutex<f64>>,
}

impl LLMBudgetGuard {
    pub fn check_before_call(&self, estimated_cost: f64) -> BudgetCheck {
        let current = *self.current_spend.lock().unwrap();
        if current + estimated_cost > self.max_cost_per_engagement {
            BudgetCheck::HardStop
        } else if current + estimated_cost > self.warn_threshold {
            BudgetCheck::Warn
        } else {
            BudgetCheck::Ok
        }
    }
    
    pub fn record_usage(&self, actual_cost: f64) {
        *self.current_spend.lock().unwrap() += actual_cost;
    }
}
```

**Files to Create:**

- `crates/sk-core/src/llm_budget.rs`

**Files to Modify:**

- `crates/sk-workflow/src/node.rs` (integrate budget checks)

**Testing:**

- Test budget enforcement
- Test alert triggering
- Test cost calculation accuracy


**Labels:** `team-c-ai-planning`, `milestone-week-5`, `priority-2-should-have`

---

## Team D: Integrations & Polish

### Issue D1: Build Nessus XML Parser

**Description:**

Build parser for Nessus XML files to extract hosts, services, and vulnerabilities.

**Acceptance Criteria:**

- [ ] Parse .nessus XML files
- [ ] Extract hosts (IP, hostname, OS)
- [ ] Extract services (port, protocol, banner)
- [ ] Extract vulnerabilities (plugin ID, severity, CVE)
- [ ] Unit tests with sample Nessus files
- [ ] Error handling for malformed XML

**Technical Approach:**

Use `quick-xml` crate for parsing:

```rust
use quick_xml::Reader;

pub struct NessusReport {
    pub hosts: Vec<NessusHost>,
    pub vulnerabilities: Vec<NessusVuln>,
}

pub fn parse_nessus_xml(xml_path: &Path) -> Result<NessusReport> {
    let mut reader = Reader::from_file(xml_path)?;
    // Parse XML structure
    // Extract ReportHost elements
    // Extract ReportItem elements (vulns)
    Ok(NessusReport { hosts, vulnerabilities })
}
```

**Files to Create:**

- `crates/sk-integrations/src/nessus/parser.rs`
- `crates/sk-integrations/src/nessus/types.rs`

**Testing:**

- Unit tests with sample .nessus files
- Test various Nessus versions
- Test edge cases (empty scans, no vulns)


**Labels:** `team-d-integrations`, `milestone-week-1`, `priority-3-nice-to-have`

---

### Issue D2: Build Nessus Import Workflow

**Description:**

Build workflow in StrikeKit to import Nessus XML and create Targets/Findings.

**Acceptance Criteria:**

- [ ] Workflow definition: Parse XML -> Create Targets -> Create Findings
- [ ] Deduplicate targets (don't create duplicates)
- [ ] Map Nessus severity to StrikeKit severity
- [ ] Link vulnerabilities to targets
- [ ] Workflow executes successfully
- [ ] Integration tests

**Technical Approach:**

Create workflow definition:

```rust
pub fn nessus_import_workflow() -> WorkflowDefinition {
    WorkflowDefinition {
        id: "nessus-import".to_string(),
        name: "Nessus Import".to_string(),
        nodes: vec![
            NodeDef {
                id: "parse".to_string(),
                node_type: NodeType::Function {
                    function_name: "parse_nessus_xml".to_string(),
                    args: hashmap!{ "file_path" => "{{inputs.nessus_file}}" },
                },
                depends_on: vec![],
                ..Default::default()
            },
            NodeDef {
                id: "create_targets".to_string(),
                node_type: NodeType::Function {
                    function_name: "create_targets_from_nessus".to_string(),
                    args: hashmap!{ "hosts" => "{{parse.output.hosts}}" },
                },
                depends_on: vec!["parse".to_string()],
                ..Default::default()
            },
            NodeDef {
                id: "create_findings".to_string(),
                node_type: NodeType::Function {
                    function_name: "create_findings_from_nessus".to_string(),
                    args: hashmap!{ "vulns" => "{{parse.output.vulnerabilities}}" },
                },
                depends_on: vec!["create_targets".to_string()],
                ..Default::default()
            },
        ],
        input_schema: None,
    }
}
```

**Files to Create:**

- `crates/sk-workflow/src/workflows/nessus_import.rs`

**Files to Modify:**

- `crates/sk-workflow/src/workflows/mod.rs`

**Testing:**

- End-to-end test: import Nessus file, verify targets/findings created
- Test deduplication
- Test error handling


**Labels:** `team-d-integrations`, `milestone-week-2`, `milestone-week-3`, `priority-3-nice-to-have`

---

### Issue D3: Build Report Generation Workflow

**Description:**

Build workflow to generate PDF reports from findings and evidence chains.

**Acceptance Criteria:**

- [ ] PDF template with findings, evidence, MITRE ATT&CK
- [ ] Evidence chains rendered in report
- [ ] Confidence scores visible
- [ ] Professional formatting
- [ ] Export workflow works end-to-end

**Technical Approach:**

Use existing report generation in StrikeKit, enhance with evidence chains:

1. Query findings for engagement
2. For each finding, query evidence chain
3. Render evidence chain (text or graph image)
4. Generate PDF using existing template system

**Files to Modify:**

- `crates/sk-ui/src/components/reports.rs` (if exists)
- Or create new report generation module

**Testing:**

- Generate reports with various engagement sizes
- Test PDF rendering quality
- Test with/without evidence chains


**Labels:** `team-d-integrations`, `milestone-week-3`, `milestone-week-4`, `priority-2-should-have`

---

### Issue D4: Build Manual Target AI Planning Workflow

**Description:**

Build workflow where user specifies target and AI generates reconnaissance plan.

**Acceptance Criteria:**

- [ ] User input: target IP/CIDR or hostname
- [ ] AI generates recon plan (discovery, scanning, enumeration)
- [ ] Plan displayed in UI for approval
- [ ] User can approve/reject/modify plan
- [ ] Approved plan executes via workflow engine

**Technical Approach:**

1. Create UI form for target input
2. Send target to AI planner
3. AI generates task graph
4. Display plan in UI with human approval gate
5. Execute approved plan

**Files to Create:**

- `crates/sk-ui/src/components/manual_target_planning.rs`

**Files to Modify:**

- `crates/sk-ui/src/app.rs` (add route)

**Testing:**

- Test with single host target
- Test with network CIDR target
- Test with web application target


**Labels:** `team-d-integrations`, `milestone-week-5`, `priority-2-should-have`

---

## Cross-Team Issues

### Issue X1: Integration Testing - Complete Workflows

**Description:**

End-to-end integration testing of all complete workflows.

**Acceptance Criteria:**

- [ ] Test: WiFi AutoPwn with evidence chain visualization
- [ ] Test: Manual target -> AI plan -> execution -> evidence graph -> report
- [ ] Test: Nessus import -> AI exploit -> evidence graph -> report
- [ ] All Priority 1 & 2 workflows tested
- [ ] Performance testing (latency, memory)
- [ ] Bug reports created for failures

**Technical Approach:**

Create integration test suite:

```rust
#[tokio::test]
async fn test_wifi_autopwn_with_evidence_chains() {
    // Setup test engagement
    // Run WiFi AutoPwn
    // Verify evidence chains created
    // Verify graph renders
}

#[tokio::test]
async fn test_nessus_to_report_workflow() {
    // Import Nessus XML
    // Verify targets/findings created
    // Generate AI exploit plan
    // Execute plan
    // Verify evidence chains
    // Generate report
}
```

**Files to Create:**

- `tests/integration/workflows.rs`

**Testing:**

Run all integration tests, document results


**Labels:** `all-teams`, `milestone-week-6`, `priority-1-must-have`

---

### Issue X2: Documentation - User Guide

**Description:**

Write comprehensive user guide for 60-day MVP features.

**Acceptance Criteria:**

- [ ] Getting started guide
- [ ] WiFi AutoPwn tutorial
- [ ] Evidence chain visualization guide
- [ ] Manual target planning guide
- [ ] Nessus import guide
- [ ] Screenshots and examples

**Technical Approach:**

Create markdown docs in `docs/` directory:
- `docs/USER_GUIDE.md`
- `docs/tutorials/WIFI_AUTOPWN.md`
- `docs/tutorials/EVIDENCE_CHAINS.md`
- `docs/tutorials/MANUAL_PLANNING.md`
- `docs/tutorials/NESSUS_IMPORT.md`


**Labels:** `all-teams`, `milestone-week-7`, `priority-2-should-have`

---

### Issue X3: Demo Preparation

**Description:**

Prepare 60-day MVP demo (script, environment, video).

**Acceptance Criteria:**

- [ ] Demo script written
- [ ] Demo environment setup (test data, configs)
- [ ] Demo video recorded (10-15 minutes)
- [ ] Presentation slides created
- [ ] Team rehearsed demo 2-3 times

**Technical Approach:**

Demo flow:
1. Show WiFi AutoPwn detecting hardware
2. Run autonomous WiFi attack
3. Show evidence chain graph (live visualization)
4. Import Nessus scan
5. AI generates exploit plan
6. Execute plan, show evidence chains
7. Generate report


**Labels:** `all-teams`, `milestone-week-8`, `priority-1-must-have`

---

## Issue Summary

**Total Issues:** 23

**By Team:**
- Team A (Evidence Chains): 5 issues
- Team B (RAG): 4 issues
- Team C (AI Planning): 4 issues
- Team D (Integrations): 4 issues
- Cross-Team: 3 issues

**By Priority:**
- Priority 1 (Must Have): 13 issues
- Priority 2 (Should Have): 7 issues
- Priority 3 (Nice to Have): 3 issues

**By Milestone:**
- Week 1: 4 issues
- Week 2: 7 issues
- Week 3: 5 issues
- Week 4: 4 issues
- Week 5: 4 issues
- Week 6: 1 issue
- Week 7: 2 issues
- Week 8: 1 issue

---

**END OF GITHUB ISSUES**
