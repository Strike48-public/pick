#!/usr/bin/env bash
# Create all GitHub issues for 60-day MVP in StrikeKit repository
# Issue #94 already created: [Team A] Design and Implement Evidence Chain Database Schema

set -euo pipefail

cd /home/jtomek/Code/strikekit

echo "Creating all remaining issues in StrikeKit repository..."
echo ""

# Team A Issues

echo "Creating Team A issues..."

gh issue create --title "Implement Evidence Chain Tracking API" --body "$(cat <<'EOF'
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


EOF
)" --label "type: feature,priority: P1,feature: evidence-chains,size: L"

echo "Issue A2 created"

gh issue create --title "Implement Confidence Scoring and Propagation" --body "$(cat <<'EOF'
**Description:**

Implement confidence scoring logic that propagates through evidence chains.

**Acceptance Criteria:**

- [ ] Confidence calculation for Hypotheses (based on supporting evidence)
- [ ] Confidence propagation to ExploitAttempts
- [ ] Confidence thresholds for human approval gates
- [ ] API to recalculate confidence when evidence updates
- [ ] Unit tests for scoring logic

**Technical Approach:**

Confidence scoring logic:

```rust
// Hypothesis confidence = weighted average of evidence
confidence_hypothesis = sum(evidence[i].confidence * weight[i]) / sum(weight[i])

// Exploit attempt confidence = hypothesis confidence * success_rate_prior
confidence_exploit = confidence_hypothesis * exploit_type_success_rate

// Approval gate thresholds
const HIGH_CONFIDENCE: f64 = 0.85;  // Auto-approve
const MEDIUM_CONFIDENCE: f64 = 0.50;  // Human review
const LOW_CONFIDENCE: f64 = 0.30;  // Block
```

Propagation rules:
- When evidence updates, recalculate dependent hypothesis confidence
- When hypothesis updates, recalculate dependent exploit confidence
- When exploit completes, update confidence based on result

**Files to Modify:**

- `crates/sk-db/src/evidence_chain.rs`
- `crates/sk-core/src/confidence.rs` (new)

**Testing:**

- Unit tests for confidence calculations
- Test propagation: evidence update triggers downstream recalculation
- Test approval gates: high/medium/low confidence routing


EOF
)" --label "type: feature,priority: P1,feature: evidence-chains,size: L"

echo "Issue A3 created"

gh issue create --title "Build Knowledge Graph Visualization UI" --body "$(cat <<'EOF'
**Description:**

Build interactive knowledge graph visualization for evidence chains using JavaScript graph library.

**Acceptance Criteria:**

- [ ] Evaluate JS graph libraries (Cytoscape.js, vis.js, D3.js)
- [ ] Choose library and integrate into StrikeKit UI
- [ ] Render nodes (Evidence, Hypothesis, Exploit, Finding)
- [ ] Render edges (causal relationships)
- [ ] Basic interactivity (zoom, pan)
- [ ] Performance tested with 100+ node graphs

**Technical Approach:**

Library recommendation: **Cytoscape.js**
- Mature, well-documented
- Good performance for 100-1000 nodes
- Built-in layouts (dagre, cose, breadthfirst)
- Easy styling

Integration approach:
```javascript
// Load evidence chain from API
const chain = await fetch(`/api/evidence-chains/${findingId}`);

// Initialize Cytoscape
const cy = cytoscape({
  container: document.getElementById('graph'),
  elements: chain.nodes_and_edges,
  style: [
    { selector: 'node[type="evidence"]', style: { 'background-color': '#0066cc' } },
    { selector: 'node[type="hypothesis"]', style: { 'background-color': '#ffaa00' } },
    { selector: 'node[type="exploit"]', style: { 'background-color': '#cc0000' } },
    { selector: 'node[type="finding"]', style: { 'background-color': '#00cc66' } }
  ],
  layout: { name: 'dagre' }
});
```

**Files to Create:**

- `crates/sk-ui/src/components/knowledge_graph.rs` (or .jsx if using React)
- `crates/sk-api/src/routes/evidence_chains.rs`

**Testing:**

- Render test graphs (10, 50, 100, 500 nodes)
- Measure render time (should be <1s for 100 nodes)
- Test zoom/pan performance


EOF
)" --label "type: feature,priority: P1,feature: evidence-chains,size: L"

echo "Issue A4 created"

gh issue create --title "Polish Knowledge Graph UI" --body "$(cat <<'EOF'
**Description:**

Add advanced interactivity and polish to knowledge graph visualization.

**Acceptance Criteria:**

- [ ] Click nodes to show details
- [ ] Color-coded confidence visualization
- [ ] Timeline view (alternative to graph)
- [ ] Graph filters (show only high-confidence chains)
- [ ] Search within graph
- [ ] Export graph (PNG, SVG, JSON)
- [ ] UI polish (tooltips, loading states, error messages)

**Technical Approach:**

Features to add:
1. Node click handler: show detail panel with evidence/hypothesis/exploit info
2. Confidence coloring: green (high), yellow (medium), red (low)
3. Timeline view: horizontal timeline with nodes sorted by timestamp
4. Filters: checkboxes to show/hide by confidence, type, timestamp
5. Search: filter graph to show only nodes matching search term
6. Export: Cytoscape built-in export + custom JSON format

**Files to Modify:**

- `crates/sk-ui/src/components/knowledge_graph.rs`

**Testing:**

- User testing: can users navigate and understand the graph?
- Performance testing: filters and search should be <100ms
- Export testing: PNG/SVG quality, JSON correctness


EOF
)" --label "type: enhancement,priority: P2,feature: evidence-chains,size: L"

echo "Issue A5 created"
echo ""

# Team B Issues

echo "Creating Team B issues..."

gh issue create --title "Setup Qdrant and Ingest ExploitDB" --body "$(cat <<'EOF'
**Description:**

Setup Qdrant vector database and build ingestion pipeline for ExploitDB (50k+ exploits).

**Acceptance Criteria:**

- [ ] Qdrant running locally via Docker
- [ ] Qdrant collection "exploits" created
- [ ] ExploitDB archive downloaded and extracted
- [ ] Ingestion pipeline parses exploits (title, description, code, platform, type)
- [ ] Embeddings generated using sentence-transformers
- [ ] All 50k+ exploits indexed
- [ ] Semantic search returns relevant results

**Technical Approach:**

Setup Qdrant:
```bash
docker run -p 6333:6333 -v $(pwd)/qdrant_storage:/qdrant/storage qdrant/qdrant
```

Ingestion pipeline (`tools/ingest_exploitdb.py`):
```python
from sentence_transformers import SentenceTransformer
from qdrant_client import QdrantClient

model = SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')
client = QdrantClient("http://localhost:6333")

# Parse exploits from ExploitDB archive
for exploit in parse_exploitdb():
    # Generate embedding from title + description
    text = f"{exploit.title} {exploit.description}"
    embedding = model.encode(text)

    # Insert into Qdrant
    client.upsert(
        collection_name="exploits",
        points=[{
            "id": exploit.id,
            "vector": embedding,
            "payload": exploit.to_dict()
        }]
    )
```

**Files to Create:**

- `tools/ingest_exploitdb.py`
- `docker-compose.yml` (add Qdrant service)

**Testing:**

- Query test: "linux privilege escalation" returns relevant exploits
- Performance test: ingestion speed >10 exploits/sec
- Verify: collection stats show 50k+ vectors


EOF
)" --label "type: feature,priority: P1,feature: rag,size: L"

echo "Issue B1 created"

gh issue create --title "Ingest PayloadsAllTheThings" --body "$(cat <<'EOF'
**Description:**

Add PayloadsAllTheThings repository to RAG knowledge base.

**Acceptance Criteria:**

- [ ] PayloadsAllTheThings repo cloned
- [ ] Ingestion pipeline parses markdown files (payloads, techniques)
- [ ] Embeddings generated and indexed in Qdrant
- [ ] Semantic search returns PATT results alongside ExploitDB
- [ ] Documentation updated with ingestion process

**Technical Approach:**

Clone PATT:
```bash
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git
```

Parse markdown structure:
```python
# PATT is organized by technique (SQL injection, XSS, etc.)
# Parse markdown files, extract payloads and explanations

for md_file in glob("PayloadsAllTheThings/**/*.md"):
    technique = parse_technique_from_path(md_file)
    payloads = parse_payloads_from_markdown(md_file)

    for payload in payloads:
        text = f"{technique} {payload.description} {payload.code}"
        embedding = model.encode(text)

        client.upsert(
            collection_name="exploits",  # Same collection as ExploitDB
            points=[{
                "id": f"patt-{payload.id}",
                "vector": embedding,
                "payload": {
                    "source": "PayloadsAllTheThings",
                    "technique": technique,
                    "payload": payload.code,
                    "description": payload.description
                }
            }]
        )
```

**Files to Create:**

- `tools/ingest_patt.py`

**Testing:**

- Query test: "SQL injection bypass" returns PATT payloads
- Verify: collection includes both ExploitDB and PATT entries
- Test filtering: can filter results by source (ExploitDB vs PATT)


EOF
)" --label "type: feature,priority: P1,feature: rag,size: M"

echo "Issue B2 created"

gh issue create --title "Build Semantic Search API" --body "$(cat <<'EOF'
**Description:**

Build API for semantic search over RAG knowledge base with filtering and ranking.

**Acceptance Criteria:**

- [ ] REST API endpoint: `POST /api/rag/search`
- [ ] Query parameters: query text, filters (platform, type, source), limit
- [ ] Returns ranked results with relevance scores
- [ ] CVE exact match search (fallback to semantic if no exact match)
- [ ] Service/version fuzzy matching
- [ ] API documentation
- [ ] Query latency <100ms (p95)

**Technical Approach:**

API endpoint in `crates/sk-api/src/routes/rag.rs`:

```rust
#[derive(Deserialize)]
struct SearchRequest {
    query: String,
    filters: Option<SearchFilters>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct SearchFilters {
    platform: Option<String>,  // "linux", "windows", etc.
    exploit_type: Option<String>,  // "remote", "local", "webapp"
    source: Option<String>,  // "ExploitDB", "PayloadsAllTheThings"
}

async fn search_exploits(req: SearchRequest) -> Result<Vec<ExploitResult>> {
    // 1. Check for CVE pattern (CVE-YYYY-NNNNN)
    if let Some(cve) = extract_cve(&req.query) {
        return search_by_cve(cve);
    }

    // 2. Generate query embedding
    let embedding = generate_embedding(&req.query);

    // 3. Query Qdrant with filters
    let results = qdrant_client.search(
        collection_name: "exploits",
        query_vector: embedding,
        filter: build_filter(req.filters),
        limit: req.limit.unwrap_or(10)
    );

    // 4. Rank and return
    Ok(results)
}
```

**Files to Create:**

- `crates/sk-api/src/routes/rag.rs`
- `crates/sk-rag/src/lib.rs` (RAG service layer)

**Testing:**

- Unit tests for query parsing, filtering, ranking
- Integration test: API returns correct results
- Performance test: p95 latency <100ms
- Load test: 100 concurrent queries


EOF
)" --label "type: feature,priority: P1,feature: rag,size: L"

echo "Issue B3 created"

gh issue create --title "Optimize RAG Performance" --body "$(cat <<'EOF'
**Description:**

Optimize RAG search performance with caching, better embeddings, and metrics.

**Acceptance Criteria:**

- [ ] Cache layer for frequent queries (Redis or in-memory)
- [ ] Experiment with better embedding models (performance vs quality)
- [ ] Add relevance scoring improvements
- [ ] Metrics tracking (query latency, hit rate, result quality)
- [ ] Performance benchmarks documented
- [ ] Cache hit rate >50% in production-like workload

**Technical Approach:**

Caching strategy:
```rust
// Cache key: hash(query + filters)
// Cache value: search results
// TTL: 1 hour

let cache_key = hash(&req.query, &req.filters);
if let Some(cached) = cache.get(&cache_key) {
    return Ok(cached);
}

let results = perform_search(&req);
cache.set(&cache_key, &results, Duration::hours(1));
```

Embedding model experiments:
- Current: `sentence-transformers/all-MiniLM-L6-v2` (fast, 384 dims)
- Try: `sentence-transformers/all-mpnet-base-v2` (slower, 768 dims, better quality)
- Measure: recall@10, query latency

Metrics to track:
- Query latency (p50, p95, p99)
- Cache hit rate
- Result relevance (user feedback)
- Embeddings generation time

**Files to Modify:**

- `crates/sk-rag/src/lib.rs`
- `crates/sk-rag/src/cache.rs` (new)

**Testing:**

- Benchmark: compare query latency before/after caching
- Load test: 1000 queries, measure cache hit rate
- A/B test: compare embedding models on known queries


EOF
)" --label "type: enhancement,priority: P2,feature: rag,size: L"

echo "Issue B4 created"
echo ""

# Team C Issues

echo "Creating Team C issues..."

gh issue create --title "Implement Reflector Agent" --body "$(cat <<'EOF'
**Description:**

Implement Reflector agent for failure analysis and replanning recommendations.

**Acceptance Criteria:**

- [ ] Reflector agent node type in workflow engine
- [ ] Failure categorization logic (L1-L4 levels)
- [ ] LLM integration for failure analysis
- [ ] Generate 3 alternative approaches with confidence scores
- [ ] Reasoning explanations for recommendations
- [ ] Unit tests for failure categorization
- [ ] Integration tests with workflow engine

**Technical Approach:**

Failure levels (from architecture doc):
- L1: Retryable (network timeout, rate limit) - Auto-retry with backoff
- L2: Fixable (wrong parameters, missing dependencies) - Modify and retry
- L3: Dead end (target not vulnerable) - Mark failed, try alternative
- L4: Blocker (no access, insufficient privileges) - Escalate to human

Reflector agent implementation:

```rust
pub struct ReflectorAgent {
    llm_client: LlmClient,
}

impl ReflectorAgent {
    pub async fn analyze_failure(
        &self,
        task: &TaskExecution,
        error: &str,
    ) -> Result<ReplanRequest> {
        // 1. Categorize failure (L1-L4)
        let level = self.categorize_failure(error);

        // 2. Generate alternatives using LLM
        let prompt = format!(
            "Task failed: {}\nError: {}\nGenerate 3 alternative approaches.",
            task.description, error
        );

        let alternatives = self.llm_client.generate(prompt).await?;

        // 3. Score alternatives by confidence
        let scored = self.score_alternatives(alternatives, task);

        Ok(ReplanRequest {
            level,
            alternatives: scored,
            reasoning: "..." // LLM-generated reasoning
        })
    }
}
```

**Files to Create:**

- `crates/sk-executor/src/reflector.rs`

**Files to Modify:**

- `crates/sk-workflow/src/types.rs` (add ReflectorAgent node type)
- `crates/sk-workflow/src/executor.rs` (execute Reflector nodes)

**Testing:**

- Unit tests: failure categorization (L1-L4)
- Unit tests: confidence scoring
- Integration test: Reflector in workflow execution
- Test LLM call latency and cost


EOF
)" --label "type: feature,priority: P1,feature: ai-planning,size: L"

echo "Issue C1 created"

gh issue create --title "Replace AutoPwn with AI Task Generation" --body "$(cat <<'EOF'
**Description:**

Replace hardcoded AutoPwn logic with LLM-powered task generation integrated with RAG.

**Acceptance Criteria:**

- [ ] LLM generates attack plans based on context (network scan, WiFi scan, Nessus import)
- [ ] RAG integration: recommend exploits from knowledge base
- [ ] Task generation prompts for network and WiFi attacks
- [ ] Generated plans match or exceed hardcoded AutoPwn quality
- [ ] A/B testing: AI plans vs hardcoded plans
- [ ] Cost tracking for LLM calls

**Technical Approach:**

AI task generation flow:

```rust
pub async fn generate_attack_plan(
    context: &AttackContext,
    rag_client: &RagClient,
) -> Result<Vec<Task>> {
    // 1. Query RAG for relevant exploits
    let exploits = rag_client.search(&context.target_info).await?;

    // 2. Build LLM prompt with context + RAG results
    let prompt = format!(
        "Target: {}\nServices: {}\nRelevant exploits: {}\n\
         Generate attack plan with phases and tasks.",
        context.target, context.services, exploits
    );

    // 3. LLM generates structured plan
    let plan = llm_client.generate_structured(prompt).await?;

    // 4. Convert plan to workflow tasks
    let tasks = plan.phases
        .flat_map(|phase| phase.tasks)
        .map(|task| Task {
            tool: task.tool,
            parameters: task.parameters,
            depends_on: task.dependencies,
        })
        .collect();

    Ok(tasks)
}
```

Prompt templates:
- Network attack: Discovery -> Port Scan -> Service Enum -> Vuln Assess -> Exploit
- WiFi attack: Adapter Check -> Scan -> Capture -> Crack -> Post-Exploit

**Files to Create:**

- `crates/sk-planner/src/ai_task_gen.rs`

**Files to Modify:**

- `crates/sk-planner/src/lib.rs`

**Testing:**

- A/B test: AI plans vs hardcoded AutoPwn (10 scenarios)
- Measure: plan quality, exploit success rate, time to compromise
- Cost test: LLM tokens per plan (<10k tokens preferred)


EOF
)" --label "type: feature,priority: P1,feature: ai-planning,size: XL"

echo "Issue C2 created"

gh issue create --title "Implement Dynamic Replanning" --body "$(cat <<'EOF'
**Description:**

Implement dynamic replanning system that adapts based on execution results and new findings.

**Acceptance Criteria:**

- [ ] Replanning triggers: phase complete, task failed, new findings discovered
- [ ] Replanning integrates with Reflector agent
- [ ] New plan preserves successful completed tasks
- [ ] Human approval gates for high-risk changes
- [ ] Replanning logic tested with realistic scenarios

**Technical Approach:**

Replanning triggers:

```rust
pub enum ReplanTrigger {
    PhaseComplete { phase_id: Id, findings: Vec<Finding> },
    TaskFailed { task_id: Id, error: String },
    NewFindings { findings: Vec<Finding> },
}

pub async fn handle_replan_trigger(
    trigger: ReplanTrigger,
    current_plan: &WorkflowExecution,
    reflector: &ReflectorAgent,
) -> Result<WorkflowExecution> {
    match trigger {
        ReplanTrigger::PhaseComplete { findings, .. } => {
            // Generate next phase based on findings
            let next_phase = generate_next_phase(findings).await?;
            current_plan.add_phase(next_phase)
        }

        ReplanTrigger::TaskFailed { task_id, error } => {
            // Use Reflector to suggest alternatives
            let alternatives = reflector.analyze_failure(task_id, &error).await?;
            current_plan.replace_task(task_id, alternatives.best())
        }

        ReplanTrigger::NewFindings { findings } => {
            // Adjust plan to exploit new findings
            let adjusted_plan = adjust_for_findings(current_plan, findings).await?;
            adjusted_plan
        }
    }
}
```

Approval gates:
- High-confidence changes (<30% plan change): Auto-approve
- Medium-confidence changes (30-70% plan change): Human review
- High-risk changes (>70% plan change): Human approval required

**Files to Create:**

- `crates/sk-planner/src/replanning.rs`

**Files to Modify:**

- `crates/sk-workflow/src/executor.rs` (trigger replanning)

**Testing:**

- Scenario test: Phase complete -> generate next phase
- Scenario test: Task failed -> alternative approach
- Scenario test: New finding -> exploit discovered vulnerability
- Test approval gates: high/medium/low risk routing


EOF
)" --label "type: feature,priority: P1,feature: ai-planning,size: L"

echo "Issue C3 created"

gh issue create --title "Add Cost Tracking and Budget Alerts" --body "$(cat <<'EOF'
**Description:**

Implement cost tracking for LLM calls with budget alerts and optimization recommendations.

**Acceptance Criteria:**

- [ ] Track LLM token usage per engagement
- [ ] Calculate cost based on model pricing (Sonnet, Opus, Haiku)
- [ ] Budget alerts when threshold reached (50%, 75%, 90%)
- [ ] Cost optimization: use cheaper models where appropriate
- [ ] Dashboard showing cost breakdown by engagement/model
- [ ] API endpoint to query cost stats

**Technical Approach:**

Cost tracking:

```rust
pub struct LlmCostTracker {
    db: StrikeKitDb,
}

impl LlmCostTracker {
    pub async fn track_call(
        &self,
        engagement_id: Id,
        model: &str,
        prompt_tokens: usize,
        completion_tokens: usize,
    ) -> Result<()> {
        let cost = self.calculate_cost(model, prompt_tokens, completion_tokens);

        self.db.insert_llm_call(LlmCall {
            engagement_id,
            model: model.to_string(),
            prompt_tokens,
            completion_tokens,
            cost,
            timestamp: Utc::now(),
        })?;

        // Check budget and send alert if threshold reached
        let total_cost = self.db.get_engagement_cost(engagement_id)?;
        if total_cost > BUDGET_THRESHOLD * 0.9 {
            self.send_budget_alert(engagement_id, total_cost)?;
        }

        Ok(())
    }

    fn calculate_cost(&self, model: &str, prompt: usize, completion: usize) -> f64 {
        // Pricing as of 2026-04-07
        match model {
            "claude-sonnet-4" => {
                (prompt as f64 * 0.003 / 1000.0) + (completion as f64 * 0.015 / 1000.0)
            }
            "claude-opus-4" => {
                (prompt as f64 * 0.015 / 1000.0) + (completion as f64 * 0.075 / 1000.0)
            }
            "claude-haiku-4" => {
                (prompt as f64 * 0.00025 / 1000.0) + (completion as f64 * 0.00125 / 1000.0)
            }
            _ => 0.0
        }
    }
}
```

Optimization strategy:
- Use Haiku for simple tasks (classification, parsing)
- Use Sonnet for complex planning
- Use Opus only when deepest reasoning required

**Files to Create:**

- `crates/sk-llm/src/cost_tracker.rs`

**Files to Modify:**

- `crates/sk-llm/src/client.rs` (integrate tracking)
- `crates/sk-api/src/routes/stats.rs` (cost API endpoint)

**Testing:**

- Unit tests: cost calculation for each model
- Integration test: track cost across multiple LLM calls
- Test budget alerts at 50%, 75%, 90% thresholds


EOF
)" --label "type: feature,priority: P2,feature: ai-planning,size: M"

echo "Issue C4 created"
echo ""

# Team D Issues

echo "Creating Team D issues..."

gh issue create --title "Build Nessus XML Parser" --body "$(cat <<'EOF'
**Description:**

Build Nessus XML parser to extract hosts, services, and vulnerabilities from .nessus files.

**Acceptance Criteria:**

- [ ] Parse ReportHost blocks (IP, OS, hostname)
- [ ] Parse ReportItem blocks (CVE, severity, service, port)
- [ ] Map Nessus data to StrikeKit types (Target, Finding)
- [ ] Handle multiple Nessus file formats (different scanner versions)
- [ ] Parser tests with sample .nessus files
- [ ] Error handling for malformed XML

**Technical Approach:**

Use `quick-xml` crate for parsing:

```rust
use quick_xml::Reader;
use quick_xml::events::Event;

pub struct NessusParser;

impl NessusParser {
    pub fn parse(xml: &str) -> Result<NessusReport> {
        let mut reader = Reader::from_str(xml);
        let mut hosts = Vec::new();

        loop {
            match reader.read_event()? {
                Event::Start(e) if e.name().as_ref() == b"ReportHost" => {
                    let host = self.parse_host(&mut reader)?;
                    hosts.push(host);
                }
                Event::Eof => break,
                _ => {}
            }
        }

        Ok(NessusReport { hosts })
    }

    fn parse_host(&self, reader: &mut Reader) -> Result<NessusHost> {
        // Extract IP, OS, hostname
        // Parse ReportItem children for vulnerabilities
    }
}
```

Map to StrikeKit types:
```rust
let target = Target {
    id: Id::new(),
    engagement_id,
    ip: host.ip,
    hostname: host.hostname,
    os: host.os,
    ...
};

let finding = Finding {
    id: Id::new(),
    engagement_id,
    target_id: target.id,
    title: vuln.name,
    cve: vuln.cve,
    severity: map_severity(vuln.severity),
    service: vuln.service,
    port: vuln.port,
    ...
};
```

**Files to Create:**

- `crates/sk-integrations/src/nessus/parser.rs`
- `crates/sk-integrations/src/nessus/types.rs`

**Testing:**

- Unit tests with sample XML snippets
- Integration test: parse full .nessus file
- Test error handling: malformed XML, missing fields


EOF
)" --label "type: feature,priority: P2,feature: integrations,size: M"

echo "Issue D1 created"

gh issue create --title "Build Nessus Import Workflow" --body "$(cat <<'EOF'
**Description:**

Build workflow to import Nessus XML files and create targets/findings in StrikeKit.

**Acceptance Criteria:**

- [ ] Workflow definition: Parse XML -> Create Targets -> Create Findings -> Link
- [ ] Workflow stored in `workflows/nessus_import.json`
- [ ] Error handling: invalid XML, duplicate entries
- [ ] Progress reporting during import
- [ ] Integration test: XML in, database entries out

**Technical Approach:**

Workflow definition:

```json
{
  "id": "nessus-import",
  "name": "Nessus Import",
  "nodes": [
    {
      "id": "parse-xml",
      "type": "Function",
      "function": "nessus::parse_file",
      "inputs": { "file_path": "${input.file_path}" }
    },
    {
      "id": "create-targets",
      "type": "Function",
      "function": "db::create_targets",
      "inputs": { "hosts": "${parse-xml.hosts}" },
      "depends_on": ["parse-xml"]
    },
    {
      "id": "create-findings",
      "type": "Function",
      "function": "db::create_findings",
      "inputs": { "vulnerabilities": "${parse-xml.vulnerabilities}" },
      "depends_on": ["create-targets"]
    }
  ]
}
```

Workflow execution:

```rust
let workflow = WorkflowDefinition::load("workflows/nessus_import.json")?;
let execution = workflow.execute(json!({
    "file_path": "/path/to/scan.nessus"
}))?;

// Wait for completion
execution.wait().await?;

// Get results
let targets = execution.get_output("create-targets")?;
let findings = execution.get_output("create-findings")?;
```

**Files to Create:**

- `workflows/nessus_import.json`

**Files to Modify:**

- `crates/sk-integrations/src/nessus/mod.rs` (workflow functions)

**Testing:**

- Integration test: import sample .nessus file
- Test duplicate handling: reimporting same file
- Test error cases: invalid XML, missing engagement_id


EOF
)" --label "type: feature,priority: P2,feature: integrations,size: M"

echo "Issue D2 created"

gh issue create --title "Build Report Generation Workflow" --body "$(cat <<'EOF'
**Description:**

Build workflow to generate PDF reports with findings, evidence chains, and MITRE ATT&CK mapping.

**Acceptance Criteria:**

- [ ] PDF template with sections: Executive Summary, Findings, Evidence, MITRE ATT&CK
- [ ] Workflow: Query Findings -> Build Evidence Chains -> Map to ATT&CK -> Generate PDF
- [ ] Findings sorted by severity
- [ ] Evidence chains visualized in report
- [ ] MITRE ATT&CK techniques mapped to findings
- [ ] Report customization options (logo, colors, sections)

**Technical Approach:**

Use `printpdf` or `wkhtmltopdf` for PDF generation:

```rust
pub async fn generate_report(engagement_id: Id) -> Result<PathBuf> {
    // 1. Query all findings for engagement
    let findings = db.get_findings(engagement_id)?;

    // 2. Build evidence chains for each finding
    let chains = findings.iter()
        .map(|f| db.get_evidence_chain(f.id))
        .collect::<Result<Vec<_>>>()?;

    // 3. Map findings to MITRE ATT&CK techniques
    let mitre_mapping = map_to_mitre(&findings);

    // 4. Generate HTML report
    let html = render_template("report.html.j2", json!({
        "findings": findings,
        "chains": chains,
        "mitre": mitre_mapping,
    }))?;

    // 5. Convert HTML to PDF
    let pdf_path = wkhtmltopdf(&html)?;

    Ok(pdf_path)
}
```

Report sections:
1. Executive Summary: High-level overview, risk rating
2. Findings: Detailed findings sorted by severity
3. Evidence: Evidence chains showing how findings were discovered
4. MITRE ATT&CK: Techniques used, mapped to findings
5. Recommendations: Remediation advice

**Files to Create:**

- `crates/sk-reporting/src/pdf.rs`
- `templates/report.html.j2`

**Files to Modify:**

- `crates/sk-api/src/routes/reports.rs` (API endpoint)

**Testing:**

- Generate test reports with sample data
- Verify PDF quality: formatting, images, tables
- Test customization: different templates, logos


EOF
)" --label "type: feature,priority: P2,feature: integrations,size: L"

echo "Issue D3 created"

gh issue create --title "Build Manual Target AI Planning Workflow" --body "$(cat <<'EOF'
**Description:**

Build workflow for user-specified targets where AI generates recon and attack plans.

**Acceptance Criteria:**

- [ ] User input: target IP/CIDR/domain
- [ ] AI generates recon plan (ping, nmap, DNS enum, etc.)
- [ ] AI generates attack plan based on recon results
- [ ] Workflow execution: Recon -> Plan -> Exploit
- [ ] Tested with multiple target types (single host, network, web app)
- [ ] Error handling for unreachable targets

**Technical Approach:**

Workflow flow:
1. User provides target (e.g., "192.168.1.0/24", "example.com")
2. AI generates recon plan:
   - Ping sweep to discover live hosts
   - Port scan (nmap -sV -sC)
   - DNS enumeration (if domain)
   - Service version detection
3. Execute recon plan
4. AI analyzes recon results and generates attack plan:
   - Query RAG for exploits matching discovered services
   - Rank exploits by likelihood of success
   - Generate workflow tasks
5. Execute attack plan with Reflector for adaptation

API endpoint:

```rust
#[derive(Deserialize)]
struct ManualTargetRequest {
    target: String,  // IP, CIDR, or domain
    engagement_id: Id,
}

async fn start_manual_target_workflow(
    req: ManualTargetRequest,
) -> Result<WorkflowExecution> {
    // 1. Generate recon plan
    let recon_plan = ai_planner.generate_recon_plan(&req.target).await?;

    // 2. Create workflow
    let workflow = WorkflowDefinition {
        id: Id::new(),
        nodes: recon_plan.to_nodes(),
    };

    // 3. Execute workflow
    let execution = workflow_engine.execute(workflow).await?;

    Ok(execution)
}
```

**Files to Create:**

- `crates/sk-planner/src/manual_target.rs`

**Files to Modify:**

- `crates/sk-api/src/routes/workflows.rs` (API endpoint)

**Testing:**

- Test with single host: 192.168.1.100
- Test with network: 192.168.1.0/24
- Test with domain: example.com
- Test unreachable targets: error handling


EOF
)" --label "type: feature,priority: P1,feature: integrations,size: L"

echo "Issue D4 created"
echo ""

# Cross-Team Issues

echo "Creating cross-team issues..."

gh issue create --title "Integration Testing - Complete Workflows" --body "$(cat <<'EOF'
**Description:**

End-to-end integration testing of all complete workflows.

**Acceptance Criteria:**

- [ ] Test: WiFi AutoPwn with evidence chains
- [ ] Test: Manual target -> AI plan -> execution -> evidence graph
- [ ] Test: Nessus import -> AI exploit -> evidence graph -> report
- [ ] Performance testing: load, latency, memory usage
- [ ] Security testing: input validation, SQL injection, XSS
- [ ] All tests documented

**Test Scenarios:**

**Scenario 1: WiFi AutoPwn**
1. Start WiFi AutoPwn
2. Scan for networks
3. Capture handshake
4. Crack password
5. Verify evidence chain: Scan Evidence -> Network Hypothesis -> Capture Attempt -> Cracked Finding
6. Check confidence scores propagate correctly

**Scenario 2: Manual Target**
1. User provides target: 192.168.1.100
2. AI generates recon plan
3. Execute recon (nmap, service detection)
4. AI generates attack plan based on discovered services
5. Execute attack (e.g., exploit vulnerable SSH)
6. Verify evidence chain and knowledge graph

**Scenario 3: Nessus Import**
1. Upload .nessus file
2. Parse and create targets/findings
3. AI generates exploit plan for critical findings
4. Execute exploits
5. Generate PDF report with evidence chains
6. Verify report quality

**Performance Tests:**
- Load: 10 concurrent engagements
- Latency: <2s for API responses
- Memory: <2GB per engagement

**Security Tests:**
- Input validation: test with malicious payloads
- SQL injection: test database queries
- XSS: test report generation

**Files to Create:**

- `tests/integration/test_wifi_autopwn.rs`
- `tests/integration/test_manual_target.rs`
- `tests/integration/test_nessus_import.rs`

**Testing:**

- Run all integration tests
- Generate test coverage report (target 80%+)
- Document test results


EOF
)" --label "type: test,priority: P1,size: L"

echo "Issue X1 created"

gh issue create --title "Documentation - User Guide" --body "$(cat <<'EOF'
**Description:**

Write comprehensive user guide for Pick + StrikeKit 60-day MVP.

**Acceptance Criteria:**

- [ ] User guide covers all Priority 1 & 2 features
- [ ] Installation instructions
- [ ] WiFi AutoPwn tutorial
- [ ] Manual target tutorial
- [ ] Evidence chain visualization guide
- [ ] Nessus import guide
- [ ] API documentation
- [ ] Screenshots and examples

**Documentation Structure:**

```
docs/
├── README.md (Overview)
├── installation.md
├── tutorials/
│   ├── wifi-autopwn.md
│   ├── manual-target.md
│   ├── nessus-import.md
│   └── evidence-chains.md
├── guides/
│   ├── knowledge-graph.md
│   ├── ai-planning.md
│   └── report-generation.md
└── api/
    ├── rest-api.md
    └── rag-api.md
```

**Content Guidelines:**

- Use clear, concise language
- Include code examples
- Add screenshots for UI features
- Provide troubleshooting tips
- Link related documentation

**Files to Create:**

- All documentation files listed above

**Testing:**

- Have non-developer follow tutorials
- Verify all examples work
- Check links are not broken


EOF
)" --label "type: docs,priority: P2,size: L"

echo "Issue X2 created"

gh issue create --title "Demo Preparation" --body "$(cat <<'EOF'
**Description:**

Prepare comprehensive demo of Pick + StrikeKit 60-day MVP.

**Acceptance Criteria:**

- [ ] Demo script written
- [ ] Demo environment setup
- [ ] Demo data prepared (sample scans, targets, findings)
- [ ] Demo video recorded
- [ ] Presentation slides prepared
- [ ] Demo rehearsals completed (3+ run-throughs)
- [ ] Backup plan for demo failures

**Demo Script:**

**Act 1: WiFi AutoPwn (5 minutes)**
1. Show WiFi adapter detection
2. Start AutoPwn
3. Show network scan results
4. Show evidence chain building in real-time
5. Show knowledge graph visualization
6. Show successful password crack

**Act 2: Manual Target AI Planning (5 minutes)**
1. User provides target: demo-target.local
2. AI generates recon plan (show planning process)
3. Execute recon
4. AI generates attack plan based on findings
5. Show RAG recommendations (exploits from knowledge base)
6. Execute exploit
7. Show evidence chain and report

**Act 3: Nessus Import (3 minutes)**
1. Upload .nessus file
2. Show parsing and target/finding creation
3. AI generates exploit plan for critical findings
4. Show knowledge graph with imported findings
5. Generate PDF report

**Act 4: Knowledge Graph Deep Dive (2 minutes)**
1. Navigate complex evidence chain
2. Filter by confidence
3. Show timeline view
4. Export graph

**Demo Environment:**

- Controlled network with vulnerable targets
- Pre-configured WiFi network for AutoPwn
- Sample .nessus file with known vulnerabilities
- Backup recordings in case of live demo failure

**Files to Create:**

- `docs/demo/demo-script.md`
- `docs/demo/demo-environment-setup.md`
- `docs/demo/presentation-slides.pdf`

**Testing:**

- Run full demo 3+ times
- Time each section (target 15 minutes total)
- Test backup plan


EOF
)" --label "type: chore,priority: P1,size: L"

echo "Issue X3 created"
echo ""

echo "All issues created successfully!"
echo ""
echo "Summary:"
echo "- Team A: 5 issues (Evidence Chains)"
echo "- Team B: 4 issues (RAG)"
echo "- Team C: 4 issues (AI Planning)"
echo "- Team D: 4 issues (Integrations)"
echo "- Cross-Team: 3 issues (Integration, Docs, Demo)"
echo "- Total: 20 issues (plus #94 already created)"
echo ""
echo "Next steps:"
echo "1. Run create-labels.sh to add labels"
echo "2. Add labels to all issues"
echo "3. Assign team members to issues"
echo "4. Start Week 1!"
