# Week 1 Detailed Checklist (April 7-13, 2026)

**Goal:** Foundation & Schema Design - Complete infrastructure setup and schema design for all teams

---

## Monday, April 7

### Team A: Evidence Chains (2 devs)
- [ ] Review existing schema in `strikekit/crates/sk-db/src/schema.rs`
- [ ] Identify gaps in evidence tracking (missing: evidence table, hypotheses, hypothesis_evidence, exploit_attempts, evidence_chains)
- [ ] Draft initial schema for 5 new tables with columns and relationships
- [ ] Share draft schema with team for early feedback

### Team B: RAG (1-2 devs)
- [ ] Setup Qdrant locally via Docker (`docker run -p 6333:6333 qdrant/qdrant`)
- [ ] Verify Qdrant API connectivity (`curl http://localhost:6333`)
- [ ] Download ExploitDB archive from https://gitlab.com/exploit-database/exploitdb
- [ ] Extract and inspect exploit file structure
- [ ] Choose embedding model (sentence-transformers/all-MiniLM-L6-v2 recommended for dev)

### Team C: AI Planning (1-2 devs)
- [ ] Review existing Reflector patterns in `strikekit/crates/sk-executor/src/planning.rs`
- [ ] Read L1-L4 failure categorization from system architecture docs
- [ ] Design Reflector agent interface (input: TaskExecution, output: ReplanRequest)
- [ ] Draft failure analysis logic pseudocode
- [ ] Identify integration points in workflow engine

### Team D: Integrations (1 dev)
- [ ] Download sample Nessus XML file for testing
- [ ] Research Rust XML parsing libraries (quick-xml vs roxmltree)
- [ ] Scaffold Nessus parser module (`strikekit/crates/sk-integrations/src/nessus.rs`)
- [ ] Write basic XML loading test
- [ ] Document Nessus XML schema structure

**End of Day Standup:** Share progress, blockers, and tomorrow's priorities

---

## Tuesday, April 8

### Team A: Evidence Chains
- [ ] Refine schema based on Monday feedback
- [ ] Add foreign key relationships and indexes
- [ ] Document schema design decisions (why confidence scoring at edge level, etc.)
- [ ] Create migration script template (`migrations/YYYYMMDD_add_evidence_chains.sql`)
- [ ] Add schema to version control

### Team B: RAG
- [ ] Build ingestion pipeline script (`strikekit/tools/ingest_exploitdb.py`)
- [ ] Parse first 10 exploits (title, description, code, platform, type)
- [ ] Generate embeddings for first 10 exploits
- [ ] Insert into Qdrant collection "exploits"
- [ ] Query test: "linux privilege escalation" should return relevant results

### Team C: AI Planning
- [ ] Implement Reflector agent struct in `strikekit/crates/sk-executor/src/reflector.rs`
- [ ] Add `ReflectorAgent` to NodeType enum in workflow engine
- [ ] Implement failure categorization logic (pattern matching on error messages)
- [ ] Write unit tests for L1-L4 classification
- [ ] Document Reflector agent contract

### Team D: Integrations
- [ ] Parse `<ReportHost>` blocks from Nessus XML
- [ ] Extract host IP, OS, hostname
- [ ] Parse `<ReportItem>` for vulnerabilities
- [ ] Extract CVE, severity, service name, port
- [ ] Write parser tests with sample XML

**End of Day Standup:** Demo progress (show parsed exploits, schema draft, etc.)

---

## Wednesday, April 9

### Team A: Evidence Chains
- [ ] Create Rust structs for new schema tables
  - `Evidence`, `Hypothesis`, `HypothesisEvidence`, `ExploitAttempt`, `EvidenceChain`
- [ ] Add to `strikekit/crates/sk-core/src/types.rs`
- [ ] Implement database access layer in `strikekit/crates/sk-db/src/evidence.rs`
- [ ] Write basic CRUD operations (create, read, list)
- [ ] Add integration tests for database operations

### Team B: RAG
- [ ] Scale ingestion to 100 exploits
- [ ] Measure ingestion speed (should be 10+ exploits/sec)
- [ ] Add metadata filtering (platform, type, date)
- [ ] Test filtered queries: "windows exploits" should exclude Linux results
- [ ] Document ingestion pipeline usage

### Team C: AI Planning
- [ ] Create Reflector agent node type in workflow definitions
- [ ] Implement execution in `strikekit/crates/sk-workflow/src/executor.rs`
- [ ] Connect to LLM provider (Prospector Studio via SDK-RS)
- [ ] Build system prompt for failure analysis
- [ ] Test Reflector with mock failed task execution

### Team D: Integrations
- [ ] Map Nessus XML data to StrikeKit types
  - `ReportHost` to `Target`
  - `ReportItem` to `Finding`
- [ ] Create Target entries in database
- [ ] Create Finding entries in database
- [ ] Link findings to targets
- [ ] Write integration test: XML in, database entries out

**End of Day Standup:** Address integration questions between teams

---

## Thursday, April 10

### Team A: Evidence Chains
- [ ] Expand CRUD operations (update, delete, link creation)
- [ ] Implement evidence chain traversal queries
  - Get all evidence for hypothesis
  - Get all hypotheses for evidence
  - Get full chain from evidence to finding
- [ ] Write comprehensive unit tests (80%+ coverage target)
- [ ] Add error handling for constraint violations

### Team B: RAG
- [ ] Scale to 1000 exploits (10% of full dataset)
- [ ] Optimize batch ingestion (process in chunks of 100)
- [ ] Add progress logging
- [ ] Test search quality: precision/recall on known queries
- [ ] Document API endpoints for semantic search

### Team C: AI Planning
- [ ] Implement recommendation generation
  - Input: failed task + error message
  - Output: 3 alternative approaches with confidence scores
- [ ] Add reasoning explanations (why this alternative?)
- [ ] Test with realistic failure scenarios
  - Network timeout
  - Authentication failure
  - Tool not found
  - Insufficient privileges
- [ ] Refine prompts based on test results

### Team D: Integrations
- [ ] Build Nessus import workflow definition
  - Node 1: Parse XML
  - Node 2: Create Targets
  - Node 3: Create Findings
  - Node 4: Link Findings to Targets
- [ ] Add to `strikekit/workflows/nessus_import.json`
- [ ] Test workflow execution end-to-end
- [ ] Add error handling (invalid XML, duplicate entries)

**End of Day Standup:** Integration checkpoint - teams discuss dependencies

---

## Friday, April 11

### Team A: Evidence Chains
- [ ] Code review of all evidence chain code
- [ ] Address review feedback
- [ ] Run full test suite
- [ ] Generate code coverage report (verify 80%+)
- [ ] Update API documentation

### Team B: RAG
- [ ] Complete ExploitDB ingestion (all 50k+ exploits)
- [ ] Verify collection stats in Qdrant dashboard
- [ ] Run performance benchmarks (query latency should be <100ms)
- [ ] Setup PayloadsAllTheThings repository clone
- [ ] Plan Monday's PATT ingestion work

### Team C: AI Planning
- [ ] Integrate Reflector into workflow engine
- [ ] Test Reflector in real workflow execution
- [ ] Measure LLM call latency and costs
- [ ] Document Reflector agent configuration
- [ ] Prepare demo for Monday standup

### Team D: Integrations
- [ ] Polish Nessus import workflow
- [ ] Add logging and progress reporting
- [ ] Write user documentation for import process
- [ ] Test with multiple Nessus XML files (different scanners, versions)
- [ ] Create example workflow for demo

**End of Week Standup:** 
- Each team demos completed milestone
- Review Week 1 goals vs actuals
- Identify blockers for Week 2
- Celebrate wins

---

## Week 1 Milestone Checklist

### Team A: Evidence Chains
- [ ] Schema design complete and documented
- [ ] Migration scripts written
- [ ] Rust structs created
- [ ] Database access layer implemented
- [ ] Unit tests written (80%+ coverage)
- [ ] Code reviewed and merged

### Team B: RAG
- [ ] Qdrant running locally
- [ ] ExploitDB fully ingested (50k+ exploits)
- [ ] Semantic search API documented
- [ ] Search quality validated
- [ ] PayloadsAllTheThings repo cloned and ready

### Team C: AI Planning
- [ ] Reflector agent interface designed
- [ ] Failure analysis logic implemented
- [ ] Reflector agent node type created
- [ ] Unit tests for failure categorization
- [ ] Integration with workflow engine complete

### Team D: Integrations
- [ ] Nessus XML parser working
- [ ] Target and Finding extraction functional
- [ ] Parser tests passing
- [ ] Nessus import workflow defined
- [ ] End-to-end workflow tested

**Definition of Done:**
- All code reviewed
- All tests passing
- Documentation updated
- No critical bugs
- Demo-ready

---

## Risk Tracking

**Monitor these risks during Week 1:**

1. **Schema Changes**: If evidence chain schema changes mid-week, allow 1-2 days buffer
2. **Qdrant Performance**: If ingestion is slow, consider batch size optimization
3. **LLM Latency**: If Reflector calls are slow, implement caching strategy
4. **Team Velocity**: If tasks take longer than expected, adjust Week 2 scope

**Escalation:** Raise blockers in daily standups, don't wait until Friday

---

## Communication

**Daily Standup Format:**
- What I completed yesterday
- What I'm working on today
- Any blockers

**Slack Channels:**
- `#team-evidence-chains` - Team A coordination
- `#team-rag` - Team B coordination
- `#team-ai-planning` - Team C coordination
- `#team-integrations` - Team D coordination
- `#60day-mvp-standup` - Daily standup reports

**Friday Demo:**
- 5 minutes per team
- Show working code, not slides
- Highlight blockers for next week

---

**END OF WEEK 1 CHECKLIST**
