# Pick Strategic Roadmap (Revised) - Lean Connector Focus

**Date:** 2026-03-12
**Strategic Goal:** Make Pick a superior tool execution connector that feeds StrikeKit

## Division of Responsibilities

### StrikeKit (Engagement Management Platform)
✅ **Already Handles:**
- Credential storage & management (SQLite with encryption)
- Target tracking & relationships
- Findings documentation
- Attack path analysis & reporting
- MITRE ATT&CK technique tracking
- Engagement workflow (Planning → Active → Complete)
- C2 infrastructure & agent management
- Team collaboration via Matrix

### Pick (Tool Execution Connector)
**Focus:** Execute pentesting tools locally and send structured data to StrikeKit

**Core Responsibilities:**
1. Tool execution (network scanning, WiFi, web, AD, etc.)
2. Output parsing → structured data
3. Send findings/creds/targets to StrikeKit via Matrix
4. Local UI for monitoring execution progress
5. Hardware detection & platform adaptation

**NOT Pick's Responsibility:**
- ❌ Persistent credential storage (StrikeKit handles this)
- ❌ Long-term engagement tracking (StrikeKit handles this)
- ❌ Report generation (StrikeKit handles this)
- ❌ Attack graph visualization (StrikeKit handles this)
- ❌ C2 infrastructure (StrikeKit handles this)

## Revised Feature Roadmap: 3-6 Months

### Phase 1: Data Pipeline & Tool Integration (Month 1-2)

#### 1.1 Structured Output Parser (Month 1) - CRITICAL
**Goal:** Parse tool outputs into structured data for StrikeKit ingestion

**Components:**
- `OutputParser` trait for tool-specific parsers
- Parsers for existing tools: nmap, masscan, wifi_scan, etc.
- Output types: `Target`, `Credential`, `Finding`, `Service`, `Vulnerability`
- JSON serialization for Matrix messages
- Error handling for malformed tool outputs

**Success Criteria:**
- Every tool output parsed into structured format
- Can extract: IPs, ports, services, credentials, vulnerabilities
- Data sent to StrikeKit via Matrix messages
- Parsing errors logged but don't crash Pick

#### 1.2 StrikeKit Integration Protocol (Month 1) - CRITICAL
**Goal:** Standardized message format for Pick → StrikeKit communication

**Components:**
- Message types: `TargetDiscovered`, `CredentialFound`, `FindingReported`, `ToolExecuted`, `ProgressUpdate`
- JSON schema for each message type
- Matrix message formatting helper
- Engagement ID tracking (from StrikeKit)
- Source attribution (which Pick instance, which tool)

**Success Criteria:**
- Pick sends structured data to StrikeKit
- StrikeKit can ingest and store Pick's findings
- Message format documented for other connectors
- Can track which Pick instance sent what data

#### 1.3 AD Tool Integration - BloodHound (Month 2) - HIGH
**Goal:** Execute BloodHound/SharpHound and send results to StrikeKit

**Components:**
- Tool wrapper: Execute SharpHound via bwrap container
- `BloodHoundParser` - Parse SharpHound JSON output
- Extract: Users, groups, computers, admin relationships, ACL paths
- Convert to `Target` and `Finding` messages for StrikeKit
- Send raw BloodHound JSON as artifact (StrikeKit stores it)

**Success Criteria:**
- Can execute SharpHound via Pick
- AD users/computers appear as Targets in StrikeKit
- ACL abuse paths appear as Findings in StrikeKit
- Raw BloodHound data available in StrikeKit for analysis

#### 1.4 AD Tool Integration - Kerberos (Month 2) - HIGH
**Goal:** Kerberoast, AS-REP roast, extract hashes for StrikeKit

**Components:**
- `KerberoastTool` - Extract service tickets
- `ASREPRoastTool` - Extract AS-REP hashes
- Parse output → `Credential` messages (type: "kerberos_hash")
- Send to StrikeKit for storage
- Include: username, hash, hash_type, domain, source_tool

**Success Criteria:**
- Can extract Kerberos hashes via Pick
- Hashes appear in StrikeKit Credentials table
- Hash type properly tagged (Kerberos, AS-REP, etc.)
- Ready for offline cracking (user does this separately)

### Phase 2: Autonomous Execution & Intelligence (Month 3-4)

#### 2.1 Tool Recommendation Engine (Month 3) - MEDIUM
**Goal:** AI-driven tool recommendations based on discovered environment

**Components:**
- `RecommendationEngine` - Analyzes discovered targets
- Input: Target list, service list, OS detection
- Output: Ranked tool recommendations with rationale
- Examples:
  - Discovered Windows DC → Recommend BloodHound, Kerberoast
  - Discovered web server → Recommend nikto, sqlmap
  - Discovered WiFi → Recommend aircrack, wifite
- Strike48 AI integration for recommendations

**Success Criteria:**
- After initial scan, AI recommends next tools
- Recommendations prioritized by exploitability
- User can approve or modify recommendations
- AutoPwn uses recommendations for autonomous flow

#### 2.2 Credential Reuse Testing (Month 3) - HIGH
**Goal:** Query StrikeKit for discovered creds, test on new targets

**Components:**
- `CredentialTester` - Tests credentials on targets
- Query StrikeKit: "Get all credentials for engagement X"
- Test against newly discovered hosts (SSH, SMB, RDP, LDAP)
- Report results back to StrikeKit (privilege_tier, works_on)
- Integration with existing LateralMovementTool

**Success Criteria:**
- Pick queries StrikeKit for existing creds
- Automatically tests creds on new targets
- Updates StrikeKit with validation results
- No local credential storage (StrikeKit is source of truth)

#### 2.3 Evidence Collection (Month 4) - MEDIUM
**Goal:** Capture evidence for StrikeKit findings

**Components:**
- `EvidenceCollector` - Hooks into tool execution
- Captures: Command executed, full output, timestamp, success/failure
- Screenshot capture for interactive tools
- File artifacts (dumped files, loot, etc.)
- Send to StrikeKit as attachments via Matrix

**Success Criteria:**
- Every tool execution captured
- Evidence attached to findings in StrikeKit
- Screenshots saved for GUI-based tools
- Files uploaded to StrikeKit storage

#### 2.4 Progress Reporting (Month 4) - MEDIUM
**Goal:** Real-time progress updates to StrikeKit

**Components:**
- `ProgressReporter` - Sends periodic status updates
- Status types: `ToolStarted`, `ToolCompleted`, `ToolFailed`, `PhaseCompleted`
- Include: Tool name, target, progress %, ETA
- AutoPwn phase tracking (Recon → Exploitation → Lateral Movement)
- Send to StrikeKit for live engagement monitoring

**Success Criteria:**
- StrikeKit shows Pick status in real-time
- Can see which tools are running
- Can see AutoPwn progress through phases
- Failure notifications sent immediately

### Phase 3: Advanced Capabilities & Performance (Month 5-6)

#### 3.1 Hash Cracking Coordination (Month 5) - LOW
**Goal:** Offload hash cracking to external service or local hashcat

**Components:**
- `HashCrackCoordinator` - Submits hashes for cracking
- Option 1: Local hashcat execution (background task)
- Option 2: Submit to external cracking service (if available)
- Poll for results, update StrikeKit when cracked
- 3-round strategy: AD patterns → wordlist → mask attack

**Success Criteria:**
- Hashes submitted for cracking automatically
- Cracked passwords appear in StrikeKit
- Runs in background, doesn't block Pick
- User can see cracking progress/results

#### 3.2 AD Tool Integration - ADCS / Certipy (Month 5) - MEDIUM
**Goal:** Scan for Active Directory Certificate Services vulnerabilities

**Components:**
- Tool wrapper: Execute Certipy via bwrap container
- `CertipyParser` - Parse Certipy output
- Identify ESC1-ESC8 vulnerabilities
- Send as `Finding` messages to StrikeKit
- Include: Vulnerability type, affected templates, exploitation steps

**Success Criteria:**
- Can run Certipy scans via Pick
- ESC vulnerabilities reported to StrikeKit as findings
- Severity scored appropriately (ESC1 = high)
- Includes remediation guidance

#### 3.3 UI Enhancements - Progress Visualization (Month 5) - LOW
**Goal:** Better local UI for monitoring tool execution

**Components:**
- Attack phase progress bar (Recon → Exploitation → Lateral Movement)
- Live tool output streaming (scrolling terminal view)
- Recently discovered targets/creds/findings (last 10)
- Current AutoPwn phase indicator
- Time elapsed / estimated remaining

**Success Criteria:**
- User can see AutoPwn progress at a glance
- Live tool output visible in UI
- Recent discoveries highlighted
- Estimated completion time shown

#### 3.4 Multi-Tool Orchestration (Month 6) - MEDIUM
**Goal:** Intelligent tool chaining and parallel execution

**Components:**
- `OrchestrationEngine` - Chains tools based on output
- Example flow: nmap → parse services → recommend tools → execute
- Parallel execution: Multiple tools on different targets
- Dependency tracking: Tool B needs Tool A's output
- Resource management: CPU/memory limits, tool queuing

**Success Criteria:**
- Multiple tools execute in parallel
- Tool chains execute automatically (scan → enum → exploit)
- Resource limits prevent system overload
- Failed tools don't block other tools

#### 3.5 Interactive Autonomy Modes (Month 6) - LOW
**Goal:** User control over AutoPwn autonomy level

**Components:**
- `AutonomyController` - Manages approval workflow
- Modes:
  - FULL_AUTO (default): Runs end-to-end
  - APPROVE_MAJOR: Asks before exploitation, lateral movement
  - STEP_BY_STEP: Presents options at each phase
  - MANUAL: No automation, user selects tools
- UI integration: Approval prompts with recommendations
- Pause/resume AutoPwn mid-execution

**Success Criteria:**
- User can set autonomy level
- FULL_AUTO matches current AutoPwn behavior
- APPROVE_MAJOR prompts for risky actions
- Can pause and resume at any time

### Phase 4: Platform & Performance (Month 5-6, Parallel)

#### 4.1 Tool Container Management (Month 5) - LOW
**Goal:** Improve bwrap container usage for tool isolation

**Components:**
- Container image management (pull, cache, update)
- Volume mounts for input/output files
- Network isolation options
- Tool version management
- Fallback to native tools if container unavailable

**Success Criteria:**
- Tools run in isolated containers by default
- Native fallback works when containers unavailable
- Tool versions tracked and updateable
- Minimal performance overhead

#### 4.2 Multi-Connector Deconfliction (Month 6) - MEDIUM
**Goal:** Coordinate multiple Pick instances via StrikeKit

**Components:**
- `ConnectorCoordinator` - Server-side in StrikeKit
- Pick queries: "Am I allowed to scan Target X?"
- StrikeKit tracks: Which connector is scanning what
- Prevents duplicate work across connectors
- Load balancing: Distribute targets across connectors

**Success Criteria:**
- Multiple Pick connectors don't duplicate scans
- Work distributed intelligently
- Failures handled (connector goes offline)
- StrikeKit shows which connector is doing what

## Implementation Priority Matrix

### CRITICAL (Must Have - Month 1-2)
| Priority | Feature | Impact | Effort | ROI |
|----------|---------|--------|--------|-----|
| P0 | Structured Output Parser | Enables all StrikeKit integration | Medium | ⭐⭐⭐⭐⭐ |
| P0 | StrikeKit Integration Protocol | Foundation for data pipeline | Medium | ⭐⭐⭐⭐⭐ |
| P1 | BloodHound Integration | AD capability parity | High | ⭐⭐⭐⭐ |
| P1 | Kerberos Tools | Critical AD attack vector | Medium | ⭐⭐⭐⭐ |

### HIGH (Should Have - Month 3-4)
| Priority | Feature | Impact | Effort | ROI |
|----------|---------|--------|--------|-----|
| P2 | Tool Recommendation Engine | AI-driven automation | Medium | ⭐⭐⭐⭐ |
| P2 | Credential Reuse Testing | Lateral movement automation | Medium | ⭐⭐⭐⭐ |
| P2 | Evidence Collection | Professional reporting | Low | ⭐⭐⭐ |
| P2 | Progress Reporting | Real-time visibility | Low | ⭐⭐⭐ |

### MEDIUM (Nice to Have - Month 5-6)
| Priority | Feature | Impact | Effort | ROI |
|----------|---------|--------|--------|-----|
| P3 | ADCS/Certipy Integration | Additional AD coverage | Medium | ⭐⭐⭐ |
| P3 | Multi-Tool Orchestration | Efficiency improvement | High | ⭐⭐⭐ |
| P3 | Multi-Connector Deconfliction | Enterprise collaboration | Medium | ⭐⭐⭐ |

### LOW (Could Have - Month 5-6)
| Priority | Feature | Impact | Effort | ROI |
|----------|---------|--------|--------|-----|
| P4 | Hash Cracking Coordination | Convenience feature | High | ⭐⭐ |
| P4 | UI Progress Visualization | Local UX improvement | Low | ⭐⭐ |
| P4 | Interactive Autonomy Modes | User control | Medium | ⭐⭐ |
| P4 | Tool Container Management | Dev experience improvement | Medium | ⭐⭐ |

## Deferred to StrikeKit

These features were in the original roadmap but belong in StrikeKit:

- ❌ Attack Path Analysis & Scoring → **StrikeKit** (already has graph relationships)
- ❌ Credential Management System → **StrikeKit** (already has credentials table + many-to-many)
- ❌ Kill Chain Progress Tracker → **StrikeKit** (already has MITRE ATT&CK tracking)
- ❌ Credential Dashboard → **StrikeKit** (already has credentials UI)
- ❌ Graph Visualization → **StrikeKit** (will add attack graph viz there)
- ❌ Enhanced Reporting → **StrikeKit** (already has PDF reports)
- ❌ Real-Time Attack Narrative → **StrikeKit** (engagement timeline)

## Success Metrics

### Integration Metrics
- **Data Quality:** 95%+ of tool outputs successfully parsed
- **Message Delivery:** 99%+ messages reach StrikeKit
- **Latency:** <1s from tool completion to StrikeKit ingestion
- **Deduplication:** 0 duplicate targets/creds in StrikeKit

### Execution Metrics
- **Tool Success Rate:** 90%+ tools execute without errors
- **Coverage:** 20+ tools integrated with structured output parsers
- **Parallelization:** 3+ tools execute simultaneously
- **Container Performance:** <10% overhead vs native execution

### User Experience Metrics
- **Time to First Finding:** <5 minutes from AutoPwn start
- **AutoPwn Completion Rate:** 80%+ runs complete without intervention
- **False Positive Rate:** <10% of reported findings are invalid
- **User Satisfaction:** "Pick is reliable and feeds good data to StrikeKit"

## Architecture Principles

### 1. Thin Client, Smart Server
- Pick = thin execution layer
- StrikeKit = smart analysis and storage layer
- Don't duplicate logic between them

### 2. Stateless Execution
- Pick doesn't maintain long-term state
- Every execution queries StrikeKit for context
- Can restart Pick without losing data

### 3. Structured Data First
- Every tool output → structured format
- Schema validation before sending to StrikeKit
- Human-readable AND machine-readable

### 4. Fail Gracefully
- Tool failures don't crash Pick
- Parse errors logged but don't block execution
- Network issues → retry with backoff

### 5. Platform Agnostic
- Container + native tool support
- Windows/Linux/macOS compatibility
- Hardware detection for optimal tool selection

## Resource Allocation (2-3 People + Crowdsource)

### Month 1-2 (Foundation)
- **Dev 1:** Structured Output Parser (1.1)
- **Dev 2:** StrikeKit Integration Protocol (1.2)
- **Dev 3:** BloodHound Integration (1.3)
- **Crowdsource:** Kerberos Tools (1.4)

### Month 3-4 (Intelligence)
- **Dev 1:** Tool Recommendation Engine (2.1)
- **Dev 2:** Credential Reuse Testing (2.2)
- **Dev 3:** Evidence Collection (2.3)
- **Crowdsource:** Progress Reporting (2.4)

### Month 5-6 (Advanced + Polish)
- **Dev 1:** Multi-Tool Orchestration (3.4)
- **Dev 2:** ADCS/Certipy Integration (3.2)
- **Dev 3:** Multi-Connector Deconfliction (4.2)
- **Crowdsource:** UI Progress Viz (3.3), Container Management (4.1)

## Next Steps

1. **Align with StrikeKit team** - Confirm message protocol and schema
2. **Create beads issues** - Convert roadmap to trackable tasks
3. **Month 1 Sprint Planning** - Focus on 1.1 and 1.2 (foundation)
4. **Set up crowdsource** - Document contribution guidelines, task breakdown
5. **Weekly sync** - Review progress, adjust priorities

## Conclusion

This **revised roadmap** positions Pick as a **lean, focused tool execution connector** that complements StrikeKit rather than duplicating it. By offloading storage, analysis, and visualization to StrikeKit, Pick can focus on what it does best:

1. **Execute tools reliably** across platforms
2. **Parse outputs accurately** into structured data
3. **Feed StrikeKit** with high-quality intelligence
4. **Automate workflows** with AI-driven tool selection

This division of labor creates a **powerful system** where Pick provides the execution layer and StrikeKit provides the intelligence layer. Together, they're superior to monolithic tools like HorusEye.
