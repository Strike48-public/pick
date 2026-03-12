# Pick Strategic Roadmap: Competitive Analysis & Feature Planning

**Date:** 2026-03-12
**Analysis Target:** HorusEye (AI-Powered Active Directory Attack Platform)
**Strategic Goal:** Make Pick superior across all pentesting domains

## Executive Summary

HorusEye represents a sophisticated, AD-focused automated pentesting platform with strong AI integration, team collaboration, and attack path analysis. Pick's strategic positioning is to:

1. **Maintain multi-domain superiority** - Cover network, web, wireless, AD, cloud (not just AD)
2. **Leverage Strike48 platform AI** - Superior AI orchestration vs bolt-on API integration
3. **Build better UX/visualization** - Real-time attack progress, credential dashboards, graph views
4. **Enable enterprise collaboration** - Multi-connector coordination via Strike48 architecture

## User Requirements (From Discovery Questions)

### Strategic Positioning
- Broader scope with multi-domain pentesting (not just AD-only)
- Match AD depth where needed + extend to other domains
- AI-first automation philosophy
- Make Pick **superior** overall

### Key Priorities (from HorusEye capabilities)
1. **Attack path analysis & scoring** ✅ CRITICAL
2. **Credential management & deduplication** ✅ CRITICAL
3. **Interactive decision trees** ✅ HIGH
4. Team collaboration - MEDIUM (Strike48 handles this via multi-connector)

### Technical Decisions
- **AI Integration:** Leverage Strike48's platform AI (not bolt-on APIs)
- **AD Approach:** Hybrid - critical tools native, specialized tools wrapped
- **Credential Management:** Local with optional sync to Strike48
- **Attack Analysis:** Real-time graph viz + AI-driven path recommendation + risk scoring
- **Autonomy:** Fully autonomous by default (can pause/intervene)
- **Platform:** Container/bwrap option + native option (user choice)
- **Reporting:** Evidence collection automation priority
- **UX Focus:** Attack progress viz, credential dashboard, better log filtering
- **Timeline:** 3-6 month strategic vision, parallel infrastructure + features

## Competitive Analysis: HorusEye Strengths

### What They Do Well

1. **Attack Detection & Scoring**
   - 13 distinct AD attack vectors identified automatically
   - Exploitability scoring (0-100) combining impact + feasibility
   - Environment-specific recommendations (not generic)

2. **Tool Integration**
   - Unified pipeline: BloodHound → Certipy → ldapdomaindump → CrackMapExec
   - Parses multiple tool outputs into coherent attack graph
   - Reduces tool fragmentation

3. **Hash Cracking Strategy**
   - 3-round approach: AD patterns → wordlist mutation → hybrid masking
   - Corporate password pattern intelligence
   - Multi-format support (Kerberoast, AS-REP, NTLM, etc.)

4. **Team Collaboration**
   - Real-time shared sessions (TCP port 31337)
   - Broadcast findings, creds, hashes across operators
   - Late-join state synchronization

5. **Interactive Decision Trees**
   - "Senior operator" mode: AI presents ranked options
   - Waits for confirmation before execution
   - Balances automation with control

6. **Credential Management**
   - Central deduplication store
   - Source attribution (which tool found it)
   - Privilege level tagging
   - JSON + TXT formats

7. **Attack Timeline & Reporting**
   - Visual ASCII representation from foothold → DA
   - Time estimates per phase
   - AI-generated explanations per step
   - 25-item domain takeover checklist

## Pick's Current State (Strengths)

1. **Multi-Domain Coverage** ✅
   - Network scanning, WiFi, web, not just AD
   - 25 registered tools across domains
   - AutoPwn orchestrator with hardware detection

2. **Strike48 Platform Integration** ✅
   - Matrix chat for collaboration
   - Server-side AI capabilities
   - Multi-connector architecture
   - Persistent conversation history

3. **Post-Exploitation Tools** ✅
   - CredentialHarvestTool (WiFi, SSH keys, env secrets)
   - LateralMovementTool (5 techniques)
   - Platform abstraction for cross-platform support

4. **Modern UI** ✅
   - Dioxus-based desktop/web UI
   - Chat interface with AI interaction
   - Log filtering with counts
   - Next Steps action buttons

5. **Flexible Deployment** ✅
   - Container/bwrap option (blackarch)
   - Native option (user installs tools)
   - Cross-platform (Linux primary, macOS/Windows supported)

## Pick's Gaps (vs HorusEye)

### Critical Gaps (Must Address)

1. **No Attack Path Analysis**
   - No vulnerability scoring/ranking system
   - No exploitability assessment
   - No attack graph generation
   - No kill chain progress tracking

2. **No Unified Credential Management**
   - CredentialHarvestTool exists but no central store
   - No deduplication across tools
   - No privilege level tagging
   - No credential reuse tracking

3. **Limited AD-Specific Capabilities**
   - No BloodHound integration/parsing
   - No Certipy ADCS scanning
   - No ldapdomaindump integration
   - No Kerberoasting/AS-REP roasting detection
   - No DCSync/Golden Ticket capabilities

4. **Basic Reporting**
   - Text reports to Strike48
   - No attack timeline visualization
   - No evidence collection automation
   - No MITRE ATT&CK mapping

### Medium Priority Gaps

5. **No Visual Attack Representation**
   - No graph/network topology view
   - No interactive attack path exploration
   - No real-time progress visualization

6. **No Advanced Hash Cracking**
   - No integrated hashcat orchestration
   - No AD-specific password pattern intelligence
   - No multi-round cracking strategy

7. **No Interactive Decision Trees**
   - Fully autonomous only (good default)
   - No "approve major decisions" mode
   - No configurable autonomy levels

## Strategic Opportunities (Pick's Advantages)

### What Pick Can Do Better

1. **Platform-Native AI vs Bolt-On**
   - HorusEye uses optional Claude API (external)
   - Pick uses Strike48's integrated AI (built-in)
   - Better context, cheaper, more sophisticated orchestration

2. **Multi-Domain Attack Coordination**
   - HorusEye = AD only
   - Pick = WiFi → Network → Web → AD → Cloud
   - Can pivot across attack surfaces automatically

3. **Modern Architecture**
   - Rust (performance, safety)
   - Dioxus (native + web UI from same code)
   - Matrix (decentralized, secure comms)
   - HorusEye = Python + terminal UI

4. **Multi-Connector Collaboration**
   - Strike48's architecture enables multiple Pick instances
   - Distributed attack from different networks
   - Shared intelligence across connectors
   - HorusEye = single instance or TCP sync

5. **Evidence Collection at Scale**
   - Screenshots, command outputs, proof files
   - Automatic timestamping and attribution
   - Integrated with report generation
   - HorusEye = text reports only

6. **Better Credential Intelligence**
   - Strike48 can analyze cred patterns across engagements
   - Learn which default passwords work where
   - Build org-specific password intelligence
   - HorusEye = per-engagement only

## Feature Roadmap: 3-6 Months (Parallel Tracks)

### Track A: Core Infrastructure (Months 1-3)

#### A1: Credential Management System (Month 1)
**Goal:** Central credential store with deduplication, privilege tagging, and reuse tracking

**Components:**
- `CredentialStore` - Local SQLite database for discovered credentials
- Schema: `{credential, type, source_tool, discovered_at, privilege_level, validated, works_on: [hosts]}`
- Deduplication logic (hash + username + domain)
- Optional sync to Strike48 server (encrypted)
- Integration with existing CredentialHarvestTool
- Integration with future attack tools (auto-try discovered creds)

**Success Criteria:**
- All tools write to central store
- No duplicate credentials
- Can query: "What creds work on Host X?"
- Can query: "What can I access with Cred Y?"
- Sync to Strike48 optional, encrypted

#### A2: Attack Path Analysis & Scoring Engine (Month 2-3)
**Goal:** Graph-based attack path analysis with exploitability scoring

**Components:**
- `AttackGraphBuilder` - Constructs graph from recon data
- Node types: Hosts, Users, Groups, Credentials, Vulnerabilities, Services
- Edge types: HasAccess, MemberOf, AdminOf, Exploits, TrustsTo
- `ExploitabilityScorer` - Impact × Feasibility → 0-100 score
- Impact factors: Privilege level, system criticality, data value
- Feasibility factors: Exploit availability, complexity, detectability
- `PathFinder` - Dijkstra/A* for optimal attack paths
- MITRE ATT&CK tactic/technique mapping
- BloodHound JSON parser (for AD environments)

**Success Criteria:**
- Can ingest: nmap, BloodHound, custom tool outputs
- Generates exploitability scores for each finding
- Can answer: "What's the fastest path to DA?"
- Can answer: "What's the stealthiest path to Host X?"
- Visualizes graph in UI (see Track B)

#### A3: Kill Chain Progress Tracker (Month 3)
**Goal:** Track progress through MITRE ATT&CK framework

**Components:**
- `TacticTracker` - Maps executed tools to ATT&CK tactics
- Tracks: Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact
- Technique attribution (e.g., "T1003.001 - LSASS Memory")
- Timeline of tactics executed
- "What's next?" recommendations based on completed tactics

**Success Criteria:**
- Every tool execution maps to ATT&CK technique
- UI shows progress through kill chain
- AI can recommend next tactic based on completed work
- Report includes ATT&CK coverage matrix

### Track B: UI/UX Enhancements (Months 1-3)

#### B1: Credential Dashboard (Month 1)
**Goal:** Dedicated view for credential management and reuse

**Components:**
- New UI component: `CredentialDashboard`
- Table view: Username, Type, Privilege, Source, Discovered, Validated
- Filters: By privilege level, by type (password/hash/key), by source tool
- Actions: Test credential, use for lateral movement, export
- Search: Full-text search across all credentials
- Highlights: New creds (last 5 min), high-privilege creds

**Success Criteria:**
- Can see all discovered creds at a glance
- Can filter/search/sort efficiently
- One-click actions (test, use, export)
- Updates in real-time as creds discovered

#### B2: Attack Progress Visualization (Month 2)
**Goal:** Real-time visual representation of attack progress

**Components:**
- Kill chain progress bar (MITRE ATT&CK phases)
- Attack timeline (chronological events with timestamps)
- Current phase indicator with time estimate
- Completed tactics (green), current (yellow), upcoming (gray)
- Integration with TacticTracker (Track A3)

**Success Criteria:**
- User can see "where we are" in the attack at a glance
- Shows estimated time to completion
- Updates live as AutoPwn progresses
- Can click on phase to see details

#### B3: Graph Visualization (Month 3)
**Goal:** Interactive attack graph and network topology view

**Components:**
- New UI component: `AttackGraphView`
- Node rendering: Hosts, users, groups, vulns (different colors/shapes)
- Edge rendering: Access relationships, group memberships, exploits
- Interactive: Click node → details panel, zoom/pan, highlight paths
- Path highlighting: Show optimal path from current position to objective
- Integration with AttackGraphBuilder (Track A2)

**Success Criteria:**
- Can visualize entire attack surface
- Can explore relationships interactively
- Can see recommended attack paths highlighted
- Performance: Handles 1000+ nodes smoothly

#### B4: Enhanced Log Filtering (Month 3)
**Goal:** Improve existing log filtering with presets and search

**Components:**
- Save filter presets (e.g., "Errors Only", "Critical Findings")
- Full-text search across log messages
- Export filtered logs (JSON, CSV, TXT)
- Highlight keywords (e.g., "CRITICAL", "password", "success")
- Log categories: Tool execution, AI reasoning, network events, findings

**Success Criteria:**
- Can save/load filter presets
- Can search logs efficiently (1000+ entries)
- Can export for external analysis
- Keywords highlighted automatically

### Track C: AD-Specific Capabilities (Months 2-4)

#### C1: BloodHound Integration (Month 2)
**Goal:** Parse BloodHound/SharpHound output for AD attack path analysis

**Components:**
- `BloodHoundParser` - Parses SharpHound JSON output
- Extracts: Users, groups, computers, domains, trusts, ACLs, sessions
- Feeds AttackGraphBuilder with AD-specific nodes/edges
- Tool wrapper: Execute SharpHound via bwrap container
- Native tool: BloodHound ingestor (Python/Rust port)

**Success Criteria:**
- Can parse SharpHound JSON output
- Can execute SharpHound via Pick
- AD graph integrates with Attack Path Analysis
- Can detect: Kerberoastable users, AS-REPable users, unconstrained delegation, DCSync rights, ACL abuse paths

#### C2: Kerberos Attack Tools (Month 3)
**Goal:** Native Kerberoast, AS-REP roasting, and ticket manipulation

**Components:**
- `KerberoastTool` - Extract service tickets and crack offline
- `ASREPRoastTool` - Extract AS-REP hashes for users without pre-auth
- `GoldenTicketTool` - Forge Kerberos TGTs (post-DA)
- `SilverTicketTool` - Forge service tickets
- Integration with CredentialStore for discovered hashes
- Integration with hash cracking (see Track D)

**Success Criteria:**
- Can identify Kerberoastable users from BloodHound data
- Can extract and crack Kerberos tickets
- Can forge tickets post-compromise
- Credentials automatically stored in CredentialStore

#### C3: ADCS / Certipy Integration (Month 4)
**Goal:** Active Directory Certificate Services vulnerability scanning

**Components:**
- Tool wrapper: Execute Certipy via bwrap container
- `CertipyParser` - Parse Certipy output (ESC1-ESC8 vulnerabilities)
- Feeds AttackGraphBuilder with certificate-based attack paths
- `CertificateAbuseTool` - Exploit identified ESC vulnerabilities
- Integration with ExploitabilityScorer (ESC1 = high score)

**Success Criteria:**
- Can run Certipy scans via Pick
- Can parse and understand ESC vulnerabilities
- Certificate attacks appear in attack graph
- Can exploit ESC vulnerabilities (e.g., ESC1 for user impersonation)

#### C4: DCSync & Domain Dominance (Month 4)
**Goal:** Post-DA persistence and domain dominance techniques

**Components:**
- `DCSyncTool` - Replicate password hashes from DC
- `GoldenTicketTool` - Already in C2, but full integration here
- `SkeletonKeyTool` - Inject skeleton key into DC
- `AdminSDHolderTool` - Modify AdminSDHolder for persistence
- Integration with CredentialStore (DCSync dumps all hashes)

**Success Criteria:**
- Can perform DCSync attack post-DA
- All domain hashes stored in CredentialStore
- Can establish multiple persistence mechanisms
- Persistence tracked in kill chain (ATT&CK Impact)

### Track D: Advanced Capabilities (Months 3-6)

#### D1: Hash Cracking Orchestration (Month 3-4)
**Goal:** Integrated hashcat with AD-specific password intelligence

**Components:**
- `HashCrackTool` - Orchestrates hashcat for multiple hash formats
- 3-round strategy (inspired by HorusEye):
  - Round 1: AD password patterns (Summer2024!, Company123, etc.)
  - Round 2: Wordlist mutation (add years, special chars)
  - Round 3: Hybrid mask attack (8-12 chars, common patterns)
- Multi-format support: Kerberoast, AS-REP, NTLM, NetNTLMv2, MsCacheV2
- Integration with CredentialStore (cracked passwords auto-stored)
- Progress reporting to UI (X% complete, Y hashes cracked)

**Success Criteria:**
- Can crack hashes automatically in background
- 3-round strategy implemented
- Cracked passwords appear in CredentialStore
- User can see progress in UI

#### D2: Username Generation & Password Spraying (Month 4)
**Goal:** Intelligent username generation and safe password spraying

**Components:**
- `UsernameGeneratorTool` - 18 format variants from names
- Formats: john.smith, jsmith, j.smith, smithj, john.s, johns, etc.
- Input: AD user list, manual names, LinkedIn scraping
- `PasswordSprayTool` - Multi-threaded SMB/LDAP sprayer
- Lockout detection (monitor failed attempts per user)
- Adjustable delays and jitter (avoid detection)
- Integration with CredentialStore (valid creds auto-stored)

**Success Criteria:**
- Can generate username variations from names
- Can safely spray passwords without lockouts
- Valid credentials automatically stored
- Lockout detection prevents account locks

#### D3: LSASS Dumping & Memory Analysis (Month 5)
**Goal:** AV-evasive memory dumping for credential extraction

**Components:**
- `LSASSDumpTool` - Auto-selects evasion method
- Methods: nanodump (advanced EDR), comsvcs (Defender), procdump (fallback)
- Platform-specific: Windows only, requires local admin
- `MimikatzParser` - Parse mimikatz/pypykatz output
- Extract: NTLM hashes, plaintext passwords, Kerberos tickets
- Integration with CredentialStore (all extracted creds stored)

**Success Criteria:**
- Can dump LSASS memory on Windows
- Auto-selects evasion method based on AV detection
- Extracted credentials stored in CredentialStore
- Works with existing LateralMovementTool

#### D4: Evidence Collection Automation (Month 5-6)
**Goal:** Automatic capture of evidence for reporting

**Components:**
- `EvidenceCollector` - Hooks into tool execution
- Captures: Command executed, stdout/stderr, timestamp, success/failure
- Screenshot capture (for UI-based tools)
- File artifacts (dumped hashes, loot files, etc.)
- `EvidenceStore` - SQLite database for evidence
- Schema: `{tool, command, output, timestamp, screenshot_path, artifact_paths, finding_id}`
- Integration with reporting (auto-attach evidence to findings)

**Success Criteria:**
- Every tool execution automatically captured
- Screenshots saved for interactive tools
- Files/artifacts tagged with tool and timestamp
- Reports include evidence automatically
- Can query: "Show me evidence for Finding X"

#### D5: Interactive Decision Trees (Month 6)
**Goal:** Configurable autonomy levels for user control

**Components:**
- `AutonomyController` - Manages execution approval workflow
- Autonomy levels:
  - FULL_AUTO (default): Runs end-to-end, no approval needed
  - APPROVE_MAJOR: Asks before exploitation, lateral movement, privilege escalation
  - STEP_BY_STEP: Presents options at each phase, waits for selection
  - MANUAL: No automation, user drives all decisions
- UI integration: Approval prompts with ranked options
- AI-generated recommendations with risk assessment
- "Pause" button to stop and review before proceeding

**Success Criteria:**
- User can set autonomy level in UI
- FULL_AUTO works like current AutoPwn
- APPROVE_MAJOR prompts for major decisions
- STEP_BY_STEP presents decision trees like HorusEye
- Can pause/resume AutoPwn mid-execution

### Track E: Reporting & Collaboration (Months 4-6)

#### E1: Enhanced Report Templates (Month 4)
**Goal:** Rich, professional reports with visualizations

**Components:**
- Attack timeline visualization (SVG/HTML)
- MITRE ATT&CK coverage matrix (heatmap)
- Executive summary (AI-generated)
- Technical findings (with evidence attached)
- Remediation guidance (AI-generated per finding)
- Credential summary table
- Attack graph visualization (embedded SVG)

**Success Criteria:**
- Reports include visual timeline
- ATT&CK matrix shows coverage
- Evidence automatically attached
- AI generates summaries and remediation
- Professional formatting (HTML/PDF)

#### E2: Real-Time Attack Narrative (Month 5)
**Goal:** Live-updating report as engagement progresses

**Components:**
- `NarrativeGenerator` - AI-generated explanations per action
- Real-time updates to Strike48 report document
- Stakeholders can watch engagement unfold
- Phases: Recon → Initial Access → Exploitation → Lateral Movement → Objectives
- Per-action narrative: "Discovered Kerberoastable user 'sqlsvc'. This service account likely has elevated privileges and may use a weak password due to lack of password rotation policies."

**Success Criteria:**
- Report updates live as AutoPwn runs
- Each action has AI-generated narrative
- Stakeholders can follow along remotely
- Timeline shows progression through phases

#### E3: Multi-Connector Coordination (Month 6)
**Goal:** Intelligent task distribution across multiple Pick instances

**Components:**
- `ConnectorCoordinator` - Server-side coordination via Strike48
- Task distribution: Divide port scanning across connectors
- Shared intelligence: One connector's findings inform others
- Credential sharing: Discovered creds available to all connectors
- Deconfliction: Avoid duplicate work (e.g., two connectors scanning same host)

**Success Criteria:**
- Multiple Pick connectors can collaborate
- Work divided intelligently (parallel scanning)
- Credentials shared across connectors
- No duplicate scanning/exploitation
- Coordinated lateral movement

## Implementation Priorities (First 3 Months)

### CRITICAL (Month 1)
1. **Credential Management System** (A1) - Foundation for everything
2. **Credential Dashboard** (B1) - User-visible improvement immediately

### HIGH (Month 2)
3. **Attack Path Analysis & Scoring** (A2) - Core differentiation vs HorusEye
4. **BloodHound Integration** (C1) - AD capability parity
5. **Attack Progress Visualization** (B2) - User-visible improvement

### MEDIUM (Month 3)
6. **Kill Chain Tracker** (A3) - Completes infrastructure foundation
7. **Kerberos Attack Tools** (C2) - Critical AD capability
8. **Hash Cracking Orchestration** (D1) - High-value automation
9. **Graph Visualization** (B3) - Major UX improvement
10. **Enhanced Log Filtering** (B4) - Quality of life improvement

## Success Metrics

### Technical Metrics
- **Attack Path Accuracy:** 90%+ paths lead to successful compromise
- **Credential Deduplication:** 0 duplicate credentials stored
- **Scoring Accuracy:** Exploitability scores correlate with success rate
- **Performance:** Graph rendering <2s for 1000+ nodes
- **Coverage:** 80%+ of MITRE ATT&CK tactics covered

### User Experience Metrics
- **Time to Compromise:** 50% reduction vs manual pentesting
- **False Positive Rate:** <10% of findings are not exploitable
- **User Satisfaction:** "Can I see what's happening?" → YES (visualizations)
- **Report Quality:** Professional, evidence-backed, actionable

### Competitive Metrics
- **AD Depth:** Match HorusEye's 13 attack vectors
- **Multi-Domain:** 5+ domains covered (network, WiFi, web, AD, cloud)
- **AI Integration:** Superior context vs bolt-on API
- **Collaboration:** Multi-connector coordination (HorusEye lacks this)

## Risk Mitigation

### Technical Risks
1. **BloodHound parsing complexity** → Start with JSON parser, add binary later
2. **Graph visualization performance** → Use WebGL/Canvas, lazy loading
3. **Cross-platform AD tools** → Focus on Linux first, bwrap for consistency
4. **Credential sync security** → Encrypt with user-provided key, optional feature

### Product Risks
1. **Scope creep** → Stick to 3-6 month roadmap, defer other features
2. **Over-automation** → Provide autonomy controls, default to full-auto
3. **Complexity vs usability** → Invest in UI/UX, make power features discoverable

### Market Risks
1. **HorusEye continues improving** → Focus on Pick's unique strengths (multi-domain, Strike48 integration)
2. **Other competitors emerge** → Build defensible moats (platform AI, multi-connector architecture)

## Conclusion

This roadmap positions Pick to be **superior** to HorusEye by:

1. **Matching their AD depth** while maintaining multi-domain coverage
2. **Exceeding their AI integration** via Strike48 platform intelligence
3. **Better UX** with modern UI, visualizations, and dashboards
4. **Unique collaboration** via multi-connector architecture
5. **Evidence-backed reporting** with automatic collection and attachment

The parallel track approach enables visible progress (UI improvements) while building critical infrastructure (credential management, attack path analysis). By Month 3, Pick will have strong differentiation. By Month 6, Pick will be the superior choice for comprehensive penetration testing.

**Next Steps:**
1. Convert this roadmap to beads issues (epics, features, tasks)
2. Set up project tracking in beads
3. Begin Month 1 work: Credential Management System + Credential Dashboard
4. Establish success metrics dashboard
5. Regular reviews (every 2 weeks) to adjust priorities based on learnings
