# System Architecture: Pick + StrikeKit Ecosystem

**Version:** 1.0
**Date:** 2026-04-07
**Status:** Architecture Definition
**Owner:** Strike48 Technical Team

---

## Executive Summary

Pick and StrikeKit form a comprehensive penetration testing platform with multiple deployment modes, C2 options, and AI orchestration. The system supports standalone operation, enterprise C2 integration (Mythic, Cobalt Strike, GoPhish), and autonomous AI-driven pentesting.

**Key Architectural Principles:**
1. **Unified Platform:** StrikeKit/Prospector Studio are one platform (strategic + tactical AI orchestration)
2. **User Choice:** Standalone, Mythic agent, or StrikeKit C2 - user decides
3. **Layered Control:** StrikeKit → Mythic → Pick (top-down orchestration)
4. **Secure Communication:** Strike48 Connector SDK (SDK-RS) for all C2 connections
5. **Integration-First:** Manage/import from Nessus, Cobalt Strike, Metasploit, GoPhish, etc.
6. **Flexible Deployment:** Pick (full tooling) OR lightweight agents depending on target constraints
7. **Multi-Platform:** Pick runs on Desktop, Android, Web, TUI

---

## Table of Contents

1. [High-Level Architecture](#1-high-level-architecture)
2. [Component Breakdown](#2-component-breakdown)
3. [Deployment Modes](#3-deployment-modes)
4. [Data Flow Patterns](#4-data-flow-patterns)
5. [Integration Architecture](#5-integration-architecture)
6. [AI Orchestration](#6-ai-orchestration)
   - 6.4 [Workflow Engine](#64-workflow-engine-deterministic-automation)
7. [Auditing & Scoping](#7-auditing--scoping)
   - 7.1 [Comprehensive Audit Log System](#71-comprehensive-audit-log-system)
   - 7.2 [Scoping & Boundary Enforcement](#72-scoping--boundary-enforcement)
8. [Security Model](#8-security-model)
9. [Implementation Phases](#9-implementation-phases)

---

## 1. High-Level Architecture

### 1.1 System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         Strike48 Platform                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                           │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │              StrikeKit (Prospector Studio)                        │  │
│  │         Strategic + Tactical AI Orchestration                     │  │
│  ├───────────────────────────────────────────────────────────────────┤  │
│  │  AI ENGINE:                                                       │  │
│  │  • LLM Integration (OpenAI, Anthropic, Ollama)                   │  │
│  │  • Task Graph Planning (DAG - non-deterministic)                 │  │
│  │  • Workflow Engine (n8n-like - deterministic)                    │  │
│  │  • Evidence-Based Reasoning                                       │  │
│  │  • Multi-Agent Coordination (Planner, Executor, Reflector)       │  │
│  │  • Knowledge Base (RAG with exploit databases)                    │  │
│  │                                                                    │  │
│  │  ENGAGEMENT MANAGEMENT:                                           │  │
│  │  • Targets, Credentials, Findings                                │  │
│  │  • C2 Infrastructure (Connector SDK-based)                       │  │
│  │  • Pivot Tracking, MITRE ATT&CK                                  │  │
│  │  • Professional Reporting (PDF/HTML)                             │  │
│  │  • Audit Logging & Timeline (immutable, tamper-evident)          │  │
│  │  • Scoping & Boundary Enforcement (real-time validation)         │  │
│  │  • Integration Management (Nessus, CS, Mythic, GoPhish)         │  │
│  │                                                                    │  │
│  │  LICENSE: AGPL-3.0                                               │  │
│  └───────────────────────┬───────────────────────────────────────────┘  │
│                          │ Strike48 Connector SDK (SDK-RS)              │
│                          │ Secure, authenticated connections            │
│                          │                                               │
│                          ▼                                               │
│              ┌─────────────────────────┐                                │
│              │        Pick             │                                │
│              │   (Tool Execution)      │                                │
│              ├─────────────────────────┤                                │
│              │ • Full Arch Linux env   │                                │
│              │ • BlackArch repo (3000+)│                                │
│              │ • Extensible (Kali, etc)│                                │
│              │ • Sandboxed/Native mode │                                │
│              │ • Multi-Platform:       │                                │
│              │   - Desktop (Linux/Mac/Win)                              │
│              │   - Android             │                                │
│              │   - Web (headless)      │                                │
│              │   - TUI (terminal)      │                                │
│              │ • Tool Orchestration    │                                │
│              │ • Evidence Generation   │                                │
│              │                         │                                │
│              │ LICENSE: MIT            │                                │
│              └─────────────────────────┘                                │
│                          │                                               │
└──────────────────────────┼───────────────────────────────────────────────┘
                           │
                           ▼
        ┌──────────────────────────────────────────────┐
        │         External Integrations                 │
        ├──────────────────────────────────────────────┤
        │ • Nessus (managed/imported)                  │
        │ • Cobalt Strike (sessions imported)          │
        │ • Mythic C2 (controlled by StrikeKit)        │
        │ • Metasploit (tool execution)                │
        │ • Burp Suite (issues imported)               │
        │ • BloodHound (AD paths imported)             │
        │ • GoPhish (social engineering campaigns)     │
        └──────────────────────────────────────────────┘
                           │
                           ▼
        ┌──────────────────────────────────────────────┐
        │         Deployment Targets                    │
        ├──────────────────────────────────────────────┤
        │ • Desktop/Laptop (Pick standalone)           │
        │ • Android devices (Pick mobile)              │
        │ • Target servers (Pick as agent)             │
        │ • Cloud instances (Pick/lightweight agents)  │
        │ • Pivots/proxies (lightweight agents)        │
        └──────────────────────────────────────────────┘
```

### 1.2 Control Hierarchy

**Top-Down Orchestration:**

```
┌─────────────────────────────────────────────────────────────────┐
│              StrikeKit (Prospector Studio)                       │
│           Strategic + Tactical AI Orchestration                  │
│  "Plan engagements, coordinate systems, manage all tools"        │
└────────────┬──────────────────────┬─────────────────────────────┘
             │                      │
             ▼                      ▼
    ┌────────────────┐     ┌────────────────┐
    │  Mythic C2     │     │ StrikeKit C2   │
    │  (Optional     │     │  (Built-in     │
    │   External)    │     │   Connector)   │
    └────────┬───────┘     └────────┬───────┘
             │                      │
             │    Connector SDK     │
             │    (SDK-RS)          │
             ▼                      ▼
    ┌─────────────────────────────────────┐
    │            Pick Instances           │
    │       (Tool Execution Agents)       │
    │  "Execute tools, generate evidence" │
    │  Desktop | Android | Web | TUI    │
    └─────────────────────────────────────┘
```

**Key Insights:**
- **StrikeKit IS the orchestrator** (no separate Prospector Studio)
- **StrikeKit can control Mythic C2** which then controls Pick agents
- **All C2 communication uses Connector SDK (SDK-RS)** for secure, authenticated connections
- **Pick has Android deployment** alongside Desktop, Web, TUI
- Enterprise teams can use existing Mythic infrastructure while gaining StrikeKit's AI orchestration

---

## 2. Component Breakdown

### 2.1 StrikeKit (Prospector Studio) - Unified Platform

**Purpose:** Complete penetration testing orchestration platform with AI engine + engagement management

**AI Engine Responsibilities:**
- LLM provider abstraction (OpenAI, Anthropic, Ollama, DeepSeek)
- Task graph planning (DAG-based, non-deterministic)
- Multi-agent coordination (Planner, Executor, Reflector)
- Evidence-based reasoning (confidence scoring)
- Knowledge base (RAG with ExploitDB, PayloadsAllTheThings)
- Cost tracking and optimization
- **Workflow Engine:** Deterministic automation (n8n-like)
  - Codeable workflows (Rust/TypeScript)
  - AI-enhanced workflows (LLM nodes)
  - Trigger-based execution (event-driven)
  - Visual workflow builder (optional)
  - Reusable workflow templates
  - Hybrid: Deterministic workflows + AI decision points

**Engagement Management Responsibilities:**

- **Engagement Lifecycle:** Planning, Active, Paused, Complete, Archived
- **Asset Management:** Targets, credentials, findings
- **C2 Infrastructure:** Built-in listener + cross-platform agent (Connector SDK-based)
- **Pivot Tracking:** Visual kill chains, lateral movement
- **MITRE ATT&CK:** Technique mapping, coverage tracking
- **Reporting:** Professional PDF/HTML reports
- **Integration Hub:** Manage/import from Nessus, Cobalt Strike, Mythic, Metasploit, GoPhish, Burp, BloodHound
- **External Tool Management:** Control Nessus scanners for long-term engagements
- **Comprehensive Auditing:** Complete audit log system
  - Every action logged (who, what, when, where)
  - Immutable audit trail (tamper-evident)
  - Timeline visualization (engagement activity over time)
  - Export for compliance (SOC 2, ISO 27001, GDPR)
  - User attribution (all actions tied to user accounts)
- **Scoping & Boundaries:** Strict in/out of scope enforcement
  - Define scope: IP ranges, domains, applications, timeframes
  - Real-time scope validation (block out-of-scope actions)
  - Scope violation alerts (immediate notification)
  - Approval workflows (out-of-scope requests require authorization)
  - Scope change tracking (audit trail of scope modifications)
  - Legal protection (prove adherence to engagement boundaries)

**Technology Stack:**
- Rust + Dioxus 0.7 (liveview)
- PostgreSQL for persistence
- Qdrant for vector search (RAG)
- Matrix connector for StrikeHub integration
- Strike48 Connector SDK (SDK-RS) for secure C2 communication
- AGPL-3.0 license

**Deployment:**
- Headless liveview server (connector mode)
- Runs in StrikeHub unified desktop
- Collaborative access via Matrix
- GraphQL API for external integrations

---

### 2.2 Pick (Tool Execution Engine)

**Purpose:** Multi-platform penetration testing tool executor with full Linux environment

**Responsibilities:**
- **Full Linux Environment:** Complete Arch Linux system, not just BlackArch tools
  - Base: Arch Linux with full package ecosystem
  - Security: BlackArch repository (3000+ pentesting tools)
  - Extensibility: Can integrate additional repositories (Kali, Parrot, custom)
  - Package Manager: pacman for on-demand installation
- **Tool Execution:** 3000+ BlackArch tools on-demand, expandable
- **Platform Abstraction:** Desktop, Android, Web, TUI
- **Sandbox Management:** proot/bwrap isolated environments
- **Native Mode:** Direct host execution for custom tools
- **Evidence Generation:** Structured output parsing
- **Autonomous Operation:** Can run standalone with local AI
- **Agent Mode:** Can be deployed as C2 agent

**Technology Stack:**
- Rust + Dioxus (multi-platform UI)
- **Full Arch Linux rootfs** (complete Linux environment, not just tools)
- BlackArch repository enabled (3000+ pentesting tools)
- Support for additional repositories (Kali, Parrot, custom)
- Platform-specific implementations (desktop, android)
- MIT license (tool execution)

**Platform Support:**
1. **Desktop:** Linux, macOS, Windows (via dioxus-desktop)
2. **Android:** Native Android app with proot sandbox
3. **Web:** Headless liveview deployment
4. **TUI:** Terminal-based interface

**Execution Modes:**
1. **Standalone:** Independent operation, no C2
2. **Mythic Agent:** Reports to Mythic server (via Connector SDK)
3. **StrikeKit Agent:** Deployed by StrikeKit C2 (via Connector SDK)
4. **Hybrid:** Can switch modes dynamically

---

### 2.3 StrikeKit C2 Infrastructure

**Purpose:** Built-in command and control using Strike48 Connector SDK

**Components:**

**Listener (Server):**
- Strike48 Connector SDK (SDK-RS) based
- Secure, authenticated connections (TLS + auth tokens)
- Agent registration and authentication
- Command queue and task dispatch
- File upload/download
- Session management
- Health monitoring

**Agent (Cross-Platform):**
- Lightweight beacon (minimal footprint)
- Interactive shell access
- Screenshot capture
- Process listing
- File operations
- **Can download/execute Pick** for full tooling
- **Uses Connector SDK for secure communication**

**Agent Types:**

```
┌─────────────────────────────────────────────────────────────┐
│                  StrikeKit C2 Agents                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────────┐        ┌──────────────────┐           │
│  │  Full Agent      │        │  Lightweight     │           │
│  │  (Pick)          │        │  Agent           │           │
│  ├──────────────────┤        ├──────────────────┤           │
│  │ • 3000+ tools    │        │ • Shell access   │           │
│  │ • BlackArch      │        │ • File ops       │           │
│  │ • AI-powered     │        │ • Screenshots    │           │
│  │ • Heavy (~50MB+) │        │ • Light (~5MB)   │           │
│  │                  │        │                  │           │
│  │ Use when:        │        │ Use when:        │           │
│  │ - Desktop/server │        │ - IoT devices    │           │
│  │ - Full pentest   │        │ - Mobile         │           │
│  │ - Tooling needed │        │ - Proxy/pivot    │           │
│  └──────────────────┘        └──────────────────┘           │
│                                                               │
│  ┌─────────────────────────────────────────────┐            │
│  │         Deployment Decision                 │            │
│  ├─────────────────────────────────────────────┤            │
│  │ StrikeKit AI decides:                       │            │
│  │ • Target capabilities (CPU, RAM, OS)        │            │
│  │ • Mission requirements (just shell or tools)│            │
│  │ • User preference (manual override)         │            │
│  └─────────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. Deployment Modes

### 3.1 Mode 1: Standalone Pick

**Use Case:** Individual pentester, laptop-based testing, no C2 needed

**Architecture:**
```
┌─────────────────────────────────────────────┐
│         Pentester's Laptop                  │
├─────────────────────────────────────────────┤
│                                             │
│  ┌───────────────────────────────────────┐ │
│  │            Pick                       │ │
│  ├───────────────────────────────────────┤ │
│  │ • Runs locally (desktop app)          │ │
│  │ • No external dependencies            │ │
│  │ • Optional: Connect to Prospector AI  │ │
│  │ • Results stored locally (SQLite)     │ │
│  │                                       │ │
│  │ AI Mode:                              │ │
│  │ - Local Ollama (offline)              │ │
│  │ - OR cloud API (online)               │ │
│  └───────────────────────────────────────┘ │
│                                             │
└─────────────────────────────────────────────┘
         │
         ▼
    ┌─────────────┐
    │   Target    │
    │   Network   │
    └─────────────┘
```

**Features:**
- Full BlackArch tooling (3000+ tools)
- Sandboxed or native execution
- AI-powered autonomous mode (optional)
- No C2 infrastructure required
- Manual workflow or AI-automated

---

### 3.2 Mode 2: Pick as Mythic Agent

**Use Case:** Enterprise red team with existing Mythic deployment

**Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│                   Enterprise Network                         │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌────────────────────────────────────────────────────────┐ │
│  │               Mythic C2 Server                         │ │
│  │         (Existing Deployment)                          │ │
│  └───────────────────┬────────────────────────────────────┘ │
│                      │                                       │
│                      │ Mythic Protocol                       │
│                      │                                       │
│         ┌────────────┼────────────┐                         │
│         │            │            │                         │
│         ▼            ▼            ▼                         │
│  ┌───────────┐ ┌───────────┐ ┌───────────┐                │
│  │ Pick      │ │ Pick      │ │ Pick      │                │
│  │ Agent 1   │ │ Agent 2   │ │ Agent 3   │                │
│  ├───────────┤ ├───────────┤ ├───────────┤                │
│  │ Target A  │ │ Target B  │ │ Target C  │                │
│  │ Desktop   │ │ Server    │ │ Android   │                │
│  └───────────┘ └───────────┘ └───────────┘                │
│                                                               │
└─────────────────────────────────────────────────────────────┘
         ▲
         │ Control & Monitoring
         │
┌────────┴────────────────────────────────────────────────────┐
│                    StrikeKit                                 │
│              (Optional Orchestration)                        │
├─────────────────────────────────────────────────────────────┤
│  • Can control Mythic server                                │
│  • Import Mythic callbacks into StrikeKit                   │
│  • AI planning via Prospector Studio                        │
│  • Unified reporting across all agents                      │
└─────────────────────────────────────────────────────────────┘
```

**Key Feature:** StrikeKit can orchestrate Mythic, which orchestrates Pick agents.

**Integration Points:**
- **StrikeKit → Mythic:** GraphQL API or Mythic REST API
- **Mythic → Pick:** Mythic agent protocol (HTTP/HTTPS)
- **Pick → Mythic:** Task results, file uploads, screenshots

**Benefits:**
- Leverage existing Mythic infrastructure
- Add StrikeKit engagement management on top
- Pick brings 3000+ tools to Mythic ecosystem
- Unified reporting in StrikeKit

---

### 3.3 Mode 3: StrikeKit C2 Deployment

**Use Case:** Team wants unified platform, no external C2 dependencies

**Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│                    Prospector Studio                         │
│                    (AI Backend)                              │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                      StrikeKit                               │
│                 (Orchestrator + C2)                          │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │          StrikeKit C2 Listener                      │    │
│  │          (0.0.0.0:8443)                             │    │
│  └────────────────────┬────────────────────────────────┘    │
│                       │                                      │
│                       │ HTTPS Beacon                         │
│                       │                                      │
└───────────────────────┼──────────────────────────────────────┘
                        │
         ┌──────────────┼──────────────┐
         │              │              │
         ▼              ▼              ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ Full Agent  │  │ Lightweight │  │ Full Agent  │
│ (Pick)      │  │ Agent       │  │ (Pick)      │
├─────────────┤  ├─────────────┤  ├─────────────┤
│ Windows     │  │ IoT Device  │  │ Linux       │
│ Desktop     │  │ (Pivot)     │  │ Server      │
│             │  │             │  │             │
│ 3000+ tools │  │ Shell only  │  │ 3000+ tools │
└─────────────┘  └─────────────┘  └─────────────┘
```

**Deployment Decision Logic:**

```rust
// Pseudocode: StrikeKit decides which agent to deploy
match target_profile {
    TargetProfile {
        os: "linux" | "macos" | "windows",
        ram: >= 2GB,
        disk: >= 500MB,
        mission: RequiresTools
    } => deploy_pick_agent(target),

    TargetProfile {
        os: "android",
        ram: >= 1GB,
        mission: RequiresTools | Reconnaissance
    } => deploy_pick_mobile(target),

    TargetProfile {
        os: _,
        ram: < 1GB,
        mission: Pivot | Shell
    } => deploy_lightweight_agent(target),

    _ => ask_user_for_manual_selection()
}
```

**Benefits:**
- No external C2 dependencies
- Integrated workflow (one platform)
- AI chooses optimal agent for target
- Lightweight pivots, heavy tooling where needed

---

### 3.4 Mode 4: Hybrid Deployment

**Use Case:** Maximum flexibility, use what fits the engagement

**Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│                    Prospector Studio                         │
│                     (AI Orchestrator)                        │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                      StrikeKit                               │
│            (Unified Engagement Management)                   │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  Manages:                                                     │
│  • All agents (Pick standalone, Mythic agents, SK C2)       │
│  • All findings (from all sources)                          │
│  • Unified reporting                                         │
│                                                               │
└──┬─────────────────┬──────────────────┬──────────────────┬──┘
   │                 │                  │                  │
   ▼                 ▼                  ▼                  ▼
┌────────┐   ┌────────────┐   ┌────────────┐   ┌────────────┐
│ Pick   │   │ Mythic C2  │   │ StrikeKit  │   │ Import     │
│ Standalone│ │ Agents     │   │ C2 Agents  │   │ External   │
│        │   │ (Pick)     │   │ (Pick +    │   │ (Nessus,   │
│        │   │            │   │  Lite)     │   │  CS logs)  │
└────────┘   └────────────┘   └────────────┘   └────────────┘

   All results flow back to StrikeKit for unified view
```

**Scenario Example:**

**Week 1: External Recon**
- Use Pick standalone on pentester laptop
- Import Nessus scan results into StrikeKit

**Week 2: Initial Access**
- Deploy StrikeKit lightweight agent to DMZ host
- Use as pivot point

**Week 3: Internal Exploitation**
- Deploy Pick (full) to pivot host
- Run 3000+ tools against internal network

**Week 4: Enterprise Integration**
- Client has Mythic infrastructure
- Deploy Pick as Mythic agents
- StrikeKit imports all Mythic data
- Unified report across all activities

---

## 4. Data Flow Patterns

### 4.1 Tool Execution Flow (Pick → StrikeKit)

```
┌────────────────────────────────────────────────────────────┐
│                   Pick (Tool Execution)                     │
├────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Receive tool execution request                          │
│     ↓                                                        │
│  2. Select execution mode (sandboxed or native)             │
│     ↓                                                        │
│  3. Execute tool (e.g., nmap, ffuf, nikto)                 │
│     ↓                                                        │
│  4. Parse tool output into structured data                  │
│     ↓                                                        │
│  5. Generate evidence objects                               │
│     ↓                                                        │
│  6. Send results to StrikeKit                               │
│                                                              │
└────────────┬───────────────────────────────────────────────┘
             │ ToolOutput + Evidence
             ▼
┌────────────────────────────────────────────────────────────┐
│                StrikeKit (Engagement Hub)                   │
├────────────────────────────────────────────────────────────┤
│                                                              │
│  7. Receive tool results from Pick                          │
│     ↓                                                        │
│  8. Store evidence in database                              │
│     ↓                                                        │
│  9. Create/update findings                                  │
│     ↓                                                        │
│ 10. Extract targets (IP addresses, hostnames)               │
│     ↓                                                        │
│ 11. Extract credentials (passwords, hashes, keys)           │
│     ↓                                                        │
│ 12. Map to MITRE ATT&CK techniques                          │
│     ↓                                                        │
│ 13. Update engagement timeline                              │
│     ↓                                                        │
│ 14. Notify Prospector Studio (for AI planning)             │
│                                                              │
└────────────────────────────────────────────────────────────┘
```

---

### 4.2 AI Orchestration Flow (Prospector → StrikeKit → Pick)

```
┌────────────────────────────────────────────────────────────┐
│              Prospector Studio (AI Brain)                   │
├────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Receive engagement objectives from user                 │
│     ↓                                                        │
│  2. Query current state from StrikeKit                      │
│     (targets, credentials, findings)                        │
│     ↓                                                        │
│  3. Generate task graph (DAG)                               │
│     - Tool selection                                        │
│     - Dependency ordering                                   │
│     - Parallel execution groups                             │
│     ↓                                                        │
│  4. Send task graph to StrikeKit                            │
│                                                              │
└────────────┬───────────────────────────────────────────────┘
             │ TaskGraph
             ▼
┌────────────────────────────────────────────────────────────┐
│              StrikeKit (Coordinator)                        │
├────────────────────────────────────────────────────────────┤
│                                                              │
│  5. Receive task graph from Prospector                      │
│     ↓                                                        │
│  6. Select Pick instances to execute tasks                  │
│     (standalone, Mythic agents, or C2 agents)               │
│     ↓                                                        │
│  7. Dispatch tasks to Pick instances                        │
│                                                              │
└────────────┬───────────────────────────────────────────────┘
             │ ToolExecutionRequest
             ▼
┌────────────────────────────────────────────────────────────┐
│                 Pick Instances                              │
├────────────────────────────────────────────────────────────┤
│                                                              │
│  8. Execute tools                                           │
│     ↓                                                        │
│  9. Generate evidence                                       │
│     ↓                                                        │
│ 10. Return results to StrikeKit                             │
│                                                              │
└────────────┬───────────────────────────────────────────────┘
             │ ToolOutput + Evidence
             ▼
┌────────────────────────────────────────────────────────────┐
│              StrikeKit (Coordinator)                        │
├────────────────────────────────────────────────────────────┤
│                                                              │
│ 11. Process results, update engagement state                │
│     ↓                                                        │
│ 12. Send findings back to Prospector                        │
│                                                              │
└────────────┬───────────────────────────────────────────────┘
             │ Findings + Evidence
             ▼
┌────────────────────────────────────────────────────────────┐
│              Prospector Studio (AI Brain)                   │
├────────────────────────────────────────────────────────────┤
│                                                              │
│ 13. Analyze results                                         │
│     ↓                                                        │
│ 14. Evidence-based reasoning                                │
│     (Does evidence support exploitation?)                   │
│     ↓                                                        │
│ 15. Update task graph (add new tasks based on findings)     │
│     ↓                                                        │
│ 16. Repeat cycle or mark engagement complete                │
│                                                              │
└────────────────────────────────────────────────────────────┘
```

---

### 4.3 Integration Import Flow (Nessus → StrikeKit → Pick)

**Phase 1: Import (60-Day MVP)**

```
┌────────────────────────────────────────────────────────────┐
│              External Tool (Nessus)                         │
├────────────────────────────────────────────────────────────┤
│                                                              │
│  • User runs Nessus scan                                    │
│  • Exports .nessus XML file                                 │
│                                                              │
└────────────┬───────────────────────────────────────────────┘
             │ nessus_scan.xml
             ▼
┌────────────────────────────────────────────────────────────┐
│                   StrikeKit                                 │
├────────────────────────────────────────────────────────────┤
│                                                              │
│  1. User imports .nessus file                               │
│     ↓                                                        │
│  2. Parse XML                                               │
│     - Extract hosts                                         │
│     - Extract services                                      │
│     - Extract vulnerabilities                               │
│     ↓                                                        │
│  3. Create Target entries                                   │
│     (IP, hostname, OS, services)                            │
│     ↓                                                        │
│  4. Create Finding entries                                  │
│     (High/Critical vulns → Findings)                        │
│     ↓                                                        │
│  5. Send to Prospector Studio for AI analysis              │
│                                                              │
└────────────┬───────────────────────────────────────────────┘
             │ Targets + Findings
             ▼
┌────────────────────────────────────────────────────────────┐
│              Prospector Studio                              │
├────────────────────────────────────────────────────────────┤
│                                                              │
│  6. Analyze vulnerabilities                                 │
│     ↓                                                        │
│  7. Prioritize by exploitability                            │
│     (Query RAG knowledge base for exploits)                 │
│     ↓                                                        │
│  8. Generate exploitation plan                              │
│     - Which Pick tools to use                               │
│     - Attack sequence                                       │
│     ↓                                                        │
│  9. Send task graph back to StrikeKit                       │
│                                                              │
└────────────┬───────────────────────────────────────────────┘
             │ TaskGraph
             ▼
┌────────────────────────────────────────────────────────────┐
│                   StrikeKit                                 │
├────────────────────────────────────────────────────────────┤
│                                                              │
│ 10. Present plan to user (HITL approval)                    │
│     ↓                                                        │
│ 11. User approves exploitation                              │
│     ↓                                                        │
│ 12. Dispatch to Pick                                        │
│                                                              │
└────────────┬───────────────────────────────────────────────┘
             │ Exploitation tasks
             ▼
┌────────────────────────────────────────────────────────────┐
│                      Pick                                   │
├────────────────────────────────────────────────────────────┤
│                                                              │
│ 13. Execute exploitation tools                              │
│     (e.g., Metasploit module, manual exploit)              │
│     ↓                                                        │
│ 14. Return success/failure + evidence                       │
│                                                              │
└────────────┬───────────────────────────────────────────────┘
             │ Results
             ▼
┌────────────────────────────────────────────────────────────┐
│                   StrikeKit                                 │
├────────────────────────────────────────────────────────────┤
│                                                              │
│ 15. Update findings with exploitation results               │
│ 16. Generate report showing:                                │
│     - Nessus found vulnerability                            │
│     - Pick successfully exploited it                        │
│     - Evidence: screenshots, shell access, etc.             │
│                                                              │
└────────────────────────────────────────────────────────────┘
```

**Phase 2: Real-Time Sync (Post-Funding)**

```
┌────────────────────────────────────────────────────────────┐
│              Nessus Server (API)                            │
└────────────┬───────────────────────────────────────────────┘
             │ Webhook / Polling
             ▼
┌────────────────────────────────────────────────────────────┐
│                   StrikeKit                                 │
├────────────────────────────────────────────────────────────┤
│                                                              │
│  • Poll Nessus API every 5 minutes                          │
│  • OR receive webhook when scan completes                   │
│  • Automatically import new findings                        │
│  • Trigger AI exploitation workflow                         │
│  • Push results back to Nessus (optional)                   │
│  • Control Nessus scanners (start/stop scans)              │
│  • Manage scan schedules for long-term engagements          │
│                                                              │
└────────────────────────────────────────────────────────────┘
```

---

### 4.4 GoPhish Social Engineering Integration

**Challenge:** How to integrate social engineering campaigns into technical pentesting workflow?

**Solution:** StrikeKit orchestrates GoPhish campaigns and correlates results with technical exploitation.

**Phase 1: Campaign Result Import (60-Day MVP)**

```
┌────────────────────────────────────────────────────────────┐
│                 GoPhish Server                              │
├────────────────────────────────────────────────────────────┤
│                                                              │
│  • User creates phishing campaign manually                  │
│  • Sends emails to targets                                  │
│  • Tracks clicks, credentials, downloads                    │
│  • Exports campaign results (CSV/API)                       │
│                                                              │
└────────────┬───────────────────────────────────────────────┘
             │ Campaign results
             ▼
┌────────────────────────────────────────────────────────────┐
│                   StrikeKit                                 │
├────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Import GoPhish campaign results                         │
│     ↓                                                        │
│  2. Create targets from clicked users                       │
│     (email → identify user → find workstation IP)           │
│     ↓                                                        │
│  3. Store harvested credentials                             │
│     ↓                                                        │
│  4. Create findings (successful phishing = vulnerability)   │
│     ↓                                                        │
│  5. Map to MITRE ATT&CK (T1566: Phishing)                  │
│     ↓                                                        │
│  6. Trigger technical exploitation                          │
│     - Deploy Pick to clicked user's machine                 │
│     - Use harvested creds for lateral movement              │
│                                                              │
└────────────────────────────────────────────────────────────┘
```

**Phase 2: AI-Powered Campaign Generation (Post-Funding)**

```
┌────────────────────────────────────────────────────────────┐
│              StrikeKit (AI Orchestrator)                    │
├────────────────────────────────────────────────────────────┤
│                                                              │
│  1. AI analyzes target organization                         │
│     - Reconnaissance (domains, email formats, employees)    │
│     - OSINT (LinkedIn, social media, recent news)          │
│     ↓                                                        │
│  2. AI generates phishing campaign                          │
│     - Email template (contextual, organization-specific)    │
│     - Landing page (credential harvester)                   │
│     - Payload (if delivering malware)                       │
│     ↓                                                        │
│  3. Human-in-the-loop approval                              │
│     (Review campaign before sending)                        │
│     ↓                                                        │
│  4. Deploy to GoPhish via API                               │
│     - Create campaign                                       │
│     - Upload email templates                                │
│     - Set target list                                       │
│     - Schedule send time                                    │
│     ↓                                                        │
│  5. Monitor campaign in real-time                           │
│     - Track email opens, clicks, submissions                │
│     ↓                                                        │
│  6. Automatic technical exploitation                        │
│     - User clicks link → identify user                      │
│     - User submits creds → store in StrikeKit              │
│     - Deploy Pick agent to clicked user's machine          │
│     - Use creds for privilege escalation                    │
│     ↓                                                        │
│  7. Unified reporting                                       │
│     - Social engineering success rate                       │
│     - Technical exploitation from phishing                  │
│     - Complete attack chain visualization                   │
│                                                              │
└────────────────────────────────────────────────────────────┘
```

**Integration Benefits:**
- **Complete Kill Chain:** Phishing → Initial Access → Lateral Movement
- **Credential Harvesting:** Auto-store and test harvested credentials
- **Target Identification:** Map email clicks to specific workstations
- **MITRE ATT&CK:** T1566 (Phishing) → T1078 (Valid Accounts) → T1021 (Remote Services)
- **Unified Reporting:** Social engineering + technical exploitation in single report

**GoPhish API Integration (Phase 2):**

```rust
// Pseudocode: GoPhish integration
pub struct GoPhishIntegration {
    api_client: GoPhishAPIClient,
}

impl GoPhishIntegration {
    pub async fn create_campaign(&self, campaign: AIGeneratedCampaign) -> Result<CampaignId> {
        // Upload email template
        let template_id = self.api_client.create_template(campaign.email_template).await?;

        // Create landing page
        let page_id = self.api_client.create_page(campaign.landing_page).await?;

        // Create campaign
        let campaign_id = self.api_client.create_campaign(CampaignConfig {
            name: campaign.name,
            template_id,
            page_id,
            smtp_profile: campaign.smtp_profile,
            targets: campaign.targets,
            launch_date: campaign.launch_date,
        }).await?;

        Ok(campaign_id)
    }

    pub async fn get_campaign_results(&self, campaign_id: CampaignId) -> Result<CampaignResults> {
        let results = self.api_client.get_results(campaign_id).await?;

        // Parse into StrikeKit data structures
        let targets = self.extract_targets(&results);
        let credentials = self.extract_credentials(&results);
        let findings = self.create_findings(&results);

        Ok(CampaignResults {
            targets,
            credentials,
            findings,
        })
    }
}
```

---

## 5. Integration Architecture

### 5.1 Integration Matrix

| Integration | Phase 1 (MVP) | Phase 2 (Post-Funding) | Pick or StrikeKit |
|-------------|---------------|------------------------|-------------------|
| **Nessus** | Import XML | API sync, auto-exploit, scanner management | StrikeKit |
| **Cobalt Strike** | Import logs | Team server API | StrikeKit |
| **Mythic C2** | Import callbacks | Agent mode + control via SDK | Both |
| **GoPhish** | Import campaign results | API control, auto-campaign generation | StrikeKit |
| **Metasploit** | Manual execute | RPC API, module library | Pick |
| **Burp Suite** | Import issues | REST API, session share | StrikeKit |
| **BloodHound** | Import JSON | Live Neo4j integration | StrikeKit |
| **Shodan/Censys** | N/A | API search, auto-import | StrikeKit |
| **Tenable.io** | N/A | API sync | StrikeKit |
| **AWS Security Hub** | N/A | Findings import/export | StrikeKit |

### 5.2 Integration Components

**StrikeKit Integration Layer:**

```rust
// Pseudocode: StrikeKit integration architecture

pub struct IntegrationManager {
    nessus: NessusIntegration,
    cobalt_strike: CobaltStrikeIntegration,
    mythic: MythicIntegration,
    gophish: GoPhishIntegration,
    metasploit: MetasploitIntegration,
    burp: BurpIntegration,
    bloodhound: BloodHoundIntegration,
    // ... more integrations
}

pub trait Integration {
    fn import(&self, source: ImportSource) -> Result<Vec<Target>, Vec<Finding>>;
    fn export(&self, targets: &[Target], findings: &[Finding]) -> Result<()>;
    fn sync(&self) -> Result<SyncStatus>;
}

// Example: Nessus integration
pub struct NessusIntegration {
    api_client: Option<NessusAPIClient>,
}

impl Integration for NessusIntegration {
    fn import(&self, source: ImportSource) -> Result<Vec<Target>, Vec<Finding>> {
        match source {
            ImportSource::File(path) => {
                // Parse .nessus XML
                let xml = std::fs::read_to_string(path)?;
                let report = parse_nessus_xml(&xml)?;

                let targets = extract_targets(&report);
                let findings = extract_findings(&report);

                Ok((targets, findings))
            }
            ImportSource::API => {
                // Phase 2: Poll Nessus API
                let client = self.api_client.as_ref()
                    .ok_or(Error::NessusAPINotConfigured)?;

                let scans = client.list_scans().await?;
                // ... process API results
            }
        }
    }
}
```

---

## 6. AI Orchestration

### 6.1 Unified AI Architecture

**StrikeKit/Prospector Studio (Strategic + Tactical AI):**
- **Strategic Planning:**
  - Engagement-level planning
  - Task graph generation (DAG)
  - Multi-agent coordination (Planner, Executor, Reflector)
  - Evidence-based reasoning across all findings
  - Knowledge base queries (RAG)
- **Tactical Execution:**
  - Target prioritization
  - Agent deployment decisions (Pick full vs lightweight)
  - Integration data correlation
  - Pivot path analysis
  - Real-time task adaptation

**Pick (Local AI - Optional):**
- Tool selection for specific tasks
- Output parsing and structuring
- Local evidence generation
- Can operate offline with local Ollama
- Can defer to StrikeKit for complex decisions

**Key Insight:** StrikeKit IS the AI orchestrator. Pick is the execution engine that can optionally use local AI for offline/standalone mode, but defers to StrikeKit for strategic planning.

### 6.2 AI Communication Pattern

```
┌─────────────────────────────────────────────────────────────┐
│            StrikeKit (Prospector Studio)                     │
│          Strategic + Tactical AI Orchestrator                │
│                                                               │
│  • Engagement planning (strategic)                           │
│  • Task graph generation                                     │
│  • Evidence reasoning                                        │
│  • Target prioritization (tactical)                          │
│  • Agent deployment decisions                                │
│                                                               │
│  GraphQL API: strikekit.strike48.com/graphql                │
│  Matrix: @strikekit:strike48.com                            │
│  Connector SDK: Secure agent communication                   │
└────────────┬────────────────────────────────────────────────┘
             │
             │ Connector SDK (SDK-RS)
             │ Tasks + Evidence
             │
             ▼
┌──────────────────────────────────────────────────────────────┐
│                        Pick Instances                         │
│                      (Execution Agents)                       │
├──────────────────────────────────────────────────────────────┤
│                                                                │
│ • Receive tasks from StrikeKit                                │
│ • Execute tools (3000+ BlackArch)                            │
│ • Generate evidence                                           │
│ • Send results back to StrikeKit                             │
│                                                                │
│ Optional Local AI (Offline Mode):                             │
│ • Basic tool selection when disconnected                      │
│ • Output parsing                                              │
│ • Defer to StrikeKit when connected                          │
│                                                                │
└──────────────────────────────────────────────────────────────┘
```

### 6.3 Evidence-Based Reasoning Flow

```
Pick executes tool
    ↓
Generates Evidence object
    {
        tool: "nmap",
        output: "22/tcp open ssh",
        confidence: 0.95,
        evidence_type: "PortOpen"
    }
    ↓
Sends to StrikeKit via Connector SDK
    ↓
StrikeKit AI analyzes evidence:
    - Evidence: Port 22 open (0.95 confidence)
    - Hypothesis: SSH service available
    - RAG Query: "SSH exploits for Linux"
    - Vulnerability: Potential weak credentials
    - Recommended Action: Hydra bruteforce
    ↓
StrikeKit generates task graph
    ↓
StrikeKit presents to user (HITL)
    ↓
User approves
    ↓
Pick executes Hydra
    ↓
Generates new evidence (credentials found)
    ↓
Cycle repeats...
```

---

## 6.4 Workflow Engine (Deterministic Automation)

**Purpose:** Codeable, deterministic workflows for pentesting automation (n8n-like)

**Key Difference from AI Task Graphs:**
- **AI Task Graphs:** Non-deterministic, LLM-powered, adaptive planning
- **Workflows:** Deterministic, codeable, repeatable automation

**Workflow Capabilities:**

```rust
// Pseudocode: Workflow definition
pub struct Workflow {
    id: WorkflowId,
    name: String,
    trigger: WorkflowTrigger,
    nodes: Vec<WorkflowNode>,
    edges: Vec<(NodeId, NodeId)>,
}

pub enum WorkflowTrigger {
    Manual,                              // User starts workflow
    Schedule(CronExpression),            // Time-based
    Event(EventType),                    // Engagement state change, finding created, etc.
    Webhook(WebhookConfig),              // External trigger (Nessus scan complete)
}

pub enum WorkflowNode {
    // Data nodes
    HttpRequest(HttpRequestConfig),      // API calls
    Database(DatabaseQuery),             // Query PostgreSQL
    FileOperation(FileOp),               // Read/write files

    // Tool execution
    PickTool(ToolExecutionConfig),       // Execute Pick tool
    ExternalTool(ExternalToolConfig),    // Nessus, Metasploit, etc.

    // Logic nodes
    Condition(ConditionExpression),      // If/else branching
    Loop(LoopConfig),                    // Iterate over items
    Delay(Duration),                     // Wait/sleep

    // AI nodes
    LLMPrompt(LLMConfig),                // Query LLM
    VectorSearch(RAGQuery),              // Search knowledge base
    EvidenceReasoning(EvidenceChain),    // AI reasoning

    // Integration nodes
    CreateTarget(TargetData),            // Add to StrikeKit
    CreateFinding(FindingData),          // Document vulnerability
    SendNotification(NotificationConfig), // Slack, email, webhook

    // Custom code
    RustFunction(FunctionName),          // Custom Rust code
    TypeScriptFunction(FunctionName),    // Custom TS code
}
```

**Example Workflow: Automated Nessus → Exploitation**

```
Trigger: Nessus scan completes (webhook)
    ↓
Node 1: Import Nessus XML
    ↓
Node 2: Filter High/Critical findings
    ↓
Node 3: For each finding (loop):
    ├─ Query RAG: Find exploits for CVE
    ├─ If exploit available (condition):
    │   ├─ Human approval (HITL node)
    │   ├─ Execute exploit via Pick
    │   └─ Create finding with results
    └─ Else: Skip to next
    ↓
Node 4: Generate report
    ↓
Node 5: Send Slack notification
```

**Visual Workflow Builder (Phase 2):**
- Drag-and-drop node editor
- Node library (pre-built components)
- Testing/debugging tools
- Version control (Git integration)
- Workflow templates (community-shared)

**Hybrid Workflows:**
- Start with deterministic flow
- Insert AI decision points where needed
- Example: "If uncertain, ask LLM to decide"
- Best of both worlds: repeatable + adaptive

---

## 7. Auditing & Scoping

### 7.1 Comprehensive Audit Log System

**Purpose:** Immutable, tamper-evident audit trail for compliance and legal protection

**What Gets Logged:**

```rust
pub struct AuditLogEntry {
    id: AuditId,
    timestamp: DateTime<Utc>,
    user_id: UserId,
    user_email: String,
    action: AuditAction,
    engagement_id: Option<EngagementId>,
    target: Option<TargetId>,
    scope_status: ScopeStatus, // InScope, OutOfScope, RequiresApproval
    result: ActionResult,
    metadata: serde_json::Value,
    hash: String, // Tamper detection (chain of hashes)
}

pub enum AuditAction {
    // Engagement actions
    EngagementCreated,
    EngagementModified,
    EngagementActivated,
    EngagementCompleted,

    // Scope actions (CRITICAL)
    ScopeChanged { old_scope: Vec<String>, new_scope: Vec<String> },
    OutOfScopeAttempt { target: String, reason: String },
    ScopeViolationOverride { approver: UserId },

    // Tool execution
    ToolExecuted { tool: String, target: String, in_scope: bool },
    AgentDeployed { target: String, in_scope: bool },

    // Data access
    CredentialAccessed { credential_id: CredentialId },
    FindingCreated,
    ReportGenerated,

    // Integration actions
    NessusImported,
    MythicConnected,
    GoPhishCampaignLaunched,
}
```

**Tamper-Evident Chain:**
```
Entry 1: hash = SHA256(timestamp + user + action + prev_hash)
Entry 2: hash = SHA256(timestamp + user + action + entry1.hash)
Entry 3: hash = SHA256(timestamp + user + action + entry2.hash)
...
```

**Timeline Visualization:**
- Horizontal timeline with all engagement activities
- Color-coded by action type
- Filter by user, tool, scope status
- Export to PDF for client reports
- Zoom in/out by timeframe

**Compliance Exports:**
- **SOC 2:** Access logs, change logs, incident logs
- **ISO 27001:** Security event logs
- **GDPR:** Data access logs, deletion logs
- **Custom:** JSON/CSV export with filtering

**Audit Query API:**
```graphql
query {
  auditLogs(
    engagementId: "eng-123"
    startDate: "2026-04-01"
    endDate: "2026-04-30"
    action: [ToolExecuted, ScopeChanged]
  ) {
    timestamp
    user {
      email
    }
    action
    scopeStatus
    metadata
  }
}
```

---

### 7.2 Scoping & Boundary Enforcement

**Purpose:** Strict enforcement of engagement scope to prevent legal/ethical violations

**Scope Definition:**

```rust
pub struct EngagementScope {
    engagement_id: EngagementId,
    in_scope: ScopeRules,
    out_of_scope: ScopeRules,
    timeframe: Timeframe,
    approval_required: Vec<ScopeException>,
}

pub struct ScopeRules {
    ip_ranges: Vec<IpRange>,        // "192.168.1.0/24"
    domains: Vec<Domain>,           // "*.example.com"
    applications: Vec<Application>, // "Web Portal", "API Server"
    ports: Option<Vec<u16>>,        // Optional port restrictions
    protocols: Option<Vec<Protocol>>, // Optional protocol restrictions
}

pub struct Timeframe {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    allowed_hours: Option<TimeRange>, // e.g., 9am-5pm only
    blackout_dates: Vec<Date>,        // No testing on these dates
}
```

**Real-Time Scope Validation:**

```rust
// Before every tool execution or agent deployment
pub fn validate_scope(target: &Target, scope: &EngagementScope) -> ScopeValidation {
    // Check IP address
    if !scope.in_scope.ip_ranges.contains(&target.ip) {
        return ScopeValidation::OutOfScope {
            reason: format!("IP {} not in scope", target.ip),
            action: ScopeAction::Block,
        };
    }

    // Check timeframe
    if !scope.timeframe.is_current_time_allowed() {
        return ScopeValidation::OutOfScope {
            reason: "Outside allowed testing hours",
            action: ScopeAction::Block,
        };
    }

    // Check explicit out-of-scope rules
    if scope.out_of_scope.matches(&target) {
        return ScopeValidation::OutOfScope {
            reason: "Explicitly marked out of scope",
            action: ScopeAction::Block,
        };
    }

    ScopeValidation::InScope
}
```

**Scope Violation Handling:**

```
User attempts action on out-of-scope target
    ↓
StrikeKit blocks action immediately
    ↓
Log scope violation attempt (audit trail)
    ↓
Alert engagement lead (Slack/email)
    ↓
Present approval workflow:
    ├─ User provides justification
    ├─ Engagement lead reviews
    ├─ Lead approves or denies
    ↓
If approved:
    ├─ Update scope to include target
    ├─ Log scope change (who, what, why)
    ├─ Allow action to proceed
    └─ Include in final report (transparency)
```

**Approval Workflows:**

```rust
pub struct ScopeApprovalRequest {
    requested_by: UserId,
    requested_at: DateTime<Utc>,
    target: String,
    justification: String,
    approver: Option<UserId>,
    status: ApprovalStatus,
}

pub enum ApprovalStatus {
    Pending,
    Approved { by: UserId, at: DateTime<Utc> },
    Denied { by: UserId, reason: String },
    Expired, // Auto-deny after 24 hours
}
```

**Legal Protection Features:**

1. **Proof of Scope Adherence:**
   - Audit log shows all actions were in scope
   - Or explicit approvals for scope expansions
   - PDF export for legal evidence

2. **Client Transparency:**
   - Client can view real-time scope status
   - Notifications for scope change requests
   - Final report includes scope adherence section

3. **Automatic Blocking:**
   - No way to bypass scope without approval
   - Even administrators cannot override (logged if attempted)
   - Multi-factor approval for sensitive scope changes

4. **Scope Drift Prevention:**
   - Regular scope reviews (weekly reminders)
   - Highlight targets at scope boundaries
   - Suggest scope refinements based on findings

**UI Features:**
- Visual scope map (IP ranges, domains highlighted)
- Traffic light indicators (green = in scope, yellow = requires approval, red = blocked)
- Scope change history timeline
- Export scope definition for client sign-off

---

## 8. Security Model

### 7.1 Authentication & Authorization

**StrikeHub Level:**
- OIDC authentication (Keycloak)
- SSO support (SAML, OAuth)
- Session management
- Token injection into connectors

**StrikeKit Level:**
- Role-Based Access Control (RBAC)
- Engagement-level permissions
- Audit logging (all actions tracked)
- Matrix integration (team collaboration)

**Pick Level:**
- Sandboxed execution (proot/bwrap isolation)
- Limited file system access
- No privilege escalation without user approval
- Tool execution logging

### 7.2 Data Protection

**In Transit:**
- TLS 1.3 for all communication
- Certificate pinning (optional)
- End-to-end encryption for sensitive data

**At Rest:**
- SQLite encryption (StrikeKit database)
- Credential storage: AES-256 encryption
- Audit logs: tamper-evident storage

**Compliance:**
- GDPR: Data retention policies, right to delete
- SOC 2: Audit trails, access controls
- ISO 27001: Security best practices

---

## 8. Implementation Phases

### Phase 1: MVP (60 Days) - Funding Demo

**Goal:** Demonstrate autonomous pentesting + integrations

**Deliverables:**
1. ✅ **Prospector Studio API:** Basic task graph generation, LLM integration
2. ✅ **Pick:** Task graph execution, evidence generation, 5 tool integrations
3. ✅ **StrikeKit:** Nessus XML import, Cobalt Strike log import, basic findings
4. ✅ **Demo Flow:** Nessus → Prospector → Pick → StrikeKit (end-to-end)
5. ✅ **XBOW:** 70%+ success on subset of benchmark

**Team:**
- Month 1: 5-6 developers (3 on Pick/Prospector, 2-3 on StrikeKit)
- Month 2: Scale to 10-12 developers (add integration team)

**Deferred:**
- Multi-agent P-E-R (full implementation)
- Real-time integrations (API sync)
- Mythic agent mode (full)
- Browser automation
- RAG knowledge base
- Polish, docs, extensive testing

---

### Phase 2: Competitive Parity (Months 3-6)

**Goal:** 85%+ XBOW success, feature parity with LuaN1ao/Shannon

**Deliverables:**
1. ✅ Multi-agent P-E-R architecture (Planner, Executor, Reflector)
2. ✅ Browser automation (Playwright integration)
3. ✅ RAG knowledge base (ExploitDB, PayloadsAllTheThings)
4. ✅ Dynamic replanning (adapt to discoveries)
5. ✅ Mythic agent mode (Pick as Mythic agent)
6. ✅ Real-time Nessus/CS integration (API sync)

---

### Phase 3: XBOW Mastery (Months 7-9)

**Goal:** 90%+ XBOW success, public validation

**Deliverables:**
1. ✅ XBOW optimization (weekly testing, iteration)
2. ✅ Cost optimization (model selection, caching)
3. ✅ Speed optimization (parallel execution tuning)
4. ✅ Public benchmark results, blog post, case studies

---

### Phase 4: Enterprise Integrations (Months 10-12)

**Goal:** 5-10 enterprise pilots, full integration suite

**Deliverables:**
1. ✅ Metasploit RPC API integration
2. ✅ Burp Suite REST API integration
3. ✅ AWS Security Hub integration
4. ✅ Azure/GCP cloud security integrations
5. ✅ BloodHound Neo4j integration
6. ✅ Splunk/ELK SIEM integration
7. ✅ Comprehensive documentation

---

## Appendices

### Appendix A: Technology Stack Summary

| Component | Tech Stack |
|-----------|-----------|
| **StrikeKit (Prospector Studio)** | Rust, Dioxus 0.7, PostgreSQL, Qdrant (RAG), GraphQL API, Matrix protocol, Strike48 Connector SDK (SDK-RS), AGPL-3.0 |
| **Pick** | Rust, Dioxus (multi-platform), BlackArch Linux (3000+ tools), proot/bwrap sandbox, Connector SDK client, MIT license |
| **StrikeHub** | Rust, Dioxus 0.6, Wry webview, Unix domain sockets (IPC), OIDC auth, MPL-2.0 |
| **Integrations** | HTTP/REST APIs, XML/JSON parsers, Connector SDK for C2 |
| **C2 Infrastructure** | Strike48 Connector SDK (SDK-RS), TLS + authentication, agent registration, task dispatch |

### Appendix B: API Endpoints (StrikeKit/Prospector Studio)

**GraphQL Schema (Example):**

```graphql
type Query {
  generateTaskGraph(engagementId: ID!, objectives: [String!]!): TaskGraph
  analyzeEvidence(evidence: [Evidence!]!): AnalysisResult
  searchExploits(query: String!, limit: Int): [Exploit!]!
  getEngagementState(engagementId: ID!): EngagementState
}

type Mutation {
  createEngagement(input: CreateEngagementInput!): Engagement
  updateTaskGraph(taskGraphId: ID!, updates: TaskGraphUpdate!): TaskGraph
  submitEvidence(engagementId: ID!, evidence: [Evidence!]!): Boolean
}

type Subscription {
  taskGraphUpdated(engagementId: ID!): TaskGraph
  newFinding(engagementId: ID!): Finding
}
```

### Appendix C: Component Ownership

| Feature | Component | Owner | Notes |
|---------|-----------|-------|-------|
| **Pick Responsibilities** | | | |
| Tool Execution | Pick | Pick team | 3000+ BlackArch tools |
| BlackArch Management | Pick | Pick team | On-demand installation |
| Sandbox/Native Toggle | Pick | Pick team | proot/bwrap or host |
| Multi-Platform Support | Pick | Pick team | Desktop/Android/Web/TUI |
| Evidence Generation | Pick | Pick team | Structured tool output |
| Connector SDK Client | Pick | Pick team | Agent communication |
| Metasploit Integration | Pick | Pick team | RPC API, module execution |
| **StrikeKit Responsibilities** | | | |
| AI Orchestration (Strategic) | StrikeKit | StrikeKit team | Task graphs, planning |
| AI Orchestration (Tactical) | StrikeKit | StrikeKit team | Target prioritization |
| LLM Integration | StrikeKit | StrikeKit team | OpenAI, Anthropic, Ollama |
| Evidence Reasoning | StrikeKit | StrikeKit team | Confidence scoring |
| RAG Knowledge Base | StrikeKit | StrikeKit team | Qdrant + ExploitDB |
| Engagement Management | StrikeKit | StrikeKit team | Full lifecycle |
| C2 Infrastructure | StrikeKit | StrikeKit team | Connector SDK server |
| Findings/Reporting | StrikeKit | StrikeKit team | PDF/HTML generation |
| MITRE ATT&CK Mapping | StrikeKit | StrikeKit team | Technique tracking |
| Nessus Integration | StrikeKit | Integration team | Import + management |
| Cobalt Strike Integration | StrikeKit | Integration team | Session import |
| GoPhish Integration | StrikeKit | Integration team | Campaign management |
| Burp Suite Integration | StrikeKit | Integration team | Issue import |
| BloodHound Integration | StrikeKit | Integration team | AD path analysis |
| **Shared Responsibilities** | | | |
| Mythic Integration | Both | Shared | Pick as agent, StrikeKit controls |
| Connector SDK Protocol | Both | Platform team | Secure communication |

---

## Document Approval

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Technical Lead | [You] | 2026-04-07 | [Pending] |
| Product Owner | [TBD] | 2026-04-07 | [Pending] |
| Architecture Review | [TBD] | 2026-04-07 | [Pending] |

---

**END OF DOCUMENT**
