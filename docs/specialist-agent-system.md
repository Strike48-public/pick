# Specialist Agent System

Pick's penetration testing system uses **dynamic specialist agent spawning** to handle deep-dive security testing across multiple domains. The Red Team agent orchestrates reconnaissance and tactical work, then spawns specialized sub-agents when encountering targets that require focused domain expertise.

## Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│                         Red Team Agent                           │
│  (Reconnaissance, initial testing, orchestration)               │
│                                                                  │
│  RED_TEAM_SYSTEM_PROMPT includes:                              │
│  - Comprehensive offensive security knowledge                   │
│  - Fast-checking methodology (quick wins)                       │
│  - Specialist spawning criteria                                │
│  - Aggression level integration                                │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 │ spawn_specialist tool
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│              SpecialistSpawner (Policy Engine)                  │
│                                                                  │
│  Evaluates spawn policy based on:                              │
│  - Aggression level (Conservative/Balanced/Aggressive/Maximum)  │
│  - Attack surface size (endpoints, technologies, auth)         │
│  - Initial findings (suspicious behavior, concerns)            │
│  - Override policy (agent judgment authority)                  │
└─────────────────────────────────────────────────────────────────┘
                                 │
                                 │ spawn via MatrixClient
                                 ▼
           ┌─────────────────────┴─────────────────────┐
           │                                            │
           ▼                                            ▼
┌──────────────────────┐                   ┌──────────────────────┐
│ web-app-specialist   │                   │  api-specialist      │
│                      │                   │                      │
│ - SQL injection      │                   │ - GraphQL introspect │
│ - XSS variants       │                   │ - JWT manipulation   │
│ - CSRF bypass        │                   │ - Rate limit bypass  │
│ - Auth bypass        │                   │ - Schema probing     │
│ - File upload        │                   │ - Batch attacks      │
│ - SSRF               │                   │ - WebSocket testing  │
└──────────────────────┘                   └──────────────────────┘
           │                                            │
           ▼                                            ▼
┌──────────────────────┐                   ┌──────────────────────┐
│ binary-specialist    │                   │ ai-security-spec.    │
│                      │                   │                      │
│ - ROP chain dev      │                   │ - Prompt injection   │
│ - Heap exploit dev   │                   │ - Training data leak │
│ - Format strings     │                   │ - Model inversion    │
│ - Race conditions    │                   │ - Jailbreak patterns │
│ - DEP/ASLR bypass    │                   │ - Indirect injection │
└──────────────────────┘                   └──────────────────────┘
           │                                            │
           └─────────────────────┬──────────────────────┘
                                 │
                                 │ EvidenceNodes with
                                 │ ValidationStatus
                                 ▼
                       ┌──────────────────┐
                       │  Validator Agent  │
                       │  (Fact-checking)  │
                       └──────────────────┘
                                 │
                                 │ Verified evidence
                                 ▼
                       ┌──────────────────┐
                       │  Report Agent    │
                       │  (Deliverable)   │
                       └──────────────────┘
```

## Aggression Level System

The **aggression level** determines how liberally the Red Team spawns specialists. It balances thoroughness (security coverage) vs. speed/cost.

### Levels

| Level | Endpoint Threshold | Spawn on Hints | Overrides | Cost Multiplier |
|-------|-------------------|----------------|-----------|-----------------|
| **Conservative** | 50+ (web), 30+ (api) | No | UpgradeOnly | 1.0x |
| **Balanced** (default) | 20+ (web), 15+ (api) | Yes | Both | 1.5x |
| **Aggressive** | 5+ (web/api) | Yes | DowngradeOnly | 3.0x |
| **Maximum** | 1+ (any target) | Yes (parallel) | None | 7.0x |

### CLI Usage

```bash
# Conservative mode (fastest, minimal specialists)
./run-pentest.sh headless dev --aggression=conservative

# Balanced mode (default)
./run-pentest.sh headless dev --aggression=balanced

# Aggressive mode (thorough, higher cost)
./run-pentest.sh headless dev --aggression=aggressive

# Maximum mode (exhaustive, very expensive)
./run-pentest.sh headless dev --aggression=maximum
```

Environment variable alternative:

```bash
export AGGRESSION_LEVEL=aggressive
./run-pentest.sh headless dev
```

### Policy Override System

Each aggression level has an **override policy** that controls what judgement calls the Red Team agent can make:

- **Conservative (UpgradeOnly)**: Agent can spawn MORE specialists than policy suggests when finding critical issues
- **Balanced (Both)**: Full judgment authority - can spawn more OR fewer based on tactical assessment
- **Aggressive (DowngradeOnly)**: Agent can skip truly trivial targets even if policy says spawn
- **Maximum (None)**: No overrides allowed - strict policy enforcement for maximum coverage

## Specialist Types

### web-app-specialist

**Domain**: Web applications, browser-based interfaces, traditional CRUD apps.

**Triggers**:
- 20+ HTTP endpoints (Balanced mode)
- Complex authentication (OAuth, SAML, MFA)
- Session management concerns
- File upload functionality
- Rich client-side JavaScript

**Expertise**:
- SQL injection (blind, time-based, second-order)
- XSS (stored, reflected, DOM-based, mutation-based)
- CSRF bypass techniques
- Authentication bypass
- Authorization flaws (IDOR, privilege escalation)
- File upload vulnerabilities
- SSRF variants
- CSP bypass techniques

**System Prompt**: [`skills/claude-red/specialists/web-app-specialist.md`](../skills/claude-red/specialists/web-app-specialist.md)

### api-specialist

**Domain**: REST APIs, GraphQL, gRPC, WebSockets.

**Triggers**:
- 15+ API endpoints (Balanced mode)
- GraphQL schema detected
- JWT/OAuth token flows
- Complex authorization logic
- Batch operations available

**Expertise**:
- GraphQL introspection and batching attacks
- JWT manipulation (alg confusion, weak signing, claims abuse)
- OAuth flow attacks (PKCE bypass, redirect manipulation)
- Rate limiting bypass
- BOLA/BFLA (broken object/function level authorization)
- Mass assignment vulnerabilities
- API versioning exploits
- WebSocket hijacking
- Schema probing and fuzzing

**System Prompt**: [`skills/claude-red/specialists/api-specialist.md`](../skills/claude-red/specialists/api-specialist.md)

### binary-specialist

**Domain**: Native binaries, memory corruption, reverse engineering.

**Triggers**:
- Crash detected during fuzzing
- Binary requires reverse engineering
- Exploit development needed
- Kernel module analysis

**Expertise**:
- ROP (Return-Oriented Programming) chain development
- Heap exploitation (use-after-free, double-free)
- Format string vulnerabilities
- Race condition exploitation
- DEP/ASLR bypass techniques
- Control flow integrity bypass
- Kernel exploit development

**System Prompt**: [`skills/claude-red/specialists/binary-specialist.md`](../skills/claude-red/specialists/binary-specialist.md)

### ai-security-specialist

**Domain**: LLMs, chatbots, AI-powered interfaces, code generation systems.

**Triggers**:
- LLM chatbot interface detected
- Code generation functionality
- AI-assisted features
- RAG (Retrieval-Augmented Generation) system

**Expertise**:
- Prompt injection (direct, indirect, adversarial)
- Training data exfiltration
- Model inversion attacks
- Jailbreak pattern generation
- Multi-step adversarial prompts
- RAG poisoning
- Function calling exploits

**System Prompt**: [`skills/claude-red/specialists/ai-security-specialist.md`](../skills/claude-red/specialists/ai-security-specialist.md)

## Spawning Flow

### 1. Red Team Reconnaissance

The Red Team agent performs initial reconnaissance:

```rust
// Red Team discovers target characteristics
let target_info = TargetInfo {
    targets: vec!["https://api.example.com".to_string()],
    endpoint_count: 47,
    technologies: vec!["GraphQL", "JWT auth"],
    auth_mechanisms: vec!["OAuth 2.0"],
    entry_points: vec!["/graphql", "/api/v2/*"],
    initial_findings: vec!["Introspection enabled"],
    concerns: vec!["Complex nested queries possible"],
};
```

### 2. Policy Evaluation

The `SpecialistSpawner` evaluates whether to spawn:

```rust
let spawner = SpecialistSpawner::new(AggressionLevel::Balanced);
let context = SpecialistContext {
    targets: target_info.targets,
    initial_findings: target_info.initial_findings,
    concerns: target_info.concerns,
    attack_surface: AttackSurface {
        endpoint_count: 47,
        technologies: vec!["GraphQL".to_string()],
        auth_mechanisms: vec!["OAuth 2.0".to_string()],
        entry_points: vec!["/graphql".to_string()],
    },
};

let decision = spawner.should_spawn(SpecialistType::Api, &context);
// Returns SpawnDecision::Spawn (47 endpoints > 15 threshold)
```

### 3. Specialist Creation

If spawn decision is positive:

```rust
let agent_info = spawner.spawn(
    &matrix_client,
    SpecialistType::Api,
    context,
    "pentest-connector-red-team",  // parent agent name
).await?;

// agent_info contains:
// - id: "agent-abc123"
// - name: "pentest-connector-api-specialist-abc123"
```

### 4. Specialist Deep Dive

The spawned specialist performs focused testing:

- Loads domain-specific system prompt
- Executes deep-dive methodology
- Produces EvidenceNodes with `source: "api-specialist"`
- Reports back to Red Team with findings

### 5. Evidence Aggregation

All evidence flows back to the Red Team:

```rust
pub struct EvidenceNode {
    pub id: String,
    pub source: String,  // "api-specialist"
    pub finding: String,
    pub validation_status: ValidationStatus,
    pub provenance: ProvenanceChain,
}
```

## Tool: spawn_specialist

The Red Team agent uses this tool to spawn specialists.

**Tool Name**: `spawn_specialist`

**Description**: "Spawn a domain-specific specialist agent for deep-dive security testing. Evaluates spawn policy based on aggression level and target characteristics. Specialists: web-app, api, binary, ai-security."

**Input Structure**:

```rust
pub struct SpawnSpecialistInput {
    /// Type of specialist to spawn
    pub specialist_type: SpecialistType,  // WebApp | Api | Binary | AiSecurity
    
    /// Target URLs, endpoints, or binaries
    pub targets: Vec<String>,
    
    /// Initial reconnaissance findings
    pub initial_findings: Vec<String>,
    
    /// Specific areas of concern
    pub concerns: Vec<String>,
    
    /// Number of endpoints discovered
    pub endpoint_count: usize,
    
    /// Technologies detected (frameworks, languages, libraries)
    pub technologies: Vec<String>,
    
    /// Authentication mechanisms
    pub auth_mechanisms: Vec<String>,
    
    /// Entry points identified
    pub entry_points: Vec<String>,
    
    /// Justification for spawning (required when overriding policy)
    pub justification: Option<String>,
}
```

**Result Structure**:

```rust
pub struct SpawnSpecialistResult {
    /// Whether the specialist was spawned
    pub spawned: bool,
    
    /// Agent ID if spawned
    pub agent_id: Option<String>,
    
    /// Agent name if spawned
    pub agent_name: Option<String>,
    
    /// Reason if not spawned
    pub reason: Option<String>,
    
    /// Spawn decision made by policy
    pub decision: String,  // "spawn" | "skip" | "ask_user" | "override_to_spawn"
    
    /// Whether policy override was used
    pub override_used: bool,
    
    /// Current aggression level
    pub aggression_level: String,
    
    /// Policy guidelines
    pub policy_guidelines: String,
}
```

**Example Tool Call**:

```json
{
  "tool": "spawn_specialist",
  "params": {
    "specialist_type": "Api",
    "targets": ["https://api.example.com"],
    "initial_findings": ["GraphQL introspection enabled"],
    "concerns": ["No rate limiting on mutations"],
    "endpoint_count": 47,
    "technologies": ["GraphQL", "Apollo Server"],
    "auth_mechanisms": ["JWT Bearer"],
    "entry_points": ["/graphql", "/api/v2/*"],
    "justification": null
  }
}
```

**Example Success Response**:

```json
{
  "spawned": true,
  "agent_id": "agent-abc123",
  "agent_name": "pentest-connector-api-specialist-abc123",
  "reason": null,
  "decision": "spawn",
  "override_used": false,
  "aggression_level": "Balanced",
  "policy_guidelines": "**Balanced Mode** - Intelligent tiered spawning:\n- Spawn api-specialist for 15+ endpoints or GraphQL/complex auth\n- Spawn on suspicious findings during initial testing\n- Balance thoroughness with efficiency"
}
```

**Example Skip Response**:

```json
{
  "spawned": false,
  "agent_id": null,
  "agent_name": null,
  "reason": "Policy says skip: Conservative mode threshold not met",
  "decision": "skip",
  "override_used": false,
  "aggression_level": "Conservative",
  "policy_guidelines": "**Conservative Mode** - Minimize sub-agents:\n- Spawn api-specialist only for 30+ endpoints\n- Handle most targets yourself using comprehensive knowledge\n- Spawn only if you find clear suspicious findings\n- Prioritize speed and efficiency"
}
```

## Implementation Status

### Completed

- ✅ Specialist agent system prompts (4 files, 500-700 lines each)
- ✅ Aggression level system (`crates/core/src/aggression.rs`)
- ✅ Specialist spawner orchestration (`crates/core/src/specialist_spawner.rs`)
- ✅ CLI parameter support (`--aggression` / `-a`)
- ✅ Environment variable support (`AGGRESSION_LEVEL`)
- ✅ Cost warnings for expensive modes
- ✅ spawn_specialist tool structure (`crates/tools/src/spawn_specialist.rs`)
- ✅ Red Team system prompt integration
- ✅ All tests passing (13 tests across aggression.rs and specialist_spawner.rs)

### Pending

- ⏸️ ToolContext enhancements (required for spawn_specialist to become functional):
  1. Matrix client injection: `ctx.matrix_client()`
  2. Aggression level propagation: `ctx.aggression_level()`
  3. Parent agent name tracking: `ctx.agent_name()`
- ⏸️ Integration testing with live Matrix agent spawning
- ⏸️ Mid-scan aggression adjustment capability

## Cost Transparency

The system displays cost warnings when expensive aggression modes are selected:

```bash
$ ./run-pentest.sh headless dev --aggression=aggressive
ℹ️  Aggressive mode may spawn multiple specialists. Estimated cost: 2-4x Conservative mode.

$ ./run-pentest.sh headless dev --aggression=maximum
⚠️  MAXIMUM mode spawns specialists for every target. This can be expensive for large networks. Estimated cost: 5-10x Conservative mode. Recommend starting with Aggressive mode first.
```

Cost multipliers relative to Conservative mode (1.0x):
- Conservative: 1.0x
- Balanced: 1.5x
- Aggressive: 3.0x
- Maximum: 7.0x

## References

### Code

- **Aggression Level**: `crates/core/src/aggression.rs`
- **Specialist Spawner**: `crates/core/src/specialist_spawner.rs`
- **spawn_specialist Tool**: `crates/tools/src/spawn_specialist.rs`
- **Red Team System Prompt**: `crates/ui/src/components/chat_panel/constants.rs`

### System Prompts

- **web-app-specialist**: `skills/claude-red/specialists/web-app-specialist.md`
- **api-specialist**: `skills/claude-red/specialists/api-specialist.md`
- **binary-specialist**: `skills/claude-red/specialists/binary-specialist.md`
- **ai-security-specialist**: `skills/claude-red/specialists/ai-security-specialist.md`

### Related Documentation

- [Three-Agent Pipeline](./three-agent-pipeline.md) - Overall Pick architecture (Red Team → Validator → Report)
- [Evidence Provenance System](./evidence-provenance.md) - How findings flow between agents
