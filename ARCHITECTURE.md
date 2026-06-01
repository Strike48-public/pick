# Pick Architecture

**Audience:** Maintainers and contributors
**For detailed ecosystem architecture:** See [docs/SYSTEM_ARCHITECTURE.md](docs/SYSTEM_ARCHITECTURE.md)

---

## Overview

Pick is a multi-platform penetration testing connector that bridges Strike48 (orchestration control plane) with local security tools. Each Pick instance IS a connector - it registers with Strike48 and executes tools locally on the machine where it runs.

**Architecture philosophy:**
- Each app (desktop, mobile, headless) is an independent connector
- Tools execute on the connector's host machine, not remotely
- Evidence flows back to Strike48 for aggregation and analysis
- Three-agent validation pipeline ensures evidence quality

---

## System Design

### High-Level Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     Strike48 Backend                             │
│                   (Routes tool requests)                        │
└───────┬─────────────────┬─────────────────┬─────────────────┬───┘
        │                 │                 │                 │
        ▼                 ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│   Desktop     │ │     Web       │ │    Mobile     │ │     TUI       │
│  (dioxus-     │ │  (dioxus-     │ │  (dioxus-     │ │  (dioxus-     │
│   desktop)    │ │   liveview)   │ │   mobile)     │ │   tui)        │
├───────────────┤ ├───────────────┤ ├───────────────┤ ├───────────────┤
│ UI + Tools    │ │ UI + Tools    │ │ UI + Tools    │ │ UI + Tools    │
│ run locally   │ │ run on server │ │ run on device │ │ run locally   │
└───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘
```

### Key Principles

1. **Each app IS a connector** - Desktop, mobile, headless, TUI all register independently
2. **Local execution** - Tools run on the connector's host (not remote execution)
3. **Evidence-based** - All tool output converted to validated evidence nodes
4. **Multi-platform** - Same core logic across all platforms via Dioxus

---

## Crate Structure

```
pick/
├── crates/
│   ├── core/          # Core types, state management, SDK integration
│   ├── platform/      # Platform abstraction (desktop, android, ios)
│   ├── ui/            # Shared Dioxus UI components + LiveView server
│   └── tools/         # Tool implementations
└── apps/
    ├── headless/      # Headless agent (pentest-agent binary)
    ├── desktop/       # Desktop app (dioxus-desktop)
    ├── web/           # Web app (dioxus-liveview + axum)
    ├── tui/           # Terminal app (dioxus-tui)
    └── mobile/        # Mobile app (dioxus-mobile)
```

### Crate Responsibilities

#### `crates/core`
- Core types: `ToolInput`, `ToolOutput`, `Evidence`, `EvidenceNode`
- State management: Global app state, connector registration
- Strike48 SDK integration: WebSocket/gRPC connection handling
- Tool registry: Maps tool names to implementations

#### `crates/platform`
- Platform abstraction traits: `NetworkOps`, `SystemInfo`, `CaptureOps`, `CommandExec`
- Platform-specific implementations: Linux, macOS, Android, iOS, Web
- Feature flags: `desktop`, `android`, `ios`, `web`

#### `crates/ui`
- Dioxus UI components: Shared across all platforms
- LiveView server: Headless mode serves UI over WebSocket
- Themes: 9 built-in themes (Strike48, Dark, Light, Dracula, Gruvbox, TokyoNight, Matrix, Cyberpunk, Nord) plus custom theme support
- Tool execution UI: Input forms, output display, evidence viewer

#### `crates/tools`
- Tool implementations: 90+ pentest tools
- External tool wrappers: BlackArch integrations (nmap, masscan, etc.)
- Evidence producers: Convert tool output to evidence nodes
- Three-agent pipeline: Red Team, Validator, Report agents

---

## Tool Execution Flow

```
1. User clicks "Run Port Scan" in UI
   └─> UI calls tool_registry.execute("port_scan", input)

2. Tool registry looks up PortScanTool
   └─> Calls PortScanTool::execute(input)

3. Tool implementation
   └─> Calls platform::NetworkOps::scan_ports(...)
       └─> Platform-specific implementation (Linux uses nmap, Android uses Java APIs, etc.)

4. Tool returns ToolOutput
   └─> Evidence producer converts to EvidenceNode
       └─> EvidenceNode sent to Strike48 via SDK

5. Strike48 aggregates evidence
   └─> Three-agent pipeline validates and synthesizes findings
```

---

## Three-Agent Validation Pipeline

Pick's evidence validation architecture uses three specialized agents:

### Red Team Agent
- Executes tools and produces raw evidence
- Focuses on breadth of coverage
- Generates evidence nodes with metadata

### Validator Agent
- Verifies evidence quality and accuracy
- Checks for false positives/negatives
- Validates tool output format and completeness

### Report Agent
- Synthesizes findings into actionable reports
- Correlates evidence across tools
- Generates natural language summaries

**Flow:**
```
Tool Output → Evidence Node → Validator → Report Agent → Final Finding
              (Red Team)      (Quality)    (Synthesis)
```

---

## Evidence Handling

### Evidence Node Structure

The actual `EvidenceNode` struct from `crates/core/src/evidence.rs`:

```rust
pub struct EvidenceNode {
    pub id: String,                           // Stable, globally unique identifier
    pub node_type: String,                    // "finding", "host", "service", etc.
    pub title: String,                        // One-line human-readable title
    pub description: String,                  // Multi-paragraph report body content
    pub affected_target: String,              // IP, CIDR, hostname, URL, etc.
    pub severity_history: Vec<SeverityHistoryEntry>, // Ordered severity history
    pub validation_status: ValidationStatus,  // Pending, Confirmed, Revised, etc.
    pub confidence: f32,                      // 0.0..=1.0 confidence score
    pub provenance: Option<Provenance>,       // Reproducibility metadata
    pub metadata: HashMap<String, serde_json::Value>, // Tool-specific detail
    pub created_at: DateTime<Utc>,            // Graph insertion timestamp
}
```

### Evidence Buffer

- Bounded buffer (configurable capacity)
- Non-blocking push operations
- Near-full detection (80% threshold)
- Automatic flush to Strike48

---

## Strike48 SDK Integration

### Connection Lifecycle

```
1. App startup
   └─> Read STRIKE48_HOST, STRIKE48_TENANT from environment

2. SDK initialization
   └─> Connect to Strike48 via WebSocket or gRPC

3. Connector registration
   └─> Register as connector with unique instance ID
       └─> Strike48 acknowledges and assigns connector session

4. Tool execution loop
   └─> Listen for tool execution requests from Strike48
       └─> Execute locally, stream evidence back

5. Graceful shutdown
   └─> Unregister connector, close connection
```

### Authentication

- JWT tokens (optional): `STRIKE48_TOKEN`
- TLS configuration: `STRIKE48_TLS`, `MATRIX_TLS_INSECURE`
- Tenant-based isolation: Each tenant has isolated connector namespace

---

## Testing Strategy

### Unit Tests
- Tool implementations: Mock platform layer
- Evidence producers: Verify conversion correctness
- Validation logic: Test all validation rules

### Integration Tests
- Strike48 SDK: Test connection, registration, tool execution
- Platform layer: Test platform-specific implementations
- End-to-end: Full tool execution flow

### Test Organization

```
Unit tests:      #[cfg(test)] modules in source files
Integration:     tests/ directory
Benchmarks:      benches/ directory (Criterion)
```

### Coverage Goals

- Minimum 80% line coverage
- 100% coverage for critical paths (authentication, evidence handling)
- Property-based testing for parsers and validators

---

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| **Linux** | ✅ Full | Desktop + headless, BlackArch tools |
| **macOS** | ✅ Full | Desktop + headless, limited tool support |
| **Android** | ⚠️ Beta | Mobile app, root detection, limited tools |
| **iOS** | 🚧 Alpha | Mobile app, sandboxed, very limited tools |
| **Web** | ✅ Full | Server-side execution, all tools available |
| **Windows** | ⚠️ WSL | Via WSL2, native support in progress |

---

## Performance Characteristics

### Tool Execution
- Concurrent tool execution: Limited by platform (default: 4 concurrent)
- Tool timeout: Configurable per tool (default: 5 minutes)
- Evidence buffer: 10,000 nodes (configurable)

### Resource Usage
- Memory: ~50-100MB baseline, scales with tool output
- CPU: Bursty during tool execution
- Network: Depends on evidence volume (typically <1MB/s)

---

## Security Model

### Isolation
- Tools run in same process (no sandbox by default)
- Optional: Run tools via bwrap (bubblewrap) on Linux
- Android: App sandbox enforced by OS

### Privilege Requirements
- WiFi tools: Require root/sudo (monitor mode, packet injection)
- Network scanning: May require CAP_NET_RAW capability
- File system access: Respects OS permissions

### Secrets Management
- Never hardcode secrets in code
- Use environment variables (`.env` file, gitignored)
- Strike48 tokens rotated regularly

---

## Deployment Modes

### Standalone (Headless)
```bash
./run-pentest.sh headless dev
```
- Connects directly to Strike48
- No GUI, serves LiveView over WebSocket
- Production deployment mode

### Desktop
```bash
sudo cargo run --package pentest-desktop
```
- Native desktop app with full GUI
- Requires sudo for WiFi tools
- Development and operator use

### Mobile
```bash
cargo mobile android build
cargo mobile ios build
```
- Native mobile app (Android/iOS)
- Touch-optimized UI
- Limited tool support (no root-requiring tools)

### Web (Server-Hosted)
```bash
cargo run --package pentest-web
```
- Server-side tool execution
- Web browser UI via LiveView
- Multi-user access

---

## Configuration

### Environment Variables

See [docs/GLOSSARY.md](docs/GLOSSARY.md) for complete variable reference.

**Required:**
- `STRIKE48_HOST` - WebSocket/gRPC endpoint
- `STRIKE48_TENANT` - Tenant identifier

**Optional:**
- `STRIKE48_INSTANCE_ID` - Unique connector ID (auto-generated if not set)
- `CONNECTOR_NAME` - Gateway identity name (default: `pentest-connector`)
- `RUST_LOG` - Logging verbosity (default: `info`)

**Legacy (Strike48 API):**
- `MATRIX_API_URL` - Strike48 API endpoint (legacy name)
- `MATRIX_TENANT_ID` - Tenant ID for API (legacy name)

---

## Future Architecture

### Planned Improvements

1. **Tool Sandboxing** - Isolate tool execution (containers, VMs, seccomp-bpf)
2. **Plugin System** - External tool plugins (WASM, dynamic libraries)
3. **Distributed Execution** - Multi-connector tool orchestration
4. **Real-time Collaboration** - Multiple operators on same engagement

### Considerations

- **Scalability** - Support 100+ concurrent connectors per Strike48 instance
- **Reliability** - Graceful degradation, automatic reconnection
- **Observability** - Metrics, tracing, profiling

---

## References

- [README.md](README.md) - Project overview
- [RUNNING.md](RUNNING.md) - Getting started guide
- [CONTRIBUTING.md](CONTRIBUTING.md) - Contribution guidelines
- [docs/GLOSSARY.md](docs/GLOSSARY.md) - Terminology reference
- [docs/SYSTEM_ARCHITECTURE.md](docs/SYSTEM_ARCHITECTURE.md) - Detailed ecosystem architecture

---

**Last updated:** 2026-05-28
