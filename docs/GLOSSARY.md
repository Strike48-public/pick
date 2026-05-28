# Pick Terminology Glossary

This document defines key terms used throughout Pick's documentation and codebase.

---

## Project & Product Names

### Pick
The name of this project - a multiplatform penetration testing connector that bridges Strike48 with local security tools.

**Previous name:** "Dioxus Pentest Connector" (deprecated as of 2026-05-28)

### Strike48
The orchestration and control plane platform that Pick connects to. Strike48 provides:
- Connector management and registration
- Tool execution requests and routing
- Evidence collection and aggregation
- Multi-connector orchestration

---

## Architecture Terms

### Connector
An application instance that registers with Strike48 and executes tools locally. Pick IS a connector - each app (desktop, mobile, headless) registers independently and runs tools on its host machine.

### Control Plane
Generic term for the orchestration server (Strike48) that manages connectors and routes tool requests.

### Three-Agent Pipeline
Pick's evidence validation architecture with three specialized agents:
- **Red Team Agent** - Executes tools and produces raw evidence
- **Validator Agent** - Verifies evidence quality and accuracy
- **Report Agent** - Synthesizes findings into actionable reports

### Evidence Node
A unit of evidence produced by a tool execution, with provenance tracking and validation metadata.

---

## Environment Variables

### Strike48 Connection
| Variable | Purpose | Example |
|----------|---------|---------|
| `STRIKE48_HOST` | WebSocket or gRPC endpoint | `wss://your-server.example.com:443` |
| `STRIKE48_TENANT` | Tenant identifier | `use-prd-c-your-tenant` |
| `STRIKE48_INSTANCE_ID` | Unique connector instance ID | `pick-connector-01` |
| `STRIKE48_TOKEN` | JWT authentication token (optional) | `eyJhbGc...` |
| `STRIKE48_TLS` | Enable/disable TLS | `true` or `false` |

### Strike48 API (Legacy "Matrix" Variables)
These variables reference Strike48's API layer. The "MATRIX" prefix is a legacy internal name for Strike48's protocol:

| Variable | Purpose | Notes |
|----------|---------|-------|
| `MATRIX_API_URL` | Strike48 HTTPS API endpoint | Same server as STRIKE48_HOST |
| `MATRIX_TENANT_ID` | Tenant ID for API calls | Same value as STRIKE48_TENANT |
| `MATRIX_TLS_INSECURE` | Accept self-signed certs | Development/testing only |

**Deprecation note:** These variables remain for backward compatibility but may be consolidated to `STRIKE48_API_*` in future versions.

### Other Configuration
| Variable | Purpose | Example |
|----------|---------|---------|
| `CONNECTOR_NAME` | Gateway identity name | `pentest-connector` (default) |
| `STRIKEHUB_SOCKET` | Unix socket for StrikeHub IPC | Set by StrikeHub automatically |
| `RUST_LOG` | Logging verbosity | `debug`, `info`, `warn`, `error` |

---

## Tool Categories

### Network Scanning
Port scanning, service enumeration, network mapping tools (nmap, rustscan, masscan)

### WiFi Tools
Wireless network scanning, monitor mode, packet capture, WPA cracking (autopwn suite)

### Credential Testing
Password spraying, default credential checks, credential harvesting

### Web Vulnerability Scanning
Web app security testing, fuzzing, SQL injection detection

### Evidence Handling
Converting tool output to validated evidence nodes with provenance tracking

### External Tools
80+ BlackArch tools integrated via the `external` module (dirbuster, nikto, sqlmap, hydra, etc.)

---

## UI Terms

### Matrix Theme
One of Pick's 8 built-in UI themes - green-on-black Matrix movie aesthetic. Not related to the Strike48 protocol.

### Easter Egg
Konami code (↑↑↓↓←→←→BA) activates a Matrix rain animation in the UI.

### Headless Mode
Pick running without a graphical UI, serving its interface via Dioxus LiveView over WebSocket or Unix socket.

### Desktop Mode
Pick running as a native desktop application with full GUI.

---

## Historical / Deprecated Terms

### "Matrix" (ambiguous - avoid in new docs)
Historically used to refer to:
1. Strike48's internal protocol name (prefer "Strike48" or "control plane")
2. A UI theme (OK - this is explicit: "Matrix theme")
3. Test matrices / comparison tables (OK - common term)

**Guidance:** When writing new documentation, use "Strike48" for the orchestration platform. Use "Matrix" only when referring to the UI theme or standard technical terms (test matrix, comparison matrix).

### "Dioxus Pentest Connector"
Former project name, replaced by "Pick" (2026-05-28).

---

**Last updated:** 2026-05-28
