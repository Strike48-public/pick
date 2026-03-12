# Pick Codebase Analysis - Tool Output Patterns

**Date:** 2026-03-12
**Purpose:** Understand current tool output format to design structured parser

## Current Architecture

### Tool Trait (`pentest_core::tools::PentestTool`)

```rust
#[async_trait]
pub trait PentestTool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn schema(&self) -> ToolSchema;
    async fn execute(&self, params: Value, ctx: &ToolContext) -> Result<ToolResult>;
}
```

### Tool Result Structure

```rust
pub struct ToolResult {
    pub success: bool,
    pub data: Value,           // <-- This is what we need to parse!
    pub error: Option<String>,
    pub duration_ms: u64,
}
```

**Key Insight:** All tool outputs are already wrapped in `ToolResult`, and the actual data is a `serde_json::Value`. This is perfect for parsing!

## Current Tool Output Formats

### 1. Port Scan (`port_scan`)

```json
{
  "host": "192.168.1.1",
  "ports": [
    {"port": 22, "open": true},
    {"port": 80, "open": true},
    {"port": 443, "open": false}
  ],
  "open_count": 2,
  "total_scanned": 3,
  "duration_ms": 1523
}
```

**Extractable:**
- Target: `host` → IP address
- Service: Each open port → service discovery
- Finding: Open ports with potential vulnerabilities

### 2. WiFi Scan (`wifi_scan`)

```json
{
  "networks": [
    {
      "ssid": "HomeNetwork",
      "bssid": "AA:BB:CC:DD:EE:FF",
      "signal_strength": -45,
      "signal_quality": 85,
      "signal_bars": 4,
      "frequency": 2437,
      "channel": 6,
      "security": "WPA2-PSK",
      "clients": 3
    }
  ],
  "count": 1
}
```

**Extractable:**
- Target: Each network (SSID/BSSID)
- Finding: Weak encryption (WEP, WPA), open networks
- Intelligence: Signal strength, client count

### 3. Network Discovery (`network_discover`)

```json
{
  "services": [
    {
      "name": "Chromecast-Living-Room",
      "service_type": "_googlecast._tcp.local.",
      "host": "192.168.1.50",
      "port": 8009,
      "txt_records": {
        "id": "abc123",
        "model": "Chromecast"
      }
    }
  ],
  "count": 1
}
```

**Extractable:**
- Target: `host` + `port`
- Service: `service_type`, `name`
- Metadata: `txt_records`

### 4. Default Credentials (`default_creds`)

```json
{
  "tested": [
    {
      "username": "admin",
      "password": "admin",
      "success": true,
      "service": "http",
      "port": 80
    },
    {
      "username": "root",
      "password": "password",
      "success": false,
      "service": "ssh",
      "port": 22
    }
  ],
  "successful_logins": 1,
  "total_tested": 2
}
```

**Extractable:**
- Credential: Successful username/password
- Finding: Default credentials accepted (HIGH severity)
- Target: Host + port + service

## Tool Registration

**Current count:** ~20 tools registered in `create_tool_registry()`

### Categories:
1. **Network scanning**: port_scan, arp_table, ssdp_discover, network_discover
2. **WiFi tools**: wifi_scan, wifi_scan_detailed, autopwn (plan, capture, crack)
3. **Vulnerability assessment**: service_banner, cve_lookup, default_creds, web_vuln_scan, smb_enum
4. **System info**: device_info, screenshot, traffic_capture
5. **File/command operations**: execute_command, read_file, write_file, list_files

## Key Observations

### ✅ What Works Well

1. **Consistent wrapping:** All tools return `ToolResult` with structured JSON in `.data`
2. **Type safety:** Tools use `serde_json::Value` which is easy to parse
3. **Timing built-in:** `execute_timed()` wrapper adds duration automatically
4. **Schema available:** Every tool has a schema describing its parameters

### ⚠️ What Needs Work

1. **No standardized output schema:** Each tool returns different JSON structure
2. **No type hints in data:** The `data` field is untyped `Value` - need to parse/validate
3. **No semantic tagging:** Tools don't explicitly mark "this is a credential" or "this is a vulnerability"
4. **Raw data only:** No distinction between "data for humans" vs "data for StrikeKit ingestion"

## Design Implications for Structured Parser

### Approach 1: Post-Processing Parser (RECOMMENDED)

**Idea:** Leave tools as-is, create parsers that extract structured data from `ToolResult.data`

```rust
pub trait OutputParser {
    fn parse(&self, tool_name: &str, result: &ToolResult) -> Vec<StructuredOutput>;
}

pub enum StructuredOutput {
    Target(TargetDiscovered),
    Credential(CredentialFound),
    Finding(FindingReported),
    Service(ServiceIdentified),
}
```

**Pros:**
- ✅ No changes to existing tools
- ✅ Can add parsers incrementally
- ✅ Easy to test (just parse JSON)
- ✅ Backwards compatible

**Cons:**
- ⚠️ Need parser for each tool
- ⚠️ Brittle if tool output format changes

### Approach 2: Tool-Embedded Parsing

**Idea:** Modify `ToolResult` to include structured outputs

```rust
pub struct ToolResult {
    pub success: bool,
    pub data: Value,  // Legacy human-readable
    pub structured: Vec<StructuredOutput>,  // New machine-readable
    pub error: Option<String>,
    pub duration_ms: u64,
}
```

**Pros:**
- ✅ Tools explicitly declare structured outputs
- ✅ Less brittle (tools control their output)
- ✅ Can version structured output independently

**Cons:**
- ❌ Requires modifying all tools
- ❌ Breaking change to `ToolResult`
- ❌ More work upfront

### Approach 3: Dual Output

**Idea:** Tools return both human-readable JSON and structured data

```rust
impl PentestTool for PortScanTool {
    async fn execute(&self, params: Value, ctx: &ToolContext) -> Result<ToolResult> {
        // ... scanning logic ...

        let data = json!({ /* human-readable */ });
        let structured = vec![
            StructuredOutput::Target(TargetDiscovered { ... }),
            StructuredOutput::Service(ServiceIdentified { ... }),
        ];

        Ok(ToolResult::with_structured(data, structured))
    }
}
```

**Pros:**
- ✅ Best of both worlds
- ✅ Tools opt-in gradually

**Cons:**
- ⚠️ Requires updating each tool
- ⚠️ Duplication of data (JSON + structured)

## Recommendation: Approach 1 (Post-Processing Parser)

Start with **post-processing parsers** because:

1. **Fastest to implement:** No tool changes needed
2. **Incremental:** Can add parsers one tool at a time
3. **Testable:** Easy to write unit tests
4. **Safe:** No risk of breaking existing tools
5. **Flexible:** Can refactor to Approach 3 later

### Implementation Plan

#### Phase 1: Parser Infrastructure
1. Define `StructuredOutput` enum
2. Define output types: `TargetDiscovered`, `CredentialFound`, `FindingReported`, etc.
3. Create `OutputParser` trait
4. Create `OutputParserRegistry`

#### Phase 2: Core Parsers
1. `PortScanParser` - Extract targets and open ports
2. `WifiScanParser` - Extract WiFi networks and vulnerabilities
3. `DefaultCredsParser` - Extract successful credentials
4. `NetworkDiscoverParser` - Extract discovered services

#### Phase 3: Integration
1. Hook parser into tool execution
2. Send structured outputs to StrikeKit via Matrix
3. Add parser for each remaining tool

## Sample Code Structure

```
crates/
├── core/
│   └── src/
│       └── output_parser.rs       # Parser traits and types
├── tools/
│   └── src/
│       ├── parsers/
│       │   ├── mod.rs              # Parser registry
│       │   ├── port_scan.rs        # PortScanParser
│       │   ├── wifi_scan.rs        # WifiScanParser
│       │   ├── default_creds.rs    # DefaultCredsParser
│       │   └── network_discover.rs # NetworkDiscoverParser
│       └── lib.rs                  # Register parsers
└── matrix/
    └── src/
        └── structured_messages.rs  # StrikeKit message protocol
```

## Next Steps

1. ✅ Codebase exploration (DONE)
2. 🔲 Define structured output types (`TargetDiscovered`, `CredentialFound`, etc.)
3. 🔲 Create `OutputParser` trait
4. 🔲 Implement first parser (PortScanParser)
5. 🔲 Test parser with real tool output
6. 🔲 Design StrikeKit integration protocol
7. 🔲 Implement remaining parsers

---

**Files to modify:**
- `crates/core/src/output_parser.rs` (NEW)
- `crates/tools/src/parsers/` (NEW directory)
- No changes to existing tools initially ✅
