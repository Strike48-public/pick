# StrikeKit Schema Analysis for Pick Integration

**Date:** 2026-03-12
**Purpose:** Define structured output types that align with StrikeKit's database schema

## StrikeKit Core Entities

### 1. Target

**Database Schema (SQLite):**
```sql
CREATE TABLE targets (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    target_type TEXT NOT NULL,        -- 'host', 'domain', 'user', 'service', 'application', 'network'
    name TEXT NOT NULL,
    description TEXT,
    ip_address TEXT,
    hostname TEXT,
    domain TEXT,
    os TEXT,
    ports TEXT NOT NULL DEFAULT '[]', -- JSON array
    tags TEXT NOT NULL DEFAULT '[]',  -- JSON array
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    -- Additional fields (from newer schema):
    status TEXT DEFAULT 'active',     -- 'active', 'archived', 'deleted'
    parent_id TEXT,                   -- Reference to parent Host
    detection_source TEXT,            -- e.g., "nmap", "manual", "pick"
    confidence INTEGER,               -- 0-100
    cpe_vendor TEXT,                  -- For service targets
    cpe_product TEXT                  -- For service targets
);
```

**Rust Type:**
```rust
pub struct Target {
    pub id: Uuid,
    pub engagement_id: Uuid,
    pub target_type: TargetType,      // Host, Domain, User, Service, Application, Network
    pub name: String,
    pub description: Option<String>,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub domain: Option<String>,
    pub os: Option<String>,
    pub ports: Vec<Port>,
    pub tags: Vec<String>,
    pub notes: Option<String>,
    pub status: TargetStatus,         // Active, Archived, Deleted
    pub parent_id: Option<Uuid>,
    pub detection_source: Option<String>,
    pub confidence: Option<u8>,
    pub cpe_vendor: Option<String>,
    pub cpe_product: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct Port {
    pub number: u16,
    pub protocol: String,             // "tcp", "udp"
    pub service: Option<String>,      // "http", "ssh", "ftp"
    pub version: Option<String>,      // "Apache 2.4.41"
    pub state: PortState,             // Open, Closed, Filtered, Unknown
}
```

**What Pick Should Send:**
```json
{
  "type": "target_discovered",
  "engagement_id": "uuid",
  "target": {
    "target_type": "host",
    "name": "192.168.1.1",
    "ip_address": "192.168.1.1",
    "hostname": "router.local",
    "os": "Linux 5.x",
    "ports": [
      {"number": 22, "protocol": "tcp", "service": "ssh", "version": "OpenSSH 8.2", "state": "open"},
      {"number": 80, "protocol": "tcp", "service": "http", "state": "open"}
    ],
    "detection_source": "pick:port_scan",
    "confidence": 85
  }
}
```

### 2. Credential

**Database Schema:**
```sql
CREATE TABLE credentials (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    target_id TEXT,                        -- Optional link to one target
    credential_type TEXT NOT NULL,         -- 'plaintext', 'ntlm_hash', 'kerberos_tgt', 'kerberos_tgs', 'ssh_key', 'api_token', 'cookie', 'certificate', 'other'
    username TEXT,
    secret TEXT NOT NULL,
    domain TEXT,
    source TEXT NOT NULL DEFAULT '',       -- Source tool/method
    status TEXT NOT NULL DEFAULT 'untested', -- 'untested', 'valid', 'invalid', 'expired'
    notes TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Many-to-many: credentials ↔ targets
CREATE TABLE credential_targets (
    id TEXT PRIMARY KEY,
    credential_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    privilege_tier TEXT NOT NULL DEFAULT 'unknown', -- 'domain_admin', 'local_admin', 'user', 'service', 'unknown'
    last_tested TEXT,
    notes TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(credential_id, target_id)
);
```

**Rust Type:**
```rust
pub struct Credential {
    pub id: Uuid,
    pub engagement_id: Uuid,
    pub target_id: Option<Uuid>,
    pub credential_type: CredentialType,  // Plaintext, NtlmHash, KerberosTgt, KerberosTgs, SshKey, ApiToken, Cookie, Certificate, Other
    pub username: Option<String>,
    pub secret: String,                   // Password, hash, key material
    pub domain: Option<String>,
    pub source: String,                   // Tool that discovered it
    pub status: CredentialStatus,         // Untested, Valid, Invalid, Expired
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct CredentialTarget {
    pub id: Uuid,
    pub credential_id: Uuid,
    pub target_id: Uuid,
    pub privilege_tier: PrivilegeTier,    // DomainAdmin, LocalAdmin, User, Service, Unknown
    pub last_tested: Option<DateTime<Utc>>,
    pub notes: Option<String>,
    pub test_result: Option<String>,      // "passed", "failed", or None
    pub created_at: DateTime<Utc>,
}
```

**What Pick Should Send:**
```json
{
  "type": "credential_found",
  "engagement_id": "uuid",
  "credential": {
    "credential_type": "plaintext",
    "username": "admin",
    "secret": "password123",
    "domain": null,
    "source": "pick:default_creds",
    "status": "valid"
  },
  "target_associations": [
    {
      "target_id": "uuid",
      "privilege_tier": "local_admin",
      "test_result": "passed"
    }
  ]
}
```

### 3. Finding

**Database Schema:**
```sql
CREATE TABLE findings (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    target_ids TEXT NOT NULL DEFAULT '[]',     -- JSON array of UUIDs
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',   -- 'informational', 'low', 'medium', 'high', 'critical'
    status TEXT NOT NULL DEFAULT 'draft',      -- 'draft', 'confirmed', 'exploited', 'mitigated', 'accepted'
    evidence TEXT NOT NULL DEFAULT '[]',       -- JSON array
    mitre_techniques TEXT NOT NULL DEFAULT '[]', -- JSON array of MITRE ATT&CK IDs
    remediation TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Many-to-many: findings ↔ targets
CREATE TABLE finding_targets (
    finding_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    service_id TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (finding_id, target_id)
);

-- Many-to-many: findings ↔ credentials
CREATE TABLE finding_credentials (
    finding_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    usage_context TEXT,
    created_at TEXT NOT NULL,
    PRIMARY KEY (finding_id, credential_id)
);

-- Many-to-many: findings ↔ CVEs
CREATE TABLE finding_cves (
    finding_id TEXT NOT NULL,
    cve_id TEXT NOT NULL,
    cvss_score REAL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (finding_id, cve_id)
);
```

**Rust Type:**
```rust
pub struct Finding {
    pub id: Uuid,
    pub engagement_id: Uuid,
    pub target_ids: Vec<Uuid>,
    pub credential_ids: Vec<Uuid>,
    pub activity_ids: Vec<Uuid>,
    pub title: String,
    pub description: String,
    pub severity: Severity,               // Informational, Low, Medium, High, Critical
    pub status: FindingStatus,            // Draft, Confirmed, Exploited, Mitigated, Accepted
    pub evidence: Vec<Evidence>,
    pub mitre_techniques: Vec<String>,    // ["T1003.001", "T1078"]
    pub remediation: Option<String>,
    pub cve_ids: Vec<String>,
    pub assigned_to: Option<String>,
    pub due_date: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct Evidence {
    pub evidence_type: String,            // "screenshot", "command_output", "file", "network_capture"
    pub description: String,
    pub data: String,                     // Path or inline content
    pub timestamp: DateTime<Utc>,
}
```

**What Pick Should Send:**
```json
{
  "type": "finding_reported",
  "engagement_id": "uuid",
  "finding": {
    "title": "Default Credentials Accepted on Web Interface",
    "description": "The web interface at http://192.168.1.1 accepts default credentials (admin/admin).",
    "severity": "high",
    "status": "confirmed",
    "evidence": [
      {
        "evidence_type": "command_output",
        "description": "Successful HTTP Basic Auth with default credentials",
        "data": "HTTP/1.1 200 OK...",
        "timestamp": "2026-03-12T12:00:00Z"
      }
    ],
    "mitre_techniques": ["T1078.001"],
    "remediation": "Change default credentials immediately and enforce strong password policy."
  },
  "target_associations": ["target-uuid"],
  "credential_associations": ["credential-uuid"]
}
```

### 4. Activity

**Database Schema:**
```sql
CREATE TABLE activities (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    target_id TEXT,
    timestamp TEXT NOT NULL,
    category TEXT NOT NULL,                    -- Activity type/category
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    command TEXT,                              -- Command executed
    output TEXT,                               -- Command output
    success INTEGER,                           -- 1 = success, 0 = failure
    mitre_techniques TEXT NOT NULL DEFAULT '[]',
    iocs TEXT NOT NULL DEFAULT '[]',           -- Indicators of Compromise
    objective_ids TEXT NOT NULL DEFAULT '[]',  -- Related objectives
    scope_reason TEXT,
    created_at TEXT NOT NULL
);
```

**What Pick Should Send:**
```json
{
  "type": "tool_executed",
  "engagement_id": "uuid",
  "activity": {
    "target_id": "uuid",
    "category": "reconnaissance",
    "title": "Port Scan - 192.168.1.1",
    "description": "Scanned ports 1-1024 on target",
    "command": "nmap -p 1-1024 192.168.1.1",
    "output": "... (abbreviated) ...",
    "success": true,
    "mitre_techniques": ["T1046"]
  }
}
```

### 5. Execution Findings (Automated Tool Output)

**Database Schema:**
```sql
CREATE TABLE execution_findings (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    execution_id TEXT NOT NULL,
    tool TEXT NOT NULL,
    finding_type TEXT NOT NULL,           -- "open_port", "weak_credential", "vulnerability", etc.
    target TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    severity TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',  -- JSON with tool-specific data
    mitre_techniques TEXT NOT NULL DEFAULT '[]',
    promoted_finding_id TEXT,             -- If promoted to main findings table
    reviewed INTEGER NOT NULL DEFAULT 0,
    confidence TEXT,
    status TEXT DEFAULT 'new',            -- 'new', 'confirmed', 'false_positive'
    dedup_key TEXT,                       -- For deduplication
    mitre_attack_id TEXT,
    mitre_attack_name TEXT,
    cvss_score REAL,
    remediation TEXT,
    phase TEXT,                           -- Kill chain phase
    is_finding INTEGER NOT NULL DEFAULT 0,
    evidence TEXT,
    created_at TEXT NOT NULL
);
```

**Purpose:** Store raw, unreviewed findings from automated tool parsing. These can be promoted to the main `findings` table after review.

**What Pick Should Send:**
```json
{
  "type": "execution_finding",
  "engagement_id": "uuid",
  "finding": {
    "tool": "port_scan",
    "finding_type": "open_port",
    "target": "192.168.1.1",
    "title": "SSH Port Open",
    "description": "Port 22 (SSH) is open on 192.168.1.1",
    "severity": "informational",
    "confidence": "high",
    "metadata": {
      "port": 22,
      "service": "ssh",
      "version": "OpenSSH 8.2"
    },
    "mitre_techniques": ["T1046"],
    "phase": "reconnaissance"
  }
}
```

## Pick → StrikeKit Message Protocol

### Message Envelope Format

All messages from Pick to StrikeKit should follow this format:

```json
{
  "message_type": "target_discovered" | "credential_found" | "finding_reported" | "tool_executed" | "progress_update",
  "engagement_id": "uuid",
  "connector_id": "pick-instance-123",
  "timestamp": "2026-03-12T12:00:00Z",
  "tool_name": "port_scan",
  "payload": { ... }
}
```

### Message Types

#### 1. TargetDiscovered
```json
{
  "message_type": "target_discovered",
  "engagement_id": "uuid",
  "connector_id": "pick-1",
  "timestamp": "2026-03-12T12:00:00Z",
  "tool_name": "port_scan",
  "payload": {
    "target_type": "host",
    "name": "192.168.1.1",
    "ip_address": "192.168.1.1",
    "hostname": "router.local",
    "os": "Linux 5.x",
    "ports": [...],
    "detection_source": "pick:port_scan",
    "confidence": 85
  }
}
```

#### 2. CredentialFound
```json
{
  "message_type": "credential_found",
  "engagement_id": "uuid",
  "connector_id": "pick-1",
  "timestamp": "2026-03-12T12:00:00Z",
  "tool_name": "default_creds",
  "payload": {
    "credential": {
      "credential_type": "plaintext",
      "username": "admin",
      "secret": "admin",
      "source": "pick:default_creds",
      "status": "valid"
    },
    "target_id": "uuid",
    "privilege_tier": "local_admin"
  }
}
```

#### 3. FindingReported
```json
{
  "message_type": "finding_reported",
  "engagement_id": "uuid",
  "connector_id": "pick-1",
  "timestamp": "2026-03-12T12:00:00Z",
  "tool_name": "default_creds",
  "payload": {
    "title": "Default Credentials Accepted",
    "description": "...",
    "severity": "high",
    "target_ids": ["uuid"],
    "credential_ids": ["uuid"],
    "evidence": [...],
    "mitre_techniques": ["T1078.001"],
    "remediation": "..."
  }
}
```

#### 4. ToolExecuted
```json
{
  "message_type": "tool_executed",
  "engagement_id": "uuid",
  "connector_id": "pick-1",
  "timestamp": "2026-03-12T12:00:00Z",
  "tool_name": "port_scan",
  "payload": {
    "target_id": "uuid",
    "category": "reconnaissance",
    "title": "Port Scan - 192.168.1.1",
    "command": "nmap -p 1-1024 192.168.1.1",
    "output": "...",
    "success": true,
    "duration_ms": 5234,
    "mitre_techniques": ["T1046"]
  }
}
```

#### 5. ProgressUpdate
```json
{
  "message_type": "progress_update",
  "engagement_id": "uuid",
  "connector_id": "pick-1",
  "timestamp": "2026-03-12T12:00:00Z",
  "payload": {
    "phase": "reconnaissance",
    "status": "in_progress",
    "current_tool": "port_scan",
    "current_target": "192.168.1.0/24",
    "progress_percent": 35,
    "eta_seconds": 180,
    "message": "Scanning network range..."
  }
}
```

## Implementation Strategy for Pick

### Phase 1: Define Structured Output Types

Create Rust types in Pick that mirror StrikeKit's schema:

```rust
// crates/core/src/output_parser.rs

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// Structured outputs that Pick can send to StrikeKit
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "message_type", rename_all = "snake_case")]
pub enum StructuredMessage {
    TargetDiscovered(TargetDiscovered),
    CredentialFound(CredentialFound),
    FindingReported(FindingReported),
    ToolExecuted(ToolExecuted),
    ProgressUpdate(ProgressUpdate),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetDiscovered {
    pub engagement_id: String,
    pub connector_id: String,
    pub timestamp: DateTime<Utc>,
    pub tool_name: String,
    pub payload: TargetPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetPayload {
    pub target_type: TargetType,
    pub name: String,
    pub ip_address: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub ports: Vec<PortInfo>,
    pub detection_source: String,
    pub confidence: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetType {
    Host,
    Domain,
    User,
    Service,
    Application,
    Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub number: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub state: PortState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unknown,
}

// Similar types for Credential, Finding, etc.
```

### Phase 2: Create OutputParser Trait

```rust
// crates/tools/src/parsers/mod.rs

use pentest_core::tools::ToolResult;
use pentest_core::output_parser::StructuredMessage;

pub trait OutputParser: Send + Sync {
    /// Parse tool output into structured messages for StrikeKit
    fn parse(&self, tool_name: &str, result: &ToolResult) -> Vec<StructuredMessage>;
}

pub struct OutputParserRegistry {
    parsers: HashMap<String, Box<dyn OutputParser>>,
}

impl OutputParserRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            parsers: HashMap::new(),
        };

        // Register parsers
        registry.register("port_scan", Box::new(PortScanParser));
        registry.register("wifi_scan", Box::new(WifiScanParser));
        registry.register("default_creds", Box::new(DefaultCredsParser));

        registry
    }

    pub fn parse(&self, tool_name: &str, result: &ToolResult) -> Vec<StructuredMessage> {
        match self.parsers.get(tool_name) {
            Some(parser) => parser.parse(tool_name, result),
            None => {
                tracing::warn!("No parser found for tool: {}", tool_name);
                vec![]
            }
        }
    }
}
```

### Phase 3: Implement Tool-Specific Parsers

```rust
// crates/tools/src/parsers/port_scan.rs

pub struct PortScanParser;

impl OutputParser for PortScanParser {
    fn parse(&self, tool_name: &str, result: &ToolResult) -> Vec<StructuredMessage> {
        if !result.success {
            return vec![];
        }

        let mut messages = vec![];

        // Extract host information
        if let Some(host) = result.data.get("host").and_then(|v| v.as_str()) {
            let ports: Vec<PortInfo> = result.data.get("ports")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter().filter_map(|p| {
                        let port = p.get("port")?.as_u64()? as u16;
                        let open = p.get("open")?.as_bool()?;

                        Some(PortInfo {
                            number: port,
                            protocol: "tcp".to_string(),
                            service: None,  // TODO: Service detection
                            version: None,
                            state: if open { PortState::Open } else { PortState::Closed },
                        })
                    }).collect()
                })
                .unwrap_or_default();

            // Create TargetDiscovered message
            messages.push(StructuredMessage::TargetDiscovered(TargetDiscovered {
                engagement_id: get_current_engagement_id(),  // TODO: From context
                connector_id: get_connector_id(),
                timestamp: Utc::now(),
                tool_name: tool_name.to_string(),
                payload: TargetPayload {
                    target_type: TargetType::Host,
                    name: host.to_string(),
                    ip_address: Some(host.to_string()),
                    hostname: None,
                    os: None,
                    ports,
                    detection_source: format!("pick:{}", tool_name),
                    confidence: Some(90),
                },
            }));
        }

        messages
    }
}
```

## Next Steps

1. ✅ Analyze StrikeKit schema (DONE)
2. 🔲 Define `StructuredMessage` enum and payload types in Pick
3. 🔲 Create `OutputParser` trait
4. 🔲 Implement `PortScanParser` (first parser)
5. 🔲 Test parser with real port scan output
6. 🔲 Implement Matrix message sending
7. 🔲 Add parsers for remaining tools

---

**Key Design Decisions:**

1. **Use StrikeKit's exact field names** - Easier for StrikeKit to ingest
2. **Many-to-many relationships** - Send IDs for linkage (targets, credentials, findings)
3. **Confidence scores** - Include when available (OS detection, service identification)
4. **MITRE ATT&CK** - Tag activities and findings with techniques
5. **Deduplication** - StrikeKit handles this server-side
6. **Evidence inline** - Small evidence (command output) inline, large files as artifacts
