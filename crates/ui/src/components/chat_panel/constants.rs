//! Constants, default agent config, and system prompt.

use pentest_core::matrix::CreateAgentInput;

/// Name used to auto-select the pentest-connector agent from the agent list.
pub const PENTEST_AGENT_NAME: &str = "pentest-connector";

pub const CHAT_MIN_WIDTH: i32 = 280;
pub const CHAT_MAX_WIDTH: i32 = 800;
pub const CHAT_DEFAULT_WIDTH: i32 = 380;

pub const POLL_INTERVAL_MS: u64 = 800;
pub const MAX_POLL_ATTEMPTS: u32 = 150;

/// Suggested quick-action prompts shown in the empty chat state.
pub const SUGGESTED_ACTIONS: &[(&str, &str)] = &[
    ("Scan Network", "Run a full network discovery — ARP, mDNS, and SSDP — and summarize what you find."),
    ("Port Scan", "Scan the local gateway for common open ports and identify running services."),
    ("WiFi Recon", "Scan for nearby WiFi networks and list SSIDs, channels, and signal strengths."),
    ("Device Info", "Get the device info for this connector — OS, hostname, architecture, and resources."),
    ("Recon Plan", "Suggest a reconnaissance plan for the network this connector is on. Don't execute anything yet."),
];

/// Build the default CreateAgentInput for auto-creating a pentest-connector persona.
///
/// `tenant_id` is the tenant/realm name (e.g. "non-prod") used to build the
/// connector address pattern `{tenant}.pentest-connector.*` so the Matrix
/// backend can match registered connector tools to this agent.
pub fn default_pentest_agent_input(tenant_id: &str) -> CreateAgentInput {
    let connector_key = format!("{}.pentest-connector.*", tenant_id);

    let mut connectors = serde_json::Map::new();
    connectors.insert(
        connector_key,
        serde_json::json!({
            "consent_mode": "auto",
            "enabled": true,
            "tool_configs": {
                "execute_command": { "consent_mode": "auto", "enabled": true },
                "screenshot": { "consent_mode": "auto", "enabled": true },
                "list_files": { "consent_mode": "auto", "enabled": true },
                "wifi_scan": { "consent_mode": "auto", "enabled": true },
                "port_scan": { "consent_mode": "auto", "enabled": true },
                "device_info": { "consent_mode": "auto", "enabled": true },
                "arp_table": { "consent_mode": "auto", "enabled": true },
                "read_file": { "consent_mode": "auto", "enabled": true },
                "network_discover": { "consent_mode": "auto", "enabled": true },
                "traffic_capture": { "consent_mode": "auto", "enabled": true },
                "write_file": { "consent_mode": "auto", "enabled": true },
                "ssdp_discover": { "consent_mode": "auto", "enabled": true }
            }
        }),
    );

    CreateAgentInput {
        name: "pentest-connector".to_string(),
        description: Some("Red team operational agent for penetration testing".to_string()),
        system_message: Some(RED_TEAM_SYSTEM_PROMPT.to_string()),
        agent_greeting: Some("Ready for red team operations. What's the target?".to_string()),
        context: Some(serde_json::json!({
            "created_by": "pentest-connector",
            "description": "Auto-created by pentest-connector"
        })),
        tools: Some(serde_json::json!({
            "allow_patterns": [],
            "deny_patterns": [],
            "predefined_names": [],
            "system_tools": {
                "system:document_list": { "consent_mode": "auto", "enabled": true },
                "system:document_read": { "consent_mode": "auto", "enabled": true },
                "system:document_write": { "consent_mode": "auto", "enabled": true },
                "system:echarts_guide": { "consent_mode": "auto", "enabled": true },
                "system:mermaid_guide": { "consent_mode": "auto", "enabled": true },
                "system:validate_echarts": { "consent_mode": "auto", "enabled": true },
                "system:validate_mermaid": { "consent_mode": "auto", "enabled": true },
                "system:validate_react": { "consent_mode": "auto", "enabled": true }
            },
            "mcp_servers": {},
            "connectors": connectors,
            "workflow_tools": {}
        })),
    }
}

const RED_TEAM_SYSTEM_PROMPT: &str = r#"You are the pentest-connector red team operational agent. You operate within an authorized penetration testing engagement using the Strike48 platform.

## Operational Framework

### Phase 0: Omnidirectional Sensing
Detect everything that communicates on the target network. Use passive and active reconnaissance:
- Network discovery (ARP, mDNS, SSDP, SNMP)
- Service enumeration (port scanning, banner grabbing)
- Wireless spectrum analysis (WiFi, BLE, Zigbee if applicable)
- DNS reconnaissance and zone enumeration

### Phase 1: Surface Inflation
Maximize the known attack surface:
- Subdomain enumeration and naming explosion
- Address space mapping (IPv4/IPv6)
- Management interface discovery
- Legacy service identification
- API endpoint enumeration
- Certificate transparency log mining

### Phase 2: Trust Abuse Hypotheses
Identify where trust is implicitly assumed:
- Identity and authentication mapping
- Transitive trust relationships
- Credential reuse patterns
- Service account permissions
- Network segmentation boundaries
- Certificate trust chains

### Phase 3: Ingress Confirmation
Prove entry points exist:
- External perimeter testing
- Protocol downgrade exploitation
- Default credential testing
- Known vulnerability validation
- Misconfiguration exploitation

### Phase 4: Internal Reality Check
Determine where the security model diverges from implementation:
- Information disclosure assessment
- Secrets in source code, configs, environment
- Shared-fate component identification
- Privilege escalation paths
- Lateral movement opportunities

### Phase 5: Chain Construction
Compound individual findings into attack chains:
- LLMNR/NBT-NS poisoning → credential capture
- Kerberos abuse (AS-REP roasting, Kerberoasting)
- Certificate abuse (ESC1-ESC8)
- Relay attacks (NTLM, SMB)
- Token impersonation chains

### Phase 6: Attacker Payoff Modeling
Rank findings by real-world attacker incentive:
- Data exfiltration potential
- Ransomware deployment feasibility
- Persistence mechanism availability
- Business impact assessment
- Remediation priority ranking

## Tool Usage
You have access to connector tools for running operations on the connected target. Always explain what you're doing before executing tools. Report findings clearly with severity ratings and remediation recommendations.

## Rules of Engagement
- Only operate within the authorized scope
- Document all actions and findings
- Do not cause denial of service
- Preserve evidence integrity
- Report critical findings immediately
"#;
