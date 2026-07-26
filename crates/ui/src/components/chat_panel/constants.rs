//! Constants, default agent config, and system prompt.

use pentest_core::matrix::CreateAgentInput;

pub const CHAT_MIN_WIDTH: i32 = 280;
pub const CHAT_MAX_WIDTH: i32 = 800;
pub const CHAT_DEFAULT_WIDTH: i32 = 380;

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
/// connector address pattern `{tenant}.{connector_name}.*` so the Matrix
/// backend can match registered connector tools to this agent.
///
/// `connector_name` controls the gateway identity. Instances sharing the same
/// name are round-robin'd; use a unique name (e.g. `pentest-connector-<hostname>`)
/// to get a dedicated agent view.
///
/// Tool configs are derived from the tool registry (stored in the global
/// session) so that every registered tool is automatically pre-approved.
///
/// This is a thin wrapper over the shared, pure builder in `pentest-core`
/// (`pentest_core::matrix::default_pentest_agent_input`); it only supplies the
/// UI's session-derived tool names so the crux middleware and the Dioxus app
/// share ONE implementation of the agent persona.
pub fn default_pentest_agent_input(tenant_id: &str, connector_name: &str) -> CreateAgentInput {
    pentest_core::matrix::default_pentest_agent_input(
        tenant_id,
        connector_name,
        &crate::session::get_tool_names(),
    )
}

/// Suffix appended to the connector name to produce the Report Agent name.
///
/// The Report Agent is a sibling of the Red Team agent under the same
/// connector identity: `{connector_name}` is Red Team, `{connector_name}-report`
/// is Report. Both are auto-registered at chat startup.
pub const REPORT_AGENT_SUFFIX: &str = "-report";

/// Build the `CreateAgentInput` for the Report Agent sibling.
///
/// The Report Agent consumes a `validated_findings_manifest` (the set of
/// `EvidenceNode`s where `is_publishable_finding()` returns true) and
/// renders the final customer-facing report. It is intentionally separated
/// from the Red Team agent so:
///
/// * Report prose is written once by an agent that never executes offensive
///   tools, reducing the chance of leaking probe state into the narrative.
/// * The Red Team prompt can stay focused on offense.
/// * The Validator's decisions (confirmed / revised / false positive) feed
///   directly into what the Report Agent sees.
///
/// Tool surface is deliberately minimal: diagram guides / validators and
/// `write_file`. No scanner tools — the Report Agent writes, it does not
/// probe.
pub fn default_report_agent_input(tenant_id: &str, connector_name: &str) -> CreateAgentInput {
    let report_name = format!("{}{}", connector_name, REPORT_AGENT_SUFFIX);
    let connector_key = format!("{}.{}.*", tenant_id, connector_name);

    // The Report Agent binds to the *Red Team* connector so it can read
    // the same evidence graph, but leaves scanner tools untouched by
    // not auto-approving them. Approved tools are the renderers only.
    let mut connectors = serde_json::Map::new();
    connectors.insert(
        connector_key,
        serde_json::json!({
            "consent_mode": "manual",
            "enabled": true,
            "tool_configs": {}
        }),
    );

    CreateAgentInput {
        name: report_name.clone(),
        description: Some(
            "Report agent: renders validated pentest findings into the final report".to_string(),
        ),
        system_message: Some(REPORT_AGENT_SYSTEM_PROMPT.to_string()),
        agent_greeting: Some(
            "Ready to render the validated findings manifest into a report.".to_string(),
        ),
        context: Some(serde_json::json!({
            "created_by": connector_name,
            "description": format!("Report sibling of {}", connector_name),
            "role": "report"
        })),
        tools: Some(serde_json::json!({
            "allow_patterns": [],
            "deny_patterns": [],
            "predefined_names": [],
            "system_tools": {
                "system:document_list": { "consent_mode": "auto", "enabled": true },
                "system:document_read": { "consent_mode": "auto", "enabled": true },
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

const REPORT_AGENT_SYSTEM_PROMPT: &str = r#"You are the Report Agent for the Strike48 pentest pipeline.

Your sole job: turn a `validated_findings_manifest` into a polished, senior-reviewer-grade penetration test report. You do not scan, probe, or execute offensive tools.

## Input Contract

The orchestrator hands you a JSON manifest shaped like this:

```json
{
  "engagement": { "target": "...", "started_at": "...", "completed_at": "..." },
  "findings": [
    {
      "id": "uuid",
      "node_type": "finding",
      "title": "...",
      "description": "...",
      "affected_target": "...",
      "validation_status": "confirmed" | "revised",
      "current_severity": "critical" | "high" | "medium" | "low" | "info",
      "severity_history": [
        { "severity": "...", "rationale": "...", "set_by": "red_team|validator", "timestamp": "..." }
      ],
      "confidence": 0.0,
      "provenance": {
        "underlying_tool": "...",
        "tool_version": "...",
        "probe_commands": [
          { "command": "...", "effective_command": "...", "description": "..." }
        ],
        "raw_response_excerpt": "..."
      },
      "metadata": { ... }
    }
  ],
  "context_nodes": [ /* validation_status == "info_only" */ ]
}
```

Every entry in `findings` is publishable — the Validator has already confirmed it. `context_nodes` carry host / tech fingerprint context; use them to set the scene, not as findings.

## Hard Rules

1. **Only report what is in the manifest.** Do not invent findings, CVEs, or attack paths. If the manifest is empty, say so plainly.
2. **Never rewrite provenance.** Render `effective_command` from each finding's `probe_commands[].command`field verbatim — this is the redacted, reviewer-reproducible form. Do not paraphrase it.
3. **Severity = `current_severity`**, which is the Validator's final call. If `severity_history` shows a revision (`set_by: validator` and severity differs from the first entry), note it in the finding: "Severity revised from X to Y — reason: ...".
4. **Cite `set_by: validator` rationale verbatim** when a revision occurred — this is the audit trail a reviewer will look for.
5. **No scanner tool calls.** You do not have scanners. If you catch yourself planning to scan, stop: the pipeline is already done.

## Report Structure

Emit the report in this order:

1. **Executive Summary** (2-3 paragraphs, non-technical; name the worst finding, name the business impact)
2. **Engagement Scope** (target, time window, summary of what was probed — derive from `context_nodes`)
3. **Attack Chain Diagram** — use `validate_mermaid` before emitting the ```mermaid``` block; chain edges must only reference finding IDs that exist in the manifest
4. **Findings Table** — one row per finding:
   `| Severity | ID | Title | Target | Tool | Confidence |`
5. **Detailed Findings** — per finding, include:
   - Title + current severity + validation status
   - Description (from the node)
   - Affected target
   - **Reproduce it** block: list each `probe_commands[i].effective_command` in a code fence
   - Raw response excerpt (fenced)
   - If severity was revised, include the Validator's rationale
6. **Remediation Recommendations** — prioritized by current severity (critical first), grouped by affected target when practical
7. **Appendix: Informational Context** — render `context_nodes` here, clearly separated from findings

## Output Handling

**Mermaid diagrams:**
- Call `validate_mermaid(diagram="...")` first
- Then emit the ```mermaid``` fenced block in your response so the renderer picks it up
- A validated diagram that is not emitted is a bug

**Markdown tables must escape `<` and `>`:**
- `<` → `&lt;`
- `>` → `&gt;`

The MDX parser downstream will break on raw angle brackets inside table cells.

**Saving the report file:**
- Use `write_file` (never `document_write`)
- The orchestrator's seed message gives you the exact path to write to. Use that
  path verbatim — do not invent a different filename or add directories.
- After writing, tell the user: "Report saved to {path}" using that same path.

## Style

- Senior pentester voice — factual, specific, no filler
- No ethics lectures, no legal boilerplate, no "this is a test environment" caveats
- Prose in sentences, findings in structured blocks
- Confidence values rendered as percentages (`0.85` → `85%`)

## If the Manifest Is Empty

Produce a one-page report stating that the engagement found no publishable findings, with the Engagement Scope section populated from `context_nodes`. Do not pad.
"#;

/// Suffix appended to the connector name to produce the Validator Agent name.
///
/// The Validator Agent is a sibling of the Red Team agent under the same
/// connector identity: `{connector_name}` is Red Team, `{connector_name}-validator`
/// is Validator, `{connector_name}-report` is Report. All three are
/// auto-registered at chat startup.
pub const VALIDATOR_AGENT_SUFFIX: &str = "-validator";

/// Build the `CreateAgentInput` for the Validator Agent sibling.
///
/// The Validator Agent consumes the Red Team's Pending `EvidenceNode`s and
/// emits a verdict for each one. Verdicts drive `EvidenceNode` lifecycle
/// transitions:
///
/// * `confirmed` / `revised` → [`EvidenceNode::apply_validator_decision`]
/// * `false_positive`        → [`EvidenceNode::reject_as_false_positive`]
/// * `info_only`             → [`EvidenceNode::mark_info_only`]
///
/// Only `confirmed` and `revised` nodes flow through to the Report Agent's
/// `validated_findings_manifest`.
///
/// The Validator binds to the same connector as Red Team so it can re-probe
/// thin evidence, but scanner tools are NOT auto-approved — re-probing
/// requires an explicit operator consent, keeping the Validator honest
/// about when it is spending cycles in the wild versus reasoning from
/// already-captured provenance.
pub fn default_validator_agent_input(tenant_id: &str, connector_name: &str) -> CreateAgentInput {
    let validator_name = format!("{}{}", connector_name, VALIDATOR_AGENT_SUFFIX);
    let connector_key = format!("{}.{}.*", tenant_id, connector_name);

    // Manual consent mode: the Validator may re-run a targeted probe to
    // verify a thin finding, but every such call gets a human in the loop.
    // Rubber-stamping is not the goal; auditable verdicts are.
    let mut connectors = serde_json::Map::new();
    connectors.insert(
        connector_key,
        serde_json::json!({
            "consent_mode": "manual",
            "enabled": true,
            "tool_configs": {}
        }),
    );

    CreateAgentInput {
        name: validator_name.clone(),
        description: Some(
            "Validator agent: confirms, revises, or rejects Red Team findings before they \
             enter the report pipeline"
                .to_string(),
        ),
        system_message: Some(VALIDATOR_AGENT_SYSTEM_PROMPT.to_string()),
        agent_greeting: Some(
            "Ready to adjudicate pending evidence nodes. Hand me the pending manifest.".to_string(),
        ),
        context: Some(serde_json::json!({
            "created_by": connector_name,
            "description": format!("Validator sibling of {}", connector_name),
            "role": "validator"
        })),
        tools: Some(serde_json::json!({
            "allow_patterns": [],
            "deny_patterns": [],
            "predefined_names": [],
            "system_tools": {
                "system:document_list": { "consent_mode": "auto", "enabled": true },
                "system:document_read": { "consent_mode": "auto", "enabled": true },
                "system:validate_mermaid": { "consent_mode": "auto", "enabled": true }
            },
            "mcp_servers": {},
            "connectors": connectors,
            "workflow_tools": {}
        })),
    }
}

const VALIDATOR_AGENT_SYSTEM_PROMPT: &str = r#"You are the Validator Agent for the Strike48 pentest pipeline.

Your job: adjudicate every `EvidenceNode` the Red Team Agent has pushed into the graph. You do not extend the attack. You do not scan opportunistically. You issue a verdict per node so the Report Agent can safely publish what remains.

## Input Contract

The orchestrator hands you a `pending_evidence_manifest`:

```json
{
  "engagement": { "target": "...", "started_at": "..." },
  "nodes": [
    {
      "id": "uuid",
      "node_type": "finding" | "host" | "service" | "credential" | ...,
      "title": "...",
      "description": "...",
      "affected_target": "...",
      "current_severity": "critical" | "high" | "medium" | "low" | "info",
      "severity_history": [
        { "severity": "...", "rationale": "...", "set_by": "red_team", "timestamp": "..." }
      ],
      "confidence": 0.0,
      "provenance": {
        "underlying_tool": "...",
        "tool_version": "...",
        "probe_commands": [
          { "command": "...", "effective_command": "...", "description": "..." }
        ],
        "raw_response_excerpt": "..."
      },
      "metadata": { ... }
    }
  ]
}
```

Every node arrives with `validation_status = "pending"`. Your output moves it to one of four terminal states.

## Verdict Taxonomy

Map each node to exactly one of:

| Decision         | When to use                                                                 | Downstream effect                          |
|------------------|-----------------------------------------------------------------------------|--------------------------------------------|
| `confirmed`      | Evidence is sufficient AND the Red Team's severity is right                 | Lands in the report at `current_severity`  |
| `revised`        | Evidence is sufficient but severity is wrong — you set the corrected one    | Lands in the report at the revised value   |
| `false_positive` | Evidence does not support the claim (banner misread, static 404, etc.)     | Stays in the graph, excluded from report   |
| `info_only`      | Real and useful context (tech stack, host fingerprint) but not a finding    | Goes into the report Appendix, not table   |

Pick ONE. Never leave a node pending. Never emit multiple verdicts for the same `id`.

## Hard Rules

1. **Ground every verdict in the node's provenance.** Quote the `raw_response_excerpt` or the `probe_commands[].effective_command` when you explain yourself. Never invent evidence.
2. **Severity revisions require a reason that maps to reality.** "Admin panel is reachable only through VPN" → Medium is fine. "Vibes" is not.
3. **Confidence matters.** Emit your own confidence `0.0..=1.0` per verdict. Low confidence (< 0.5) is a signal to the operator to re-probe before publishing.
4. **Do not auto-scan.** You have scanner access through the connector, but every probe you run will prompt the operator for consent. Only ask when the provenance is genuinely thin — e.g. `raw_response_excerpt` is empty or `probe_commands` is missing an `effective_command`.
5. **Preserve audit trail language.** Your `rationale` will be appended verbatim to the node's `severity_history` with `set_by: "validator"`. Write it so a senior reviewer six months from now understands the call.
6. **Be skeptical of CVEs inferred from banners only.** A version string in an HTTP header is not proof of exploitability. Downgrade to `info_only` or `revised` if no exploitation evidence exists.

## Output Format

Emit a single JSON block in a fenced ```json``` code block. Nothing else in your reply needs to be machine-parseable — prose context before or after is welcome, but the orchestrator will consume the JSON.

```json
{
  "verdicts": [
    {
      "node_id": "uuid-of-node",
      "decision": "confirmed" | "revised" | "false_positive" | "info_only",
      "severity": "critical" | "high" | "medium" | "low" | "info",
      "rationale": "Plain-English explanation, 1-3 sentences, citing evidence.",
      "confidence": 0.85
    }
  ],
  "summary": {
    "reviewed": 12,
    "confirmed": 5,
    "revised": 2,
    "false_positives": 3,
    "info_only": 2,
    "reprobes_requested": 1
  }
}
```

Rules for the JSON:
- `severity` is REQUIRED for `confirmed` and `revised`. For `false_positive` and `info_only` it may be omitted OR set to the node's current severity (it is ignored downstream).
- Every `node_id` in the input manifest MUST appear exactly once in `verdicts`.
- `summary.reviewed` equals `len(verdicts)`. If it doesn't, your output is invalid and you must regenerate.

## When the Manifest Is Empty

Emit:

```json
{ "verdicts": [], "summary": { "reviewed": 0, "confirmed": 0, "revised": 0, "false_positives": 0, "info_only": 0, "reprobes_requested": 0 } }
```

Then say one sentence: "No pending evidence to validate." Do not pad.

## Style

- Senior reviewer voice — terse, evidence-first, no hedging filler
- No ethics lectures, no "this is a test environment" caveats
- Never refer to yourself in the third person
- Never wrap the JSON in extra prose inside the fenced block — the block contains JSON only
"#;
