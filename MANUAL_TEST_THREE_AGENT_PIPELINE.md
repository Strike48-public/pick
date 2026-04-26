# Manual Testing Guide: Three-Agent Pipeline (PR #61)

## Overview

This guide provides step-by-step instructions for manually testing the complete three-agent penetration testing pipeline: **Red Team → Validator → Report**.

## Prerequisites

```bash
# 1. Check out the PR branch
git fetch fork feature/three-agent-pipeline
git checkout feature/three-agent-pipeline

# 2. Build
cargo build

# 3. Verify environment
cat .env | grep -E "STRIKE48_HOST|TENANT_ID"
```

## Quick Smoke Test (5 minutes)

### Step 1: Inject Test Evidence

```bash
# Start the connector
./run-pentest.sh headless dev

# In the chat, run:
inject_test_evidence count=5 severity=mixed target=192.168.1.100
```

**Expected Output:**
```json
{
  "success": true,
  "evidence_created": 5,
  "nodes": [
    {"id": "...", "type": "open_port", "title": "Port 22/tcp open on 192.168.1.100", "severity": "Critical"},
    {"id": "...", "type": "service_banner", "title": "Service banner on 192.168.1.100:80", "severity": "High"},
    {"id": "...", "type": "web_tech", "title": "Web technologies identified on http://192.168.1.100", "severity": "Medium"},
    {"id": "...", "type": "default_cred", "title": "Default credentials on 192.168.1.100", "severity": "Low"},
    {"id": "...", "type": "open_port", "title": "Port 22/tcp open on 192.168.1.100", "severity": "Info"}
  ],
  "message": "Created 5 test evidence nodes. Use Validator Agent to adjudicate, then Generate Report."
}
```

### Step 2: Try to Generate Report (Should Fail)

1. Click the **"Generate Report"** button (FileText icon in chat header)
2. Observe error message

**Expected:** Gate error appears: *"Cannot generate report while 5 evidence nodes are still Pending"*

**Why:** Orchestrator blocks report generation when evidence is un-adjudicated

### Step 3: Validate Evidence

**How to access Validator Agent:**
1. Look for the agent selector/switcher in the UI (typically in chat panel header or sidebar)
2. Switch to the **Validator Agent** conversation (should be auto-registered as a sibling)
3. If you don't see it listed, check that the agent auto-registration completed on startup

**In the Validator Agent conversation, send this message:**

```
Please review all pending evidence nodes and validate them:
- Mark real findings as Confirmed or Revised
- Mark false positives as FalsePositive
- Mark informational items as InfoOnly
```

**Expected:** Validator responds with validation decisions for each node

**Note:** The Validator Agent needs to be able to:
- See the current evidence graph
- Call functions to update validation status
- Update severity if revising a finding

If the Validator doesn't have access to evidence or update functions, file this as a bug.

### Step 4: Generate Report (Should Succeed)

1. Return to main chat
2. Click **"Generate Report"** button again
3. Observe Report Agent conversation spawned

**Expected:**
- Report Agent receives seeded conversation
- JSON manifest contains:
  - `validated_findings` array with Confirmed/Revised evidence
  - `provenance` blocks with redacted commands
  - `info_only_count` and `false_positive_count` summaries
- FalsePositive nodes excluded from findings list

### Step 5: Verify Provenance Redaction

Inspect the JSON manifest in the Report Agent conversation. Check that:

✅ No secrets visible in `effective_command` fields
✅ Commands are properly redacted
✅ Response excerpts are truncated to ~2KB

---

## Comprehensive Testing (30+ minutes)

### Test Suite 1: Real Tool Evidence

**Goal:** Verify evidence production from actual scanning tools

#### 1A: Nmap Scan

```bash
# Run nmap against a test target (use a safe lab environment)
nmap target=192.168.1.1 scan_type=connect ports=22,80,443 service_detection=true
```

**Verify:**
- Evidence nodes created for each open port
- Node type: `open_port`
- Severity assigned based on port sensitivity
- Provenance includes nmap command and XML output excerpt
- Metadata contains port, protocol, service, version

#### 1B: Service Banner Grab

```bash
service_banner host=192.168.1.1 port=22
```

**Verify:**
- Evidence node created if banner retrieved
- Node type: `service_banner`
- Severity based on version information
- Banner text in metadata

#### 1C: WhatWeb Scan

```bash
whatweb url=http://192.168.1.1
```

**Verify:**
- Evidence node created if technologies detected
- Node type: `web_tech`
- Technologies listed in metadata
- Severity based on version info

### Test Suite 2: Validation Lifecycle

**Goal:** Verify evidence moves through validation states correctly

#### 2A: Confirm a Finding

1. Inject test evidence: `inject_test_evidence count=1 severity=high`
2. Use Validator to mark as **Confirmed**
3. Generate report

**Verify:**
- Finding appears in Report Agent manifest
- Severity matches original assessment
- `validation_status`: `"confirmed"`

#### 2B: Revise Severity

1. Inject test evidence: `inject_test_evidence count=1 severity=critical`
2. Use Validator to downgrade to **Medium** (Revised state)
3. Generate report

**Verify:**
- Finding appears in Report Agent manifest
- Severity shows **Medium** (validator's call)
- `severity_history` shows both Critical and Medium entries
- `validation_status`: `"revised"`

#### 2C: Mark as False Positive

1. Inject test evidence: `inject_test_evidence count=2`
2. Mark first as Confirmed, second as FalsePositive
3. Generate report

**Verify:**
- Only Confirmed finding in `validated_findings`
- FalsePositive NOT in findings list
- `false_positive_count`: 1 in summary

#### 2D: Info-Only Evidence

1. Inject test evidence: `inject_test_evidence count=1 severity=info`
2. Mark as **InfoOnly**
3. Generate report

**Verify:**
- Not in `validated_findings` array
- `info_only_count`: 1 in summary

### Test Suite 3: Provenance Redaction

**Goal:** Verify secrets are stripped from provenance

#### 3A: Test Redaction Patterns

Create test evidence with various sensitive patterns:

```bash
# Inject evidence with sensitive command
inject_test_evidence count=1
```

Then manually inspect the provenance blocks in the Report Agent manifest for these redaction patterns:

| Pattern | Input | Expected Redacted Output |
|---------|-------|-------------------------|
| Authorization header | `Authorization: Bearer abc123` | `Authorization: [REDACTED]` |
| URL userinfo | `http://user:pass@example.com` | `http://[REDACTED]@example.com` |
| Password flag | `--password hunter2` | `--password [REDACTED]` |
| API key flag | `--api-key=secret123` | `--api-key=[REDACTED]` |
| Long tokens | `ghp_1234567890abcdef...` | `[REDACTED_TOKEN]` |
| Env secrets | `API_KEY=secret` | `API_KEY=[REDACTED]` |

**Note:** The current implementation covers main patterns. See developer review for bypass cases to address in follow-up.

### Test Suite 4: Gate Enforcement

**Goal:** Verify orchestrator prevents invalid states

#### 4A: Block Mixed Validation States

1. Inject 3 evidence nodes
2. Validate only 2 (leave 1 Pending)
3. Try to generate report

**Expected:** Gate blocks with error: *"Cannot generate report while 1 evidence nodes are still Pending"*

#### 4B: Empty Graph

1. Clear evidence (restart connector or wait for next session)
2. Generate report immediately

**Expected:** 
- Gate allows (empty graph = no pending nodes)
- Report shows: *"No publishable findings"*

#### 4C: All False Positives

1. Inject 3 evidence nodes
2. Mark all as FalsePositive
3. Generate report

**Expected:**
- Report shows: *"No publishable findings"*
- `false_positive_count`: 3
- Empty `validated_findings` array

### Test Suite 5: Agent Registration

**Goal:** Verify Validator and Report agents auto-register

#### 5A: Check Agent List

1. Open chat panel
2. Look for registered agents

**Expected:**
- Validator Agent present
- Report Agent present
- Both have `consent_mode: "manual"` (no auto-execution)

#### 5B: Verify Consent Mode

1. Ask Validator Agent to run a tool
2. Observe behavior

**Expected:**
- Tool execution requires manual approval
- No automatic execution (safety feature)

### Test Suite 6: Parallel Report Generation

**Goal:** Test concurrent report requests

#### 6A: Rapid Double-Click

1. Inject and validate 2 evidence nodes
2. Click "Generate Report" twice rapidly

**Current Behavior:** Two report conversations spawn (no debouncing yet - see developer review)

**Expected After Fix:** Only one report conversation

---

## Test Evidence Reference

### inject_test_evidence Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `count` | Integer | 3 | Number of evidence nodes to create |
| `severity` | String | "mixed" | Severity: `critical`, `high`, `medium`, `low`, `info`, or `mixed` |
| `target` | String | "192.168.1.100" | Target IP/hostname |

### Example Commands

```bash
# Create 5 mixed-severity findings
inject_test_evidence count=5 severity=mixed

# Create 3 high-severity findings
inject_test_evidence count=3 severity=high target=10.0.0.1

# Create single critical finding
inject_test_evidence count=1 severity=critical
```

---

## Validation Checklist

Use this checklist during manual testing:

### Evidence Production
- [ ] nmap creates evidence nodes for open ports
- [ ] service_banner creates evidence for banners
- [ ] whatweb creates evidence for tech stack
- [ ] inject_test_evidence creates specified count
- [ ] Evidence includes provenance metadata

### Validation Lifecycle
- [ ] All evidence starts in Pending state
- [ ] Validator can mark as Confirmed
- [ ] Validator can mark as Revised (with new severity)
- [ ] Validator can mark as FalsePositive
- [ ] Validator can mark as InfoOnly
- [ ] Severity history maintains audit trail

### Gate Enforcement
- [ ] Gate blocks report when evidence is Pending
- [ ] Gate allows report when all validated
- [ ] Gate allows report on empty graph
- [ ] FalsePositive nodes excluded from report
- [ ] InfoOnly nodes excluded from findings

### Report Generation
- [ ] Report Agent spawns new conversation
- [ ] Manifest contains validated findings
- [ ] Manifest excludes FalsePositive nodes
- [ ] Counts accurate (info_only, false_positive)
- [ ] Provenance included for each finding

### Provenance Redaction
- [ ] No Authorization headers visible
- [ ] No URL credentials visible
- [ ] No password flags visible
- [ ] No API keys visible
- [ ] Long tokens redacted

### Agent Registration
- [ ] Validator Agent auto-registers
- [ ] Report Agent auto-registers
- [ ] Generate Report button appears
- [ ] Manual consent mode enforced

---

## Troubleshooting

### No Evidence Created

**Symptom:** Tools run but no evidence nodes appear

**Check:**
1. Look for `push_evidence` logs in console
2. Verify tools have `provenance` in result
3. Check if `ui-integration` feature is enabled

### Gate Always Passes

**Symptom:** Can generate report with Pending evidence

**Possible Causes:**
1. Evidence graph not being populated
2. Gate logic bypassed
3. Wrong validation status

**Debug:**
1. Check `EVIDENCE_GRAPH` contents
2. Verify `gate_for_report` is called
3. Check `validation_status` values

### Validator Not Responding

**Symptom:** Validator Agent doesn't mark evidence

**Check:**
1. Verify Validator Agent is registered
2. Check system prompt loaded
3. Verify evidence nodes accessible to agent

### Report Shows Empty Findings

**Symptom:** Report generated but no findings listed

**Possible Causes:**
1. All evidence marked as FalsePositive or InfoOnly
2. Evidence graph empty
3. Gate allowing empty manifest

**Debug:**
1. Check evidence graph contents before report
2. Verify `is_publishable_finding` logic
3. Check `validated_findings` filter in orchestrator

---

## Success Criteria

✅ **Pipeline is working correctly when:**

1. Tools produce evidence nodes automatically
2. Evidence starts in Pending state
3. Gate blocks report until all validated
4. Validator can transition evidence through states
5. Report generation succeeds after validation
6. Report contains only publishable findings
7. FalsePositive nodes excluded
8. Provenance redacts sensitive data
9. Severity from validator takes precedence
10. Audit trail preserved in severity_history

---

## Next Steps After Testing

If all tests pass:
1. Document any issues found
2. Test provenance redaction bypass cases (see developer review)
3. Add `write_file` tool to Report Agent
4. Implement debouncing for Generate Report button
5. Consider raising `RAW_RESPONSE_MAX_BYTES` to 8192
6. Sanitize all user-facing strings for prompt injection

---

## Developer Review Issues to Verify

From code review, these issues were identified:

### 🛑 BLOCKER (NOW FIXED)
- ✅ Producer wiring added (this PR)

### ⚠️ CONCERNS
- [ ] Report Agent needs `write_file` tool
- [ ] `RAW_RESPONSE_MAX_BYTES` too small (2048 → 8192?)
- [ ] Parallel Generate Report clicks not debounced
- [ ] User-facing strings not sanitized (prompt injection)

### Redaction Bypasses
- [ ] Short flags: `mysql -p hunter2`
- [ ] Aliases: `--pass`, `--pw`, `--apikey`
- [ ] Cookie flags: `curl --cookie` / `curl -b`
- [ ] GitHub/Slack tokens: `ghp_...`, `xoxb-...`
- [ ] JSON bodies: `{"token":"abc123"}`
- [ ] URL query: `?token=x&format=json` (eats `&format`)

Test these specific cases and file issues for any that fail.

---

*Last Updated: 2026-04-23*
*Branch: feature/three-agent-pipeline*
*Testing PR #61 with Producer Wiring Complete*
