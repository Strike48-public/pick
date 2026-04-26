# Scope Enforcement & Provenance Test Plan

## Your Networks
- **In Scope**: `10.0.4.0/24` and `10.0.8.0/24`
- **Out of Scope**: Gateways `10.0.4.1` and `10.0.8.1`, SSH/RDP ports

## Test Scenarios

### Scenario 1: ✅ ALLOWED - In-Scope Target
**Target**: `10.0.4.100` (any host in 10.0.4.0/24 except .1)

**Test with nuclei**:
```bash
# Through Strike48 UI, run:
nuclei --target http://10.0.4.100

# Expected result:
✅ Scope check passes
✅ Scan executes normally
✅ Report includes provenance:
   - underlying_tool: { "type": "external", "name": "nuclei", "version": "..." }
   - probe_commands: [{ "command": "nuclei -u http://10.0.4.100 ...", "effective_command": "nuclei -u http://10.0.4.100 ..." }]
   - raw_response_excerpt: First 4KB of nuclei JSON output
   - timestamp: UTC completion time
```

**Test with web_vuln_scan**:
```bash
# Through Strike48 UI, run:
web_vuln_scan --url http://10.0.4.100

# Expected result:
✅ Scope check passes
✅ Scan executes normally
✅ Report includes provenance:
   - underlying_tool: { "type": "custom_s48", "detector": "web-vuln-scan", "version": "0.1.0" }
   - probe_commands: [{ "command": "web_vuln_scan --url http://10.0.4.100", ... }]
```

---

### Scenario 2: ❌ BLOCKED - Gateway (Out of Scope via Deny List)
**Target**: `10.0.4.1` (your gateway/router)

**Test with nuclei**:
```bash
nuclei --target http://10.0.4.1

# Expected result:
❌ BLOCKED with error:
"Target 10.0.4.1 is out of scope: Target matches out-of-scope rule: Router/gateway - DO NOT SCAN (10.0.4.1/32)"

❌ Scan does NOT execute
❌ No findings generated
✅ Logged with reason
```

**Test with web_vuln_scan**:
```bash
web_vuln_scan --url http://10.0.4.1

# Expected result:
❌ BLOCKED - same error message
```

---

### Scenario 3: ❌ BLOCKED - Out of Scope Network
**Target**: `192.168.1.100` (not in your 10.0.4.0/24 or 10.0.8.0/24 networks)

**Test**:
```bash
nuclei --target http://192.168.1.100

# Expected result:
❌ BLOCKED with error:
"Target 192.168.1.100 is out of scope: Target does not match any in-scope rules (deny by default)"
```

---

### Scenario 4: ❌ BLOCKED - Production Domain
**Target**: `api.production.com`

**Test**:
```bash
web_vuln_scan --url https://api.production.com

# Expected result:
❌ BLOCKED with error:
"Target api.production.com is out of scope: Target matches out-of-scope rule: Production systems - FORBIDDEN (*.production.com)"
```

---

### Scenario 5: ✅ ALLOWED - Local Domain
**Target**: `test.local`

**Test**:
```bash
web_vuln_scan --url http://test.local

# Expected result:
✅ Allowed (matches in-scope wildcard *.local)
```

---

### Scenario 6: ❌ BLOCKED - High Risk Port (SSH)
**Target**: `10.0.4.100:22`

**Test**:
```bash
# If you have a tool that can target specific ports
nmap --target 10.0.4.100 --port 22

# Expected result:
❌ BLOCKED with error:
"Target 10.0.4.100:22 is out of scope: Target matches out-of-scope rule: SSH and RDP - high risk services (ports: [22, 3389])"
```

---

## Provenance Verification Checklist

For each ALLOWED scan, verify the report includes:

### ✅ Provenance Structure
```json
{
  "provenance": {
    "underlying_tool": {
      "type": "external" | "custom_s48",
      "name": "nuclei" | "detector": "web-vuln-scan",
      "version": "..."
    },
    "probe_commands": [
      {
        "command": "full command with potential credentials",
        "effective_command": "sanitized command (credentials redacted)",
        "description": "Human-readable description"
      }
    ],
    "raw_response_excerpt": "First 4KB of tool output...",
    "timestamp": "2026-04-22T14:45:00.123456Z"
  }
}
```

### ✅ Sanitization Test

If you run a command with credentials (e.g., Bearer token), verify sanitization:

**Command**:
```bash
# Hypothetical - if nuclei supported auth headers
nuclei --target http://10.0.4.100 --header "Authorization: Bearer sk-abc123secret456"
```

**Expected in provenance**:
```json
{
  "probe_commands": [
    {
      "command": "nuclei ... --header \"Authorization: Bearer sk-abc123secret456\"",
      "effective_command": "nuclei ... --header \"Authorization: <REDACTED>\""
    }
  ]
}
```

---

## Where to Load Scope Config

Pick will auto-detect scope config in this order:
1. Session-specific: `<workspace>/<session-id>/scope.toml`
2. **Project-level**: `.pick/scope.toml` ← We created this
3. Fallback: Permissive (allows all, logs warning)

Since we created `.pick/scope.toml`, Pick will load it automatically when tools execute.

---

## How to Test via Strike48 UI

1. **Go to**: `https://studio.strike48.test/`
2. **Approve connector**: Look for `pick-test-001` waiting for approval
3. **Open tool execution panel**
4. **Run commands** as shown in scenarios above
5. **Check results**:
   - Blocked scans show error immediately
   - Allowed scans execute and generate reports with provenance

---

## Monitoring During Tests

**Watch logs in real-time**:
```bash
tail -f /home/jtomek/tmp/pentest.log | grep -E "scope|verify|BLOCKED|provenance"
```

**Key log messages to look for**:
- `"Verifying target X against scope"`
- `"Target X is in scope: <reason>"`
- `"Target X is out of scope: <reason>"`
- `"No scope configuration set - allowing all targets"` (shouldn't see this now)

---

## Expected Outcomes Summary

| Scenario | Target | Result | Reason |
|----------|--------|--------|--------|
| 1 | 10.0.4.100 | ✅ ALLOWED | Matches 10.0.4.0/24 |
| 2 | 10.0.4.1 | ❌ BLOCKED | Out-of-scope: gateway |
| 3 | 192.168.1.100 | ❌ BLOCKED | Not in any in-scope rule |
| 4 | api.production.com | ❌ BLOCKED | Matches *.production.com deny list |
| 5 | test.local | ✅ ALLOWED | Matches *.local wildcard |
| 6 | 10.0.4.100:22 | ❌ BLOCKED | Port 22 in deny list |

---

## Quick Test Commands

Copy-paste these into Strike48 UI:

```bash
# ✅ Should work
nuclei --target http://10.0.4.100
web_vuln_scan --url http://10.0.8.50

# ❌ Should block
nuclei --target http://10.0.4.1
web_vuln_scan --url https://api.production.com
nuclei --target http://192.168.1.100
```

---

## Notes

- **Scope config location**: `/home/jtomek/Code/pick/.pick/scope.toml`
- **Logs**: `/home/jtomek/tmp/pentest.log`
- **Pick process**: Running in background (check with `ps aux | grep pentest`)
- **Permissive mode**: If scope config fails to load, Pick logs warning but allows all (fail-open for dev)
