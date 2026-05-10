# Evidence Validation Guide

## Overview

Pick uses a three-agent workflow to ensure high-quality pentest reports:

1. **Red Team Agent** - Discovers findings
2. **Validator Agent** - Verifies accuracy ← **You are here**
3. **Report Agent** - Generates deliverables

This guide explains how to validate findings before report generation.

---

## Why Validation Matters

**Problem:** Automated scanners produce false positives:
- Port appears "open" but isn't actually running a service
- Version detection misidentifies software
- Error pages reported as "web applications"
- Test environments reported as "production exposures"

**Solution:** The Validator Agent reviews each finding for accuracy before it reaches the client.

**Your role:** Review Validator decisions and override when you have domain-specific knowledge.

---

## Validation Workflow

### Step 1: Red Team Produces Findings

Red Team Agent runs scans and produces evidence nodes. Each finding is marked `Pending` until validated.

**Example findings:**
- "Port 22/tcp open on 192.168.1.100" (Severity: High)
- "Apache 2.4.50 detected on 192.168.1.100:80" (Severity: Medium)
- "SQL injection in /api/users endpoint" (Severity: Critical)

### Step 2: Validator Reviews Findings

Validator Agent automatically reviews each pending finding:

1. Checks provenance (commands executed, responses received)
2. Verifies response data supports the finding
3. Assesses severity appropriateness
4. Makes decision: Confirmed | FalsePositive | NeedsReview

**You'll be notified** when validation is complete.

### Step 3: You Review Validator Decisions

Open the Evidence Dashboard to see validation results:

- **Green checkmark** = Confirmed (will appear in report)
- **Red X** = FalsePositive (excluded from report)
- **Yellow warning** = NeedsReview (requires your judgment)

**Your job:** Spot-check Validator decisions and override if needed.

### Step 4: Generate Report

Once all findings are validated (no `Pending` or `NeedsReview` statuses), you can generate the report.

**Report contains:** Only `Confirmed` findings with full provenance.

---

## Validation Statuses Explained

### ✅ Confirmed

**Meaning:** Finding is accurate and exploitable.

**What happens:** Appears in final report with full details.

**Example:**
```
Finding: Port 22/tcp open on 192.168.1.100
Status: Confirmed
Severity: High
Rationale: Nmap response shows "OpenSSH 7.4" running on port 22.
          Service banner confirms SSH service is accessible.
          Severity High is appropriate for remote administration exposure.
```

### ❌ FalsePositive

**Meaning:** Finding looks like an issue but isn't exploitable.

**What happens:** Excluded from report, logged for audit trail.

**Example:**
```
Finding: Apache 2.4.50 vulnerable to CVE-2021-41773
Status: FalsePositive
Severity: N/A (excluded)
Rationale: Response shows "404 Not Found" - no vulnerable endpoint.
          Version detection is likely incorrect.
          No path traversal confirmed.
```

### ⚠️ NeedsReview

**Meaning:** Validator uncertain - requires your judgment.

**Why:** Incomplete provenance, needs context, or edge case.

**Example:**
```
Finding: Internal IP 192.168.1.5 in HTTP response
Status: NeedsReview
Rationale: Cannot determine if this is test or production environment.
          Operator context needed.
Action Required: Review and set status manually
```

**What to do:** Click "Review" and decide:
- Is this a real issue in this environment?
- Should it be included in the report?
- What severity is appropriate?

---

## How to Override Validator Decisions

If Validator got it wrong, you can override:

### Via UI (Recommended)

1. Open Evidence Dashboard
2. Find the finding you want to override
3. Click "Override" button
4. Select new status: Confirmed | FalsePositive | NeedsReview
5. Provide rationale: "Why is this the correct status?"
6. Click "Save Override"

**Your override will be logged** for audit trail.

### Via Command Line

```bash
# Override to Confirmed
override_validation finding-abc123 Confirmed "Domain expert confirms this is exploitable in production"

# Override to FalsePositive
override_validation finding-abc123 FalsePositive "Service is behind WAF - not directly exploitable"

# Set to NeedsReview (for later)
override_validation finding-abc123 NeedsReview "Awaiting client confirmation on environment classification"
```

---

## Common Validation Scenarios

### Scenario 1: Port Open but No Service

**Finding:** "Port 443/tcp open on 192.168.1.100"  
**Validator Decision:** Confirmed  
**Your Analysis:** Response shows "Connection refused" after initial handshake

**Action:**
```bash
override_validation finding-xyz Confirmed "Connection refused indicates misconfiguration not open service"
```

**Correct Status:** FalsePositive

---

### Scenario 2: Version Detection Incorrect

**Finding:** "Apache 2.4.50 CVE-2021-41773 vulnerable"  
**Validator Decision:** Confirmed  
**Your Analysis:** Server banner shows "Apache 2.4.51" (patched version)

**Action:**
```bash
override_validation finding-xyz FalsePositive "Version detection incorrect - banner shows 2.4.51 (patched)"
```

**Correct Status:** FalsePositive

---

### Scenario 3: Test vs Production Environment

**Finding:** "SQL injection in /api/test/users"  
**Validator Decision:** NeedsReview  
**Your Analysis:** `/api/test/` endpoints are test-only, not production

**Action:**
```bash
override_validation finding-xyz FalsePositive "Test environment endpoint - not reachable from production"
```

**Correct Status:** FalsePositive

---

### Scenario 4: Severity Too Low

**Finding:** "Default admin credentials admin:admin on management portal"  
**Validator Decision:** Confirmed, Severity: Medium  
**Your Analysis:** This is the production management portal with full system access

**Action:**
```bash
override_validation finding-xyz Confirmed "Severity should be Critical - production mgmt portal w/ full access" --severity Critical
```

**Correct Status:** Confirmed (Critical)

---

## Validation Best Practices

### 1. Validate as Findings Arrive

Don't wait until the end to validate all findings at once:

- **Good:** Validate each finding as it appears
- **Bad:** Wait until 100+ findings accumulated

**Why:** Easier to remember context, faster feedback loop.

### 2. Spot-Check Validator Decisions

You don't need to review every single finding:

- **Review all NeedsReview** (requires your decision)
- **Spot-check 10-20% of Confirmed** (validate quality)
- **Review Critical/High findings** (high impact)
- **Randomly sample Low/Info** (catch patterns)

**Goal:** Ensure Validator is working correctly, not duplicate all its work.

### 3. Document Override Rationale

Always provide clear rationale when overriding:

- **Bad:** "This is wrong"
- **Good:** "Response shows 503 Service Unavailable, not actual vulnerability"

**Why:** Helps future audits, improves Validator rules, trains team members.

### 4. Watch for Patterns

If you override the same type of finding repeatedly:

- Document the pattern
- Report it to development team
- Request Validator rule improvement

**Example:** "Validator always confirms WAF errors as findings - should detect 403 Forbidden with WAF signature"

### 5. Use Environment Context

You know the target environment better than Validator:

- Internal vs external network
- Test vs production systems
- Business criticality
- Compensating controls (WAF, IDS, etc.)

**Your context improves validation quality.**

---

## Troubleshooting

### Can't Generate Report - "Evidence Pending Validation"

**Problem:** Report generation fails with message "Cannot generate report: 3 findings pending validation"

**Solution:**
1. Open Evidence Dashboard
2. Filter by status: Pending
3. Run `validate_all_pending`
4. Review any NeedsReview results
5. Try generating report again

---

### Validator Marks Everything as NeedsReview

**Problem:** Validator can't make decisions - everything requires manual review

**Causes:**
- Incomplete provenance (missing commands or responses)
- Tools not providing response excerpts
- Response truncation too aggressive

**Solution:**
1. Check a NeedsReview finding: `review_evidence finding-abc123`
2. Look for missing data:
   - Are probe commands present?
   - Is raw_response_excerpt populated?
   - Is response truncated too early?
3. Fix tool integration if data is missing
4. Adjust `RAW_RESPONSE_MAX_BYTES` if truncation is too aggressive

---

### Validator Confirmed a False Positive

**Problem:** Validator marked a non-issue as Confirmed

**Immediate Solution:**
```bash
override_validation finding-abc123 FalsePositive "Response shows error page not vulnerability"
```

**Long-term Solution:**
1. Document the false positive pattern
2. Report to development team
3. Request validation rule improvement
4. Share with team in weekly review

---

## Validation Metrics

Track these metrics to improve validation quality:

| Metric | Target | Why It Matters |
|--------|--------|----------------|
| False Positive Rate | < 5% | Client trust, report quality |
| NeedsReview Rate | < 10% | Operator efficiency |
| Override Rate | < 15% | Validator accuracy |
| Validation Time | < 30 sec/finding | Operator productivity |

**Review metrics weekly** to identify improvement opportunities.

---

## FAQ

### Do I need to validate every single finding?

**No.** Validator Agent handles bulk validation. You only need to:
- Review NeedsReview findings (Validator uncertain)
- Spot-check Confirmed findings (quality assurance)
- Override incorrect decisions (domain knowledge)

### What if I'm unsure about a finding?

Set it to `NeedsReview` with detailed notes:
```bash
override_validation finding-abc123 NeedsReview "Need client clarification on whether 192.168.1.5 is test or prod"
```

Then follow up with client or team lead.

### Can I skip validation and generate the report?

**No.** Report generation is **blocked** by the Orchestrator Gate if any findings are:
- Pending (not yet validated)
- NeedsReview (requires decision)

This ensures only accurate findings reach the client.

### What happens to FalsePositive findings?

- **Not included in report** (client doesn't see them)
- **Logged for audit trail** (you can review them later)
- **Used to improve Validator** (patterns identified)

### How do I revert an override?

Review the finding again and set it back to original status:
```bash
# Validator said Confirmed, you overrode to FalsePositive, now reverting
override_validation finding-abc123 Confirmed "After re-review, original decision was correct"
```

---

## Related Documentation

- [Validator Agent README](../agents/validator/README.md) - Validator capabilities and commands
- [MANUAL_TEST_THREE_AGENT_PIPELINE.md](../MANUAL_TEST_THREE_AGENT_PIPELINE.md) - Testing the pipeline
- [evidence.rs](../crates/core/src/evidence.rs) - Evidence node implementation
- [orchestrator.rs](../crates/core/src/orchestrator.rs) - Gate enforcement logic

---

## Support

Questions about validation workflow?

1. Check [Validator Agent README](../agents/validator/README.md)
2. Review [MANUAL_TEST_THREE_AGENT_PIPELINE.md](../MANUAL_TEST_THREE_AGENT_PIPELINE.md)
3. Ask in #pick-support Slack channel
4. File issue: https://github.com/Strike48-public/pick/issues
