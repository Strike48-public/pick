# Validator Agent

## Purpose

Reviews raw pentest findings from the Red Team Agent for accuracy and severity assessment before inclusion in client reports.

## Capabilities

- **False Positive Detection** - Identifies findings that appear to be issues but aren't exploitable
- **Severity Adjustment** - Recalibrates severity ratings based on context and exploitability
- **Evidence Verification** - Validates that provenance supports the finding's claims
- **Rationale Logging** - Provides clear justification for validation decisions

## When Evidence Needs Validation

Evidence enters the pipeline in `Pending` status and requires validation before report generation:

- **Automatic:** Pick UI will notify when new findings need validation
- **Manual:** Use `validate_evidence <id>` command to validate specific findings
- **Batch:** Use `validate_all_pending` to process all pending evidence

## Commands

### validate_evidence \<evidence_id\>

Validate a single finding.

**Example:**
```
validate_evidence finding-abc123
```

**Output:**
- Decision: `Confirmed` | `FalsePositive` | `NeedsReview`
- Adjusted Severity (if different from original)
- Rationale explaining the decision

### validate_all_pending

Validate all evidence in `Pending` status.

**Example:**
```
validate_all_pending
```

**Progress:** Shows validation progress and summary of decisions.

### review_validation \<evidence_id\>

Review a previous validation decision.

**Example:**
```
review_validation finding-abc123
```

### override_validation \<evidence_id\> \<new_status\> \<reason\>

Override a Validator decision.

**Example:**
```
override_validation finding-abc123 Confirmed "Domain expert knowledge confirms this is exploitable"
```

## Decision Criteria

### Confirmed

Finding is accurate and exploitable. Will appear in report.

**Criteria:**
- Provenance commands support the finding
- Response excerpt confirms the vulnerability
- Severity matches exploitability
- No false positive indicators present

### FalsePositive

Finding appears to be an issue but isn't exploitable or accurate.

**Criteria:**
- Response indicates error or unavailability
- Port open but no service running
- Version detection incorrect
- Test environment not production exposure

**Examples:**
- Port scan shows 443/tcp open, but connection refused
- Banner says "Apache 2.4.50" but response shows 404 error page
- Private IP range found in response headers (expected in test env)

### NeedsReview

Validator uncertain - requires operator judgment.

**Criteria:**
- Incomplete provenance (missing commands or responses)
- Needs environment context
- Edge case not covered by validation rules
- Conflicting indicators

**Examples:**
- Finding: "Internal IP 192.168.1.5 in HTTP response"
- Rationale: "Cannot determine if this is test or production environment. Operator context needed."

## Validation Workflow

```
┌──────────────┐
│   Red Team   │  Discovers findings (Status: Pending)
│    Agent     │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│  Validator   │  Reviews findings
│    Agent     │  (Confirmed | FalsePositive | NeedsReview)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Orchestrator │  ✅ ALLOWS when all Confirmed or FalsePositive
│    Gate      │  ❌ BLOCKS if any Pending or NeedsReview
└──────┬───────┘
       │
       ▼
┌──────────────┐
│   Report     │  Generates client deliverable
│    Agent     │  (Only includes Confirmed findings)
└──────────────┘
```

**Key Points:**
- Report generation **fails** if any evidence is `Pending` or `NeedsReview`
- Only `Confirmed` findings appear in reports
- `FalsePositive` findings are excluded but logged for audit trail
- `NeedsReview` requires manual operator decision before proceeding

## Best Practices

1. **Validate as findings arrive** - Don't batch at end
2. **Review Validator decisions** - Spot-check for quality
3. **Override when you have context** - You know the environment better
4. **Document override rationale** - Helps future audits
5. **Watch for patterns** - If Validator consistently misses something, report it

## Troubleshooting

### Problem: Validator marks everything as NeedsReview

**Solution:** Provenance is likely incomplete. Ensure tools are producing full probe commands and response excerpts.

**Diagnostic Commands:**
```
# Check if evidence has provenance
review_evidence finding-abc123

# Look for missing fields:
- provenance.probe_commands (should have at least 1 command)
- provenance.raw_response_excerpt (should have response data)
```

---

### Problem: Can't generate report - "Evidence pending validation"

**Solution:** Run `validate_all_pending` or manually review each pending finding.

**Steps:**
1. List pending evidence: `list_pending_evidence`
2. Validate all at once: `validate_all_pending`
3. OR validate individually: `validate_evidence <id>`

---

### Problem: Validator confirmed a false positive

**Solution:** Override with `override_validation <id> FalsePositive "<reason>"` and consider improving validation rules.

**Example:**
```
# Override incorrect validation
override_validation finding-abc123 FalsePositive "Response shows 'Service Unavailable' not actual vulnerability"

# Document for future improvement
report_validation_issue finding-abc123 "Validator should detect 503 responses as FalsePositive"
```

## Implementation Notes

### Current Status (PR #61)

- ✅ Evidence graph with Pending status
- ✅ Provenance tracking (commands + responses)
- ✅ Orchestrator gate enforcement
- 🚧 Validator Agent implementation (planned)
- 🚧 UI validation dashboard (planned)
- 🚧 Override workflow (planned)

### Future Enhancements

- **Auto-validation rules** - Common patterns (e.g., connection refused = FalsePositive)
- **ML-based validation** - Learn from operator overrides
- **Batch validation UI** - Review multiple findings at once
- **Validation metrics** - Track false positive rate, override frequency

## Related Documentation

- [VALIDATION_GUIDE.md](../../docs/VALIDATION_GUIDE.md) - Operator validation workflow
- [MANUAL_TEST_THREE_AGENT_PIPELINE.md](../../MANUAL_TEST_THREE_AGENT_PIPELINE.md) - Testing the pipeline
- [evidence.rs](../../crates/core/src/evidence.rs) - Evidence node types
- [orchestrator.rs](../../crates/core/src/orchestrator.rs) - Gate enforcement logic
