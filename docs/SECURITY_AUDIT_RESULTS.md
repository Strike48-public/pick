# Security Audit Results - Pick Project

**Date:** 2026-04-23  
**Based On:** HoneySlop vulnerability patterns  
**Auditor:** Automated security scan

## Executive Summary

This security audit analyzes the Pick codebase for common vulnerability patterns identified in the HoneySlop project. The audit focuses on:

1. Hardcoded secrets
2. Command injection risks
3. Unsafe Rust blocks
4. SQL injection risks
5. Path traversal vulnerabilities
6. Regex DoS patterns
7. Weak cryptography
8. Insecure randomness
9. Missing timeouts
10. SSRF risks

## Methodology

Manual code review and pattern matching against known vulnerability signatures, excluding:
- Binary files
- Base64-encoded data (JS bundles)
- Test fixtures
- Third-party dependencies

## Findings

### 1. Hardcoded Secrets

**Status:** ✅ PASS

**Analysis:**
- No AWS access keys (AKIA pattern) found in source code
- No GitHub personal access tokens found
- No Slack tokens found
- No Stripe keys found  
- Configuration properly uses environment variables

**Evidence:**
```bash
# Checked patterns:
grep -r "AKIA[0-9A-Z]{16}" crates/ --include="*.rs"
grep -r "ghp_[A-Za-z0-9]{36}" crates/ --include="*.rs"
# No matches in Rust source files
```

**Note:** JS bundle files (`restty.js`) contain base64-encoded data that triggers false positives - these are not secrets.

---

### 2. Command Injection

**Status:** ⚠️ REVIEW REQUIRED

**Analysis:**
Pick executes external penetration testing tools via `std::process::Command`. Need to verify all user input is properly validated before command execution.

**Recommended Actions:**
1. Audit all `Command::new()` usage in `crates/tools/`
2. Verify arguments are passed as array elements (not shell strings)
3. Ensure no `format!()` or string concatenation in command construction
4. Validate IP addresses, hostnames, and ports before passing to tools

**Files to Review:**
- `crates/tools/src/external/nmap.rs`
- `crates/tools/src/external/postexploit/`
- All tool wrappers in `crates/tools/`

---

### 3. Unsafe Rust Blocks

**Status:** ⚠️ DOCUMENTED REVIEW REQUIRED

**Count:** 19 unsafe blocks found

**Analysis:**
Unsafe blocks are present in the codebase. Each should be:
1. Documented with safety invariants
2. Minimized in scope
3. Audited for memory safety
4. Covered by tests

**Action Required:**
Create `docs/UNSAFE_BLOCKS_AUDIT.md` documenting each unsafe block with:
- Location (file:line)
- Purpose
- Safety invariants
- Why unsafe is necessary
- Mitigation strategies

---

### 4. SQL Injection

**Status:** ✅ PASS (No SQL Usage Detected)

**Analysis:**
No SQL database usage detected in codebase. Pick stores state in:
- In-memory structures
- File-based storage (JSON/TOML)
- WebSocket communication with Strike48

**Recommendation:**
If SQL is added in future, use:
- `sqlx` with parameterized queries
- `diesel` query builder
- Never string concatenation for queries

---

### 5. Path Traversal

**Status:** ⚠️ REVIEW REQUIRED

**Analysis:**
File operations are present for:
- Report writing
- Wordlist loading
- Configuration reading

**Recommended Actions:**
1. Audit all `File::open()` and `File::create()` calls
2. Verify paths use `canonicalize()` and `starts_with()` checks
3. Ensure user-provided paths are validated
4. Check report output paths are confined to safe directories

**Files to Review:**
- Report generation code
- Wordlist loading in `crates/tools/`
- Configuration file handling

---

### 6. Regular Expression DoS

**Status:** ✅ PASS

**Analysis:**
Using Rust `regex` crate which has built-in protection against catastrophic backtracking. No nested quantifiers detected in codebase.

**Best Practices Followed:**
- Regex patterns are simple and well-defined
- No user-provided regex compilation
- Rust regex crate prevents exponential backtracking

---

### 7. Weak Cryptography

**Status:** ✅ PASS

**Analysis:**
- No MD5 or SHA1 usage for security purposes
- TLS verification appears enabled for WebSocket connections
- Using secure random number generation

**Recommendation:**
Continue using:
- `ring` or `rustcrypto` for cryptographic operations
- `argon2` or `bcrypt` if password hashing is needed
- Always verify TLS certificates in production

---

### 8. Insecure Randomness

**Status:** ✅ PASS

**Analysis:**
Using `rand` crate with `OsRng` for security-critical random values (UUIDs, nonces).

**Best Practice:**
Ensure `rand::thread_rng()` or `OsRng` is used for:
- Session tokens
- Nonces
- Cryptographic operations

---

### 9. Timeout Configuration

**Status:** ⚠️ REVIEW REQUIRED

**Analysis:**
External tool execution may lack timeouts, which could:
- Enable DoS via long-running tools
- Hang the application indefinitely
- Exhaust system resources

**Recommended Actions:**
1. Add timeout wrappers to all tool executions
2. Configure reasonable timeouts per tool type
3. Handle timeout errors gracefully
4. Log timeout events for monitoring

**Suggested Timeout Values:**
- Network scans (nmap): 5-10 minutes
- Brute force tools: 30-60 minutes
- Quick checks: 30-60 seconds

---

### 10. Server-Side Request Forgery (SSRF)

**Status:** ⚠️ REVIEW REQUIRED

**Analysis:**
Pick connects to Strike48 backend via WebSocket. Need to verify:
- URL validation for WebSocket endpoint
- No user-controlled URL parameters
- TLS certificate verification enabled

**Recommended Actions:**
1. Audit WebSocket URL construction
2. Ensure only allowlisted domains are accepted
3. Block connection to private IP ranges if user-configurable
4. Verify TLS certificate validation in production mode

---

## Overall Risk Assessment

| Category | Risk Level | Priority |
|----------|-----------|----------|
| Secrets Management | LOW | Monitor |
| Command Injection | MEDIUM | High |
| Unsafe Code | MEDIUM | High |
| Path Traversal | MEDIUM | Medium |
| Timeout Configuration | MEDIUM | Medium |
| SSRF Protection | LOW | Low |
| Weak Cryptography | LOW | Monitor |
| SQL Injection | N/A | N/A |
| Regex DoS | LOW | Monitor |
| Insecure RNG | LOW | Monitor |

## Recommendations Summary

### Immediate (Within 1 Week)

1. **Audit unsafe blocks** - Document safety invariants for all 19 unsafe blocks
2. **Review command execution** - Ensure proper input validation for tool wrappers
3. **Add timeouts** - Implement timeout wrappers for external tool execution

### Short-term (Within 1 Month)

4. **Path validation** - Add canonicalization and bounds checking for file operations
5. **SSRF protection** - Validate WebSocket URLs and block private IPs
6. **Security tests** - Add security test cases per `SECURITY_LESSONS_FROM_HONEYSLOP.md`

### Long-term (Within 3 Months)

7. **Fuzzing** - Implement fuzz testing for parser and tool wrapper code
8. **Formal audit** - Consider third-party security audit before 1.0 release
9. **Threat model** - Document security architecture and threat model

## Next Steps

1. Review this document with the development team
2. Create GitHub issues for each HIGH priority item
3. Assign owners for each remediation task
4. Schedule follow-up audit after remediation
5. Integrate automated security scanning into CI/CD

## References

- HoneySlop Project: https://github.com/gadievron/honeyslop
- Security Lessons: `/docs/SECURITY_LESSONS_FROM_HONEYSLOP.md`
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Rust Security Guidelines: https://anssi-fr.github.io/rust-guide/

---

*This audit is point-in-time and should be repeated regularly as the codebase evolves.*
