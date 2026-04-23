# Security Audit Tracking

**Branch:** `feature/security-audit-and-hardening`  
**Created:** 2026-04-23  
**Status:** In Progress

## Overview

This document tracks the security audit and hardening work for the Pick project based on lessons learned from the HoneySlop vulnerability canary project.

## Documentation Completed

- [x] `docs/SECURITY_LESSONS_FROM_HONEYSLOP.md` - Comprehensive vulnerability guide
- [x] `docs/SECURITY_AUDIT_RESULTS.md` - Initial security assessment
- [x] `scripts/security-audit.sh` - Automated security scanning
- [x] `scripts/security-audit-simple.sh` - Simplified audit script

## High Priority Tasks (Week 1)

### 1. Audit Unsafe Blocks
**Priority:** HIGH  
**Effort:** 4-6 hours  
**Status:** Not Started

**Description:**
Document safety invariants for all 19 unsafe blocks found in the codebase.

**Tasks:**
- [ ] Create `docs/UNSAFE_BLOCKS_AUDIT.md`
- [ ] Find all unsafe blocks: `rg "unsafe " crates/ -n`
- [ ] For each unsafe block, document:
  - Location (file:line)
  - Purpose (why unsafe is needed)
  - Safety invariants (what makes it safe)
  - Alternative considered
  - Test coverage
- [ ] Add inline safety comments to each unsafe block
- [ ] Create tracking issue for removing/minimizing unsafe usage

**Files to Audit:**
```bash
# Find all unsafe blocks
cd ~/Code/pick
rg "unsafe " crates/ -n > unsafe-blocks-list.txt
```

**Documentation Template:**
```markdown
## Unsafe Block: crates/example/src/lib.rs:42

**Purpose:** FFI call to external C library for performance

**Safety Invariants:**
1. Input pointer is non-null (checked on line 40)
2. Buffer size is validated (checked on line 41)
3. No concurrent access (mutex held on line 38)

**Why Unsafe:**
FFI boundary requires unsafe block for C library call

**Alternatives Considered:**
- Safe Rust implementation: 10x slower in benchmarks
- External process: Too much overhead

**Mitigation:**
- Comprehensive unit tests covering edge cases
- Fuzz testing of input validation
- Clear documentation of preconditions

**Test Coverage:** 95% (see tests/ffi_tests.rs)
```

---

### 2. Review Command Execution
**Priority:** HIGH  
**Effort:** 6-8 hours  
**Status:** Not Started

**Description:**
Audit all tool wrappers to ensure proper input validation and prevent command injection.

**Tasks:**
- [ ] Audit `crates/tools/src/external/nmap.rs`
- [ ] Audit `crates/tools/src/external/postexploit/`
- [ ] Audit all tool wrappers in `crates/tools/src/`
- [ ] Create input validation utility module
- [ ] Add IP address validation helper
- [ ] Add hostname validation helper
- [ ] Add port validation helper
- [ ] Ensure all `Command::new()` uses array arguments
- [ ] Add security tests for command injection

**Validation Functions Needed:**
```rust
// crates/core/src/validation.rs

/// Validates IPv4 address format
pub fn validate_ipv4(ip: &str) -> Result<Ipv4Addr>;

/// Validates IPv6 address format  
pub fn validate_ipv6(ip: &str) -> Result<Ipv6Addr>;

/// Validates hostname (no shell metacharacters)
pub fn validate_hostname(host: &str) -> Result<String>;

/// Validates port number (1-65535)
pub fn validate_port(port: u16) -> Result<u16>;

/// Validates CIDR notation
pub fn validate_cidr(cidr: &str) -> Result<IpNetwork>;
```

**Security Test Cases:**
```rust
#[test]
fn test_command_injection_semicolon() {
    let malicious = "127.0.0.1; rm -rf /";
    assert!(execute_nmap(malicious).is_err());
}

#[test]
fn test_command_injection_pipe() {
    let malicious = "127.0.0.1 | cat /etc/passwd";
    assert!(execute_nmap(malicious).is_err());
}

#[test]
fn test_command_injection_backticks() {
    let malicious = "127.0.0.1 `whoami`";
    assert!(execute_nmap(malicious).is_err());
}
```

---

### 3. Add Timeout Wrappers
**Priority:** HIGH  
**Effort:** 4-6 hours  
**Status:** Not Started

**Description:**
Implement timeout wrappers for all external tool execution to prevent DoS.

**Tasks:**
- [ ] Create timeout wrapper utility in `crates/core/src/timeout.rs`
- [ ] Define timeout constants per tool category
- [ ] Wrap all tool executions with timeouts
- [ ] Add timeout configuration to settings
- [ ] Handle timeout errors gracefully
- [ ] Add timeout metrics/logging
- [ ] Test timeout behavior

**Implementation:**
```rust
// crates/core/src/timeout.rs

use tokio::time::{timeout, Duration};

pub struct ToolTimeout {
    pub quick_scan: Duration,      // 60 seconds
    pub network_scan: Duration,     // 10 minutes  
    pub brute_force: Duration,      // 60 minutes
    pub default: Duration,          // 5 minutes
}

impl Default for ToolTimeout {
    fn default() -> Self {
        Self {
            quick_scan: Duration::from_secs(60),
            network_scan: Duration::from_secs(600),
            brute_force: Duration::from_secs(3600),
            default: Duration::from_secs(300),
        }
    }
}

pub async fn execute_with_timeout<F, T>(
    future: F,
    timeout_duration: Duration,
    tool_name: &str,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    match timeout(timeout_duration, future).await {
        Ok(result) => result,
        Err(_) => {
            log::warn!("Tool '{}' exceeded timeout of {:?}", tool_name, timeout_duration);
            Err(Error::ToolTimeout {
                tool: tool_name.to_string(),
                duration: timeout_duration,
            })
        }
    }
}
```

**Configuration:**
```toml
# Config.toml
[timeouts]
quick_scan = 60        # seconds
network_scan = 600     # 10 minutes
brute_force = 3600     # 1 hour
default = 300          # 5 minutes
```

---

## Medium Priority Tasks (Week 2-3)

### 4. Implement Path Validation
**Priority:** MEDIUM  
**Effort:** 3-4 hours  
**Status:** Not Started

**Tasks:**
- [ ] Create path validation utility in `crates/core/src/paths.rs`
- [ ] Audit all `File::open()` calls
- [ ] Audit all `File::create()` calls
- [ ] Implement `safe_file_access()` helper
- [ ] Add tests for path traversal prevention
- [ ] Document safe file access patterns

**Implementation:**
```rust
// crates/core/src/paths.rs

use std::path::{Path, PathBuf};

/// Safely access a file within a base directory
pub fn safe_file_access(base: &Path, user_path: &str) -> Result<PathBuf> {
    let base_canonical = base.canonicalize()
        .map_err(|e| Error::InvalidPath(format!("Base path error: {}", e)))?;
    
    let requested = base_canonical.join(user_path);
    let canonical = requested.canonicalize()
        .map_err(|e| Error::InvalidPath(format!("Path error: {}", e)))?;
    
    // Ensure path stays within base directory
    if !canonical.starts_with(&base_canonical) {
        return Err(Error::PathTraversal {
            requested: user_path.to_string(),
            base: base_canonical.display().to_string(),
        });
    }
    
    Ok(canonical)
}
```

---

### 5. Add SSRF Protection
**Priority:** MEDIUM  
**Effort:** 2-3 hours  
**Status:** Not Started

**Tasks:**
- [ ] Create URL validation utility
- [ ] Audit WebSocket connection code
- [ ] Block private IP ranges
- [ ] Verify TLS certificate validation
- [ ] Add URL allowlist configuration
- [ ] Test SSRF prevention

**Implementation:**
```rust
// crates/core/src/url_validation.rs

use url::Url;
use std::net::IpAddr;

pub fn validate_websocket_url(url_str: &str) -> Result<Url> {
    let url = Url::parse(url_str)
        .map_err(|e| Error::InvalidUrl(e.to_string()))?;
    
    // Only allow wss:// (encrypted WebSocket)
    if url.scheme() != "wss" {
        return Err(Error::InsecureScheme(url.scheme().to_string()));
    }
    
    // Block private IPs
    if let Some(host) = url.host() {
        if let url::Host::Ipv4(ip) = host {
            if is_private_ip(ip.into()) {
                return Err(Error::PrivateIpBlocked(ip.to_string()));
            }
        }
    }
    
    Ok(url)
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private() || 
            ip.is_loopback() || 
            ip.is_link_local() ||
            ip.is_multicast() ||
            ip.is_documentation()
        },
        IpAddr::V6(ip) => {
            ip.is_loopback() || 
            ip.is_multicast() ||
            ip.is_unspecified()
        }
    }
}
```

---

### 6. Create Security Test Suite
**Priority:** MEDIUM  
**Effort:** 6-8 hours  
**Status:** Not Started

**Tasks:**
- [ ] Create `crates/core/tests/security_tests.rs`
- [ ] Add command injection tests
- [ ] Add path traversal tests
- [ ] Add SSRF tests
- [ ] Add timeout tests
- [ ] Add input validation tests
- [ ] Integrate into CI pipeline

**Test Categories:**
```rust
// crates/core/tests/security_tests.rs

mod command_injection_tests {
    // Test malicious inputs are rejected
}

mod path_traversal_tests {
    // Test directory escape attempts are blocked
}

mod ssrf_tests {
    // Test private IP blocking
}

mod timeout_tests {
    // Test operations respect timeouts
}

mod input_validation_tests {
    // Test all validation functions
}
```

---

## Low Priority Tasks (Week 4)

### 7. Implement Fuzzing
**Priority:** LOW  
**Effort:** 8-12 hours  
**Status:** Not Started

**Tasks:**
- [ ] Set up `cargo-fuzz`
- [ ] Create fuzz targets for parsers
- [ ] Create fuzz targets for validation functions
- [ ] Run fuzz tests for 24+ hours
- [ ] Document fuzzing setup
- [ ] Integrate into CI (optional)

---

### 8. Document Threat Model
**Priority:** LOW  
**Effort:** 4-6 hours  
**Status:** Not Started

**Tasks:**
- [ ] Create `docs/THREAT_MODEL.md`
- [ ] Document assets
- [ ] Document threat actors
- [ ] Document attack vectors
- [ ] Document mitigations
- [ ] Document assumptions

---

### 9. Plan Security Audit
**Priority:** LOW  
**Effort:** Research + coordination  
**Status:** Not Started

**Tasks:**
- [ ] Research security audit firms
- [ ] Get quotes for security audit
- [ ] Define audit scope
- [ ] Schedule audit for pre-1.0 release
- [ ] Prepare documentation for auditors

---

## Progress Tracking

### Week 1 Goals
- [ ] Complete unsafe blocks audit
- [ ] Complete command execution review
- [ ] Implement timeout wrappers

### Week 2-3 Goals
- [ ] Implement path validation
- [ ] Add SSRF protection
- [ ] Create security test suite

### Week 4 Goals
- [ ] Set up fuzzing
- [ ] Document threat model
- [ ] Plan external security audit

---

## Metrics

| Metric | Baseline | Target | Current |
|--------|----------|--------|---------|
| Unsafe blocks documented | 0/19 | 19/19 | 0/19 |
| Security tests | 0 | 20+ | 0 |
| Tools with timeouts | 0 | 100% | 0% |
| Code coverage | 65% | 80% | 65% |

---

## Review Checklist

Before marking this feature complete:

- [ ] All HIGH priority tasks completed
- [ ] All MEDIUM priority tasks completed or deferred with justification
- [ ] Security tests passing
- [ ] Documentation updated
- [ ] CI/CD integration complete
- [ ] Code review by at least 2 developers
- [ ] Security review by security-focused developer
- [ ] All unsafe blocks documented
- [ ] No hardcoded secrets
- [ ] Input validation comprehensive
- [ ] Timeouts configured
- [ ] Path operations safe
- [ ] SSRF protections in place

---

## Resources

- **HoneySlop:** https://github.com/gadievron/honeyslop
- **Security Lessons:** `docs/SECURITY_LESSONS_FROM_HONEYSLOP.md`
- **Audit Results:** `docs/SECURITY_AUDIT_RESULTS.md`
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **Rust Security:** https://anssi-fr.github.io/rust-guide/

---

## Notes

- This is security-critical work - take time to do it right
- When in doubt, ask for a second opinion
- Document your reasoning for all decisions
- Security is never "done" - plan for ongoing maintenance
