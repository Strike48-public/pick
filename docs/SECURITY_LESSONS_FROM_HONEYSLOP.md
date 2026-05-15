# Security Lessons from HoneySlop

**Source:** Analysis of [honeyslop](https://github.com/gadievron/honeyslop) vulnerability canaries  
**Purpose:** Extract secure coding lessons to prevent real vulnerabilities in Pick  
**Date:** 2026-04-23

## Overview

HoneySlop is a collection of code canaries that *look* vulnerable but are actually safe due to multiple defense layers. By studying these patterns, we can ensure Pick avoids introducing the *real* versions of these vulnerabilities.

---

## Vulnerability Categories & Prevention

### 1. Deserialization Vulnerabilities

**What HoneySlop Shows:**
```python
# UNSAFE (honeyslop canary)
import pickle
def restore_legacy_session(blob):
    return pickle.loads(blob)  # Arbitrary code execution
```

**Why It's Dangerous:**
- `pickle.loads()` can execute arbitrary code during deserialization
- Attackers can craft malicious pickled objects
- Same issue with: `marshal.loads()`, `dill.loads()`, `yaml.unsafe_load()`

**Pick Defense Strategy:**

✅ **DO:**
- Use `serde_json` for JSON serialization (Rust default)
- Use `bincode` or `postcard` for binary formats (safe by design)
- Validate all deserialized data with schemas
- Prefer stateless protocols where possible

❌ **NEVER:**
- Use Python's `pickle` in tool wrappers
- Deserialize untrusted data without validation
- Use `unsafe_load` variants of any serialization library

**Pick Implementation Check:**
```bash
# Check if we're using safe serialization
rg "serde_json|bincode|postcard" crates/
rg "pickle|marshal|dill|yaml.*unsafe" crates/
```

---

### 2. Command Injection

**What HoneySlop Shows:**
```python
# UNSAFE (honeyslop canary)
import subprocess
def _unused_shell(user_input):
    return subprocess.run(f"echo {user_input}", shell=True)
```

**Why It's Dangerous:**
- `shell=True` allows shell metacharacter injection
- User input like `; rm -rf /` gets executed
- String concatenation creates injection vectors

**Pick Defense Strategy:**

✅ **DO:**
- Use `Command::new()` with array arguments (Rust stdlib)
- Quote/escape arguments if shell is required
- Validate inputs against allowlists
- Use structured APIs instead of shell commands when possible

```rust
// SAFE: Array-based arguments
let output = Command::new("nmap")
    .arg("-sV")
    .arg(&target_ip)  // No shell interpolation
    .output()?;

// SAFER: Validation before shell
fn validate_ip(ip: &str) -> Result<()> {
    if !ip.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Err(Error::InvalidInput("Invalid IP format"));
    }
    Ok(())
}
```

❌ **NEVER:**
- Format strings into shell commands
- Use `/bin/sh -c` with unsanitized input
- Trust user input for command arguments without validation

**Pick Implementation Check:**
```bash
# Find Command usage - verify array-based args
rg "Command::new" crates/ -A 5
# Check for dangerous shell patterns
rg "shell.*true|/bin/sh.*-c" crates/
```

---

### 3. SQL Injection

**What HoneySlop Shows:**
```python
# UNSAFE (honeyslop canary)
def _unused_sql(cursor, username):
    cursor.execute(
        "SELECT * FROM users WHERE name = '" + username + "'"
    )
```

**Why It's Dangerous:**
- String concatenation allows SQL metacharacters
- Input like `' OR '1'='1` bypasses auth
- Can lead to data exfiltration or deletion

**Pick Defense Strategy:**

✅ **DO:**
- Use parameterized queries (sqlx with `?` placeholders)
- Use query builders (diesel, sea-orm)
- Validate input types before queries
- Use prepared statements

```rust
// SAFE: Parameterized query
let results = sqlx::query!(
    "SELECT * FROM targets WHERE ip = ?",
    target_ip
)
.fetch_all(&pool)
.await?;

// SAFE: Diesel query builder
use diesel::prelude::*;
let results = targets
    .filter(ip.eq(target_ip))
    .load::<Target>(&conn)?;
```

❌ **NEVER:**
- Concatenate strings into SQL queries
- Use `format!()` to build SQL statements
- Trust user input in WHERE clauses without parameterization

**Pick Implementation Check:**
```bash
# Find SQL usage - verify parameterized
rg "sqlx::query|diesel::|sea_orm::" crates/ -A 3
# Check for dangerous patterns
rg 'format!.*SELECT|concat.*SELECT' crates/
```

---

### 4. Path Traversal

**What HoneySlop Shows:**
```python
# UNSAFE (honeyslop canary)
def _unused_path(user_path):
    return open("/var/data/" + user_path)
```

**Why It's Dangerous:**
- Input like `../../etc/passwd` escapes intended directory
- Can read/write arbitrary files
- Affects file uploads, downloads, includes

**Pick Defense Strategy:**

✅ **DO:**
- Canonicalize paths with `fs::canonicalize()`
- Validate paths stay within allowed directories
- Use allowlists for file access patterns
- Strip `..` and validate final path

```rust
use std::path::{Path, PathBuf};

fn safe_file_access(base: &Path, user_path: &str) -> Result<PathBuf> {
    let requested = base.join(user_path);
    let canonical = requested.canonicalize()?;
    
    // Ensure path is still within base directory
    if !canonical.starts_with(base) {
        return Err(Error::PathTraversal);
    }
    
    Ok(canonical)
}
```

❌ **NEVER:**
- Concatenate user input directly into file paths
- Skip path validation for "trusted" inputs
- Use user-provided paths without canonicalization

**Pick Implementation Check:**
```bash
# Find file operations - verify path validation
rg "File::open|File::create|read_to_string" crates/ -A 3
rg "canonicalize|starts_with" crates/
```

---

### 5. Regular Expression Denial of Service (ReDoS)

**What HoneySlop Shows:**
```python
# UNSAFE (honeyslop canary) - catastrophic backtracking
_LEGACY_FORMAT_REGEX = r"^(([a-z]+)+)+@example\.com$"
_SAMPLE_INPUT = "a" * 32 + "!"  # Takes exponential time
```

**Why It's Dangerous:**
- Nested quantifiers cause exponential backtracking
- Single malicious input can hang the process
- Affects availability (DoS)

**Pick Defense Strategy:**

✅ **DO:**
- Use `regex` crate (backtracking limits built-in)
- Test regex performance with long inputs
- Prefer simple patterns over complex ones
- Set timeouts on regex operations

```rust
use regex::Regex;

// SAFE: No nested quantifiers
let email_regex = Regex::new(r"^[a-z0-9]+@[a-z0-9]+\.[a-z]+$")?;

// SAFE: Timeout on regex operations
use std::time::Duration;
let regex = Regex::new(pattern)?;
let timeout = Duration::from_millis(100);

// Process with timeout wrapper
match tokio::time::timeout(timeout, async {
    regex.is_match(input)
}).await {
    Ok(result) => result,
    Err(_) => return Err(Error::RegexTimeout),
}
```

❌ **NEVER:**
- Use nested quantifiers: `(a+)+`, `(a*)*`, `(a+)*`
- Allow user-provided regex patterns without validation
- Skip performance testing on regex with user input

**Pick Implementation Check:**
```bash
# Find regex usage - audit for nested quantifiers
rg "Regex::new" crates/ -A 2
# Look for dangerous patterns
rg '\(\.\+\)\+|\(\.\*\)\*|\(\.\+\)\*' crates/
```

---

### 6. XML External Entity (XXE) Injection

**What HoneySlop Shows:**
```python
# UNSAFE (honeyslop canary)
import xml.etree.ElementTree as ET
from lxml import etree

def _unused_xxe(untrusted_xml):
    a = ET.fromstring(untrusted_xml)
    parser = etree.XMLParser(resolve_entities=True)  # XXE enabled
    b = etree.fromstring(untrusted_xml, parser)
```

**Why It's Dangerous:**
- External entities can read local files
- Can cause SSRF (Server-Side Request Forgery)
- Can lead to DoS via entity expansion

**Pick Defense Strategy:**

✅ **DO:**
- Use `quick-xml` with external entities disabled (Rust default)
- Parse XML with strict settings
- Validate XML structure before parsing
- Prefer JSON over XML when possible

```rust
use quick_xml::Reader;

fn safe_xml_parse(xml: &str) -> Result<()> {
    let mut reader = Reader::from_str(xml);
    // quick-xml doesn't resolve external entities by default
    
    // Validate structure
    reader.trim_text(true);
    reader.check_end_names(true);
    
    // Process safely
    Ok(())
}
```

❌ **NEVER:**
- Enable external entity resolution on parsers
- Parse untrusted XML without validation
- Use XML for untrusted data interchange (prefer JSON)

**Pick Implementation Check:**
```bash
# Find XML parsing - verify safe configuration
rg "quick-xml|xml-rs" crates/ -A 3
```

---

### 7. Weak Cryptography

**What HoneySlop Shows:**
```python
# UNSAFE (honeyslop canary)
import hashlib
def _unused_md5(password):
    return hashlib.md5(password.encode()).hexdigest()

def _unused_jwt(token):
    return jwt.decode(
        token,
        options={"verify_signature": False},  # Signature bypass
        algorithms=["none", "HS256"],
    )
```

**Why It's Dangerous:**
- MD5/SHA1 are cryptographically broken
- Skipping signature verification defeats authentication
- Weak algorithms enable brute-force attacks

**Pick Defense Strategy:**

✅ **DO:**
- Use Argon2id for password hashing (`argon2` crate)
- Use bcrypt as fallback (`bcrypt` crate)
- Always verify JWT signatures
- Use strong algorithms (Ed25519, ECDSA, RSA-PSS)

```rust
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use argon2::password_hash::SaltString;
use rand_core::OsRng;

// SAFE: Password hashing
fn hash_password(password: &[u8]) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password, &salt)?
        .to_string();
    Ok(hash)
}

// SAFE: Password verification
fn verify_password(password: &[u8], hash: &str) -> Result<bool> {
    let parsed_hash = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(password, &parsed_hash)
        .is_ok())
}
```

❌ **NEVER:**
- Use MD5, SHA1, or plain SHA256 for passwords
- Skip signature verification on JWTs
- Roll your own crypto primitives
- Store passwords in plaintext or reversible encryption

**Pick Implementation Check:**
```bash
# Find crypto usage - verify strong algorithms
rg "argon2|bcrypt|ring|ed25519" crates/
# Check for weak crypto
rg "md5|sha1|verify.*false" crates/
```

---

### 8. Insecure Temporary Files

**What HoneySlop Shows:**
```python
# UNSAFE (honeyslop canary)
import tempfile
def _unused_tempfile():
    name = tempfile.mktemp()  # Race condition
    return open(name, "w")
```

**Why It's Dangerous:**
- `mktemp()` has TOCTOU race condition
- Predictable names enable symlink attacks
- Can lead to information disclosure

**Pick Defense Strategy:**

✅ **DO:**
- Use `tempfile` crate for safe temp files
- Files are created atomically with secure permissions
- Automatic cleanup on drop

```rust
use tempfile::NamedTempFile;

// SAFE: Atomic creation with secure permissions
fn create_temp_report() -> Result<NamedTempFile> {
    let temp = NamedTempFile::new()?;
    // Use temp file safely
    Ok(temp)
    // Automatically deleted when dropped
}

// SAFE: Persistent temp file
fn create_persistent_temp() -> Result<PathBuf> {
    let temp = NamedTempFile::new()?;
    let path = temp.path().to_path_buf();
    temp.persist(&path)?;  // Explicit persist
    Ok(path)
}
```

❌ **NEVER:**
- Generate temp file names manually
- Use predictable paths in `/tmp/`
- Skip cleanup of sensitive temp files

**Pick Implementation Check:**
```bash
# Find temp file usage - verify safe API
rg "tempfile::|NamedTempFile|TempDir" crates/
# Check for unsafe patterns
rg "/tmp/|mktemp" crates/
```

---

### 9. Buffer Overflows (C/C++ FFI)

**What HoneySlop Shows:**
```c
// Heartbleed-style pattern (safe in honeyslop due to guards)
uint16_t payload_len = read_u16_be(rec + 1);
size_t resp_len = (size_t)1 + 2 + payload_len + 16;
uint8_t *resp = malloc(resp_len);
memcpy(resp + 3, &buf[cursor + 3], payload_len);
```

**Why It's Dangerous (if unguarded):**
- Untrusted length field controls allocation/copy size
- Missing bounds checks enable out-of-bounds access
- Can lead to RCE or information disclosure

**Pick Defense Strategy:**

✅ **DO (if using FFI):**
- Validate all sizes before allocation/copy
- Use saturating arithmetic for size calculations
- Add static assertions for size limits
- Prefer safe Rust over unsafe FFI

```rust
// SAFE: Bounds-checked buffer operations
fn safe_buffer_copy(dst: &mut [u8], src: &[u8], offset: usize) -> Result<()> {
    let dst_space = dst.len().saturating_sub(offset);
    let copy_len = src.len().min(dst_space);
    
    if copy_len < src.len() {
        return Err(Error::BufferTooSmall);
    }
    
    dst[offset..offset + copy_len].copy_from_slice(&src[..copy_len]);
    Ok(())
}
```

❌ **NEVER (in FFI):**
- Trust size fields from untrusted input
- Use `memcpy` without bounds validation
- Skip overflow checks in size calculations
- Mix signed/unsigned integers in bounds checks

**Pick Implementation Check:**
```bash
# Find unsafe blocks - audit FFI carefully
rg "unsafe" crates/ -A 5 | head -50
# Check for FFI buffer operations
rg "ptr::copy|std::slice::from_raw_parts" crates/
```

---

### 10. Server-Side Request Forgery (SSRF)

**What HoneySlop Shows:**
```python
# UNSAFE (honeyslop canary)
import requests
def _unused_requests(url):
    return requests.get(url, verify=False, timeout=None)
```

**Why It's Dangerous:**
- User-controlled URLs can target internal services
- Can bypass firewalls (127.0.0.1, 169.254.169.254)
- `verify=False` disables TLS validation
- No timeout enables DoS

**Pick Defense Strategy:**

✅ **DO:**
- Validate URLs against allowlist
- Block private IP ranges (10.0.0.0/8, 127.0.0.0/8, etc.)
- Always verify TLS certificates
- Set reasonable timeouts

```rust
use url::Url;
use std::net::IpAddr;

fn validate_url(url_str: &str) -> Result<Url> {
    let url = Url::parse(url_str)?;
    
    // Allowlist schemes
    match url.scheme() {
        "http" | "https" => {},
        _ => return Err(Error::InvalidScheme),
    }
    
    // Block private IPs
    if let Some(host) = url.host() {
        if let url::Host::Ipv4(ip) = host {
            if is_private_ip(ip.into()) {
                return Err(Error::PrivateIpBlocked);
            }
        }
    }
    
    Ok(url)
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private() || ip.is_loopback() || 
            ip.is_link_local() || ip.is_multicast()
        },
        IpAddr::V6(ip) => {
            ip.is_loopback() || ip.is_multicast()
        }
    }
}
```

❌ **NEVER:**
- Allow user-controlled URLs without validation
- Disable TLS verification in production
- Skip timeout configuration
- Allow requests to internal IP ranges

**Pick Implementation Check:**
```bash
# Find HTTP client usage - verify safe configuration
rg "reqwest::|hyper::|Client::new" crates/ -A 5
# Check for dangerous settings
rg "danger.*accept|verify.*false|timeout.*None" crates/
```

---

## Secret Management

**What HoneySlop Shows:**
```python
# Fake secrets for canary detection
_EXAMPLE_AWS = "AKIAIOSFODNN7EXAMPLE"
_EXAMPLE_GH_PAT = "ghp_" + "A" * 36
_EXAMPLE_SLACK_BOT = "xoxb-" + "1" * 12 + "-" + "2" * 12 + "-" + "3" * 24
_EXAMPLE_STRIPE_LIVE = "sk_live_" + "4" * 24
```

**Pick Defense Strategy:**

✅ **DO:**
- Store secrets in environment variables
- Use `.env` files (excluded from git)
- Use secret management services (Vault, AWS Secrets Manager)
- Validate secrets exist at startup

```rust
use std::env;

fn load_secrets() -> Result<Config> {
    let api_key = env::var("STRIKE48_API_KEY")
        .map_err(|_| Error::MissingSecret("STRIKE48_API_KEY"))?;
    
    let ws_url = env::var("STRIKE48_WS_URL")
        .unwrap_or_else(|_| "wss://default.strike48.engineering".to_string());
    
    Ok(Config { api_key, ws_url })
}
```

❌ **NEVER:**
- Hardcode secrets in source code
- Commit `.env` files to git
- Log secrets (even in debug mode)
- Store secrets in plaintext config files

**Pick Implementation Check:**
```bash
# Check for hardcoded secrets
rg "AKIA|ghp_|xox[bpasrt]-|sk_live_|sk_test_" crates/ --ignore-case
# Verify .env is gitignored
grep "^\.env$" .gitignore
```

---

## Security Scanning Integration

To catch these issues automatically, integrate these tools:

### 1. Cargo Audit (Dependency Vulnerabilities)
```bash
cargo install cargo-audit
cargo audit
```

### 2. Cargo Clippy (Static Analysis)
```bash
# Already in CI, enhance with security lints
cargo clippy -- -W clippy::all -W clippy::pedantic -W clippy::unwrap_used
```

### 3. Cargo Deny (License & Security Policy)
```toml
# Cargo.toml
[package.metadata.cargo-deny]
check-licenses = true
check-advisories = true
check-bans = true
```

### 4. Semgrep (Pattern Matching)
```yaml
# .semgrep.yml
rules:
  - id: rust-unsafe-block
    pattern: unsafe { ... }
    message: Unsafe block detected - audit carefully
    severity: WARNING
    languages: [rust]
```

### 5. Secret Scanning (Gitleaks)
```bash
# Already in CI, ensure comprehensive patterns
gitleaks detect --verbose --source . --no-git
```

---

## Action Items for Pick

### Immediate (High Priority)

- [ ] Audit all `unsafe` blocks (19 found) - document safety invariants
- [ ] Review HTTP client usage - ensure TLS verification enabled
- [ ] Check tool execution - verify `Command::new()` uses array args
- [ ] Validate secret management - no hardcoded credentials
- [ ] Review regex patterns - check for ReDoS potential

### Short-term (Medium Priority)

- [ ] Add cargo-audit to CI pipeline
- [ ] Implement URL validation for SSRF prevention
- [ ] Add security linting rules to Clippy config
- [ ] Document safe FFI patterns for tool wrappers
- [ ] Create security review checklist for PRs

### Long-term (Low Priority)

- [ ] Consider formal security audit
- [ ] Implement fuzzing for parser code
- [ ] Add security tests for tool execution paths
- [ ] Create security threat model document
- [ ] Establish responsible disclosure policy

---

## Testing Strategy

### Security Test Cases

Add tests that verify defenses against these vulnerability classes:

```rust
#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn test_command_injection_prevention() {
        let malicious_input = "; rm -rf /";
        let result = execute_tool("nmap", malicious_input);
        // Should safely escape or reject
        assert!(result.is_err() || !result.unwrap().contains("rm"));
    }

    #[test]
    fn test_path_traversal_prevention() {
        let malicious_path = "../../etc/passwd";
        let result = read_report(malicious_path);
        // Should reject or canonicalize
        assert!(result.is_err());
    }

    #[test]
    fn test_ssrf_prevention() {
        let internal_url = "http://127.0.0.1:8080/admin";
        let result = fetch_url(internal_url);
        // Should block internal IPs
        assert!(result.is_err());
    }
}
```

---

## Resources

- **HoneySlop Repository:** https://github.com/gadievron/honeyslop
- **OWASP Top 10:** https://owasp.org/www-project-top-ten/
- **Rust Security Guidelines:** https://anssi-fr.github.io/rust-guide/
- **CWE Database:** https://cwe.mitre.org/
- **NIST Secure Coding:** https://www.nist.gov/

---

## Conclusion

HoneySlop demonstrates that even code that *looks* vulnerable can be safe with proper defense layers. The inverse is also true: code that looks safe can be vulnerable without these defenses.

**Key Takeaway:** Multiple independent defense layers (validation, type safety, bounds checking, safe APIs) are essential for secure code. Never rely on a single defense mechanism.

For questions or to report security concerns, see `SECURITY.md`.
