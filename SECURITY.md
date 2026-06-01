# Security Policy

## Supported Versions

Pick follows semantic versioning. Security updates are provided for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| main    | :white_check_mark: |
| 0.x.x   | :white_check_mark: |

We recommend always running the latest version from the `main` branch or the most recent release.

---

## Reporting a Vulnerability

**DO NOT** open public GitHub issues for security vulnerabilities.

### How to Report

Send security vulnerability reports to: **security@strike48.com**

### What to Include

Please provide:

1. **Description** - Clear explanation of the vulnerability
2. **Impact** - Potential security impact (data leakage, privilege escalation, etc.)
3. **Reproduction** - Step-by-step instructions to reproduce
4. **Environment** - OS, Rust version, Pick version
5. **Proof of Concept** - Code snippet or example (if applicable)
6. **Suggested Fix** - Proposed remediation (optional)

### Response Timeline

- **Initial response:** Within 48 hours
- **Status update:** Within 7 days
- **Fix timeline:** Varies by severity (see below)

### Severity Levels

| Level | Description | Fix Timeline |
|-------|-------------|--------------|
| **Critical** | Remote code execution, authentication bypass | 1-3 days |
| **High** | Privilege escalation, sensitive data exposure | 7 days |
| **Medium** | Information disclosure, DoS | 30 days |
| **Low** | Minor issues with limited impact | 90 days |

---

## Security Best Practices

### For Operators

#### Never Commit Secrets

- API keys, tokens, credentials
- Real Strike48 instance URLs
- Customer or tenant names (PII)
- `.env` files

Use `.env.example` templates and keep actual `.env` files gitignored.

#### Secure Configuration

```bash
# Use TLS in production
STRIKE48_HOST=wss://your-server.example.com:443
STRIKE48_TLS=true

# Never disable TLS verification in production
MATRIX_TLS_INSECURE=false
```

#### Privilege Management

- Run headless mode without sudo when possible
- Only use sudo for WiFi tools that require it
- Never run Pick as root unnecessarily

#### Network Security

- Firewall Pick instances appropriately
- Use VPNs for remote connector access
- Implement network segmentation

### For Developers

#### Code Review

All PRs undergo security review before merge. Focus areas:

- Input validation
- SQL injection prevention (parameterized queries)
- XSS prevention (sanitize HTML)
- Command injection prevention
- File path traversal prevention
- Unsafe code blocks (require `// SAFETY:` comments)

#### Dependency Security

```bash
# Run security audit before releasing
cargo audit

# Check for known vulnerabilities
cargo deny check
```

#### Secrets Management

```rust
// BAD - hardcoded secret
const API_KEY: &str = "sk-abc123";

// GOOD - environment variable
let api_key = std::env::var("STRIKE48_TOKEN")
    .context("STRIKE48_TOKEN not set")?;
```

#### Error Handling

```rust
// BAD - exposes internal details
Err(format!("Database error: {}", e))

// GOOD - generic message, log details
tracing::error!(error = %e, "database operation failed");
Err("Internal server error".into())
```

---

## Known Security Considerations

### Tool Execution Isolation

**Current:** Tools run in same process as Pick (no sandbox by default)

**Recommendation:** Use bubblewrap on Linux for tool isolation:

```bash
# Install bubblewap
sudo apt install bubblewrap

# Pick will use bwrap when available
```

### WiFi Tools Require Root

WiFi penetration testing tools require elevated privileges:

- Monitor mode (airmon-ng)
- Packet injection (aireplay-ng)
- Raw socket access

**Mitigation:** Run only WiFi tools with sudo, not the entire application.

### Credential Storage

**Current:** Credentials stored in memory during tool execution

**Recommendation:** Use secure memory APIs (mlock, SecStr) for sensitive data.

### Third-Party Tool Security

Pick integrates 70+ external BlackArch tools. We do not audit third-party tool codebases.

**Responsibility:** Operators should:
- Review tools before use
- Keep tools updated
- Monitor tool behavior
- Report suspicious activity

---

## Security Features

### Authentication

- JWT token authentication with Strike48
- TLS/SSL for all network communication
- Certificate validation (can be disabled for dev with `MATRIX_TLS_INSECURE=true`)

### Evidence Integrity

- Immutable evidence nodes
- Provenance tracking (chain of custody)
- Cryptographic hashing of evidence data
- Validator agent verifies evidence quality

### Audit Logging

- All tool executions logged
- Connector registration/unregistration logged
- Evidence submission logged
- Timestamps in UTC

### Network Security

- TLS 1.2+ required for production
- WebSocket Secure (wss://) for connector protocol
- Certificate pinning (optional, Strike48 server configuration)

---

## Vulnerability Disclosure

### Public Disclosure

Once a vulnerability is fixed:

1. Security advisory published on GitHub
2. CVE assigned (if applicable)
3. Release notes include security section
4. Credits given to reporter (with permission)

### CVE Process

Critical vulnerabilities receive CVE identifiers:

- **CVE Authority:** GitHub Security Advisories
- **CWE Classification:** Common Weakness Enumeration
- **CVSS Scoring:** Industry-standard severity scoring

---

## Security Updates

### Notification Channels

- GitHub Security Advisories (watch repository)
- Release notes (tagged releases)
- Email (for registered Strike48 customers)

### Update Process

```bash
# Check current version
cargo --version

# Update Pick
git pull origin main
cargo build --release

# Verify update
./target/release/pentest-agent --version
```

---

## Compliance

### Data Protection

Pick processes security testing data that may include:

- Network traffic
- Credentials (during testing)
- System information
- Screenshots

**Responsibility:** Operators must ensure compliance with:
- GDPR (EU)
- CCPA (California)
- Local data protection laws
- Penetration testing authorization requirements

### Authorization Requirements

**CRITICAL:** Pick is designed for authorized penetration testing only.

- Obtain written authorization before testing
- Respect scope boundaries
- Comply with all applicable laws
- Report findings responsibly

---

## Security Contacts

- **Vulnerability Reports:** security@strike48.com
- **General Security Questions:** GitHub Discussions
- **Strike48 Support:** Contact your administrator

---

## Security Acknowledgments

We thank the following security researchers for responsible disclosure:

_(This section will be updated as vulnerabilities are reported and fixed)_

---

**Last updated:** 2026-05-28
