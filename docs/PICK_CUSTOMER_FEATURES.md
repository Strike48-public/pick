# Pick: Adaptive Penetration Testing Platform

## Overview

Pick is an open-source penetration testing platform that combines 90+ integrated security tools with adaptive multi-agent reasoning. When automated attacks encounter obstacles, Pick figures out alternative approaches, validates findings through independent verification, and adjusts its strategy based on what it discovers.

Built for red teamers, penetration testers, and security learners, Pick handles the technical orchestration of complex attack chains while you focus on strategic decisions. Use Pick standalone for solo assessments, or integrate with StrikeKit for enterprise red team operations with team collaboration and engagement management.

**Key Capabilities:**
- Adaptive execution that adjusts strategy when obstacles are encountered
- Multi-agent validation architecture to verify findings before reporting
- 90+ integrated tools with access to 3,000+ BlackArch tools for learning
- Multi-platform deployment (desktop, headless, web, mobile, Kubernetes)
- Standalone operation or enterprise integration via StrikeKit

---

## How Pick Works

### Multi-Agent Validation Architecture

Pick uses independent agents working together to ensure reliable results:

**Red Team Agent** → Executes penetration testing tactics and techniques  
**Validator Agent** → Independently verifies findings and prevents false positives  
**Report Generator** → Documents only validated findings with confidence levels

This separation of execution and verification reduces wasted time chasing false positives and provides clear audit trails showing how each vulnerability was discovered and validated.

### Adaptive Execution

Unlike traditional pentesting tools that fail when they encounter unexpected responses, Pick treats obstacles as new information and adapts its approach:

**Scenario Examples:**
- Web application returns unexpected error → Pick tries different encoding techniques and payload variations
- Port scan blocked by firewall → Pick adjusts timing, fragmentation, and scan techniques
- Initial exploit fails → Pick analyzes the failure and pivots to alternative attack vectors
- Authentication bypass needed → Pick orchestrates credential harvesting and brute force strategies

Pick doesn't blindly follow scripts—it figures out what the target actually needs and adjusts its strategy accordingly.

### Unified Tool Orchestration

Pick integrates 90+ security tools and has access to learn from 3,000+ BlackArch tools. Rather than requiring manual tool chaining and output parsing, Pick understands tool capabilities, knows which tools work well together, and orchestrates complex multi-tool attack chains automatically.

**From reconnaissance to exploitation to post-exploitation**, Pick handles the technical execution while you provide strategic guidance and oversight.

---

## Use Cases

### External Network Penetration Testing

**Scenario:** Security assessment of external network infrastructure

Pick orchestrates the complete external penetration testing workflow:
1. **Reconnaissance** - Host discovery, port scanning, service enumeration
2. **Vulnerability Assessment** - Service banner analysis, CVE lookup, default credential checking
3. **Exploitation** - Automated exploitation attempts with validated results
4. **Post-Exploitation** - Credential harvesting, lateral movement planning
5. **Reporting** - Validated findings with attack chain documentation

**Value:** Complete external network assessments without manual tool chaining or output correlation.

---

### WiFi Security Assessment

**Scenario:** Wireless network security testing and WPA/WPA2 password auditing

Pick's AutoPWN feature provides fully orchestrated WiFi penetration testing:
1. **Network Discovery** - Scan for WiFi networks with signal strength filtering
2. **Target Selection** - Intelligent filtering by security type and signal quality
3. **Monitor Mode Management** - Automated wireless interface configuration
4. **Handshake Capture** - Deauthentication attacks and packet capture orchestration
5. **Password Cracking** - Dictionary attacks with wordlist management
6. **Cleanup** - Automatic restoration of network interfaces

**Value:** Professional-grade WiFi security assessments with hardware-level access in a multi-platform deployment model.

**Technical Note:** Configurable sandbox profiles allow WiFi hardware passthrough while maintaining isolation for other operations—enabling WiFi pentesting even in containerized deployments.

---

### Web Application Security Testing

**Scenario:** Comprehensive web application vulnerability assessment

Pick orchestrates web application testing across the OWASP Top 10 and beyond:
- **Content Discovery** - Directory/file enumeration, endpoint discovery, parameter detection
- **Vulnerability Scanning** - SQL injection, XSS, command injection, authentication bypass
- **Web Fuzzing** - Parameter fuzzing, subdomain enumeration, DNS discovery
- **CMS/Framework Detection** - Automated identification and targeted scanning
- **API Security** - REST/GraphQL endpoint testing and authentication analysis

**Integrated Tools:** ffuf, gobuster, sqlmap, nuclei, nikto, wpscan, arjun, and 30+ web security tools

**Value:** Comprehensive web application security testing with tool selection based on discovered technologies.

---

### Learning & Skill Development

**Scenario:** Security professionals and students learning penetration testing methodology

Pick serves as an interactive learning platform:
- **Watch agents demonstrate real-world pentesting** - Observe tool selection, decision-making, and attack chains
- **Understand methodology** - See how reconnaissance informs exploitation, and how tools chain together
- **Practice safely** - Use against authorized targets in controlled environments
- **Build skills progressively** - Start with guided attacks, transition to strategic oversight

**Value:** Learn by observing adaptive agent behavior, then take increasing control as skills develop.

---

### Red Team Operations (with StrikeKit)

**Scenario:** Multi-week red team engagements with team collaboration

When integrated with StrikeKit, Pick enables enterprise red team operations:
- **Engagement Management** - Track targets, credentials, findings, and attack paths
- **Team Collaboration** - Matrix integration for real-time collaboration
- **C2 Infrastructure** - Built-in command and control with cross-platform agents
- **Pivot Tracking** - Document lateral movement and attack chain progression
- **Client Deliverables** - PDF reports with findings and remediation guidance

**Value:** Solo pentester capabilities scale to full red team operations with engagement tracking and team coordination.

---

### Beyond These Use Cases

With access to 90+ integrated tools and the ability to learn from 3,000+ BlackArch tools, Pick supports extensive security testing scenarios:

**Network Security:**
- Internal network penetration testing
- Cloud infrastructure assessment
- Network device security auditing
- SNMP enumeration and exploitation

**Credential Attacks:**
- Password cracking (50+ protocols via Hydra)
- Hash cracking with GPU acceleration (Hashcat)
- Kerberoasting and Windows authentication attacks
- Default credential auditing

**Post-Exploitation:**
- Windows credential extraction (Impacket suite)
- Linux privilege escalation enumeration
- Lateral movement orchestration
- Active Directory exploitation

**OSINT & Reconnaissance:**
- Subdomain enumeration and discovery
- DNS analysis and zone transfers
- Social media and data breach correlation
- Asset discovery and mapping

**Specialized Testing:**
- SMB/Windows share enumeration
- Database security assessment
- IoT device security testing
- Network service exploitation

**The key difference:** Pick doesn't just provide access to these tools—it understands when to use them, how to chain them together, and how to validate their results.

---

## Platform Capabilities

### Integrated Security Tools (90+)

Pick provides unified orchestration across industry-standard penetration testing tools:

**Network Scanning & Discovery:**
nmap, rustscan, masscan, arp-scan, netdiscover, nbtscan, unicornscan, hping3

**Web Application Testing:**
ffuf, gobuster, nikto, dirb, sqlmap, nuclei, wpscan, wfuzz, feroxbuster, arjun, commix, dirsearch, xsstrike, hakrawler, httprobe, wafw00f, whatweb, skipfish, dalfox, joomscan, droopescan

**DNS & Subdomain Enumeration:**
sublist3r, amass, subfinder, assetfinder, dnsenum, dnsrecon, fierce

**Credential Attacks:**
hydra (50+ protocols), john (password cracking), hashcat (GPU acceleration), aircrack-ng (WiFi)

**Post-Exploitation:**
impacket suite (secretsdump, psexec, wmiexec, getuserspns), crackmapexec, evil-winrm, linpeas

**Network Exploitation:**
bettercap, responder, socat, ncat, tshark

**OSINT & Reconnaissance:**
theHarvester, spiderfoot, recon-ng, whois, gau, waybackurls, gospider, katana, paramspider, eyewitness, cewl

**SMB & Windows:**
enum4linux, enum4linux-ng, smbmap, ldapsearch, onesixtyone

**Additional Capabilities:**
exiftool (forensics), changeme (default credentials), crunch (wordlist generation), searchsploit, testssl, sslscan

**Learning from 3,000+ BlackArch Tools:**
Pick has access to the full BlackArch repository for learning tool capabilities, output patterns, and orchestration strategies.

---

### Multi-Platform Deployment

Deploy Pick wherever your security testing needs to happen:

**Desktop Application**
- Native Linux/macOS/Windows GUI with full tool access
- WiFi hardware passthrough for wireless security testing
- Configurable sandbox profiles (restrictive, WiFi-enabled, permissive)

**Headless Agent**
- Server/container deployment with web-based UI
- Kubernetes-native with Helm charts
- StrikeHub integration for automated lifecycle management
- Minimal scratch-based container images

**Web Application**
- Browser-based interface with server-side tool execution
- No client-side installation required
- Multi-user support via LiveView architecture

**Mobile Applications**
- Native Android and iOS apps
- On-device tool execution for physical security assessments
- Perfect for WiFi surveys and network reconnaissance in the field

**Terminal UI (TUI)**
- Terminal-based interface for SSH/remote environments
- Full functionality in console-only environments

---

### Adaptive Reasoning

Pick's multi-agent architecture enables adaptive decision-making:

**Tool Selection:**
- Analyzes target characteristics to choose appropriate tools
- Understands which tools provide overlapping vs. complementary data
- Prioritizes faster tools for initial reconnaissance, comprehensive tools for validation

**Attack Chain Orchestration:**
- Reconnaissance findings inform exploitation strategy
- Successful exploits trigger post-exploitation workflows
- Blocked techniques trigger alternative approaches

**Real-Time Adjustment:**
- Target rate limiting detected → adjust timing and concurrency
- Service behaving unexpectedly → try alternative interrogation techniques
- Initial exploit failed → analyze error output and pivot strategy

**Validation Logic:**
- Independent Validator agent confirms findings before reporting
- Cross-references results from multiple tools for confidence scoring
- Identifies false positives through behavioral analysis

---

### Open Source & Auditable

Pick is fully open source and auditable:
- Complete source code available on GitHub
- Review agent decision-making logic and tool orchestration
- Contribute integrations, improvements, and bug fixes
- No proprietary "black box" decision-making

**Security & Privacy:**
- All tool execution happens locally (your infrastructure)
- No telemetry or data collection
- Full control over results and findings
- Auditable logs showing every decision and action

---

## Enterprise Integration: StrikeKit

### When You Need Team Collaboration

Pick operates standalone for solo penetration testers and learners. When you need team coordination, engagement tracking, and client deliverables, integrate with StrikeKit.

**StrikeKit Adds:**

**Engagement Management**
- Track red team engagements with workflow states (Planning → Active → Paused → Complete)
- Target tracking (hosts, services, network topology)
- Credential storage and organization (passwords, hashes, tokens, API keys)
- Findings documentation with severity ratings and remediation guidance

**C2 Infrastructure**
- Built-in HTTPS listener with lightweight cross-platform agents
- Automatic extraction of targets, credentials, and findings from command output
- Pivot tracking and lateral movement documentation
- Attack chain visualization

**Team Collaboration**
- Matrix integration for real-time team communication
- Shared engagement context across team members
- Real-time oversight and aggression controls for autonomous agents
- Activity logging and audit trails

**Client Deliverables**
- PDF report generation with findings and recommendations
- MITRE ATT&CK technique mapping and tagging
- Methodology checklists (external, internal, web app, Active Directory)
- Objective tracking and scope drift detection

**Workflow Orchestration**
- Multi-phase engagement planning
- Blocker tracking and resolution workflows
- Automated task assignment and execution
- Progress monitoring and status reporting

### Architecture: Pick + StrikeKit

```
┌─────────────────────────────────────────────────────────┐
│                     StrikeKit                           │
│         (Engagement Management & Collaboration)         │
│                                                          │
│  • Target Tracking        • Team Collaboration          │
│  • Findings Management    • C2 Infrastructure           │
│  • PDF Reports            • Matrix Integration          │
└────────────────────┬────────────────────────────────────┘
                     │
                     │ Orchestrates
                     ▼
┌─────────────────────────────────────────────────────────┐
│                        Pick                             │
│         (Adaptive Pentesting Execution)                 │
│                                                          │
│  • Multi-Agent Validation  • 90+ Integrated Tools       │
│  • Adaptive Reasoning      • 3,000+ BlackArch Learning  │
│  • Tool Orchestration      • Multi-Platform Deployment  │
└─────────────────────────────────────────────────────────┘
```

**Use Pick Standalone When:**
- Solo penetration testing or bug bounty hunting
- Learning and skill development
- Quick assessments and vulnerability validation
- Personal security research projects

**Use Pick + StrikeKit When:**
- Multi-week red team engagements
- Team-based penetration testing operations
- Client-facing assessments requiring deliverables
- Enterprise security programs with compliance requirements
- Operations requiring C2 infrastructure and pivot tracking

---

## Getting Started

### Installation

**Desktop (Linux/macOS/Windows):**
```bash
# Clone repository
git clone https://github.com/Strike48-public/pick.git
cd pick

# Run desktop application
cargo run --package pentest-desktop
```

**Headless Agent (Server/Container):**
```bash
# Using convenience script
./run-pentest.sh headless

# Or with Docker
docker pull strike48/pick-connector:latest
docker run -p 3030:3030 strike48/pick-connector
```

**Kubernetes:**
```bash
# Using Helm
helm repo add pick https://strike48-public.github.io/pick
helm install pick pick/pick-connector
```

### Quick Start

1. **First Run** - Pick automatically detects your platform and available tools
2. **Dashboard** - Access the Quick Actions dashboard for common workflows
3. **Tool Execution** - Select tools manually or let agents orchestrate automatically
4. **Results** - View validated findings with confidence levels and evidence

### Configuration

**Environment Variables:**
- `STRIKE48_HOST` - Backend integration endpoint (optional for standalone)
- `RUST_LOG` - Logging level (debug, info, warn, error)
- `CONNECTOR_NAME` - Unique identifier for this Pick instance

**Optional Integrations:**
- **StrikeKit** - Enterprise engagement management and team collaboration
- **Matrix** - Real-time agent communication and oversight
- **Custom Wordlists** - Provide domain-specific dictionaries for password attacks

### System Requirements

**Minimum:**
- Linux, macOS, or Windows
- 4GB RAM
- 2GB disk space

**Recommended:**
- 8GB+ RAM for complex assessments
- SSD for faster tool execution
- WiFi adapter with monitor mode support (for wireless testing)

**For WiFi Testing:**
- Requires root/administrator privileges for hardware access
- External WiFi adapter recommended to avoid connection loss
- See docs/AUTOPWN.md for recommended hardware

---

## Community & Support

**Documentation:**
- Full documentation at https://github.com/Strike48-public/pick/docs
- Tool-specific guides and examples
- Architecture and development documentation

**Community:**
- GitHub Issues for bug reports and feature requests
- Discussions for questions and community support
- Contributing guidelines for code contributions

**Enterprise Support:**
- StrikeKit integration documentation
- Enterprise deployment guides
- Professional services available

---

## Open Source

Pick is MIT licensed and fully open source:
- **Repository:** https://github.com/Strike48-public/pick
- **License:** MIT
- **Contributing:** Pull requests welcome

**Why Open Source?**
- Build trust through code transparency
- Enable community contributions and improvements
- Allow security audits and verification
- Provide learning opportunities for security professionals

---

*Pick: Adaptive penetration testing with multi-agent validation*

*For enterprise red team operations, see StrikeKit integration documentation.*
