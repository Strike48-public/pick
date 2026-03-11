# Network Vulnerability Assessment Prompt

**IMPORTANT:** This assessment should only be conducted on networks you own or have explicit written permission to test. Unauthorized network scanning and penetration testing is illegal.

---

## Objective

Perform comprehensive network vulnerability assessment to identify:
- Live hosts and their services
- Potential security vulnerabilities
- Misconfigurations
- Default credentials
- Exploitable services
- Security weaknesses

---

## Phase 1: Network Discovery

**Goal:** Understand the network topology and identify all live hosts.

### Actions

1. **ARP Table Scan** (`arp_table`)
   - Discover hosts on the local network segment
   - Collect IP addresses, MAC addresses, and manufacturers
   - Identify the network gateway

2. **mDNS/DNS-SD Discovery** (`network_discover`)
   - Find services advertising via mDNS
   - Identify Chromecasts, printers, smart devices
   - Discover service types: `_http._tcp.local.`, `_googlecast._tcp.local.`, etc.

3. **SSDP Discovery** (`ssdp_discover`)
   - Locate UPnP-enabled devices
   - Identify routers, media servers, IoT devices
   - Check for exposed UPnP services

4. **WiFi Scanning** (`wifi_scan`)
   - Enumerate visible wireless networks
   - Identify SSIDs, BSSIDs, channels, signal strength
   - Detect security protocols (WEP/WPA/WPA2/Open)

### Expected Output

```json
{
  "network_range": "192.168.1.0/24",
  "gateway": "192.168.1.1",
  "hosts": [
    {
      "ip": "192.168.1.10",
      "mac": "AA:BB:CC:DD:EE:FF",
      "manufacturer": "Apple Inc.",
      "hostname": "johns-macbook"
    }
  ],
  "services": [...],
  "wifi_networks": [...]
}
```

---

## Phase 2: Host Enumeration

**Goal:** For each discovered host, identify running services, open ports, and operating system.

### Actions

1. **Port Scanning** (`port_scan`)
   - Scan common ports: 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443
   - Use aggressive scan for comprehensive results
   - Record response times and service banners

2. **Service Detection** (`service_banner`)
   - Connect to open ports and grab banners
   - Identify service type and version
   - Extract software versions from banners

3. **OS Fingerprinting** (`execute_command` with `nmap -O`)
   - Attempt to identify operating system
   - Use TCP/IP stack fingerprinting
   - Collect OS version details

### Expected Output

```json
{
  "host": "192.168.1.10",
  "open_ports": [
    {
      "port": 22,
      "service": "ssh",
      "version": "OpenSSH 8.2p1 Ubuntu",
      "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
    },
    {
      "port": 80,
      "service": "http",
      "version": "nginx 1.18.0",
      "banner": "Server: nginx/1.18.0 (Ubuntu)"
    }
  ],
  "os": "Linux 5.4 (Ubuntu 20.04)"
}
```

---

## Phase 3: Service Analysis & Vulnerability Assessment

**Goal:** Identify security vulnerabilities in discovered services.

### Actions

1. **CVE Lookup** (`cve_lookup`)
   - Match service versions to known CVEs
   - Query CVE databases (NVD, Exploit-DB)
   - Assign CVSS severity scores

2. **Default Credentials** (`default_creds_test`)
   - Test common username/password combinations
   - Services to test: SSH, HTTP auth, FTP, Telnet, SNMP, SMB
   - Database of default credentials by manufacturer/device

3. **Web Service Analysis** (for HTTP/HTTPS)
   - **Admin Panel Detection** - Check for `/admin`, `/administrator`, `/login`, `/wp-admin`
   - **Directory Listing** - Test for exposed directories
   - **Information Disclosure** - Check `robots.txt`, `.git`, `.env`, backups
   - **Common Vulnerabilities** - Basic SQLi, XSS, CSRF checks
   - **HTTP Headers** - Check for security headers (CSP, HSTS, X-Frame-Options)
   - **SSL/TLS Configuration** - Test cipher suites, certificate validity

4. **SMB/CIFS Analysis** (`smb_enum`)
   - Enumerate shares (`net view`, `smbclient -L`)
   - Check for anonymous access
   - Test for null sessions
   - Identify writable shares

5. **SSH Analysis**
   - Check for weak ciphers and MACs
   - Test for key-based authentication
   - Attempt password authentication with common credentials

6. **Database Services** (MySQL, PostgreSQL, MongoDB)
   - Test for anonymous access
   - Check for default credentials (root/root, postgres/postgres)
   - Attempt to enumerate databases

### Expected Output

```json
{
  "vulnerabilities": [
    {
      "host": "192.168.1.10",
      "port": 80,
      "service": "nginx 1.18.0",
      "cve": "CVE-2021-23017",
      "severity": "HIGH",
      "cvss": 7.5,
      "description": "DNS resolver off-by-one heap write",
      "remediation": "Upgrade to nginx 1.20.1 or later"
    }
  ],
  "default_credentials": [
    {
      "host": "192.168.1.1",
      "service": "http",
      "username": "admin",
      "password": "admin",
      "status": "SUCCESS"
    }
  ],
  "misconfigurations": [
    {
      "host": "192.168.1.10",
      "issue": "Directory listing enabled",
      "path": "/backup",
      "severity": "MEDIUM"
    }
  ]
}
```

---

## Phase 4: Traffic Analysis (Optional)

**Goal:** Capture and analyze network traffic for sensitive data and protocol weaknesses.

### Actions

1. **Packet Capture** (`traffic_capture`)
   - Capture traffic on network interface
   - Filter by protocol (HTTP, FTP, Telnet, SMTP)
   - Look for cleartext credentials

2. **Protocol Analysis**
   - Identify unencrypted protocols
   - Extract credentials from cleartext traffic
   - Detect protocol downgrade attacks

### Expected Output

```json
{
  "cleartext_protocols": ["http", "ftp", "telnet"],
  "credentials_found": [
    {
      "protocol": "ftp",
      "username": "admin",
      "password": "password123",
      "timestamp": "2026-03-09T10:15:30Z"
    }
  ]
}
```

---

## Phase 5: Reporting

**Goal:** Generate comprehensive vulnerability report with actionable recommendations.

### Report Structure

#### 1. Executive Summary
- Total hosts discovered
- Total vulnerabilities found
- Severity breakdown (Critical, High, Medium, Low)
- Overall risk assessment

#### 2. Network Topology
- Network diagram (if possible)
- List of discovered hosts with services
- Network segmentation analysis

#### 3. Vulnerability Details
For each vulnerability:
- **Host & Service** - IP, port, service version
- **Vulnerability** - CVE ID, description
- **Severity** - CVSS score, risk rating
- **Proof of Concept** - Evidence/screenshot
- **Impact** - Potential consequences
- **Remediation** - Specific fix recommendations

#### 4. Default Credentials
- List of devices/services with default credentials
- Immediate action required

#### 5. Misconfigurations
- Exposed admin panels
- Directory listings
- Missing security headers
- Weak SSL/TLS configurations

#### 6. Recommendations
- Prioritized remediation plan
- Quick wins (low effort, high impact)
- Long-term security improvements

#### 7. Appendix
- Raw scan data
- Tool outputs
- Detailed technical findings

---

## Tools Available

| Tool | Purpose | Usage |
|------|---------|-------|
| `arp_table` | Discover local network hosts | Network discovery |
| `network_discover` | mDNS/DNS-SD service discovery | Service enumeration |
| `ssdp_discover` | UPnP device discovery | IoT/device discovery |
| `wifi_scan` | Wireless network scanning | WiFi enumeration |
| `port_scan` | TCP port scanning | Service discovery |
| `service_banner` | Service version detection | Banner grabbing |
| `cve_lookup` | CVE database lookup | Vulnerability matching |
| `default_creds_test` | Default credential testing | Authentication testing |
| `web_vuln_scan` | Web vulnerability scanning | Web app testing |
| `smb_enum` | SMB share enumeration | File share discovery |
| `traffic_capture` | Network packet capture | Traffic analysis |
| `execute_command` | Run system commands | Advanced testing |

---

## Constraints & Best Practices

### Legal & Ethical
- ⚠️ **Authorization Required** - Only test networks you own or have written permission to test
- 📋 **Document Everything** - Keep detailed logs of all actions taken
- 🚫 **No Destructive Actions** - Avoid DoS, data modification, or service disruption
- 🤝 **Responsible Disclosure** - Report vulnerabilities responsibly

### Technical
- ⏱️ **Rate Limiting** - Avoid aggressive scanning that could trigger IDS/IPS
- 🔇 **Stealth** - Be mindful of detection when required
- 💾 **Data Privacy** - Handle captured data securely
- 🔄 **Reproducibility** - Document steps for verification

### Reporting
- 📊 **Executive Summary** - Non-technical overview for stakeholders
- 🔍 **Technical Details** - Detailed findings for security team
- 🎯 **Actionable** - Clear remediation steps
- 📈 **Prioritization** - Severity-based risk ranking

---

## Example Workflow

```bash
# Phase 1: Discovery
arp_table → network_discover → ssdp_discover → wifi_scan

# Phase 2: Enumeration
for each host:
  port_scan → service_banner → os_fingerprint

# Phase 3: Vulnerability Assessment
for each service:
  cve_lookup → default_creds_test
  if web_service:
    web_vuln_scan
  if smb_service:
    smb_enum

# Phase 4: Traffic Analysis (optional)
traffic_capture → protocol_analysis

# Phase 5: Generate Report
compile_findings → risk_assessment → remediation_plan
```

---

## Success Criteria

✅ All live hosts discovered
✅ All open services identified
✅ Service versions detected
✅ CVEs matched to vulnerable services
✅ Default credentials identified
✅ Misconfigurations documented
✅ Comprehensive report generated
✅ Remediation priorities established

---

## Notes

- This is a **comprehensive** assessment - adjust scope based on time/authorization
- Some tools may require root/admin privileges (traffic capture, raw sockets)
- Results will vary based on network configuration and security controls
- Always verify findings before reporting (avoid false positives)

---

**Last Updated:** 2026-03-09
