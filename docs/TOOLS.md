# Pick Tool Catalog

Complete reference of all penetration testing tools available in Pick.

**Total tools:** 80+ (native + external integrations)

---

## Table of Contents

- [Network Scanning](#network-scanning)
- [WiFi Tools](#wifi-tools)
- [Web Vulnerability Scanning](#web-vulnerability-scanning)
- [Credential Testing](#credential-testing)
- [Enumeration](#enumeration)
- [Exploitation](#exploitation)
- [Post-Exploitation](#post-exploitation)
- [Evidence & Reporting](#evidence--reporting)
- [Specialized Tools](#specialized-tools)

---

## Network Scanning

### Port Scanning

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `port_scan` | Native | TCP port scanning with concurrent connections | No |
| `nmap` | External | Comprehensive network scanner (service detection, OS fingerprinting) | Yes (some features) |
| `rustscan` | External | Ultra-fast port scanner (faster than nmap for initial discovery) | No |
| `masscan` | External | Internet-scale port scanner (1000+ ports/sec) | Yes |
| `masscan_fast` | External | Masscan in fast mode (optimized for speed) | Yes |
| `unicornscan` | External | Asynchronous stateless TCP/UDP scanner | Yes |
| `hping3` | External | Network probing and packet crafting | Yes |

### Network Discovery

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `arp_table` | Native | Read local ARP cache | No |
| `network_discover` | Native | mDNS service discovery (Bonjour, Avahi) | No |
| `ssdp_discover` | Native | UPnP device discovery via SSDP | No |
| `netdiscover` | External | Active/passive ARP reconnaissance | Yes |
| `arpscan` | External | ARP scanning and fingerprinting | Yes |
| `arping` | External | Send ARP REQUEST packets | Yes |

### Service Enumeration

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `service_banner` | Native | Grab service banners | No |
| `nmap_vuln` | External | Nmap with vulnerability scripts | Yes |

---

## WiFi Tools

### WiFi Scanning

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `wifi_scan` | Native | Basic WiFi network scanning | Yes |
| `wifi_scan_detailed` | Native | Detailed WiFi info (channels, signal strength, encryption) | Yes |

### WiFi Penetration Testing (Autopwn Suite)

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `autopwn_plan` | Native | Generate attack plan for WiFi target | Yes |
| `autopwn_capture` | Native | Capture WPA handshakes | Yes |
| `autopwn_crack` | Native | Crack captured handshakes | Yes |
| `autopwn_orchestrator` | Native | Full automated WiFi attack workflow | Yes |
| `autopwn_network_plan` | Native | Network-wide attack planning | Yes |
| `aircrackng` | External | WEP/WPA/WPA2 cracking suite | Yes |
| `bettercap` | External | Man-in-the-middle attack framework | Yes |
| `responder` | External | LLMNR/NBT-NS/MDNS poisoning | Yes |

---

## Web Vulnerability Scanning

### Web Application Testing

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `web_vuln_scan` | Native | Generic web vulnerability scanner | No |
| `nikto` | External | Web server vulnerability scanner | No |
| `nikto_ng` | External | Next-generation Nikto | No |
| `sqlmap` | External | Automatic SQL injection exploitation | No |
| `xsstrike` | External | XSS vulnerability detection | No |
| `dalfox` | External | Fast parameter analysis and XSS scanning | No |
| `nuclei` | External | Template-based vulnerability scanner | No |
| `wpscan` | External | WordPress security scanner | No |
| `joomscan` | External | Joomla vulnerability scanner | No |
| `droopescan` | External | Drupal/Joomla/Moodle scanner | No |
| `wafw00f` | External | Web application firewall detection | No |

### Content Discovery

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `ffuf` | External | Fast web fuzzer | No |
| `ffuf_dns` | External | DNS subdomain fuzzing | No |
| `feroxbuster` | External | Fast content discovery (Rust) | No |
| `gobuster` | External | Directory/file/DNS busting | No |
| `dirb` | External | Web content scanner | No |
| `dirsearch` | External | Web path scanner | No |
| `wfuzz` | External | Web application fuzzer | No |

### Parameter Discovery

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `arjun` | External | HTTP parameter discovery | No |
| `paramspider` | External | Parameter mining from web archives | No |

### Reconnaissance

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `katana` | External | Next-gen web crawler | No |
| `gospider` | External | Fast web spider (Go) | No |
| `hakrawler` | External | Web crawler for wayback/robots/sitemap | No |
| `gau` | External | Fetch known URLs from AlienVault, Common Crawl, URLScan | No |
| `waybackurls` | External | Fetch URLs from Wayback Machine | No |
| `whatweb` | External | Web scanner and fingerprinting | No |

---

## Credential Testing

### Credential Harvesting

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `credential_harvest` | Native | Extract credentials from memory/files | Yes (memory) |
| `default_creds` | Native | Test default credentials | No |

### Password Cracking

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `john` | External | John the Ripper password cracker | No |
| `hashcat` | External | Advanced password recovery | No |
| `crunch` | External | Wordlist generator | No |

### Authentication Testing

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `hydra` | External | Network logon cracker (SSH, FTP, HTTP, etc.) | No |
| `changeme` | External | Default credential scanner | No |

---

## Enumeration

### DNS Enumeration

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `subfinder` | External | Subdomain discovery | No |
| `sublist3r` | External | Subdomain enumeration | No |
| `assetfinder` | External | Find domains and subdomains | No |
| `amass` | External | In-depth DNS enumeration | No |
| `dnsenum` | External | DNS enumeration | No |
| `dnsrecon` | External | DNS reconnaissance | No |
| `fierce` | External | DNS reconnaissance and subdomain brute-forcing | No |

### SMB/NetBIOS Enumeration

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `smb_enum` | Native | SMB share enumeration | No |
| `smbmap` | External | SMB share enumeration and exploitation | No |
| `enum4linux` | External | Windows/Samba enumeration | No |
| `enum4linux_ng` | External | Next-gen enum4linux | No |
| `nbtscan` | External | NetBIOS name scanner | No |

### SNMP Enumeration

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `snmpwalk` | External | SNMP MIB tree walker | No |
| `onesixtyone` | External | Fast SNMP scanner | No |

### LDAP Enumeration

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `ldapsearch` | External | LDAP search utility | No |

---

## Exploitation

### Exploit Frameworks

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `searchsploit` | External | Exploit-DB search | No |

### Command Injection

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `commix` | External | Command injection exploitation | No |

---

## Post-Exploitation

### Lateral Movement

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `lateral_movement` | Native | Automated lateral movement | Varies |
| `impacket_psexec` | External | PsExec via Impacket | No |
| `impacket_wmiexec` | External | WMI execution via Impacket | No |
| `impacket_secretsdump` | External | Dump secrets via DCSync | No |
| `impacket_getuserspns` | External | Kerberoasting via Impacket | No |
| `evilwinrm` | External | WinRM shell | No |
| `crackmapexec` | External | Swiss army knife for pentesting networks | No |

### Privilege Escalation

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `linpeas` | External | Linux privilege escalation enumeration | No |

---

## Evidence & Reporting

### Evidence Collection

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `screenshot` | Native | Screen capture (base64 PNG) | No |
| `traffic_capture` | Native | Network packet capture (PCAP) | Yes |
| `inject_test_evidence` | Native | Test tool for three-agent pipeline | No |
| `tshark` | External | Network protocol analyzer | Yes |

### Session Management

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `session_export` | Native | Export session data | No |
| `begin_scan` | Native | Initialize scan session | No |

### File Operations

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `list_files` | Native | List files in directory | No |
| `read_file` | Native | Read file contents | No |
| `write_file` | Native | Write file contents | No |

---

## Specialized Tools

### System Information

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `device_info` | Native | System/device information gathering | No |
| `execute_command` | Native | Shell command execution | Depends |

### OSINT & Reconnaissance

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `whois` | External | Domain WHOIS lookup | No |
| `theharvester` | External | OSINT and email harvesting | No |
| `spiderfoot` | External | Automated OSINT intelligence gathering | No |
| `recon_ng` | External | Full-featured reconnaissance framework | No |

### Metadata Analysis

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `exiftool` | External | Read/write metadata | No |
| `cewl` | External | Custom wordlist generator from websites | No |

### Network Utilities

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `ncat` | External | Netcat replacement | No |
| `socat` | External | Multipurpose relay | No |
| `httprobe` | External | HTTP/HTTPS probe | No |

### SSL/TLS Testing

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `sslscan` | External | SSL/TLS scanner | No |
| `testssl` | External | Testing TLS/SSL encryption | No |

### Screenshot & Reporting

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `eyewitness` | External | Screenshot web applications | No |
| `skipfish` | External | Web application security scanner | No |

### CVE & Vulnerability Lookup

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `cve_lookup` | Native | CVE database lookup | No |

### Three-Agent Pipeline

| Tool | Type | Description | Requires Root |
|------|------|-------------|---------------|
| `spawn_specialist` | Native | Spawn specialized validation agent | No |

---

## Tool Dependencies

### External Dependencies

Most external tools require installation of BlackArch repository or manual installation:

```bash
# Install BlackArch repository (Arch Linux)
curl -O https://blackarch.org/strap.sh
chmod +x strap.sh
sudo ./strap.sh

# Install specific tools
sudo pacman -S nmap masscan rustscan nikto sqlmap hydra
```

### Platform-Specific Notes

- **Linux:** Full tool support (all tools available)
- **macOS:** Limited tool support (no BlackArch, manual install required)
- **Android:** Very limited tool support (no root-requiring tools without root)
- **iOS:** Extremely limited (sandbox restrictions)
- **Windows:** Via WSL2 (full Linux tool support)

---

## Tool Categories Summary

| Category | Native | External | Total |
|----------|--------|----------|-------|
| Network Scanning | 4 | 7 | 11 |
| WiFi Tools | 5 | 3 | 8 |
| Web Vulnerability | 1 | 19 | 20 |
| Credential Testing | 2 | 3 | 5 |
| Enumeration | 1 | 16 | 17 |
| Exploitation | 0 | 2 | 2 |
| Post-Exploitation | 1 | 8 | 9 |
| Evidence & Reporting | 6 | 1 | 7 |
| Specialized | 4 | 11 | 15 |
| **Total** | **24** | **70** | **94** |

---

## Adding New Tools

See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines on adding new tools.

**Quick reference:**

1. Create tool file in `crates/tools/src/`
2. Implement `PentestTool` trait
3. Add to `create_tool_registry()` in `lib.rs`
4. Implement platform-specific functionality in `crates/platform/`
5. Add tests
6. Update this catalog

---

**Last updated:** 2026-05-28
