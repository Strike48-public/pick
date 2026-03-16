# Roadmap: 30 → 100 Tools for Pick

**Current Status:** 30 tools (20 native + 10 external)
**Target:** 100 tools
**Gap:** 70 tools needed
**Strategy:** Prioritize by value, focus on CLI-friendly tools with clear automation potential

---

## Tool Selection Criteria

✅ **Include:**
- Clear CLI interfaces (avoid GUI-only)
- Wide protocol/format support (maximize coverage)
- Active maintenance (community-supported)
- Structured output (JSON, XML, or parseable)
- Minimal dependencies
- High pentesting value

❌ **Exclude:**
- GUI-only tools
- Abandoned/unmaintained projects
- Tools that duplicate existing functionality
- Overly complex setup requirements
- Platform-specific without cross-platform value

---

## Phase Distribution (70 Tools)

| Phase | Tools | Focus | Timeline |
|-------|-------|-------|----------|
| **Phase 3** | 15 tools | Web Application Security | 1 week |
| **Phase 4** | 15 tools | Post-Exploitation & Lateral Movement | 1 week |
| **Phase 5** | 15 tools | Network Exploitation & MITM | 1 week |
| **Phase 6** | 10 tools | Forensics & Analysis | 1 week |
| **Phase 7** | 15 tools | Specialized & Utility Tools | 1 week |

**Total:** 70 tools, ~5 weeks

---

## Phase 3: Web Application Security (15 Tools)

**Goal:** Comprehensive web app testing coverage

### Tier 1: Scanners & Fuzzing (8 tools)
1. **SQLMap** - SQL injection automation (Python)
2. **Nuclei** - Template-based vulnerability scanner (Go)
3. **WPScan** - WordPress vulnerability scanner (Ruby)
4. **Wfuzz** - Web application fuzzer (Python)
5. **Arjun** - HTTP parameter discovery (Python)
6. **Commix** - Command injection exploitation (Python)
7. **NoSQLMap** - NoSQL injection automation (Python)
8. **XSStrike** - XSS detection and exploitation (Python)

### Tier 2: Content Discovery & Analysis (7 tools)
9. **Feroxbuster** - Content discovery (Rust, fast alternative to dirb/gobuster)
10. **Dirsearch** - Web path scanner (Python)
11. **Hakrawler** - Fast web crawler (Go)
12. **Sublist3r** - Subdomain enumeration (Python)
13. **Amass** - In-depth DNS enumeration (Go)
14. **httprobe** - HTTP probe for domains (Go)
15. **Waybackurls** - Fetch URLs from Wayback Machine (Go)

**Implementation Notes:**
- Most are Python/Go (easy CLI integration)
- SQLMap is #1 priority (industry standard)
- Nuclei has 1000+ vulnerability templates
- Focus on structured output (JSON preferred)

---

## Phase 4: Post-Exploitation & Lateral Movement (15 Tools)

**Goal:** Windows/Linux post-exploitation, credential harvesting, persistence

### Tier 1: Windows Post-Exploitation (8 tools)
1. **Impacket-Secretsdump** - Extract Windows credentials (Python)
2. **Impacket-PSExec** - Remote command execution via SMB (Python)
3. **Impacket-WMIExec** - WMI-based execution (Python)
4. **Impacket-GetUserSPNs** - Kerberoasting (Python)
5. **Impacket-GetNPUsers** - AS-REP roasting (Python)
6. **BloodHound-Python (bloodhound-py)** - AD attack path mapping (Python)
7. **CrackMapExec** - Swiss army knife for pentesting networks (Python)
8. **Evil-WinRM** - Windows Remote Management shell (Ruby)

### Tier 2: Linux Post-Exploitation (4 tools)
9. **LinPEAS** - Linux privilege escalation enumeration (Bash)
10. **LinEnum** - Linux enumeration (Bash)
11. **Linux-Exploit-Suggester** - Suggest kernel exploits (Perl)
12. **GTFOBins Lookup** - SUID/capabilities abuse (Data/Script)

### Tier 3: Cross-Platform (3 tools)
13. **PEASS-ng** - Privilege escalation suite (Bash/PowerShell)
14. **LaZagne** - Credential recovery (Python)
15. **Mimipenguin** - Linux credential dumper (Python/Bash)

**Implementation Notes:**
- Impacket scripts can be wrapped into 1-2 tools with subcommands
- BloodHound requires Neo4j (consider SharpHound collector only)
- CrackMapExec is extremely valuable (network pivoting)
- LinPEAS is trivial (bash script)

---

## Phase 5: Network Exploitation & MITM (15 Tools)

**Goal:** Network attacks, traffic manipulation, credential interception

### Tier 1: MITM & Interception (6 tools)
1. **Bettercap** - MITM framework (Go)
2. **Responder** - LLMNR/NBT-NS poisoning (Python)
3. **mitmproxy** - Interactive HTTPS proxy (Python)
4. **SSLstrip** - SSL stripping attack (Python)
5. **DNSChef** - DNS proxy for phishing (Python)
6. **Evilgrade** - Fake update attacks (Perl)

### Tier 2: Network Reconnaissance (5 tools)
7. **Netdiscover** - Active/passive network reconnaissance (C)
8. **ARPscan** - ARP scanning tool (C)
9. **Nbtscan** - NetBIOS name scanner (C)
10. **SNMPwalk** - SNMP enumeration (C)
11. **Onesixtyone** - Fast SNMP scanner (C)

### Tier 3: Protocol Analysis (4 tools)
12. **Wireshark/TShark** - Packet analysis (C)
13. **Scapy** - Packet manipulation (Python)
14. **Yersinia** - Layer 2 attack framework (C)
15. **Ettercap** - Comprehensive MITM suite (C)

**Implementation Notes:**
- Bettercap and Responder are top priorities
- mitmproxy excellent for API testing
- TShark provides CLI access to Wireshark
- Scapy requires Python scripting (advanced)

---

## Phase 6: Forensics & Analysis (10 Tools)

**Goal:** Memory forensics, disk analysis, artifact extraction

### Tier 1: Memory Forensics (3 tools)
1. **Volatility 3** - Memory forensics framework (Python)
2. **Rekall** - Memory forensics (Python)
3. **Lime** - Linux memory extractor (C kernel module)

### Tier 2: Disk Forensics (4 tools)
4. **Sleuth Kit (TSK)** - File system analysis (C)
5. **Autopsy** - Digital forensics platform (Java, CLI via TSK)
6. **Foremost** - File carving (C)
7. **Bulk Extractor** - Extract features from disk images (C++)

### Tier 3: Artifact Analysis (3 tools)
8. **ExifTool** - Metadata extraction (Perl)
9. **Strings** - Extract strings from binaries (C, GNU utility)
10. **Binwalk** - Firmware analysis (Python)

**Implementation Notes:**
- Volatility 3 is Python 3 (easier than v2)
- TSK provides CLI tools (fls, icat, etc.)
- ExifTool handles 100+ file formats
- Foremost and Bulk Extractor are fast C tools

---

## Phase 7: Specialized & Utility Tools (15 Tools)

**Goal:** Fill gaps, add specialized capabilities

### Tier 1: Password & Hash Tools (5 tools)
1. **Hashcat** - GPU password cracking (C/OpenCL)
2. **CeWL** - Custom wordlist generator from websites (Ruby)
3. **Crunch** - Wordlist generator (C)
4. **hash-identifier** - Hash type identification (Python)
5. **Pipal** - Password analysis (Ruby)

### Tier 2: Wireless Tools (4 tools)
6. **Aircrack-ng** - WiFi security suite (C)
7. **Wifite** - Automated WiFi attack tool (Python)
8. **Reaver** - WPS PIN attack (C)
9. **Bully** - WPS brute-force (C)

### Tier 3: Utility & Automation (6 tools)
10. **Searchsploit** - Exploit database search (Bash)
11. **Metasploit (msfconsole)** - Exploitation framework (Ruby)
12. **Ncat** - Netcat alternative (C, from Nmap)
13. **Socat** - Relay/redirect (C)
14. **Proxychains** - Proxy tools through SOCKS/HTTP (C)
15. **Ngrok** - Secure tunneling (Go binary)

**Implementation Notes:**
- Hashcat requires GPU drivers (optional)
- Aircrack-ng suite = multiple tools (aireplay, airodump, etc.)
- Metasploit via msfconsole RPC interface
- Searchsploit queries local exploit-db
- Proxychains needs configuration

---

## Implementation Strategy

### Batch Processing
- Group similar tools by language/runtime
- Implement Python tools together (shared parsing patterns)
- Implement Go tools together (similar CLI patterns)
- Create reusable parsers per output format

### Code Organization
```
crates/tools/src/external/
  web/           # Phase 3 (sqlmap, nuclei, wpscan, etc.)
  postexploit/   # Phase 4 (impacket, crackmapexec, linpeas, etc.)
  network/       # Phase 5 (bettercap, responder, tshark, etc.)
  forensics/     # Phase 6 (volatility, sleuthkit, exiftool, etc.)
  specialized/   # Phase 7 (hashcat, aircrack, metasploit, etc.)
```

### Testing Strategy
- Unit tests for schema validation (all tools)
- Integration tests for output parsing
- Runtime tests marked as `#[ignore]` (require sandbox)
- Manual testing via Strike48 chat

### Dependency Management
- Track all external_dependencies in schemas
- Document installation time per tool
- Note special requirements (GPU, kernel modules, etc.)
- Create installation bundles for common tool groups

---

## Tool Count Breakdown

| Category | Current | Phase 3 | Phase 4 | Phase 5 | Phase 6 | Phase 7 | Total |
|----------|---------|---------|---------|---------|---------|---------|-------|
| **Network Scanning** | 4 | - | - | 5 | - | 1 | 10 |
| **Web Testing** | 5 | 15 | - | - | - | - | 20 |
| **Post-Exploitation** | 2 | - | 15 | - | - | - | 17 |
| **Network Exploitation** | - | - | - | 10 | - | 1 | 11 |
| **Forensics** | - | - | - | - | 10 | - | 10 |
| **Password/Hash** | 2 | - | - | - | - | 5 | 7 |
| **Wireless** | 3 | - | - | - | - | 4 | 7 |
| **Specialized** | - | - | - | - | - | 9 | 9 |
| **Native Tools** | 14 | - | - | - | - | - | 14 |
| **TOTAL** | **30** | **45** | **60** | **70** | **80** | **95+** | **100+** |

---

## Success Metrics

### Per Phase
- ✅ All tools compile without errors
- ✅ All schemas declare external dependencies
- ✅ Unit tests pass (schema validation)
- ✅ Integration tests pass (parsing)
- ✅ Documentation updated
- ✅ Committed and pushed

### Overall (100 Tools)
- ✅ 100+ registered tools in registry
- ✅ All external tools declare dependencies
- ✅ Comprehensive test coverage
- ✅ Clear documentation
- ✅ Organized by category
- ✅ Ready for production use

---

## Timeline Estimate

| Phase | Tools | Days | Calendar |
|-------|-------|------|----------|
| Phase 3 | 15 | 5 | Week 1 |
| Phase 4 | 15 | 5 | Week 2 |
| Phase 5 | 15 | 5 | Week 3 |
| Phase 6 | 10 | 3 | Week 4 |
| Phase 7 | 15 | 5 | Week 5 |
| **Total** | **70** | **23** | **~5 weeks** |

**Aggressive:** 3 tools/day = ~23 days
**Realistic:** 2-3 tools/day = ~30 days
**Conservative:** 1-2 tools/day = ~50 days

---

## Next Steps

**Immediate (Phase 3):**
1. Start with SQLMap (highest priority, well-documented)
2. Add Nuclei (template-based, structured output)
3. Batch implement remaining 13 web tools
4. Test end-to-end via Strike48 chat
5. Commit and push

**Do you want to start with Phase 3 (Web Application Security)?**
