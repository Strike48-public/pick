# Tool Metadata Schema v1.0

## Overview

This schema defines the YAML metadata format for tools in the Pick platform. It combines best practices from Nuclei, MITRE ATT&CK, and Metasploit while adding Pick-specific extensions for scope enforcement, provenance tracking, and AI-powered discovery.

## Schema Structure

```yaml
id: <string>              # Unique tool identifier (lowercase, hyphenated)
version: <string>         # Tool version (semver preferred)

info:
  name: <string>          # Human-readable tool name
  description: <string>   # Clear, concise description (1-2 sentences)
  author: <string>        # Original tool author(s)
  license: <string>       # SPDX license identifier
  homepage: <string>      # Tool homepage URL
  repository: <string>    # Source repository URL

classification:
  category: <string>      # Primary category (see Category Taxonomy)
  subcategory: <string>   # Optional subcategory
  attack_phases: [<string>]  # Attack lifecycle phases
  mitre_techniques: [<string>]  # MITRE ATT&CK technique IDs (T####.###)
  severity: <string>      # Tool severity: info|low|medium|high|critical
  
capabilities: [<string>]  # List of tool capabilities (see Capability Taxonomy)

targets:
  - type: <string>        # Target type: ip|cidr|hostname|url|file|hash
    scope_required: <bool>  # Whether scope validation is required
    description: <string>  # Optional target description

parameters:
  - name: <string>        # Parameter name
    type: <string>        # Type: string|int|float|bool|enum|array
    required: <bool>      # Whether parameter is required
    default: <any>        # Default value (if not required)
    description: <string> # Parameter description
    values: [<any>]       # Valid values (for enum type)
    examples: [<string>]  # Example values

metadata:
  verified: <bool>        # Whether tool has been tested and verified
  installation:
    apt: <string>         # Debian/Ubuntu package name
    brew: <string>        # Homebrew formula name
    pacman: <string>      # Arch Linux package name
    cargo: <string>       # Rust crate name
    pip: <string>         # Python package name
    go: <string>          # Go package import path
    manual: <string>      # Manual installation instructions
  documentation: <string> # Official documentation URL
  
tags: [<string>]          # Free-form tags for discovery

provenance:
  scope_enforcement: <bool>      # Whether tool enforces scope
  command_sanitization: <bool>   # Whether commands are sanitized
  raw_response_capture: <bool>   # Whether raw output is captured

usage_patterns:
  common_workflows:
    - name: <string>      # Workflow name
      command: <string>   # Command template with {param} placeholders
      description: <string>  # Workflow description
      example_output: <string>  # Optional example output

alternatives:
  - name: <string>        # Alternative tool name
    reason: <string>      # Why to use alternative
    when_to_use: <string> # Specific scenarios for alternative

# Optional: Tool-specific extensions
extensions:
  <key>: <value>          # Tool-specific metadata
```

## Category Taxonomy

Primary categories (based on industry standard classifications):

- `reconnaissance` - Information gathering, OSINT, scanning
- `enumeration` - Service enumeration, banner grabbing
- `exploitation` - Exploit frameworks, exploit modules
- `webapp` - Web application testing
- `network` - Network scanning, packet analysis
- `password` - Password cracking, brute forcing
- `wireless` - Wireless network testing
- `forensics` - Digital forensics, memory analysis
- `reverse-engineering` - Binary analysis, decompilation
- `social-engineering` - Phishing, pretexting
- `post-exploitation` - Privilege escalation, lateral movement
- `reporting` - Report generation, documentation

## Capability Taxonomy

Hierarchical capability structure:

```
reconnaissance/
  ├── subdomain-enumeration
  │   ├── active
  │   └── passive
  ├── port-scanning
  │   ├── full
  │   └── fast
  ├── service-detection
  └── os-fingerprinting

webapp/
  ├── sql-injection
  ├── xss
  ├── csrf
  ├── file-upload
  ├── cms-scanning
  └── api-testing

network/
  ├── packet-capture
  ├── traffic-analysis
  ├── mitm
  └── sniffing

password/
  ├── hash-cracking
  ├── password-spraying
  ├── brute-force
  └── wordlist-generation

wireless/
  ├── wpa-cracking
  ├── wep-cracking
  ├── deauth-attack
  └── evil-twin

exploitation/
  ├── remote-code-execution
  ├── privilege-escalation
  ├── buffer-overflow
  └── exploit-development

forensics/
  ├── memory-analysis
  ├── disk-forensics
  ├── file-recovery
  └── timeline-analysis
```

## MITRE ATT&CK Mapping

Common technique mappings:

- `T1595` - Active Scanning
- `T1595.001` - Scanning IP Blocks
- `T1595.002` - Vulnerability Scanning
- `T1046` - Network Service Discovery
- `T1110` - Brute Force
- `T1110.001` - Password Guessing
- `T1110.002` - Password Cracking
- `T1110.003` - Password Spraying
- `T1040` - Network Sniffing
- `T1557` - Adversary-in-the-Middle
- `T1083` - File and Directory Discovery
- `T1059` - Command and Scripting Interpreter
- `T1003` - OS Credential Dumping

Full reference: https://attack.mitre.org/techniques/enterprise/

## Attack Phases

Standard attack lifecycle phases:

- `reconnaissance` - Initial information gathering
- `scanning` - Active probing and enumeration
- `exploitation` - Gaining initial access
- `persistence` - Maintaining access
- `privilege-escalation` - Elevating privileges
- `lateral-movement` - Moving through network
- `exfiltration` - Data theft
- `command-and-control` - C2 communications

## Severity Levels

- `info` - Informational tool (no direct security impact)
- `low` - Minor findings, low risk
- `medium` - Moderate security concerns
- `high` - Significant security issues
- `critical` - Critical vulnerabilities, immediate action required

## Example: Complete Tool Definition

See `tools/metadata/nmap.yaml` for a complete example.

## Validation Rules

1. `id` must be unique, lowercase, hyphenated (e.g., `nmap`, `sqlmap`, `nuclei-engine`)
2. `version` should follow semver when possible
3. `classification.category` must be from Category Taxonomy
4. `capabilities` should use hierarchical format (e.g., `reconnaissance/port-scanning/full`)
5. `mitre_techniques` must be valid ATT&CK technique IDs
6. `targets[].type` must be valid target type
7. `parameters[].type` must be valid parameter type
8. At least one `usage_patterns.common_workflows` entry required
9. `provenance` fields document security guarantees
10. `tags` should include relevant search terms

## File Naming Convention

- Location: `tools/metadata/{category}/{tool-id}.yaml`
- Example: `tools/metadata/reconnaissance/nmap.yaml`

## Version History

- v1.0 (2026-04-22) - Initial schema definition
