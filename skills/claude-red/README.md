# Claude-Red Skills Integration

This directory contains offensive security skills extracted from the [Claude-Red](https://github.com/SnailSploit/claude-red) repository and adapted for Pick's multi-agent penetration testing pipeline.

## Directory Structure

```
claude-red/
├── condensed/
│   └── core-bundle.md          # Condensed skills for Red Team agent (~1,700 tokens)
├── specialists/
│   ├── web-app-specialist.md   # Full web application testing skills
│   ├── api-specialist.md       # Full API security testing skills
│   ├── binary-specialist.md    # Full binary analysis and exploit dev skills
│   └── ai-security-specialist.md # Full AI/LLM security testing skills
└── README.md                   # This file
```

## Integration Points

### Red Team Agent
- Loads `condensed/core-bundle.md` in system prompt
- Provides comprehensive knowledge across all domains
- Uses condensed methodology to decide when to spawn specialists
- Total addition: ~1,700 tokens (minimal context overhead)

### Specialist Agents
- Each loads full domain-specific skills from `specialists/`
- Web App Specialist: SQLi, XSS, SSRF, SSTI, XXE, file upload, etc.
- API Specialist: GraphQL, JWT, OAuth, REST vulnerabilities
- Binary Specialist: Exploit development, crash analysis, reverse engineering
- AI Security Specialist: Prompt injection, jailbreaking, RAG poisoning

## Skills Condensation Strategy

**Core Bundle (for Red Team):**
- Fast-checking methodology (complete checklist)
- Vulnerability classes with key patterns and real CVEs
- Attack chain construction guidance
- Spawn decision criteria

**Specialist Skills (for sub-agents):**
- Full methodologies from Claude-Red SKILL.md files
- Complete checklists and test cases
- Detailed CVE case studies and PoCs
- Tool-specific guidance and command examples

## Source Attribution

Original skills by [SnailSploit](https://snailsploit.com) from the [Claude-Red](https://github.com/SnailSploit/claude-red) project (MIT License).

Adapted for Pick's multi-agent architecture with permission under MIT license terms.

## Maintenance

Skills should be periodically updated to reflect:
- New CVEs and vulnerability patterns
- Emerging attack techniques
- Tool evolution and new capabilities
- Mitigation bypasses and evasion methods

Update cadence: Quarterly review recommended, immediate updates for critical new techniques.
