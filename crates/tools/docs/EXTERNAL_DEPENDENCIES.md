# External Dependencies in Pick Tools

This document explains how Pick handles external tool dependencies.

## Overview

Pick supports 10 external penetration testing tools that are installed on-demand via `pacman` from the BlackArch repository. These tools are declared in the tool schema so users know what will be installed before execution.

## How It Works

### 1. Dependency Declaration

Each external tool declares its dependencies in the `ToolSchema`:

```rust
use pentest_core::tools::{ExternalDependency, ToolSchema};

ToolSchema::new("nmap", "Network scanner...")
    .external_dependency(ExternalDependency::new(
        "nmap",        // Binary name
        "nmap",        // Package name
        "Network Mapper - Security scanner for network exploration"
    ))
```

### 2. On-Demand Installation

When a tool is executed for the first time:

1. Pick checks if the binary exists using `which <binary_name>`
2. If not found, installs via `pacman -S --noconfirm <package_name>`
3. Installation typically takes 5-30 seconds depending on the package
4. Once installed, the tool is cached in the sandbox rootfs

### 3. User Visibility

Users can see which tools require external dependencies:

**Via Tool Schema (JSON):**
```json
{
  "name": "nmap",
  "description": "Industry-standard network scanner...",
  "external_dependencies": [
    {
      "binary_name": "nmap",
      "package_name": "nmap",
      "description": "Network Mapper - Security scanner for network exploration"
    }
  ],
  "parameters": { ... }
}
```

**Via Strike48 Chat:**
When a user asks to use a tool, the AI can check the schema and inform them:
- "This will install nmap (Network Mapper) on first use, which takes ~15 seconds."
- Tool installation happens automatically and transparently

## External Tools List

| Tool | Binary | Package | Description |
|------|--------|---------|-------------|
| **nmap** | nmap | nmap | Network Mapper - Security scanner for network exploration |
| **ffuf** | ffuf | ffuf | Fast web fuzzer written in Go |
| **gobuster** | gobuster | gobuster | Directory/DNS/vhost bruteforce tool written in Go |
| **rustscan** | rustscan | rustscan | Modern ultra-fast port scanner written in Rust |
| **masscan** | masscan | masscan | Internet-scale asynchronous TCP port scanner |
| **nikto** | nikto | nikto | Web server vulnerability scanner |
| **dirb** | dirb | dirb | Web content scanner for dictionary-based attacks |
| **enum4linux** | enum4linux | enum4linux | SMB/Windows enumeration tool |
| **hydra** | hydra | hydra | Parallelized login bruteforcer (THC Hydra) |
| **john** | john | john | John the Ripper password cracker |

## Implementation Details

### Core Types

**`ExternalDependency` struct:**
```rust
pub struct ExternalDependency {
    pub binary_name: String,   // Binary to check/execute
    pub package_name: String,  // Package to install via pacman
    pub description: String,   // Human-readable description
}
```

**`ToolSchema` methods:**
```rust
.external_dependency(dep: ExternalDependency) -> Self
.has_external_dependencies() -> bool
```

### Installation Helper

**`ensure_tool_installed()` function:**
- Checks if binary exists via `which`
- Installs via `pacman -S --noconfirm` if missing
- Logs installation progress
- Returns `Result<()>` for error handling

**`is_tool_installed()` function:**
- Checks if a binary is installed without triggering installation
- Useful for pre-flight checks

## Testing

External dependencies are tested in:
- `tests/external_dependencies_test.rs` - Verifies all 10 tools declare dependencies
- `tests/external_tools_test.rs` - Verifies tool registration and schema validity

## Benefits

1. **Transparency** - Users know what will be installed before execution
2. **On-Demand** - Tools only installed when needed, reducing bloat
3. **Sandbox Isolation** - Tools run in isolated environment
4. **Auto-Installation** - No manual setup required
5. **Persistent** - Once installed, tools remain available across sessions

## Future Enhancements

Potential future improvements:
- Batch installation of multiple tools
- Pre-install common tools at setup time
- Progress indicators for installation
- Disk space estimation before installation
- Dependency version information
