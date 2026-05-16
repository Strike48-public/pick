# CLAUDE.md - Pick Project

This file provides project-specific guidance for the Pick penetration testing connector.

**Inherits from:** `/home/jtomek/Code/CLAUDE.md` (root configuration)

---

## Project Overview

Pick is a multi-platform penetration testing connector built with Dioxus (Rust). Each app instance IS a connector that registers with Strike48 and executes tools locally.

**Key technologies:**
- Rust (stable 1.92+)
- Dioxus (UI framework)
- Tokio (async runtime)
- Strike48 SDK (Matrix communication)

---

## Development Environment

### Prerequisites

- Rust 1.92+ (required by egui dependencies)
- Cargo and rustup
- libpcap-dev (for packet capture features)
- libssl-dev (for TLS)
- protobuf-compiler (for Protocol Buffers)

### Launch Commands

```bash
# Headless connector (preferred for testing)
./run-pentest.sh headless dev

# Or with just
just run-headless-env
```

### Current Configuration

- **Host:** `wss://disco-ball-us.strike48.com:443`
- **Tenant:** `use-prd-c-disco-ball`
- **Config:** `.env` file in project root

---

## Merge Conflict Resolution Checklist

When merging PRs that change function signatures, follow this systematic approach:

### 1. Identify Signature Changes

```bash
# Check what changed in the target branch
git diff main...HEAD -- '*.rs' | grep -A 5 -B 5 "^-.*fn.*\|^+.*fn.*"
```

### 2. Search for All Call Sites

**CRITICAL:** Don't assume you found all call sites. Search comprehensively:

```bash
# Find all references to the changed function
rg "function_name" --type rust

# Or use grep
grep -r "function_name" crates/ apps/ --include="*.rs"
```

### 3. Update Each Call Site

- Verify the new signature in the source
- Update ALL call sites to match
- Don't commit until all call sites are fixed

### 4. Local Validation BEFORE Push

**MANDATORY** before pushing any merge conflict resolution:

```bash
# 1. Check compilation
cargo check --all-targets

# 2. Run tests
cargo test --lib --bins

# 3. Run clippy
cargo clippy --all-targets -- -D warnings

# 4. Check for uncommitted changes
git status
git diff
```

### 5. Common Patterns to Watch

| Pattern | What to search for | Why |
|---------|-------------------|-----|
| Function signature change | All call sites of the function | Multiple callers may exist |
| Struct field addition | Struct construction sites | Builder patterns, Default impls |
| Enum variant change | Match statements | Exhaustive matching required |
| Trait method change | All trait implementations | Multiple impls across crates |

### 6. Red Flags

- **"It compiles locally but CI fails"** → Check for uncommitted changes
- **"Fixed one call site"** → Search for others before assuming you're done
- **"Merge conflict in function body"** → Signature may have changed too

---

## Common Gotchas

### Android Clippy Import

Always `use pentest_core::error::{Error, Result};` - missing `Error` import causes CI failure.

### Gitleaks Full History Scan

Gitleaks scans entire PR commit history. Secrets must never have existed in ANY commit. Use interactive rebase if one sneaks in.

### Hot Reload Limitation

`.rs` changes require full rebuild. Hot-reload does NOT pick up logic changes.

### Clippy Strictness

CI runs clippy with `-D warnings` (warnings = errors). Fix all warnings locally before pushing.

---

## Testing Requirements

### Test Coverage

- Minimum 80% coverage required
- Use `#[ignore]` for tests requiring exclusive resource access
- Tests must be concurrent-safe (no shared mutable globals without proper locking)

### Evidence Buffer Tests

Three tests in `crates/tools/src/evidence_producer.rs` are marked `#[ignore]` because they require exclusive buffer access:
- `evidence_buffer_enforces_capacity_limit`
- `evidence_buffer_near_full_detection`
- `push_is_non_blocking`

Run these separately: `cargo test --test evidence_producer -- --ignored`

### Screenshot Tests

Screenshot capture fails gracefully in headless CI environments (Wayland/X11 not available). This is expected behavior.

---

## CI/CD Pipeline

### GitHub Actions Workflows

| Workflow | Purpose | Trigger |
|----------|---------|---------|
| Multi-Arch Docker | Build arm64/amd64 images | PR, push to main |
| Helm Publish | Package Helm chart | PR, push to main |
| PII Check | Scan for sensitive data | PR |
| Rust Tests | Run test suite | PR, push to main |

### Build Time Expectations

- **Cargo check:** ~1-2 minutes (incremental)
- **Full test suite:** ~3-5 minutes
- **Docker multi-arch:** ~15-20 minutes
- **All checks:** ~20-30 minutes total

---

## Git Workflow

### Remotes

- `origin` = `Strike48-public/pick` (protected main)
- `fork` = `jtomek-strike48/pick` (your fork)

### Push Policy

Main branch is protected. Push to fork, then create PR:

```bash
git push fork feature/my-branch
gh pr create --base main
```

### Pre-Push Hook

The project has a pre-push hook that runs `cargo check --all-targets` automatically. Bypass with `--no-verify` only if you have a good reason.

---

## Code Quality Standards

### Required Before Commit

```bash
cargo fmt --all           # Format code
cargo clippy -- -D warnings  # Lint with zero warnings
cargo test                # Run tests
```

### Commit Message Format

Follow conventional commits:

```
<type>: <description>

<optional body>
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `ci`

**Never include:**
- Claude attribution lines
- Customer/tenant names (PII)
- Emojis or em-dashes

---

## Security Considerations

### Secrets Management

- Never commit secrets (API keys, tokens, credentials)
- Use `.env` files (already in `.gitignore`)
- Environment variables for sensitive config

### Customer Data

Customer/tenant names are PII. Never reference them in public artifacts:
- ❌ "Fixed issue for <customer-name> deployment"
- ✅ "Fixed deployment issue in production environment"

---

## Documentation

### Agent Notes Policy

Never commit agent planning documents:
- `*_PLAN.md`
- `*_IMPLEMENTATION.md`
- `START-HERE-*.md`
- `TESTING-*-TOMORROW.md`
- Files with ALL_CAPS names (except README, LICENSE, etc.)

These are session artifacts, not permanent documentation.

### Markdown Formatting

Markdown is auto-formatted via hooks and SpecKit integration. Format manually:

```bash
source .specify/scripts/bash/common.sh
format_markdown <file>
```

---

## Performance Notes

### Rust Build Optimization

- Use `cargo check` for fast syntax validation
- Use `cargo clippy` for linting (faster than full build)
- Use `cargo build` only when you need an executable
- Use `--all-targets` to include tests, benches, examples

### Test Execution

```bash
cargo test --lib --bins       # Fast: unit + integration tests only
cargo test --all-targets      # Slower: includes benchmarks, examples
cargo test -- --nocapture     # Show println! output
```

---

## Getting Help

- Local testing: `./run-pentest.sh headless dev`
- CI logs: `gh run view <run-id> --log-failed`
- PR status: `gh pr view <number>`

---

*This CLAUDE.md inherits from `/home/jtomek/Code/CLAUDE.md` for general patterns and adds Pick-specific guidance.*
