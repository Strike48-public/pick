# PR Testing Strategy

## Overview

This document outlines the testing strategy to ensure PRs are CI-ready before submission and to avoid "hiccups" like we had with PR #61.

## Pre-Push Checklist

Before pushing any PR branch, run these commands locally:

```bash
# 1. Format check
cargo fmt --all --check

# 2. Clippy with warnings as errors (matches CI)
cargo clippy --all-targets --all-features -- -D warnings

# 3. Run tests
cargo test --all-features

# 4. Check for security advisories
cargo audit

# 5. Verify build works
cargo build --release
```

## CI Failure Response Protocol

When CI fails on a PR:

### 1. Identify the Failure Type

```bash
gh pr checks <PR_NUMBER> --repo Strike48-public/pick
```

Common failure types:
- **Format** - Code not formatted with `cargo fmt`
- **Clippy** - Linting warnings/errors
- **Test** - Test failures
- **Build** - Compilation errors
- **Gitleaks** - Secrets detected in commits
- **Dependency Audit** - Vulnerable dependencies

### 2. Reproduce Locally

```bash
# Check out the PR branch
git fetch origin pull/<PR_NUMBER>/head:pr-<PR_NUMBER>
git checkout pr-<PR_NUMBER>

# Run the failing check locally
cargo fmt --all --check           # For format failures
cargo clippy -- -D warnings        # For clippy failures
cargo test                         # For test failures
cargo build                        # For build failures
```

### 3. Fix and Verify

```bash
# Fix the issue
cargo fmt --all                    # Auto-fix formatting
# ... make other fixes ...

# Verify the fix
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release

# Commit and push
git add -A
git commit -m "fix: resolve <issue_type> CI failure"
git push origin <branch_name>
```

## Common CI Issues and Fixes

### Format Failures

**Symptom:** CI fails on "Format" check

**Fix:**
```bash
cargo fmt --all
git commit -am "fix: format code with cargo fmt"
git push
```

### Clippy Errors

**Symptom:** CI fails on "Clippy" check with specific warnings

**Common issues:**
- `unused-imports` - Remove unused imports
- `len-zero` - Use `!vec.is_empty()` instead of `vec.len() > 0`
- `unnecessary-to-owned` - Remove unnecessary `.to_string()` calls
- `manual_checked_ops` - Use `checked_div()` instead of manual checks

**Fix:**
```bash
# Run clippy to see errors
cargo clippy --all-targets --all-features -- -D warnings

# Fix issues based on output
# Then verify
cargo clippy --all-targets --all-features -- -D warnings

git commit -am "fix: resolve clippy warnings"
git push
```

### Circular Dependency Issues

**Symptom:** `cyclic package dependency` error

**Common cause:** Adding a dependency that creates a circular reference

**Fix:**
- Use feature flags with optional dependencies
- Use static buffers or callbacks to break the cycle
- Refactor to move shared code to a lower-level crate

### Test Failures

**Symptom:** CI fails on "Test" check

**Fix:**
```bash
# Run tests locally
cargo test --all-features

# Debug specific test
cargo test <test_name> -- --nocapture

# Fix the test or implementation
git commit -am "fix: resolve test failures"
git push
```

### Gitleaks Failures

**Symptom:** CI fails on "Gitleaks" check - secret detected

**Fix:**
```bash
# Find the commit with the secret
git log --all --full-history -- "*<file_with_secret>*"

# Remove from history (DANGEROUS - coordinate with team)
git filter-branch --force --index-filter \
  'git rm --cached --ignore-unmatch <file_with_secret>' \
  --prune-empty --tag-name-filter cat -- --all

# Force push (only if approved)
git push origin <branch> --force
```

**Prevention:** 
- Never commit `.env` files
- Use `.gitignore` for sensitive files
- Use placeholder values in committed config examples

## Pre-Merge Verification

Before requesting PR merge:

```bash
# 1. Rebase on main
git fetch origin main
git rebase origin/main

# 2. Run full test suite
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release

# 3. Check CI status
gh pr checks <PR_NUMBER> --repo Strike48-public/pick

# 4. Verify all checks are green
# All checks should show "pass" status
```

## Automated Pre-Push Checks

To automate these checks, you can add a git pre-push hook:

```bash
# Create .git/hooks/pre-push
cat > .git/hooks/pre-push <<'EOF'
#!/bin/bash
set -e

echo "Running pre-push checks..."

echo "1. Checking format..."
cargo fmt --all --check

echo "2. Running clippy..."
cargo clippy --all-targets --all-features -- -D warnings

echo "3. Running tests..."
cargo test --all-features

echo "All checks passed!"
EOF

chmod +x .git/hooks/pre-push
```

## When Multiple PRs Are Open

Priority order for testing and merging:

1. **Security fixes** - Highest priority
2. **Dependency updates** - Quick wins
3. **Bug fixes** - Blocking issues
4. **Features** - New functionality
5. **POCs/experiments** - Lowest priority

**Merge order to minimize conflicts:**
1. Merge smallest/simplest first (e.g., Actions Checkout v5)
2. Merge security fixes next
3. Merge features that touch different areas
4. Handle conflicts in remaining PRs

## CI Wait Times

After pushing:
- Format check: ~15-30 seconds
- Clippy: ~2-4 minutes
- Tests: ~2-5 minutes
- Full CI: ~5-7 minutes

**Don't close the session until CI passes** - the "landing the plane" protocol.

## Testing New PRs Before Pushing

For substantial PRs (like three-agent pipeline):

### 1. Local Testing

```bash
# Run the application
./run-pentest.sh headless dev

# Test the feature manually
# ... use the feature ...

# Check logs for errors
tail -f logs/*.log
```

### 2. Pre-Flight Checks

```bash
# All formatting, linting, tests
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo build --release
```

### 3. Create PR

```bash
# Push branch
git push origin <branch>

# Create PR
gh pr create --repo Strike48-public/pick \
  --title "feat: ..." \
  --body "..." \
  --base main
```

### 4. Monitor CI

```bash
# Watch CI status
gh pr checks <PR_NUMBER> --repo Strike48-public/pick --watch
```

### 5. Fix Any Failures

```bash
# If CI fails, fix and push again
# Repeat until all checks pass
```

## Summary

**Key Principles:**

1. ✅ **Always run local checks before pushing**
2. ✅ **Fix CI failures immediately - don't let them accumulate**
3. ✅ **Use `cargo fmt` and `cargo clippy -- -D warnings` to match CI**
4. ✅ **Monitor CI after pushing - don't assume it passes**
5. ✅ **Don't close the session until CI is green** (landing the plane)
6. ✅ **Test features locally before creating PRs**
7. ✅ **Small, focused PRs are easier to test and review**

**Tools:**

- `cargo fmt --all --check` - Check formatting
- `cargo clippy --all-targets --all-features -- -D warnings` - Lint with warnings as errors
- `cargo test --all-features` - Run test suite
- `cargo audit` - Check dependencies for vulnerabilities
- `gh pr checks <PR>` - Monitor CI status

**Follow this strategy and you'll avoid CI hiccups!** 🚀
