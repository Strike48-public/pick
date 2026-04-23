#!/usr/bin/env bash
# Security audit script based on HoneySlop vulnerability patterns
# Scans Pick codebase for potential security issues

set -euo pipefail

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==================================="
echo "Pick Security Audit"
echo "Based on HoneySlop Vulnerability Patterns"
echo "==================================="
echo ""

# Track findings
CRITICAL=0
WARNING=0
INFO=0

# Helper functions
critical() {
    echo -e "${RED}[CRITICAL]${NC} $1"
    ((CRITICAL++))
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    ((WARNING++))
}

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
    ((INFO++))
}

echo "1. Checking for hardcoded secrets..."
echo "-----------------------------------"
if rg -i "AKIA[0-9A-Z]{16}" crates/ 2>/dev/null; then
    critical "Found AWS access key pattern"
fi
if rg "ghp_[A-Za-z0-9]{36}" crates/ 2>/dev/null; then
    critical "Found GitHub PAT pattern"
fi
if rg "xox[bpasrt]-[0-9A-Za-z-]+" crates/ 2>/dev/null; then
    critical "Found Slack token pattern"
fi
if rg "sk_live_[A-Za-z0-9]{24,}" crates/ 2>/dev/null; then
    critical "Found Stripe live key pattern"
fi
if rg "-----BEGIN.*PRIVATE KEY-----" crates/ 2>/dev/null; then
    critical "Found private key in code"
fi
info "Secret scan complete"
echo ""

echo "2. Checking for command injection risks..."
echo "-------------------------------------------"
if rg "Command::new.*format!" crates/ 2>/dev/null; then
    warning "Found format! with Command::new - verify arguments are safe"
fi
if rg "shell.*true|/bin/sh.*-c" crates/ 2>/dev/null; then
    warning "Found shell=true or /bin/sh -c pattern"
fi
info "Command injection scan complete"
echo ""

echo "3. Checking for unsafe blocks..."
echo "---------------------------------"
UNSAFE_COUNT=$(rg "unsafe \{" crates/ --count-matches 2>/dev/null | awk -F: '{sum+=$2} END {print sum+0}')
if [ "${UNSAFE_COUNT:-0}" -gt 0 ]; then
    warning "Found $UNSAFE_COUNT unsafe blocks - ensure they are documented and audited"
    echo "Locations:"
    rg "unsafe \{" crates/ -n 2>/dev/null | head -20 || true
fi
info "Unsafe block scan complete"
echo ""

echo "4. Checking for SQL injection risks..."
echo "---------------------------------------"
if rg "format!.*SELECT|format!.*INSERT|format!.*UPDATE|format!.*DELETE" crates/ 2>/dev/null; then
    critical "Found format! used with SQL keywords - use parameterized queries"
fi
if rg "concat!.*SELECT|concat!.*INSERT" crates/ 2>/dev/null; then
    critical "Found concat! with SQL - use parameterized queries"
fi
info "SQL injection scan complete"
echo ""

echo "5. Checking for path traversal risks..."
echo "----------------------------------------"
if rg "join\(.*user|join\(.*input" crates/ 2>/dev/null; then
    warning "Found path join with user/input variable - verify canonicalization"
fi
if rg "File::open.*\+|File::create.*\+" crates/ 2>/dev/null; then
    warning "Found string concatenation with File operations"
fi
info "Path traversal scan complete"
echo ""

echo "6. Checking for regex DoS risks..."
echo "-----------------------------------"
if rg '\(\.\+\)\+|\(\.\*\)\*|\(\.\+\)\*' crates/ 2>/dev/null; then
    warning "Found nested regex quantifiers - potential ReDoS"
fi
info "Regex DoS scan complete"
echo ""

echo "7. Checking for weak cryptography..."
echo "-------------------------------------"
if rg "md5|Md5" crates/ 2>/dev/null | grep -v "// " | grep -v "//" ; then
    warning "Found MD5 usage - use SHA-256 or stronger"
fi
if rg "sha1|Sha1" crates/ 2>/dev/null | grep -v "// " | grep -v "//" ; then
    warning "Found SHA-1 usage - use SHA-256 or stronger"
fi
if rg "verify.*false|danger.*accept" crates/ 2>/dev/null; then
    critical "Found TLS verification disabled"
fi
info "Cryptography scan complete"
echo ""

echo "8. Checking for insecure random number generation..."
echo "------------------------------------------------------"
if rg "rand::random\(\)|random\(\)" crates/ 2>/dev/null; then
    info "Found random() usage - verify OsRng used for security-critical values"
fi
info "RNG scan complete"
echo ""

echo "9. Checking for timeout configuration..."
echo "-----------------------------------------"
if rg "timeout.*None|\.timeout\(None\)" crates/ 2>/dev/null; then
    warning "Found operations without timeout - could enable DoS"
fi
info "Timeout scan complete"
echo ""

echo "10. Checking for URL validation..."
echo "-----------------------------------"
if rg "reqwest::|hyper::" crates/ 2>/dev/null | head -5; then
    info "Found HTTP client usage - verify URL validation and SSRF protection"
fi
info "URL validation scan complete"
echo ""

# Summary
echo "==================================="
echo "Security Audit Summary"
echo "==================================="
echo -e "${RED}Critical issues: $CRITICAL${NC}"
echo -e "${YELLOW}Warnings: $WARNING${NC}"
echo -e "${GREEN}Info: $INFO${NC}"
echo ""

if [ "$CRITICAL" -gt 0 ]; then
    echo -e "${RED}FAILED: Critical security issues found${NC}"
    echo "Review issues above and fix before deployment"
    exit 1
elif [ "$WARNING" -gt 0 ]; then
    echo -e "${YELLOW}PASSED WITH WARNINGS: Review recommended${NC}"
    echo "See docs/SECURITY_LESSONS_FROM_HONEYSLOP.md for guidance"
    exit 0
else
    echo -e "${GREEN}PASSED: No critical issues found${NC}"
    echo "Continue with regular security best practices"
    exit 0
fi
