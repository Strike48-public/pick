#!/usr/bin/env bash
# Simplified security audit for Pick
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Use command to bypass shell functions
RG="command rg"

echo "=================================="
echo "Pick Security Audit (Simplified)"
echo "=================================="
echo ""

# 1. Secrets
echo "1. Hardcoded Secrets Check"
echo "--------------------------"
$RG -i "AKIA[0-9A-Z]{16}" crates/ && echo "WARNING: AWS key pattern found" || echo "OK: No AWS keys"
$RG "ghp_[A-Za-z0-9]{36}" crates/ && echo "WARNING: GitHub PAT found" || echo "OK: No GitHub tokens"
echo ""

# 2. Command Injection
echo "2. Command Injection Check"
echo "--------------------------"
$RG "format!.*Command::new" crates/ && echo "WARNING: format! with Command" || echo "OK: No format! with Command"
echo ""

# 3. Unsafe Blocks
echo "3. Unsafe Block Count"
echo "---------------------"
UNSAFE_COUNT=$($RG "unsafe " crates/ -c 2>/dev/null | awk -F: '{s+=$2} END {print s+0}')
echo "Found: $UNSAFE_COUNT unsafe blocks"
[ "$UNSAFE_COUNT" -gt 0 ] && echo "REVIEW NEEDED: Audit all unsafe blocks"
echo ""

# 4. SQL Injection
echo "4. SQL Injection Check"
echo "----------------------"
$RG "format!.*(SELECT|INSERT|UPDATE|DELETE)" crates/ && echo "WARNING: SQL with format!" || echo "OK: No SQL string formatting"
echo ""

# 5. Path Traversal
echo "5. Path Traversal Check"
echo "-----------------------"
$RG "File::(open|create).*\+" crates/ && echo "INFO: File ops with concatenation" || echo "OK: No obvious path concat"
echo ""

# 6. Weak Crypto
echo "6. Weak Cryptography Check"
echo "--------------------------"
$RG "\bmd5\b|\bMd5\b" crates/ --type rust && echo "INFO: MD5 usage found" || echo "OK: No MD5"
$RG "verify.*false" crates/ && echo "WARNING: TLS verification disabled" || echo "OK: TLS verification enabled"
echo ""

# 7. Timeouts
echo "7. Timeout Configuration Check"
echo "-------------------------------"
$RG "timeout.*None" crates/ && echo "INFO: Operations without timeout" || echo "OK: Timeouts configured"
echo ""

echo "=================================="
echo "Audit Complete"
echo "=================================="
echo "Review any WARNING items immediately"
echo "Review INFO items for context"
echo ""
echo "See docs/SECURITY_LESSONS_FROM_HONEYSLOP.md for detailed guidance"
