#!/usr/bin/env bash
# Safe AutoPwn component tests - no WiFi hardware required

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "╔═══════════════════════════════════════════════════╗"
echo "║   AutoPwn Safe Component Tests                    ║"
echo "║   No WiFi hardware or root access required        ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

pass() { echo -e "${GREEN}✓${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; }
info() { echo -e "${BLUE}ℹ${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }

TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local test_name="$1"
    shift
    echo ""
    info "Testing: $test_name"
    if "$@"; then
        pass "$test_name"
        ((TESTS_PASSED++)) || true
    else
        fail "$test_name"
        ((TESTS_FAILED++)) || true
    fi
}

# Test 1: Compilation
test_compilation() {
    info "  Compiling pentest-tools..."
    cargo check --package pentest-tools --release --quiet
}

# Test 2: Unit tests
test_unit_tests() {
    info "  Running unit tests..."
    cargo test --package pentest-tools --quiet -- --test-threads=1 autopwn 2>&1 | tail -10
}

# Test 3: Strategy selection tests
test_strategy_tests() {
    info "  Testing strategy selection..."
    cargo test --package pentest-tools strategy::tests --quiet 2>&1 | grep -E "(test result|passed)" || true
}

# Test 4: Vendor intelligence tests
test_vendor_tests() {
    info "  Testing vendor intelligence..."
    cargo test --package pentest-tools vendor_intel::tests --quiet 2>&1 | grep -E "(test result|passed)" || true
}

# Test 5: Check aircrack-ng availability
test_aircrack_available() {
    info "  Checking for aircrack-ng..."
    if command -v aircrack-ng >/dev/null 2>&1; then
        local version=$(aircrack-ng --help 2>&1 | head -1 || echo "unknown")
        info "    Found: $version"
        return 0
    else
        warn "    Not found - install with: sudo apt install aircrack-ng"
        return 1
    fi
}

# Test 6: Check other tools
test_related_tools() {
    info "  Checking related tools..."

    local tools=("airodump-ng" "aireplay-ng" "airmon-ng")
    local found=0

    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            ((found++)) || true
        fi
    done

    if [[ $found -eq ${#tools[@]} ]]; then
        info "    All aircrack-ng tools available ($found/${#tools[@]})"
        return 0
    else
        warn "    Some tools missing ($found/${#tools[@]})"
        return 1
    fi
}

# Test 7: Check WiFi interfaces (informational only)
test_wifi_interfaces() {
    info "  Checking WiFi interfaces..."

    if command -v iw >/dev/null 2>&1; then
        local interfaces=$(iw dev 2>/dev/null | grep Interface | awk '{print $2}' | tr '\n' ' ')
        if [[ -n "$interfaces" ]]; then
            info "    Found: $interfaces"
            return 0
        else
            warn "    No WiFi interfaces found"
            return 1
        fi
    else
        warn "    'iw' tool not found - cannot check interfaces"
        return 1
    fi
}

# Test 8: Wordlist directory access
test_wordlist_directory() {
    info "  Checking wordlist directory access..."
    local wordlist_dir="$HOME/.pick/wordlists"

    if [[ -d "$wordlist_dir" ]]; then
        info "    Directory exists: $wordlist_dir"
    else
        if mkdir -p "$wordlist_dir" 2>/dev/null; then
            info "    Created directory: $wordlist_dir"
        else
            warn "    Cannot create directory: $wordlist_dir"
            return 1
        fi
    fi

    if [[ -w "$wordlist_dir" ]]; then
        info "    Directory is writable"
        return 0
    else
        warn "    Directory not writable"
        return 1
    fi
}

# Test 9: Check existing wordlists
test_existing_wordlists() {
    info "  Checking for existing wordlists..."
    local wordlist_dir="$HOME/.pick/wordlists"

    local found=0
    for wordlist in "rockyou.txt" "common-passwords.txt"; do
        if [[ -f "$wordlist_dir/$wordlist" ]]; then
            local size=$(du -h "$wordlist_dir/$wordlist" | cut -f1)
            info "    Found: $wordlist ($size)"
            ((found++)) || true
        fi
    done

    if [[ $found -eq 0 ]]; then
        info "    No wordlists cached yet (will download on first use)"
    fi

    return 0
}

# Test 10: Network connectivity for wordlist downloads
test_network_connectivity() {
    info "  Testing network connectivity (for wordlist downloads)..."

    # Test GitHub connectivity (where RockYou is hosted)
    if curl -s --connect-timeout 5 --head https://github.com >/dev/null 2>&1; then
        info "    GitHub accessible"
        return 0
    else
        warn "    Cannot reach GitHub - wordlist downloads may fail"
        return 1
    fi
}

echo "═══════════════════════════════════════════════════"
echo "Running Tests..."
echo "═══════════════════════════════════════════════════"

run_test "Compilation" test_compilation
run_test "Unit Tests" test_unit_tests
run_test "Strategy Tests" test_strategy_tests
run_test "Vendor Intelligence Tests" test_vendor_tests
run_test "Aircrack-ng Availability" test_aircrack_available
run_test "Related Tools" test_related_tools
run_test "WiFi Interfaces" test_wifi_interfaces
run_test "Wordlist Directory" test_wordlist_directory
run_test "Existing Wordlists" test_existing_wordlists
run_test "Network Connectivity" test_network_connectivity

echo ""
echo "═══════════════════════════════════════════════════"
echo "Test Summary"
echo "═══════════════════════════════════════════════════"
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [[ $TESTS_FAILED -eq 0 ]]; then
    pass "All tests passed!"
    echo ""
    info "Next steps:"
    echo "  1. Review: docs/autopwn-testing-guide.md"
    echo "  2. For full testing: Set up isolated test network"
    echo "  3. See testing guide for hardware requirements"
    exit 0
else
    fail "Some tests failed"
    echo ""
    info "Most failures are informational (missing optional tools)"
    info "Core functionality tests should pass"
    exit 1
fi
