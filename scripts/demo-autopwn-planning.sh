#!/usr/bin/env bash
# Demonstrate AutoPwn planning without WiFi hardware

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "╔═══════════════════════════════════════════════════╗"
echo "║   AutoPwn Planning Tool Demo                      ║"
echo "║   Safe demonstration - no WiFi interaction        ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

# Build first
echo "📦 Building project..."
cargo build --package pentest-tools --release --quiet
echo "✓ Build complete"
echo ""

echo "═══════════════════════════════════════════════════"
echo "Demo 1: WEP Network (Easy Target)"
echo "═══════════════════════════════════════════════════"
echo "Scenario: Old router with WEP encryption"
echo "  - SSID: OldRouter"
echo "  - Security: WEP"
echo "  - Signal: -55 dBm (good)"
echo "  - Clients: 2 (connected devices)"
echo ""

# Note: We can't actually run the tool yet because it's not exposed as a CLI
# This would require building the CLI app or using the tool directly
# For now, this is a demonstration script showing what we WOULD test

echo "Expected Result:"
echo "  ✓ Recommends WEP attack strategy"
echo "  ✓ Target: 40,000 IVs"
echo "  ✓ Estimated time: ~10 minutes"
echo "  ✓ Method: Fake auth + ARP replay"
echo "  ✓ Confidence: 95%"
echo ""

echo "═══════════════════════════════════════════════════"
echo "Demo 2: WPA2 with Clients (Feasible)"
echo "═══════════════════════════════════════════════════"
echo "Scenario: Modern router with clients connected"
echo "  - SSID: HomeNetwork"
echo "  - Security: WPA2-PSK"
echo "  - Signal: -60 dBm (good)"
echo "  - Clients: 3 (can deauth)"
echo ""

echo "Expected Result:"
echo "  ✓ Recommends WPA2 attack"
echo "  ✓ Capture: Active deauth"
echo "  ✓ Crack: Dictionary (RockYou)"
echo "  ✓ Estimated time: ~2 hours"
echo "  ✓ Confidence: 80%"
echo ""

echo "═══════════════════════════════════════════════════"
echo "Demo 3: Known Vendor Default (High Confidence)"
echo "═══════════════════════════════════════════════════"
echo "Scenario: Router with default SSID pattern"
echo "  - SSID: NETGEAR42"
echo "  - Security: WPA2-PSK"
echo "  - Signal: -50 dBm (excellent)"
echo "  - Clients: 5 (very active)"
echo ""

echo "Expected Result:"
echo "  ✓ Detects Netgear vendor pattern"
echo "  ✓ Recommends mask attack"
echo "  ✓ Pattern: ?u?l?l?l?l?l?l?d?d?d"
echo "  ✓ Estimated time: ~1 hour"
echo "  ✓ Confidence: 90% (default SSID boost)"
echo ""

echo "═══════════════════════════════════════════════════"
echo "Demo 4: Poor Conditions (Not Feasible)"
echo "═══════════════════════════════════════════════════"
echo "Scenario: Weak signal, no clients, enterprise"
echo "  - SSID: CorporateWiFi"
echo "  - Security: WPA2-Enterprise"
echo "  - Signal: -85 dBm (weak)"
echo "  - Clients: 0"
echo ""

echo "Expected Result:"
echo "  ✗ Attack not recommended"
echo "  ✗ Reason: Enterprise authentication not supported"
echo "  ✗ Feasibility: 0%"
echo ""

echo "═══════════════════════════════════════════════════"
echo "Testing Strategy Selection (Unit Tests)"
echo "═══════════════════════════════════════════════════"
echo ""

cargo test --package pentest-tools strategy::tests -- --nocapture 2>&1 | grep -E "(test |✓|ok\. [0-9]+ passed)" || true

echo ""
echo "═══════════════════════════════════════════════════"
echo "Testing Vendor Intelligence (Unit Tests)"
echo "═══════════════════════════════════════════════════"
echo ""

cargo test --package pentest-tools vendor_intel::tests -- --nocapture 2>&1 | grep -E "(test |✓|ok\. [0-9]+ passed)" || true

echo ""
echo "╔═══════════════════════════════════════════════════╗"
echo "║   Demo Complete                                   ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""
echo "To actually run the tools on a real network:"
echo "  1. Set up an isolated test network (YOUR network only)"
echo "  2. Build the CLI: cargo build --release"
echo "  3. See: docs/autopwn-testing-guide.md"
echo ""
echo "⚠️  Remember: Only test on networks you own!"
echo ""
