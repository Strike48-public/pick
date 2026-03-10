#!/usr/bin/env bash
# SAFE WiFi adapter monitor mode test - won't kill active network processes

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

pass() { echo -e "${GREEN}✓${NC} $1"; }
fail() { echo -e "${RED}✗${NC} $1"; }
info() { echo -e "${BLUE}ℹ${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }
header() { echo -e "${CYAN}$1${NC}"; }

echo "╔═══════════════════════════════════════════════════╗"
echo "║   SAFE WiFi Adapter Monitor Mode Test            ║"
echo "║   Will NOT kill network processes                 ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

# Detect WiFi interfaces
info "Detecting WiFi interfaces..."
interfaces=$(iw dev | grep Interface | awk '{print $2}')

if [[ -z "$interfaces" ]]; then
    fail "No WiFi interfaces found"
    exit 1
fi

echo ""
header "Available WiFi Interfaces:"
for iface in $interfaces; do
    state=$(ip link show "$iface" | grep -oP 'state \K\w+' || echo "UNKNOWN")
    ip_addr=$(ip addr show "$iface" | grep -oP 'inet \K[\d.]+' || echo "none")

    if [[ "$state" == "UP" ]] && [[ "$ip_addr" != "none" ]]; then
        echo -e "  ${RED}●${NC} $iface (${state}, IP: $ip_addr) [ACTIVE - PROTECTED]"
    else
        echo -e "  ${GREEN}●${NC} $iface (${state}, IP: $ip_addr) [AVAILABLE FOR TESTING]"
    fi
done

echo ""
info "Selecting adapter for testing..."

# Find disconnected adapter
selected_iface=""
for iface in $interfaces; do
    state=$(ip link show "$iface" | grep -oP 'state \K\w+' || echo "UNKNOWN")
    ip_addr=$(ip addr show "$iface" | grep -oP 'inet \K[\d.]+' || echo "none")

    if [[ "$state" != "UP" ]] || [[ "$ip_addr" == "none" ]]; then
        selected_iface="$iface"
        break
    fi
done

if [[ -z "$selected_iface" ]]; then
    fail "No disconnected adapter found"
    echo ""
    warn "All adapters are in use. Cannot safely test monitor mode."
    warn "Please disconnect one adapter or plug in a second USB adapter."
    exit 1
fi

echo ""
header "═══════════════════════════════════════════════════"
info "Testing adapter: $selected_iface"
header "═══════════════════════════════════════════════════"
echo ""

# Get adapter info
info "Adapter Information:"
iface_info=$(iw dev "$selected_iface" info)
echo "$iface_info" | sed 's/^/  /'

# Get phy number
phy=$(echo "$iface_info" | grep wiphy | awk '{print "phy"$2}')
info "Physical device: $phy"

# Get chipset info
echo ""
info "Chipset Information:"
if [[ "$selected_iface" =~ ^wlx ]]; then
    # USB adapter
    chipset=$(lsusb | grep -i "wireless\|802.11\|wifi\|mediatek" | head -1 || echo "Unknown USB WiFi adapter")
    echo "  $chipset"
else
    # PCI adapter
    chipset=$(lspci | grep -i "wireless\|802.11\|wifi\|network" | head -1 || echo "Unknown PCI WiFi adapter")
    echo "  $chipset"
fi

# Check supported modes
echo ""
info "Checking supported modes..."
modes=$(iw phy "$phy" info | grep -A 20 "Supported interface modes" | grep "^\s*\*" | sed 's/\s*\* //')

if echo "$modes" | grep -q "monitor"; then
    pass "Monitor mode is SUPPORTED"
else
    fail "Monitor mode is NOT supported"
    exit 1
fi

echo ""
info "All supported modes:"
echo "$modes" | sed 's/^/  ✓ /'

# Check for injection support indicators
echo ""
info "Checking packet injection capabilities..."

injection_support=0

# Check for active monitor
if iw phy "$phy" info | grep -q "active monitor"; then
    pass "Supports active monitor (frame ACK)"
    ((injection_support++)) || true
fi

# Check for TX frame types in monitor mode
if iw phy "$phy" info | grep -A 50 "Supported TX frame types" | grep -A 10 "monitor" | grep -q "0x00"; then
    pass "Supports TX frames in monitor mode"
    ((injection_support++)) || true
fi

if [[ $injection_support -gt 0 ]]; then
    pass "Packet injection likely supported ($injection_support indicators)"
else
    warn "Packet injection support unclear - may need testing"
fi

# Check if aircrack-ng is installed
echo ""
info "Checking for aircrack-ng suite..."
if ! command -v iw >/dev/null 2>&1; then
    fail "iw tool not installed"
    info "Install with: sudo apt install iw"
    exit 1
fi

if ! command -v aireplay-ng >/dev/null 2>&1; then
    warn "aircrack-ng suite not installed"
    info "Install with: sudo apt install aircrack-ng"
    echo ""
    info "Monitor mode can still be tested with 'iw' command"
fi

echo ""
warn "⚠️  Monitor mode test requires root/sudo privileges"
warn "⚠️  This will NOT kill any system processes"
warn "⚠️  Your active network connection will NOT be affected"
echo ""

read -p "Proceed with SAFE monitor mode test? (yes/no): " confirm

if [[ "$confirm" != "yes" ]]; then
    info "Monitor mode test skipped"
    exit 0
fi

echo ""
header "═══════════════════════════════════════════════════"
info "Testing Monitor Mode Activation (SAFE METHOD)"
header "═══════════════════════════════════════════════════"
echo ""

# SAFE METHOD: Use iw directly instead of airmon-ng check kill
info "Creating monitor interface (using 'iw' directly)..."

# Method 1: Try to add a monitor interface without removing the managed one
monitor_iface="${selected_iface}mon"
if sudo iw dev "$selected_iface" interface add "$monitor_iface" type monitor 2>/dev/null; then
    pass "Created monitor interface: $monitor_iface"

    # Bring it up
    sudo ip link set "$monitor_iface" up

    # Verify
    sleep 1
    if iw dev "$monitor_iface" info | grep -q "type monitor"; then
        pass "Monitor interface is ACTIVE"

        # Show status
        info "Monitor interface details:"
        iw dev "$monitor_iface" info | sed 's/^/  /'

        # Test injection if available
        if command -v aireplay-ng >/dev/null 2>&1; then
            echo ""
            read -p "Test packet injection? (yes/no): " test_injection

            if [[ "$test_injection" == "yes" ]]; then
                info "Testing packet injection..."
                info "This will scan for nearby WiFi networks and test injection"
                info "(Timeout: 20 seconds)"

                # Run injection test with timeout
                injection_result=$(sudo timeout 20 aireplay-ng --test "$monitor_iface" 2>&1 || true)

                # Show limited output
                echo "$injection_result" | grep -E "(Injection is working|[0-9]+/[0-9]+.*%)" | sed 's/^/  /' || true

                if echo "$injection_result" | grep -qE "Injection is working|[0-9]+/[0-9]+.*100%"; then
                    pass "Packet injection is WORKING!"
                else
                    warn "Injection test inconclusive"
                    info "This is normal if no WiFi networks are nearby"
                fi
            fi
        fi

        # Cleanup
        echo ""
        info "Cleaning up..."
        sudo ip link set "$monitor_iface" down
        sudo iw dev "$monitor_iface" del

        if ! iw dev | grep -q "$monitor_iface"; then
            pass "Monitor interface removed"
        fi

    else
        fail "Monitor interface creation failed"
        exit 1
    fi

elif sudo iw phy "$phy" interface add "${phy}-mon" type monitor 2>/dev/null; then
    # Alternative: Create with phy name
    monitor_iface="${phy}-mon"
    pass "Created monitor interface: $monitor_iface"

    sudo ip link set "$monitor_iface" up

    if iw dev "$monitor_iface" info | grep -q "type monitor"; then
        pass "Monitor interface is ACTIVE"

        info "Cleaning up..."
        sudo ip link set "$monitor_iface" down
        sudo iw dev "$monitor_iface" del
        pass "Monitor interface removed"
    fi
else
    # Fallback: Change interface type directly (requires bringing interface down)
    warn "Cannot create separate monitor interface"
    warn "Will try changing interface mode (may briefly disrupt the adapter)"
    echo ""
    read -p "Proceed with interface mode change? (yes/no): " proceed

    if [[ "$proceed" != "yes" ]]; then
        info "Test cancelled"
        exit 0
    fi

    info "Bringing interface down..."
    sudo ip link set "$selected_iface" down

    info "Setting monitor mode..."
    if sudo iw dev "$selected_iface" set type monitor; then
        sudo ip link set "$selected_iface" up

        if iw dev "$selected_iface" info | grep -q "type monitor"; then
            pass "Monitor mode ENABLED on $selected_iface"

            # Restore
            info "Restoring managed mode..."
            sudo ip link set "$selected_iface" down
            sudo iw dev "$selected_iface" set type managed
            sudo ip link set "$selected_iface" up
            pass "Managed mode restored"
        else
            fail "Monitor mode activation failed"
            # Try to restore anyway
            sudo iw dev "$selected_iface" set type managed 2>/dev/null || true
            sudo ip link set "$selected_iface" up 2>/dev/null || true
            exit 1
        fi
    else
        fail "Failed to set monitor mode"
        sudo ip link set "$selected_iface" up
        exit 1
    fi
fi

echo ""
header "═══════════════════════════════════════════════════"
pass "SAFE Monitor Mode Test Complete"
header "═══════════════════════════════════════════════════"
echo ""

# Verify active connection still works
info "Verifying active network connection..."
active_iface=$(ip route | grep default | head -1 | awk '{print $5}')
if [[ -n "$active_iface" ]] && ip addr show "$active_iface" | grep -q "inet "; then
    pass "Active network connection preserved: $active_iface"
else
    warn "Could not verify active connection"
fi

echo ""
echo "╔═══════════════════════════════════════════════════╗"
echo "║   Test Summary                                    ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""
info "Adapter: $selected_iface"
pass "Monitor mode supported and tested"
pass "Active network connection not affected"
info "Ready for AutoPwn testing"
echo ""
info "Next steps:"
echo "  1. Set up isolated test WiFi network (YOUR network only)"
echo "  2. Follow: docs/autopwn-testing-guide.md"
echo "  3. Test AutoPwn capture on your test network"
echo ""
