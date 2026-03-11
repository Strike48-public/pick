#!/usr/bin/env bash
# Network Recovery Script
# Use this if autopwn or monitor mode kills your network connection

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║    Network Recovery Script                    ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════╝${NC}"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}ERROR: This script must be run with sudo${NC}"
   echo "Usage: sudo ./recover-network.sh"
   exit 1
fi

echo -e "${YELLOW}[1/6]${NC} Stopping all monitor mode interfaces..."

# Find and stop all monitor interfaces
for iface in $(iw dev | grep -oP '(?<=Interface\s).*mon.*' || true); do
    echo -e "  ${BLUE}→${NC} Stopping monitor mode on: $iface"
    airmon-ng stop "$iface" 2>/dev/null || true
done

# Also try stopping monitor mode on common interface names
for iface in wlan0mon wlan1mon wlp0s20f3mon wlx00c0caad0e76mon; do
    if iw dev | grep -q "$iface"; then
        echo -e "  ${BLUE}→${NC} Stopping monitor mode on: $iface"
        airmon-ng stop "$iface" 2>/dev/null || true
    fi
done

echo -e "${GREEN}✓${NC} Monitor mode stopped on all interfaces"
echo ""

echo -e "${YELLOW}[2/6]${NC} Killing any lingering aircrack-ng processes..."

# Kill aircrack-ng processes
pkill -9 airodump-ng 2>/dev/null || true
pkill -9 aireplay-ng 2>/dev/null || true
pkill -9 airmon-ng 2>/dev/null || true

echo -e "${GREEN}✓${NC} Processes killed"
echo ""

echo -e "${YELLOW}[3/6]${NC} Restarting NetworkManager..."

# Restart NetworkManager
systemctl restart NetworkManager

# Wait for NetworkManager to start
sleep 2

# Check if NetworkManager is running
if systemctl is-active --quiet NetworkManager; then
    echo -e "${GREEN}✓${NC} NetworkManager is running"
else
    echo -e "${RED}✗${NC} NetworkManager failed to start"
    echo -e "${YELLOW}Trying to start manually...${NC}"
    systemctl start NetworkManager
    sleep 2
fi

echo ""

echo -e "${YELLOW}[4/6]${NC} Bringing up WiFi interfaces..."

# Bring up all WiFi interfaces
for iface in $(iw dev | grep -oP '(?<=Interface\s)(?!.*mon).*' || true); do
    echo -e "  ${BLUE}→${NC} Bringing up: $iface"
    ip link set "$iface" up 2>/dev/null || true
done

echo -e "${GREEN}✓${NC} WiFi interfaces enabled"
echo ""

echo -e "${YELLOW}[5/6]${NC} Scanning for available networks..."

# Give NetworkManager time to scan
sleep 3

# List available WiFi networks
echo -e "${BLUE}Available networks:${NC}"
nmcli device wifi list | head -10 || true

echo ""

echo -e "${YELLOW}[6/6]${NC} Checking connection status..."
echo ""

# Show connection status
nmcli device status

echo ""

# Check if we're connected
CONNECTED=$(nmcli -t -f STATE general || echo "disconnected")

if [[ "$CONNECTED" == "connected" ]]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✓ Network connection RESTORED                ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"

    # Show current connection details
    echo ""
    echo -e "${BLUE}Current connection:${NC}"
    nmcli -t -f NAME,TYPE,DEVICE connection show --active | grep -v '^:' || true

else
    echo -e "${YELLOW}╔════════════════════════════════════════════════╗${NC}"
    echo -e "${YELLOW}║  ⚠  Not connected - manual reconnection needed║${NC}"
    echo -e "${YELLOW}╚════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}To connect manually:${NC}"
    echo ""
    echo "  1. List networks:"
    echo "     nmcli device wifi list"
    echo ""
    echo "  2. Connect to a network:"
    echo "     sudo nmcli device wifi connect \"SSID\" password \"PASSWORD\""
    echo ""
    echo "  Or use the GUI network manager in your system tray"
fi

echo ""
echo -e "${BLUE}Recovery script completed.${NC}"
