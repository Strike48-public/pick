#!/usr/bin/env bash
# EMERGENCY WiFi Recovery - Run this if your network is down NOW

[[ $EUID -ne 0 ]] && exec sudo "$0" "$@"

echo "🚨 EMERGENCY NETWORK RECOVERY"
echo ""

# Stop ALL monitor interfaces immediately
echo "→ Stopping monitor mode..."
for iface in $(iw dev 2>/dev/null | grep -oP '(?<=Interface\s).*' || true); do
    [[ $iface == *mon* ]] && airmon-ng stop "$iface" 2>/dev/null
done

# Kill all aircrack processes
echo "→ Killing aircrack processes..."
pkill -9 airodump-ng aireplay-ng airmon-ng 2>/dev/null || true

# Restart NetworkManager NOW
echo "→ Restarting NetworkManager..."
systemctl restart NetworkManager
sleep 3

# Status
nmcli device status

echo ""
if nmcli -t -f STATE general 2>/dev/null | grep -q connected; then
    echo "✓ CONNECTED!"
else
    echo "⚠ Still disconnected - run: sudo ./recover-network.sh"
    echo "   Or manually: sudo nmcli device wifi connect \"YourSSID\" password \"YourPassword\""
fi
