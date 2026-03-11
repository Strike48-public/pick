# Network Recovery Scripts

If autopwn or monitor mode kills your network connection, use these recovery scripts.

---

## 🚨 Emergency Recovery (FAST)

**When:** Your network is down RIGHT NOW and you need it back IMMEDIATELY.

```bash
cd ~/Code/pick
sudo ./emergency-wifi-fix.sh
```

**What it does:**
- Stops all monitor mode interfaces
- Kills aircrack-ng processes
- Restarts NetworkManager
- Shows connection status

**Time:** ~5 seconds

---

## 🔧 Full Recovery (THOROUGH)

**When:** You want a complete network recovery with detailed status.

```bash
cd ~/Code/pick
sudo ./recover-network.sh
```

**What it does:**
1. Stops all monitor mode interfaces (wlan0mon, wlan1mon, etc.)
2. Kills lingering aircrack-ng processes (airodump-ng, aireplay-ng)
3. Restarts NetworkManager service
4. Brings up all WiFi interfaces
5. Scans for available networks
6. Shows detailed connection status
7. Provides manual reconnection instructions if needed

**Time:** ~10-15 seconds

**Example output:**
```
╔════════════════════════════════════════════════╗
║    Network Recovery Script                    ║
╚════════════════════════════════════════════════╝

[1/6] Stopping all monitor mode interfaces...
  → Stopping monitor mode on: wlx00c0caad0e76mon
✓ Monitor mode stopped on all interfaces

[2/6] Killing any lingering aircrack-ng processes...
✓ Processes killed

[3/6] Restarting NetworkManager...
✓ NetworkManager is running

[4/6] Bringing up WiFi interfaces...
  → Bringing up: wlp0s20f3
  → Bringing up: wlx00c0caad0e76
✓ WiFi interfaces enabled

[5/6] Scanning for available networks...
Available networks:
  *  SSID           MODE   CHAN  RATE  SIGNAL
  *  Tomek          Infra  5     130   ▂▄▆█
     Guest-Network  Infra  11    54    ▂▄__

[6/6] Checking connection status...

DEVICE         TYPE      STATE
wlp0s20f3      wifi      connected
wlx00c0caad0e76 wifi      disconnected

╔════════════════════════════════════════════════╗
║  ✓ Network connection RESTORED                ║
╚════════════════════════════════════════════════╝

Current connection:
Tomek 1,802-11-wireless,wlp0s20f3
```

---

## 📋 Manual Recovery Commands

If the scripts don't work, run these commands manually:

### 1. Stop monitor mode
```bash
sudo airmon-ng stop wlan0mon
sudo airmon-ng stop wlx00c0caad0e76mon
```

### 2. Kill aircrack processes
```bash
sudo pkill -9 airodump-ng
sudo pkill -9 aireplay-ng
```

### 3. Restart NetworkManager
```bash
sudo systemctl restart NetworkManager
```

### 4. List available networks
```bash
nmcli device wifi list
```

### 5. Connect to a network
```bash
sudo nmcli device wifi connect "YourSSID" password "YourPassword"
```

---

## 🛡️ Prevention: Before Running Autopwn

### Check your connection method
```bash
nmcli device status
```

**Safe:** Using ethernet (`enp0s31f6`) or VPN (`tailscale0`)
**Risky:** Connected via WiFi (`wlp0s20f3` = CONNECTED)

### Identify which adapter will be used
```bash
cat ~/.config/pentest-connector/settings.json | grep wifi_adapter
```

**Safe:** USB adapter (`wlx00c0caad0e76`) different from active connection
**Risky:** Same adapter as active WiFi connection

### The WiFi Warning Dialog

The autopwn Quick Action should show a warning if you're connected via WiFi:

```
⚠️  WiFi Connection Warning

You are currently connected via WiFi.
Running autopwn will temporarily disconnect NetworkManager.

Adapter: wlp0s20f3 (Internal WiFi)
Selected: wlx00c0caad0e76 (USB Adapter)

Risk Level: MEDIUM

Proceed anyway?
[Cancel] [Proceed]
```

---

## 🔍 Troubleshooting

### "NetworkManager won't start"

```bash
# Check logs
sudo journalctl -u NetworkManager -n 50

# Force restart
sudo systemctl stop NetworkManager
sudo killall NetworkManager
sudo systemctl start NetworkManager
```

### "Interface stuck in monitor mode"

```bash
# Check interfaces
iw dev

# Manually stop monitor mode
sudo ip link set wlan0mon down
sudo iw dev wlan0mon del

# Restart interface
sudo ip link set wlan0 up
```

### "Can't see any networks"

```bash
# Check if interface is up
ip link show

# Check if rfkill is blocking
rfkill list

# Unblock if needed
sudo rfkill unblock wifi

# Rescan
sudo nmcli device wifi rescan
```

### "Connected but no internet"

```bash
# Check DNS
systemd-resolve --status

# Restart DNS resolver
sudo systemctl restart systemd-resolved

# Flush DNS cache
sudo resolvectl flush-caches

# Renew DHCP lease
sudo dhclient -r && sudo dhclient
```

---

## 🚀 Quick Reference

| Situation | Command |
|-----------|---------|
| Emergency (network down NOW) | `sudo ./emergency-wifi-fix.sh` |
| Full recovery with status | `sudo ./recover-network.sh` |
| Check current connection | `nmcli device status` |
| List available networks | `nmcli device wifi list` |
| Connect manually | `sudo nmcli device wifi connect "SSID" password "PASS"` |
| Check what's in monitor mode | `iw dev \| grep mon` |
| Kill all aircrack processes | `sudo pkill -9 airodump-ng aireplay-ng` |

---

## 📝 Notes

- **Recovery scripts are safe** - They won't delete data or break your system
- **Run with sudo** - Network management requires root privileges
- **USB adapter behavior** - USB WiFi adapters will disconnect when in monitor mode (this is expected)
- **Internal WiFi** - Should stay connected unless explicitly used for autopwn
- **Automatic reconnection** - NetworkManager will usually auto-reconnect after restart

---

**Last Updated:** 2026-03-10
