# WiFi Hardware Access in Sandboxed Environment

## Overview

The dioxus-connector uses proot for sandboxed command execution. By default, WiFi hardware access is **enabled** to support penetration testing tools like `airmon-ng`, `airodump-ng`, and `iw` that require direct access to wireless adapters.

## What Gets Shared with the Sandbox

When `hardware_wifi_access` is enabled (default), the sandbox shares:

### 1. Device Nodes (`/dev`)
- **Shared via**: `--dev-bind /dev /dev`
- **Provides**: Direct access to wireless adapters (`/dev/rfkill`, etc.)
- **Required for**: Hardware control, monitor mode, packet injection

### 2. Sysfs (`/sys`)
- **Shared via**: `--bind /sys /sys`
- **Provides**: Network interface information and wireless hardware metadata
- **Contains**:
  - `/sys/class/net/*` - Network interface configuration
  - `/sys/class/ieee80211/*` - Wireless PHY (physical layer) information
  - `/sys/devices/*/net/*` - Device tree for network hardware

### 3. Runtime Directories (`/run`)
- **Shared via**: `--bind /run/NetworkManager /run/NetworkManager` (if exists)
- **Shared via**: `--bind /run/wpa_supplicant /run/wpa_supplicant` (if exists)
- **Provides**: Unix sockets for NetworkManager and wpa_supplicant communication
- **Required for**: Integration with system network management

## Configuration

### Default Behavior (Enabled)

```rust
let config = SandboxConfig::default();
// hardware_wifi_access = true by default
```

The connector automatically enables hardware WiFi access for all sandboxed commands.

### Explicitly Enable (if needed)

```rust
let config = SandboxConfig::default()
    .with_hardware_wifi();
```

### Disable for More Isolation

```rust
let config = SandboxConfig::default()
    .without_hardware_wifi();
```

When disabled:
- `/dev` is an isolated devtmpfs (no host hardware)
- `/sys` is not mounted
- `/run` directories are not shared
- WiFi tools will not work

## How WiFi Tools Use These Mounts

### `iw` (Wireless Configuration)

```bash
# Reads from /sys/class/net/wlan0/phy80211/
iw dev wlan0 scan

# Accesses /sys to enumerate wireless interfaces
iw dev
```

**Requires**: `/sys/class/net` and `/sys/class/ieee80211`

### `airmon-ng` (Monitor Mode)

```bash
# Changes interface mode via sysfs and rfkill
airmon-ng start wlan0
```

**Requires**:
- `/sys/class/net/wlan0/*` (read/write)
- `/dev/rfkill` (device node)
- `/sys/class/ieee80211/*` (PHY info)

### `airodump-ng` / `aireplay-ng` (Packet Capture/Injection)

```bash
# Opens raw sockets on monitor mode interface
airodump-ng wlan0mon
aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon
```

**Requires**:
- Monitor mode interface (created via airmon-ng)
- `/dev/rfkill` (to check radio status)
- Raw socket capabilities (via `CAP_NET_RAW` on tools)

## CRITICAL: Must Run Application with Sudo

**To access WiFi hardware, run the application with sudo on the host:**

```bash
sudo cargo run --package pentest-desktop
```

**Why this is required:**
- WiFi tools need to access `/dev/rfkill` and network interfaces
- These require **real root privileges**, not just user namespace root
- Proot user namespace alone provides "fake root" that can't access hardware
- Running with sudo on the host preserves real root inside the sandbox

**Inside the sandbox:**
- You are UID 0 (root)
- Commands work WITHOUT sudo prefix (already root)
- Don't use `sudo iw dev` - just use `iw dev`

See [PROOT_SUDO_EXPLAINED.md](./PROOT_SUDO_EXPLAINED.md) for detailed explanation of user namespace root vs real root.

---

## Verifying WiFi Access Inside Sandbox

### Check Interface Visibility

Run inside sandboxed shell:

```bash
# Should list wireless interfaces
iw dev

# Should show network interfaces including wlan0, wlp3s0, etc.
ls /sys/class/net/

# Should show wireless PHYs
ls /sys/class/ieee80211/
```

### Check Device Access

```bash
# Should exist and be accessible
ls -la /dev/rfkill

# Should show wireless device nodes
ls -la /sys/class/net/wlan0/
```

### Test Basic WiFi Commands

```bash
# Should list wireless interfaces
iw dev

# Should scan for networks (may require root)
sudo iw dev wlan0 scan

# Should show interface details
ip link show wlan0
```

## Troubleshooting

### "No wireless interfaces found"

**Cause**: WiFi adapter not detected or proot isolation too strict

**Solutions**:
1. Verify hardware WiFi access is enabled (check `SandboxConfig`)
2. Check if `/sys/class/net/` contains your wireless interface on the host
3. Ensure the connector is running with sufficient permissions
4. Check kernel driver support: `lsmod | grep -i wireless`

### "Operation not permitted" when enabling monitor mode

**Cause**: Missing rfkill device access or insufficient capabilities

**Solutions**:
1. Ensure `/dev/rfkill` is accessible: `ls -la /dev/rfkill`
2. Check rfkill status on host: `rfkill list`
3. Unblock wireless if blocked: `sudo rfkill unblock wifi`
4. Verify `airmon-ng` has file capabilities: `getcap /usr/sbin/airmon-ng`

### "/sys/class/net/wlan0: No such file or directory"

**Cause**: Sysfs not mounted or interface doesn't exist on host

**Solutions**:
1. Verify sysfs mount inside sandbox: `mount | grep sysfs`
2. Check if interface exists on host: `ip link show wlan0`
3. Ensure hardware WiFi access is enabled in config
4. Check proot arguments: should include `--bind /sys /sys`

### "Cannot connect to wpa_supplicant"

**Cause**: Runtime socket directory not shared

**Solutions**:
1. Check if `/run/wpa_supplicant` exists on host
2. Verify it's mounted in sandbox: `ls /run/wpa_supplicant`
3. Ensure wpa_supplicant service is running: `systemctl status wpa_supplicant`

## Security Considerations

### Why Enable by Default?

This is a **penetration testing** tool designed for authorized security assessments. The primary use case requires direct hardware access to wireless adapters.

### Attack Surface

When hardware WiFi access is enabled:
- ✅ **Pros**: Full WiFi tool functionality, monitor mode, packet injection
- ⚠️ **Cons**: Sandbox has access to real hardware, less isolation

**Mitigation**: The sandbox still provides:
- User namespace isolation (runs as root inside, unprivileged outside)
- Filesystem isolation (separate rootfs)
- Process isolation (separate PID namespace via --unshare-pid if needed)
- No host filesystem access (except explicitly mounted paths)

### When to Disable

Disable hardware WiFi access (`without_hardware_wifi()`) when:
- Running non-WiFi related tools
- Maximum isolation is required
- Testing in environments without wireless hardware
- Compliance requires strict sandbox boundaries

## Implementation Details

### Proot Arguments

**With hardware WiFi access** (default):

```bash
proot \
  --bind /path/to/rootfs / \
  --dev-bind /dev /dev \        # Share host devices
  --proc /proc \
  --bind /sys /sys \             # Share sysfs for wireless info
  --bind /run/NetworkManager /run/NetworkManager \  # If exists
  --bind /run/wpa_supplicant /run/wpa_supplicant \  # If exists
  --share-net \                  # Share network namespace
  ...
```

**Without hardware WiFi access**:

```bash
proot \
  --bind /path/to/rootfs / \
  --dev /dev \                   # Isolated devtmpfs
  --proc /proc \
  --share-net \                  # Share network namespace
  ...
```

### Key Differences

| Resource | With Hardware WiFi | Without Hardware WiFi |
|----------|-------------------|----------------------|
| `/dev` | Host devices (--dev-bind) | Isolated devtmpfs (--dev) |
| `/sys` | Host sysfs | Not mounted |
| `/run/NetworkManager` | Host socket (if exists) | Not mounted |
| `/run/wpa_supplicant` | Host socket (if exists) | Not mounted |
| Wireless tools | ✅ Fully functional | ❌ Cannot access hardware |

## Testing the Configuration

### Create a Test Script

```bash
#!/bin/bash
# test_wifi_access.sh

echo "=== Testing WiFi Access in Sandbox ==="

echo ""
echo "1. Checking /sys/class/net:"
ls -la /sys/class/net/ 2>/dev/null || echo "❌ /sys/class/net not accessible"

echo ""
echo "2. Checking /sys/class/ieee80211:"
ls -la /sys/class/ieee80211/ 2>/dev/null || echo "❌ /sys/class/ieee80211 not accessible"

echo ""
echo "3. Checking /dev/rfkill:"
ls -la /dev/rfkill 2>/dev/null || echo "❌ /dev/rfkill not accessible"

echo ""
echo "4. Listing wireless interfaces with iw:"
iw dev 2>/dev/null || echo "❌ iw command failed"

echo ""
echo "5. Listing network interfaces:"
ip link show | grep -E 'wl|wlan' || echo "❌ No wireless interfaces found"

echo ""
echo "=== Test Complete ==="
```

### Run via Execute Command Tool

```json
{
  "command": "bash",
  "args": ["-c", "ls /sys/class/net/ && iw dev"],
  "timeout_seconds": 10
}
```

Expected output should show wireless interfaces like `wlan0`, `wlp3s0`, etc.

## Related Documentation

- [AUTOPWN.md](./AUTOPWN.md) - Automated WiFi penetration testing
- [Sandbox Configuration](../crates/platform/src/desktop/sandbox/config.rs)
- [Proot Executor](../crates/platform/src/desktop/sandbox/proot.rs)

---

**Last Updated**: 2026-03-05
**Version**: 0.1.0
