# Why Pick Requires Sudo for WiFi Tools

This document explains the technical requirements for WiFi penetration testing and why certain Pick features require root privileges.

---

## Quick Answer

**WiFi penetration testing tools require direct hardware access to wireless adapters.** This includes:
- Enabling monitor mode
- Packet injection
- Raw socket access
- Changing MAC addresses
- Controlling RF parameters

These operations require kernel-level privileges that only root (sudo) can provide.

---

## What is Bubblewrap (bwrap)?

**Bubblewrap** (`bwrap`) is a lightweight Linux sandboxing tool that creates isolated namespaces for running applications.

**Pick can optionally use bwrap to:**
- Isolate tool execution from the main process
- Limit filesystem access
- Restrict network capabilities
- Provide defense-in-depth security

**However:** Even with bwrap, WiFi tools still need elevated privileges because they require hardware access that cannot be namespaced.

---

## Why WiFi Tools Specifically Need Root

### 1. Monitor Mode

**What it is:** WiFi monitor mode allows the adapter to capture all wireless traffic, not just packets addressed to it.

**Why root is required:**
- Requires changing the adapter's operating mode via kernel drivers
- Uses `nl80211` netlink interface (privileged)
- Disables firmware-level filtering

**Tools that need this:**
- `wifi_scan`
- `wifi_scan_detailed`
- `autopwn_capture`
- `aircrack-ng`
- `airodump-ng`

### 2. Packet Injection

**What it is:** Sending raw 802.11 frames to the wireless medium.

**Why root is required:**
- Raw socket creation requires `CAP_NET_RAW` capability
- Firmware must be instructed to transmit crafted frames
- Timing and sequence control requires kernel access

**Tools that need this:**
- `autopwn_crack`
- `aireplay-ng`
- `mdk4`

### 3. Interface Management

**What it is:** Creating virtual interfaces, changing MAC addresses, setting channels.

**Why root is required:**
- `iw` commands require `CAP_NET_ADMIN` capability
- `/dev/rfkill` access needs root
- `/sys/class/net/` modifications are privileged

**Operations:**
- Creating `mon0` monitor interface
- MAC address spoofing
- Channel hopping
- TX power adjustment

### 4. Raw Socket Access

**What it is:** Creating sockets that can send/receive raw Ethernet frames.

**Why root is required:**
- `socket(AF_PACKET, SOCK_RAW, ...)` requires `CAP_NET_RAW`
- Bypasses normal network stack
- Can forge source addresses

---

## Security Implications

### Running Pick with Sudo

**Risks:**
- Pick process runs as root
- Compromised tool execution could affect entire system
- Malicious tools could escape sandbox

**Mitigations:**
- Pick only uses sudo for WiFi-specific operations
- Desktop mode runs GUI as user, tools as root
- Bubblewrap isolation (when available) limits blast radius

### Alternative: Capabilities

**Can we use Linux capabilities instead of sudo?**

Partially. You can grant specific capabilities:

```bash
# Grant CAP_NET_RAW and CAP_NET_ADMIN to the binary
sudo setcap cap_net_raw,cap_net_admin+eip /path/to/pentest-headless
```

**Limitations:**
- Still requires initial sudo to set capabilities
- Doesn't work for all WiFi operations
- Some drivers require full root regardless
- Capabilities don't persist across binary updates

### Recommended Approach

**For operators:**
1. Run Pick headless mode with sudo only when using WiFi tools
2. Use network scanning tools (port_scan, nmap) without sudo
3. Isolate Pick instances to dedicated VMs/containers when possible

**For development:**
1. Test WiFi features in isolated environments
2. Use `just run-headless-sudo` or `./run-pentest.sh headless` (includes sudo)
3. Never run development builds as root unnecessarily

---

## Platform Differences

### Linux

**Full WiFi support:**
- All monitor mode operations work
- Packet injection supported (driver-dependent)
- Bubblewrap available for isolation

**Recommended:**
```bash
# Install bubblewrap
sudo apt install bubblewrap

# Pick will automatically use it when available
./run-pentest.sh headless
```

### macOS

**Limited WiFi support:**
- Monitor mode supported via `airport` utility
- Packet injection NOT supported on most hardware
- No bubblewrap (use sandbox-exec instead)

**Requires:**
- Xcode command-line tools
- May require disabling System Integrity Protection (SIP) for some tools

### Android

**Root required:**
- Must have rooted device for monitor mode
- Requires custom firmware on many chipsets
- Pick's Android app detects root and warns if unavailable

**See:** [ANDROID_BUILD.md](ANDROID_BUILD.md) for details

### Windows (WSL)

**Works via WSL2:**
- Run Pick in WSL2 with Linux WiFi adapter passthrough
- Or use external WiFi adapter in WSL
- Native Windows support in development

---

## Alternatives to Running as Root

### Option 1: Network Namespace Isolation

Run Pick in a dedicated network namespace with only the WiFi adapter:

```bash
# Create network namespace
sudo ip netns add pick-ns
sudo ip netns exec pick-ns ./run-pentest.sh headless
```

**Benefits:**
- Isolates network access
- Limits blast radius of compromised tools

### Option 2: Dedicated WiFi Adapter

Use an external USB WiFi adapter for pentesting:

**Benefits:**
- Main internet connection stays active
- Can pass adapter to VM/container
- Physical isolation from production network

**Recommended adapters:** See [README.md](../README.md#recommended-wifi-adapters)

### Option 3: Remote Tool Execution

Configure Pick to execute WiFi tools on a remote machine:

**Benefits:**
- Operator machine doesn't need sudo
- Tools run in isolated environment
- Can use dedicated pentesting hardware

**Trade-offs:**
- More complex setup
- Network latency affects real-time tools

---

## Non-WiFi Tools (No Sudo Required)

These Pick tools work **without sudo**:

**Network Scanning:**
- `port_scan` - TCP connect scanning
- `arp_table` - Read ARP cache
- `network_discover` - mDNS discovery
- `ssdp_discover` - UPnP discovery

**Web Testing:**
- `web_vuln_scan` - HTTP vulnerability scanning
- All external web tools (nikto, sqlmap, etc.)

**System Information:**
- `device_info` - System information gathering
- `list_files` - File system enumeration
- `read_file` - File reading (within permissions)

**External Tools:**
Most BlackArch tools work without root unless they specifically need raw sockets or hardware access.

---

## Frequently Asked Questions

### Q: Can I run Pick without ever using sudo?

**A:** Yes, if you only use non-WiFi tools. Network scanning, web testing, and credential testing work without sudo.

### Q: Why doesn't Pick use setuid instead?

**A:** Setuid binaries are security risks. Modern Linux recommends capabilities or explicit sudo instead.

### Q: Can I audit what Pick does with root privileges?

**A:** Yes. Pick is open source. Review:
- `crates/platform/src/linux.rs` - Linux-specific operations
- `crates/tools/src/wifi_scan.rs` - WiFi tool implementations
- `crates/tools/src/external/aircrack.rs` - External tool wrappers

### Q: Does Strike48 require sudo?

**A:** No. Strike48 (the control plane) runs as a normal user. Only Pick connectors need sudo for WiFi operations.

---

## Security Best Practices

1. **Principle of Least Privilege:**
   - Only use sudo for operations that require it
   - Run non-WiFi tasks without sudo

2. **Audit Tool Execution:**
   - Review logs in `~/tmp/pentest.log`
   - Monitor tool behavior with `strace` if suspicious

3. **Isolate Pentesting:**
   - Use dedicated machines/VMs for pentesting
   - Don't run Pick with sudo on production systems

4. **Keep Pick Updated:**
   - Security fixes may reduce privilege requirements
   - Future versions may support capability-based execution

5. **Report Security Issues:**
   - Use [GitHub Security Advisories](https://github.com/Strike48-public/pick/security/advisories/new)
   - See [SECURITY.md](../SECURITY.md) for full reporting process

---

## References

- [Linux Capabilities Man Page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Bubblewrap Documentation](https://github.com/containers/bubblewrap)
- [nl80211 Interface](https://wireless.wiki.kernel.org/en/developers/documentation/nl80211)
- [WiFi Monitor Mode](https://en.wikipedia.org/wiki/Monitor_mode)
- [Aircrack-ng Suite](https://www.aircrack-ng.org/)

---

**Last updated:** 2026-05-28
