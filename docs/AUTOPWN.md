# Autopwn - Automated WiFi Penetration Testing

## Overview

The **Autopwn** tool provides automated WiFi penetration testing capabilities for WPA/WPA2 networks. It orchestrates a complete attack workflow from network discovery to password cracking.

## Features

- **Automated Workflow**: Seamless orchestration of all attack phases
- **WPA/WPA2 Support**: Handshake capture and dictionary attacks
- **Intelligent Target Selection**: Filters networks by signal strength and security type
- **Progress Logging**: Real-time status updates during attack phases
- **Desktop Linux Support**: Optimized for BlackArch/penetration testing distributions

## Requirements

### System Requirements

- **Platform**: Linux Desktop (Debian/Arch-based distributions)
- **Privileges**: **Must run application with sudo** (real root required for hardware access)
- **WiFi Adapter**: Monitor mode capable wireless adapter
- **Sandbox**: Hardware WiFi access enabled (default configuration)

**CRITICAL - Run with Sudo:**
```bash
sudo cargo run --package pentest-desktop
```

**Why sudo is required:**
- Autopwn needs to put WiFi card in monitor mode (airmon-ng)
- Requires access to `/dev/rfkill` and network interfaces
- Needs **real root on host** for hardware access

**Important Notes**:
- The connector uses proot for sandboxing
- WiFi hardware access is **enabled by default** - see [WIFI_HARDWARE_ACCESS.md](./WIFI_HARDWARE_ACCESS.md)
- Inside proot, commands run as UID 0 - no `sudo` prefix in commands

### Software Dependencies

The autopwn tool requires the aircrack-ng suite:

```bash
# BlackArch / Arch Linux
sudo pacman -S aircrack-ng

# Debian / Ubuntu
sudo apt-get install aircrack-ng
```

Required tools:
- `airmon-ng` - Enable/disable monitor mode
- `airodump-ng` - Capture handshakes
- `aireplay-ng` - Deauthentication attacks
- `aircrack-ng` - Password cracking

## Usage

### Tool Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `interface` | string | auto | Wireless interface to use (e.g., wlan0) |
| `min_signal` | integer | -70 | Minimum signal strength in dBm (-100 to 0) |
| `wordlist` | string | null | Path to password wordlist file |
| `max_targets` | integer | 5 | Maximum number of targets to attempt |
| `stop_on_success` | boolean | true | Stop after first successful crack |
| `handshake_timeout` | integer | 120 | Handshake capture timeout (seconds) |
| `deauth_count` | integer | 10 | Number of deauth packets to send |

### Example Usage via UI

#### Quick Actions (Recommended)

1. **Access Dashboard**: From the home screen after connecting
2. **Click Autopwn**: Located in the "Quick Actions" section
3. **Select Interface**: AI agent will list available wireless interfaces using `list_wifi_interfaces` tool
4. **Choose Interface**: Pick your wireless adapter (e.g., wlan0, wlp3s0)
5. **Specify Wordlist**: Provide path to your password dictionary
6. **Execute**: Agent runs autopwn with your configuration

#### Via Tools Page

1. **Navigate to Tools**: Click the "Tools" tab in the main interface
2. **Use Chat**: Autopwn is available as a tool that can be invoked via chat
3. **Provide Parameters**: Specify interface and wordlist in your request

### Example Usage via Chat

First, list available wireless interfaces:

```
Use the list_wifi_interfaces tool to show me available wireless adapters
```

Then run autopwn with your chosen interface:

```
Use the autopwn tool with interface=wlan0 and wordlist=/usr/share/wordlists/rockyou.txt and min_signal=-65
```

### Command-Line Equivalent

If executed directly (not through the connector), the workflow is equivalent to:

```bash
# 1. Enable monitor mode
sudo airmon-ng start wlan0

# 2. Scan for networks
sudo iw dev wlan0mon scan

# 3. Capture handshake
sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w /tmp/capture wlan0mon

# 4. Deauth to force handshake
sudo aireplay-ng --deauth 10 -a AA:BB:CC:DD:EE:FF wlan0mon

# 5. Crack handshake
sudo aircrack-ng -w /path/to/wordlist.txt /tmp/capture-01.cap

# 6. Restore managed mode
sudo airmon-ng stop wlan0mon
```

## Helper Tools

### list_wifi_interfaces

A companion tool that enumerates available wireless network interfaces on the system.

**Purpose**: Help users identify which WiFi adapter to use with autopwn

**Usage**: Automatically called when clicking the Autopwn Quick Action, or can be invoked manually via chat

**Output Format**:
```json
{
  "interfaces": [
    {
      "interface": "wlan0",
      "phy": "phy0",
      "mac_address": "00:11:22:33:44:55"
    }
  ],
  "count": 1,
  "raw_output": "..."
}
```

**Requirements**:
- Linux system with `iw` package installed
- Falls back to basic interface listing if `iw` unavailable

## Workflow Phases

### Phase 1: Initialization
- Check root privileges (`id -u`)
- Verify aircrack-ng suite installation
- Detect or validate wireless interface

### Phase 2: Network Discovery
- Scan for WiFi networks using `iw scan`
- Parse network details (SSID, BSSID, channel, signal strength)

### Phase 3: Target Selection
- Filter networks by security type (WPA/WPA2 only)
- Filter by minimum signal strength
- Sort by signal strength (strongest first)
- Limit to max_targets

### Phase 4: Monitor Mode
- Kill interfering processes (`airmon-ng check kill`)
- Enable monitor mode on wireless interface
- Verify monitor interface creation

### Phase 5: Attack Loop
For each target:
1. **Capture Handshake**
   - Start `airodump-ng` capture (background)
   - Send deauthentication packets with `aireplay-ng`
   - Wait for handshake capture (timeout: handshake_timeout)
   - Verify handshake with `aircrack-ng`

2. **Crack Password**
   - Run dictionary attack with `aircrack-ng`
   - Parse output for KEY FOUND message
   - Extract password from results

3. **Result Logging**
   - Success: Log password and optionally stop
   - Failure: Log error and continue to next target

### Phase 6: Cleanup
- Restore managed mode (`airmon-ng stop`)
- Restart NetworkManager (if available)
- Return attack results

## Output Format

```json
{
  "results": [
    {
      "ssid": "TargetNetwork",
      "bssid": "AA:BB:CC:DD:EE:FF",
      "success": true,
      "password": "cracked_password",
      "error": null
    },
    {
      "ssid": "AnotherNetwork",
      "bssid": "11:22:33:44:55:66",
      "success": false,
      "password": null,
      "error": "Password not found in wordlist"
    }
  ],
  "total_attempts": 2,
  "successful_cracks": 1
}
```

## Security & Legal Considerations

### Legal Warning

**⚠️ CRITICAL: This tool is for authorized security testing only.**

Unauthorized access to wireless networks is **illegal** in most jurisdictions and may result in:
- Criminal charges
- Civil liability
- Network access revocation
- Professional consequences

### Authorized Use Cases

✅ **Legal Uses**:
- Testing your own WiFi networks
- Authorized penetration testing with written permission
- Educational security research in controlled environments
- Security audits with proper authorization

❌ **Illegal Uses**:
- Attacking networks you don't own or have permission to test
- Unauthorized access to any wireless network
- Using captured credentials without authorization

### Best Practices

1. **Always obtain written authorization** before testing any network
2. **Document your testing scope** and time windows
3. **Maintain audit logs** of all autopwn sessions
4. **Secure captured data** (handshakes, passwords)
5. **Report findings responsibly** to network owners

## Troubleshooting

### "Autopwn requires root privileges"

**Solution**: Run the connector application with sudo:

```bash
sudo cargo run --package pentest-desktop
```

### "Required tool 'airmon-ng' not found"

**Solution**: Install the aircrack-ng suite:

```bash
# BlackArch / Arch
sudo pacman -S aircrack-ng

# Debian / Ubuntu
sudo apt-get install aircrack-ng
```

### "No wireless interface found"

**Causes**:
- No WiFi adapter connected
- WiFi adapter not recognized by kernel
- Missing wireless drivers

**Solutions**:
- Verify adapter is connected: `lsusb` or `lspci | grep -i network`
- Check kernel drivers: `dmesg | grep -i wireless`
- Install adapter drivers if needed

### "Failed to enable monitor mode"

**Causes**:
- NetworkManager interfering with monitor mode
- Adapter doesn't support monitor mode
- Interface already in use

**Solutions**:
- Stop NetworkManager: `sudo systemctl stop NetworkManager`
- Check adapter capabilities: `iw list | grep monitor`
- Use a monitor mode capable adapter (e.g., Alfa AWUS036ACH)

### "No handshake captured"

**Causes**:
- No clients connected to target network
- Insufficient signal strength
- Deauth packets not reaching target
- Handshake already cached

**Solutions**:
- Increase deauth packet count (e.g., 50)
- Move closer to target AP
- Wait for clients to connect naturally
- Increase handshake timeout

### "Password not found in wordlist"

**Causes**:
- Password not in dictionary
- Wordlist path incorrect
- Insufficient wordlist coverage

**Solutions**:
- Use comprehensive wordlists (e.g., rockyou.txt)
- Generate targeted wordlists with crunch/hashcat
- Combine multiple wordlists
- Consider rainbow tables for common passwords

## Wordlists

### Recommended Wordlists

**General Purpose**:
- `/usr/share/wordlists/rockyou.txt` - 14M passwords (most popular)
- `/usr/share/wordlists/fasttrack.txt` - Common weak passwords

**BlackArch Specific**:
```bash
# Install wordlist collection
sudo pacman -S wordlists

# Common locations
/usr/share/wordlists/
/usr/share/seclists/Passwords/
```

### Custom Wordlist Generation

```bash
# Generate numeric passwords (8 digits)
crunch 8 8 0123456789 > numbers-8.txt

# Generate targeted wordlist with rules
hashcat --stdout -r rules/best64.rule wordlist.txt > enhanced.txt
```

## Performance Notes

- **Handshake capture**: Typically 30-120 seconds
- **Dictionary attack speed**: Depends on wordlist size and CPU
  - ~1000-5000 passwords/second on average hardware
  - rockyou.txt (14M passwords): 45 minutes to 4 hours
- **Memory usage**: Minimal (<100MB)
- **Network impact**: Causes brief disconnection for targeted clients

## Future Enhancements

### Phase 2 (Planned)

- [ ] WPS PIN attacks (Pixie Dust, brute force)
- [ ] WEP attack support (ARP replay, fragmentation)
- [ ] Real-time progress UI dashboard
- [ ] Pause/resume functionality

### Phase 3 (Planned)

- [ ] PMKID attacks (clientless WPA2 cracking)
- [ ] Hash capture without deauth
- [ ] Integrated hashcat support for GPU acceleration
- [ ] Multi-target parallel attacks

### Phase 4 (Planned)

- [ ] Wordlist management UI
- [ ] Attack result export (CSV, JSON, PDF reports)
- [ ] Historical attack analytics
- [ ] Integration with cloud cracking services

## Implementation Details

### Technology Stack

- **Language**: Rust
- **Async Runtime**: Tokio
- **Command Execution**: Platform-abstracted via pentest-platform crate
- **UI Integration**: Dioxus components

### Architecture

```
┌─────────────────────────────────────────────┐
│           AutopwnTool (PentestTool)         │
│  - Schema definition                        │
│  - Parameter validation                     │
│  - Execution orchestration                  │
└──────────────────┬──────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────┐
│       run_autopwn_workflow()                │
│  - Interface detection                      │
│  - Network scanning                         │
│  - Target filtering                         │
│  - Monitor mode management                  │
│  - Attack loop                              │
└──────────────────┬──────────────────────────┘
                   │
        ┌──────────┴──────────┐
        ▼                     ▼
┌───────────────────┐  ┌─────────────────┐
│  capture_handshake │  │ crack_handshake │
│  - airodump-ng    │  │ - aircrack-ng   │
│  - aireplay-ng    │  │ - dictionary    │
└───────────────────┘  └─────────────────┘
```

### Error Handling

All external command failures are wrapped in `Error::ToolExecution` with descriptive messages. The tool gracefully handles:
- Missing dependencies
- Permission errors
- Interface failures
- Capture timeouts
- Cracking failures

## Contributing

Contributions are welcome! Areas for improvement:
- Additional attack vectors (WPS, WEP, PMKID)
- Enhanced network parsing (802.11 frame analysis)
- GPU acceleration integration
- Mobile platform support (Android with root)

## License

MIT License - See LICENSE file for details.

## Credits

- **Aircrack-ng Team**: Core attack tool suite
- **Dioxus**: Cross-platform UI framework
- **Strike48**: Connector SDK architecture

---

**Last Updated**: 2026-03-05
**Version**: 0.1.0 (Phase 1 MVP)
