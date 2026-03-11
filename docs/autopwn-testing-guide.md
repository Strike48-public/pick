# AutoPwn Testing Guide

## ⚠️ Legal & Safety Notice

**CRITICAL:** WiFi penetration testing is ILLEGAL unless:
- You own the network
- You have explicit written authorization
- You're testing in an isolated lab environment

**Never test on:**
- Public WiFi networks
- Neighbor's networks
- Corporate networks without authorization
- Any network you don't control

## Testing Levels

### Level 1: Safe Component Tests (No WiFi Required)

These tests can run safely on any system without special hardware or permissions.

#### 1.1 Attack Planning Tool

Test the strategy selection without actual WiFi:

```bash
# Build the project
cargo build --package pentest-tools --release

# Test WEP network planning
# This should return attack strategy without touching WiFi
```

**Test tool schema:**
```rust
// In a test file or via tool registry
autopwn_plan {
  ssid: "TestNetwork",
  bssid: "00:11:22:33:44:55",
  security: "WPA2-PSK",
  signal: -55,
  clients: 3,
  channel: 6
}
```

Expected: Returns attack plan with WPA strategy, active deauth, dictionary attack.

#### 1.2 Vendor Intelligence

Test vendor detection:
- `NETGEAR42` → Should detect Netgear patterns
- `TP-LINK_A1B2` → Should detect TP-Link patterns
- `MyNetwork` → Should fall back to generic patterns

```rust
// Run unit tests
cargo test --package pentest-tools vendor_intel
cargo test --package pentest-tools strategy
```

#### 1.3 Wordlist Management

Test wordlist download (safe, just HTTP):

```bash
# This will download to ~/.pick/wordlists/
# Downloads ~1MB common passwords file (quick test)
```

Create a minimal test tool that calls:
```rust
wordlist::ensure_wordlist(&COMMON_PASSWORDS).await?
```

Expected: Downloads file, shows progress, caches for reuse.

### Level 2: Dependency Verification (No WiFi Required)

Check that required tools are installed:

#### 2.1 Check aircrack-ng Suite

```bash
# Check installations
which aircrack-ng
which airodump-ng
which aireplay-ng
which airmon-ng

# Check versions
aircrack-ng --version
```

Expected: Version 1.6+ recommended

#### 2.2 Install if Missing (Ubuntu/Debian)

```bash
sudo apt update
sudo apt install -y aircrack-ng
```

#### 2.3 Check Optional Tools

```bash
# For mask attacks (future)
which hashcat

# For MAC cloning
which macchanger
```

### Level 3: Hardware Capability Tests (WiFi Adapter Required)

Tests WiFi adapter capabilities without attacking networks.

#### 3.1 Check WiFi Adapters

```bash
# List wireless interfaces
iw dev

# Check driver capabilities
iw list | grep -A 10 "Supported interface modes"
```

Look for:
- `monitor` mode support
- `AP/VLAN` for injection

#### 3.2 Test Monitor Mode (Safe)

```bash
# Enable monitor mode manually
sudo airmon-ng check kill
sudo airmon-ng start wlan0

# Verify
iw dev  # Should show wlan0mon or similar

# IMPORTANT: Disable afterwards
sudo airmon-ng stop wlan0mon
sudo systemctl start NetworkManager
```

This tests if your adapter supports the basic operation needed.

#### 3.3 Test Packet Injection

```bash
# With monitor mode enabled
sudo aireplay-ng --test wlan0mon
```

Expected: Shows injection success rate (30/30: 100%)

### Level 4: Controlled Environment Testing (Test Network Required)

**Set up an isolated test environment:**

#### 4.1 Create Test WiFi Network

**Option A: Dedicated Router**
- Old router configured for testing
- Physically isolated (not connected to internet)
- Known SSID and password

**Option B: Raspberry Pi Access Point**
```bash
# On Raspberry Pi with hostapd
sudo apt install hostapd

# Configure test WPA2 network
# SSID: "TestNet-AutoPwn"
# Password: "TestPassword123"
```

**Option C: Virtual Test Environment**
- Use VirtualBox with USB WiFi adapter passthrough
- Isolated network in VM

#### 4.2 Test Network Configurations

Create test cases:
1. **WPA2-PSK Easy:** SSID="TestNet", Password="password123" (in RockYou)
2. **WPA2-PSK Hard:** SSID="TestNet", Password="Xk9#mP2$vL4@" (not in wordlist)
3. **WEP (if supported):** 64-bit or 128-bit key

#### 4.3 End-to-End Test Script

```bash
#!/usr/bin/env bash
# test-autopwn.sh - Full integration test

set -euo pipefail

TEST_SSID="TestNet-AutoPwn"
TEST_BSSID="00:11:22:33:44:55"  # Your test AP MAC
TEST_CHANNEL=6

echo "=== AutoPwn Integration Test ==="
echo "⚠️  Ensure this is YOUR test network!"
read -p "Continue? (yes/no): " confirm
[[ "$confirm" == "yes" ]] || exit 1

# Phase 1A: Planning
echo "Phase 1A: Attack Planning"
cargo run --release -- autopwn_plan \
  --ssid "$TEST_SSID" \
  --bssid "$TEST_BSSID" \
  --security "WPA2-PSK" \
  --signal -50 \
  --clients 1 \
  --channel "$TEST_CHANNEL"

# Phase 1B: Capture (manual trigger)
echo "Phase 1B: Packet Capture"
echo "This will enable monitor mode and capture handshake"
read -p "Run capture? (yes/no): " run_capture

if [[ "$run_capture" == "yes" ]]; then
  cargo run --release -- autopwn_capture \
    --ssid "$TEST_SSID" \
    --bssid "$TEST_BSSID" \
    --channel "$TEST_CHANNEL" \
    --method wpa \
    --timeout 120
fi

# Phase 1C: Cracking
echo "Phase 1C: Password Cracking"
echo "Provide path to capture file from Phase 1B"
read -p "Capture file path: " capture_file

if [[ -f "$capture_file" ]]; then
  cargo run --release -- autopwn_crack \
    --capture-file "$capture_file" \
    --bssid "$TEST_BSSID" \
    --method quick \
    --timeout 300
fi

echo "=== Test Complete ==="
```

#### 4.4 Expected Results

**Phase 1A (Planning):**
- ✓ Analyzes target
- ✓ Recommends WPA strategy
- ✓ Shows feasibility score
- ✓ Lists attack steps

**Phase 1B (Capture):**
- ✓ Enables monitor mode
- ✓ Starts airodump-ng
- ✓ Sends deauth packets
- ✓ Captures handshake
- ✓ Verifies handshake is valid
- ✓ Saves to `/tmp/autopwn-TIMESTAMP/`
- ✓ Disables monitor mode on completion

**Phase 1C (Cracking):**
- ✓ Downloads wordlist (first run)
- ✓ Tries common passwords
- ✓ Runs aircrack-ng
- ✓ Reports password if found
- ✓ Handles timeout gracefully

### Level 5: Unit Tests

Run existing Rust unit tests:

```bash
# Run all autopwn tests
cargo test --package pentest-tools autopwn

# Specific test modules
cargo test --package pentest-tools vendor_intel::tests
cargo test --package pentest-tools strategy::tests
cargo test --package pentest-tools types::tests
```

### Level 6: Dry Run Mode (Future Enhancement)

**Recommendation:** Add a `--dry-run` flag that:
- Simulates all operations without actual WiFi interaction
- Validates parameters
- Shows what would be executed
- Useful for testing without hardware

Example:
```rust
if params["dry_run"].as_bool().unwrap_or(false) {
    tracing::info!("DRY RUN: Would enable monitor mode on wlan0");
    tracing::info!("DRY RUN: Would start capture...");
    return Ok(json!({"dry_run": true, "would_execute": "..."}));
}
```

## CI/CD Testing

### What Can Run in CI

**Safe for CI (no hardware):**
- ✓ Unit tests (`cargo test`)
- ✓ Strategy selection tests
- ✓ Vendor intelligence tests
- ✓ Type parsing tests
- ✓ Compilation checks

**NOT safe for CI:**
- ✗ Monitor mode tests (requires specific hardware)
- ✗ Packet capture (needs WiFi adapter)
- ✗ Integration tests with real WiFi

### GitHub Actions Test Matrix

```yaml
name: AutoPwn Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install aircrack-ng
        run: sudo apt-get install -y aircrack-ng
      - name: Run unit tests
        run: cargo test --package pentest-tools autopwn
      - name: Check compilation
        run: cargo check --package pentest-tools --release
```

## Troubleshooting

### Common Issues

**"airmon-ng not found"**
```bash
sudo apt install aircrack-ng
```

**"Monitor mode not supported"**
- Check adapter chipset: `lspci | grep -i network` or `lsusb`
- Some adapters don't support monitor mode
- Recommended: Atheros, Ralink, Realtek chipsets

**"No handshake captured"**
- Increase timeout
- Ensure clients are connected
- Try multiple deauth attempts
- Verify signal strength

**"Permission denied"**
- All WiFi operations require root/sudo
- Run with sudo or configure passwordless sudo for testing

**"Wordlist download fails"**
- Check internet connection
- GitHub may rate-limit downloads
- Manually download to `~/.pick/wordlists/`

## Success Criteria

### Minimal Acceptance Test

- [ ] `cargo test --package pentest-tools` passes
- [ ] `autopwn_plan` returns valid strategy
- [ ] `autopwn_capture` enables/disables monitor mode
- [ ] `autopwn_crack` downloads wordlist
- [ ] No compiler warnings
- [ ] Clean error handling

### Full Integration Test

- [ ] Complete WPA handshake capture on test network
- [ ] Successfully crack test password from wordlist
- [ ] All cleanup happens (monitor mode disabled)
- [ ] Captures saved to accessible location
- [ ] Error states handled gracefully

## Next Steps

1. **Start with Level 1** - Safe component tests
2. **Verify dependencies** - Level 2
3. **Check hardware** - Level 3 (if you have compatible adapter)
4. **Set up test environment** - Level 4 (if proceeding to full testing)
5. **Add dry-run mode** - Makes testing safer and easier

## References

- [Aircrack-ng Documentation](https://www.aircrack-ng.org/)
- [WiFi Monitor Mode Compatibility](https://www.aircrack-ng.org/doku.php?id=compatibility_drivers)
- [Test WiFi Networks Setup](https://github.com/aircrack-ng/aircrack-ng/wiki/Tutorial)
