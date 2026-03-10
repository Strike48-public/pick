# AutoPwn Full Integration Testing - Tomorrow

## 🎯 Branch for Testing

**Branch:** `test/autopwn-full-integration`

```bash
git checkout test/autopwn-full-integration
```

## ✅ What's Included

This branch contains the complete AutoPwn implementation ready for testing:

### Phase 1A: Attack Planning ✅
- **Tool:** `autopwn_plan`
- Analyzes WiFi targets (WEP/WPA/WPA2)
- Recommends optimal attack strategy
- Vendor intelligence for default routers
- Feasibility scoring

### Phase 1B: Packet Capture ✅
- **Tool:** `autopwn_capture`
- WPA handshake capture (passive/active deauth)
- WEP IV collection with ARP replay
- Auto-cleanup on errors
- Saves to `/tmp/autopwn-{timestamp}/`

### Phase 1C: Password Cracking ✅
- **Tool:** `autopwn_crack`
- Multiple methods: quick, dictionary, mask, remote
- Wordlist management (auto-download RockYou, Common)
- Timeout handling

### Hardware Validated ✅
- **USB Adapter:** wlx00c0caad0e76 (MediaTek MT7612U)
- Monitor mode: ✅ Working
- Packet injection: ✅ Supported
- Safe testing: ✅ Won't disrupt active network (wlp0s20f3)

## 🧪 Testing Checklist

### Before You Start

**Prerequisites:**
- [ ] You have an isolated test WiFi network (YOUR network only)
  - Old router OR Raspberry Pi AP
  - Simple WPA2 password (e.g., "TestPassword123")
  - NOT connected to internet (air-gapped for safety)
- [ ] Test network details noted:
  - SSID: ________________
  - BSSID (MAC): ________________
  - Channel: ________________
  - Password: ________________

**Safety:**
- [ ] You OWN the test network
- [ ] Network is isolated (not your main internet)
- [ ] USB adapter (wlx00c0caad0e76) is plugged in
- [ ] Active internet (wlp0s20f3) is unaffected

### Test Procedure

#### Step 1: Build the Project

```bash
cd /home/jtomek/Code/pick
cargo build --release
```

#### Step 2: Test with QuickAction UI

**Launch the app:**
```bash
cargo run --release
```

**In the UI:**

1. **Navigate to WiFi Scan**
   - Select USB adapter: `wlx00c0caad0e76`
   - Scan for networks
   - Verify you can see your test network

2. **Test AutoPwn Plan (Phase 1A)**
   - Find your test network in scan results
   - Click QuickAction or context menu
   - Select "AutoPwn Plan"
   - Verify strategy recommendation appears
   - Expected: Shows WPA attack strategy with details

3. **Test AutoPwn Capture (Phase 1B)**
   - Select your test network
   - Click "AutoPwn Capture"
   - Parameters should auto-fill:
     - SSID: [from scan]
     - BSSID: [from scan]
     - Channel: [from scan]
   - Click execute
   - Watch for:
     - ✓ Monitor mode enabled
     - ✓ Packet capture started
     - ✓ Deauth packets sent (if clients present)
     - ✓ Handshake captured
     - ✓ Monitor mode disabled
     - ✓ Files saved to `/tmp/autopwn-TIMESTAMP/`

4. **Test AutoPwn Crack (Phase 1C)**
   - After capture completes
   - Note the capture file path from logs
   - Click "AutoPwn Crack"
   - Parameters:
     - Capture file: [from previous step]
     - BSSID: [same as capture]
     - Method: `quick`
     - Timeout: `300` (5 minutes)
   - Click execute
   - Watch for:
     - ✓ Wordlist download (first run only)
     - ✓ Trying common passwords
     - ✓ Running aircrack-ng
     - ✓ Password found (if in wordlist)

#### Step 3: Verify Results

**Check capture files:**
```bash
ls -lah /tmp/autopwn-*/
```

Expected files:
- `capture-01.cap` - Packet capture
- `capture-01.csv` - Metadata (from airodump)

**Check wordlists:**
```bash
ls -lah ~/.pick/wordlists/
```

Expected files (after first crack):
- `common-passwords.txt` (~1MB)
- `rockyou.txt` (~134MB, if quick mode ran long enough)

**Verify network restored:**
```bash
iw dev
ip addr show wlp0s20f3
```

Expected:
- No monitor interfaces remaining
- wlp0s20f3 still connected with IP
- Internet still working

### Test Scenarios

#### Scenario A: Easy Test (Recommended First)
- **Setup:** Test network with password in RockYou
- **Password:** `password123` or `TestPassword123`
- **Expected:** Quick mode finds password in 1-2 minutes
- **Result:** ✅ Full end-to-end success

#### Scenario B: Hard Test
- **Setup:** Test network with strong password
- **Password:** `Xk9#mP2$vL4@` (not in any wordlist)
- **Expected:** Crack times out, no password found
- **Result:** ✅ Proper timeout handling

#### Scenario C: WEP Test (If Available)
- **Setup:** Old router with WEP encryption
- **Expected:** Phase 1B captures IVs, Phase 1C cracks immediately
- **Result:** ✅ WEP is broken in minutes

## 🐛 Troubleshooting

### "Monitor mode not supported"
- Check USB adapter is plugged in: `lsusb | grep MediaTek`
- Run hardware test: `./scripts/test-monitor-mode-safe.sh`

### "No handshake captured"
- Increase timeout in capture parameters
- Ensure test network has clients connected
- Try multiple capture attempts
- Check signal strength (move closer)

### "Wordlist download fails"
- Check internet connection
- Manually download to `~/.pick/wordlists/rockyou.txt`
- GitHub may rate-limit, retry later

### "Permission denied"
- AutoPwn requires sudo for monitor mode
- Ensure sudo is configured
- Or run entire app with sudo (not recommended for UI)

### "Active network disrupted"
- Should NOT happen with safe implementation
- If it does: `sudo systemctl restart NetworkManager`
- Report as bug if this occurs

## 📊 Success Criteria

### Minimum Success
- [ ] Phase 1A: Plan returns strategy
- [ ] Phase 1B: Captures handshake without errors
- [ ] Phase 1C: Runs crack (even if password not found)
- [ ] Monitor mode cleanup works
- [ ] Active network unaffected

### Full Success
- [ ] All phases complete
- [ ] Password found (if in wordlist)
- [ ] No manual cleanup needed
- [ ] UI remains responsive
- [ ] Clear error messages on failure

## 📝 Notes to Document

During testing, note:
- [ ] Time taken for each phase
- [ ] Any UI responsiveness issues
- [ ] Error messages encountered
- [ ] Success rate of handshake capture
- [ ] Wordlist download time (first run)
- [ ] Whether cleanup happens automatically

## 🚀 After Testing

### If Successful
1. Document test results
2. Take screenshots of QuickAction flow
3. Note any UX improvements needed
4. Consider merging to main autopwn branch

### If Issues Found
1. Document the exact issue
2. Note steps to reproduce
3. Check logs in terminal
4. Review implementation for bugs

## 📚 Reference Files

- **Testing Guide:** `docs/autopwn-testing-guide.md`
- **Safe Hardware Test:** `scripts/test-monitor-mode-safe.sh`
- **Component Tests:** `scripts/test-autopwn-safe.sh`
- **Planning Demo:** `scripts/demo-autopwn-planning.sh`

## 🔒 Legal Reminder

**CRITICAL:** Only test on networks you own. Testing unauthorized networks is illegal.

- ✅ Your test router/AP
- ✅ Isolated lab network
- ✅ Explicitly authorized network
- ❌ Public WiFi
- ❌ Neighbor's networks
- ❌ Corporate networks without written permission

## ⚡ Quick Start Tomorrow

```bash
# 1. Switch to testing branch
cd /home/jtomek/Code/pick
git checkout test/autopwn-full-integration

# 2. Verify hardware
./scripts/test-monitor-mode-safe.sh

# 3. Build and run
cargo build --release
cargo run --release

# 4. Test the QuickAction flow
# (See Step 2 above)

# 5. Report results
```

Good luck with testing! 🎉
