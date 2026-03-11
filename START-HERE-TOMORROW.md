# 🚀 Start Here Tomorrow - AutoPwn Testing

## Quick Start

```bash
cd /home/jtomek/Code/pick
git checkout test/autopwn-full-integration
cargo build --release
cargo run --release
```

Then open: **`docs/TESTING-AUTOPWN-TOMORROW.md`**

## What You're Testing

**Complete AutoPwn System** - automated WiFi penetration testing with 3 phases:

1. **Plan** - Analyze target and recommend strategy
2. **Capture** - Capture WPA handshake or WEP IVs
3. **Crack** - Break password using wordlists

## What You Need

✅ **Isolated test WiFi network** (YOUR network only!)
- Old router OR Raspberry Pi AP
- Simple WPA2 password (e.g., "TestPassword123")
- NOT connected to internet (air-gapped)

✅ **USB WiFi adapter** (already validated)
- Adapter: wlx00c0caad0e76
- Chipset: MediaTek MT7612U
- Monitor mode: ✅ Working
- Packet injection: ✅ Working

✅ **Your internet connection** (protected)
- Adapter: wlp0s20f3
- Will NOT be affected by testing

## Testing Flow

### In the UI:

1. **WiFi Scan** → Select USB adapter (wlx00c0caad0e76)
2. **Scan** → Find your test network
3. **QuickAction: AutoPwn Plan** → See recommended strategy
4. **QuickAction: AutoPwn Capture** → Capture handshake
5. **QuickAction: AutoPwn Crack** → Crack the password

## Expected Results

**Phase 1A (Plan):**
- Shows WPA/WEP attack strategy
- Displays feasibility score
- Lists required steps
- ~1 second

**Phase 1B (Capture):**
- Enables monitor mode
- Captures handshake
- Disables monitor mode
- Saves to `/tmp/autopwn-TIMESTAMP/`
- ~1-2 minutes

**Phase 1C (Crack):**
- Downloads wordlist (first run only)
- Tries common passwords first
- Runs aircrack-ng
- Reports password if found
- ~1-5 minutes (depends on password)

## Safety Checks ✅

- ✅ Only operates on USB adapter (not your active WiFi)
- ✅ Automatic cleanup on errors
- ✅ Monitor mode auto-disabled
- ✅ Active internet connection preserved
- ✅ All validated in safe testing

## Documentation

| File | Purpose |
|------|---------|
| **docs/TESTING-AUTOPWN-TOMORROW.md** | **👈 READ THIS FIRST** |
| AUTOPWN-BRANCH-README.md | Branch overview |
| docs/autopwn-testing-guide.md | Comprehensive guide |
| scripts/test-autopwn-safe.sh | Component tests (optional) |

## Test Scenarios

### Scenario 1: Easy Win (Recommended)
- Password: `password123` or similar common password
- Expected: Found in 1-2 minutes
- Result: Full success end-to-end

### Scenario 2: Timeout Test
- Password: Strong random (e.g., `Xk9#mP2$vL4@`)
- Expected: Times out, no password found
- Result: Validates proper timeout handling

### Scenario 3: WEP (If Available)
- Old router with WEP encryption
- Expected: Cracks in minutes
- Result: Shows WEP vulnerability

## ⚠️ Critical Safety Rules

**ONLY TEST ON:**
- ✅ Your own router/AP
- ✅ Isolated lab network
- ✅ Explicitly authorized networks

**NEVER TEST ON:**
- ❌ Public WiFi
- ❌ Neighbor's networks
- ❌ Corporate networks (without written authorization)
- ❌ Any network you don't own

**Testing unauthorized networks is ILLEGAL.**

## Troubleshooting Quick Refs

**Monitor mode fails:**
```bash
./scripts/test-monitor-mode-safe.sh
```

**No handshake captured:**
- Move closer to test AP
- Increase timeout
- Ensure clients connected
- Try multiple attempts

**Network disrupted:**
```bash
sudo systemctl restart NetworkManager
```

**Wordlist download fails:**
- Check internet connection
- Manually download to `~/.pick/wordlists/`

## After Testing

Document:
- [ ] Time taken for each phase
- [ ] Success rate
- [ ] Any errors encountered
- [ ] UI responsiveness
- [ ] Screenshots of flow

## Branch Info

**Current Branch:** `test/autopwn-full-integration`
**Based On:** `feature/wifi-adapter-selection`
**Status:** Ready for testing
**Last Commit:** Hardware validation + testing docs

## Related Branches

- `feature/wifi-adapter-selection` - Base work with WiFi adapter selection
- `feature/autopwn-tool` - Earlier AutoPwn attempt (superseded)
- `test/autopwn-full-integration` - **👈 USE THIS ONE**

---

## The One Command You Need

```bash
git checkout test/autopwn-full-integration && cargo run --release
```

**Then follow: `docs/TESTING-AUTOPWN-TOMORROW.md`**

Good luck! 🎉
