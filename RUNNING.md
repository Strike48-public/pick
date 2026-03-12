# Quick Start Guide - Running the Pentest Connector

This guide shows the **easiest ways** to run the connector with proper WiFi hardware access.

---

## 🚀 The Easiest Way (Recommended)

### Option 1: Simple Shell Script

```bash
# First time setup: Copy .env.example to .env
cp .env.example .env
# Edit .env with your configuration

# Run headless (auto-prompts for sudo if needed)
./run-pentest.sh headless

# Run desktop
./run-pentest.sh desktop

# Run in release mode
./run-pentest.sh headless release
```

**What it does:**
- ✅ Automatically uses sudo (required for WiFi)
- ✅ Loads config from .env file
- ✅ Logs output to ~/tmp/pentest.log
- ✅ Shows colored status messages

---

### Option 2: Just Commands (Simplest)

```bash
# First time: Copy .env.example to .env
cp .env.example .env

# Run headless with your config from .env
just run-headless-env

# Or run with default dev settings
just run-headless-dev
```

**Available just recipes:**

| Command | Description |
|---------|-------------|
| `just run-headless-dev` | Headless with defaults + sudo + logging |
| `just run-headless-env` | Headless with .env config + sudo + logging |
| `just run-headless-sudo` | Headless with sudo (manual env vars) |
| `just run-desktop-sudo` | Desktop with sudo |
| `just run-desktop-release-sudo` | Desktop release with sudo |

---

## 📝 Your Current Command (Simplified)

### Before (Complex):
```bash
STRIKE48_HOST="wss://jt-demo-01.strike48.engineering" \
STRIKE48_TENANT=non-prod \
MATRIX_API_URL=https://jt-demo-01.strike48.engineering \
MATRIX_TENANT_ID=non-prod \
RUST_LOG=debug \
just run-headless | tee -a ~/tmp/pentest.log
```

### After (Simple):

**Option A - Using .env file:**
```bash
# One-time setup
cp .env.example .env
# Edit .env with your values

# Every time you run:
just run-headless-env
```

**Option B - Using shell script:**
```bash
# One-time setup
cp .env.example .env

# Every time you run:
./run-pentest.sh headless
```

**Option C - Using shell alias (add to ~/.bashrc or ~/.zshrc):**
```bash
alias pentest='cd ~/Code/dioxus-connector && just run-headless-env'

# Then just run:
pentest
```

---

## ⚙️ Configuration File (.env)

Create `.env` from the example:

```bash
cp .env.example .env
```

Edit `.env` to customize:

```bash
# Your Strike48 configuration
STRIKE48_HOST=wss://jt-demo-01.strike48.engineering
STRIKE48_TENANT=non-prod
MATRIX_API_URL=https://jt-demo-01.strike48.engineering
MATRIX_TENANT_ID=non-prod

# Logging
RUST_LOG=debug

# Optional: Custom instance ID
# STRIKE48_INSTANCE_ID=my-pentest-01
```

---

## 🔧 Advanced Usage

### Manual Control (If You Need It)

If you want full control, you can still use the long form:

```bash
# With sudo (required for WiFi)
sudo -E env \
    STRIKE48_HOST="wss://jt-demo-01.strike48.engineering" \
    STRIKE48_TENANT=non-prod \
    MATRIX_API_URL=https://jt-demo-01.strike48.engineering \
    MATRIX_TENANT_ID=non-prod \
    RUST_LOG=debug \
    cargo run --package pentest-headless 2>&1 | tee -a ~/tmp/pentest.log
```

**Note the changes from your original:**
- Added `sudo -E` at the beginning (preserves environment variables)
- Changed to `2>&1` to capture both stdout and stderr

### Justfile Variables

You can override justfile defaults:

```bash
# Override Strike48 host
STRIKE48_HOST=wss://custom.host just run-headless-dev

# Override tenant
STRIKE48_TENANT=production just run-headless-dev
```

---

## 🛠️ Troubleshooting

### "Operation not permitted" or WiFi tools don't work

**Cause**: Not running with sudo

**Solution**: Use one of the sudo-enabled commands:
```bash
just run-headless-dev        # Has sudo built-in
./run-pentest.sh headless   # Has sudo built-in
```

### "Connection refused" or "Failed to connect"

**Cause**: Incorrect Strike48 host or network issues

**Solution**: Check your .env file:
```bash
cat .env | grep STRIKE48_HOST
# Should match your Strike48 instance
```

### Log file growing too large

**Location**: `~/tmp/pentest.log`

**Clean up**:
```bash
# View last 100 lines
tail -100 ~/tmp/pentest.log

# Clear log file
> ~/tmp/pentest.log

# Or delete it
rm ~/tmp/pentest.log
```

---

## 📊 Comparison

### Complexity Levels

| Method | Complexity | Flexibility | Setup Time |
|--------|-----------|-------------|------------|
| `./run-pentest.sh` | ⭐ Simple | ⭐⭐ Medium | 1 minute |
| `just run-headless-env` | ⭐⭐ Easy | ⭐⭐⭐ High | 1 minute |
| Manual env vars | ⭐⭐⭐⭐ Complex | ⭐⭐⭐⭐⭐ Full | 0 minutes |

**Recommendation**: Start with `./run-pentest.sh` or `just run-headless-env`

---

## 🎯 Quick Reference Card

```bash
# ONE-TIME SETUP
cp .env.example .env
# Edit .env with your configuration

# RUN METHODS (pick one)
./run-pentest.sh headless        # Easiest
just run-headless-env            # Simple with just
just run-headless-dev            # Uses defaults from justfile

# DESKTOP APP (with WiFi access)
./run-pentest.sh desktop
just run-desktop-sudo

# VIEW LOGS
tail -f ~/tmp/pentest.log

# STOP APPLICATION
Ctrl+C
```

---

## 🔐 Why Sudo?

**WiFi penetration testing requires direct hardware access:**
- Monitor mode (airmon-ng)
- Packet capture (airodump-ng)
- Packet injection (aireplay-ng)
- Interface scanning (iw)
- Access to /dev/rfkill and /sys/class/net

All the provided methods (`run-pentest.sh`, `just run-*-dev`, `just run-*-sudo`) include sudo automatically.

See [docs/BWRAP_SUDO_EXPLAINED.md](docs/BWRAP_SUDO_EXPLAINED.md) for technical details.

---

## 📚 Next Steps

1. **First run**: Use `./run-pentest.sh headless`
2. **Configure**: Edit `.env` file with your Strike48 instance
3. **Create alias** (optional): Add to `~/.bashrc` or `~/.zshrc`:
   ```bash
   alias pentest='cd ~/Code/dioxus-connector && ./run-pentest.sh headless'
   ```
4. **Test WiFi tools**: Try `list_wifi_interfaces` or click "Autopwn"

---

**Last Updated**: 2026-03-05
