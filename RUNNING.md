# Quick Start Guide - Running Pick

This guide shows the **easiest ways** to run Pick with proper WiFi hardware access.

---

## The Easiest Way (Recommended)

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
- Automatically uses sudo (required for WiFi)
- Loads config from .env file
- Logs output to ~/tmp/pentest.log
- Shows colored status messages

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

## Your Current Command (Simplified)

### Before (Complex):
```bash
STRIKE48_HOST="wss://matrix.example.com" \
STRIKE48_TENANT=non-prod \
MATRIX_API_URL=https://matrix.example.com \
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
alias pick='cd ~/Code/pick && just run-headless-env'

# Then just run:
pick
```

---

## Configuration File (.env)

Create `.env` from the example:

```bash
cp .env.example .env
```

Edit `.env` to customize:

```bash
# Your Strike48 configuration
STRIKE48_HOST=wss://matrix.example.com
STRIKE48_TENANT=non-prod
MATRIX_API_URL=https://matrix.example.com
MATRIX_TENANT_ID=non-prod

# Logging
RUST_LOG=debug

# Optional: Custom instance ID
# STRIKE48_INSTANCE_ID=my-pentest-01
```

---

## Advanced Usage

### Manual Control (If You Need It)

If you want full control, you can still use the long form:

```bash
# With sudo (required for WiFi)
sudo -E env \
    STRIKE48_HOST="wss://matrix.example.com" \
    STRIKE48_TENANT=non-prod \
    MATRIX_API_URL=https://matrix.example.com \
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

## Demo Stack: Pick + Scan Targets (docker compose)

`docker-compose.targets.yml` (the target-agnostic base) plus one fragment per
scan target under `targets/` (`targets/dvwa.yml`, `targets/juice-shop.yml`) stand
up the live demo: the headless Pick connector plus two deliberately vulnerable
web apps, scanning over an isolated bridge and registering with a Strike48
backend (Studio).

```bash
# One-time setup: copy the example and set STRIKE48_TENANT (the demo realm's
# tenant UUID). The init-dev demo:pick tasks generate this file for you.
cp .env.dvwa.example .env.dvwa

just targets-up      # build + start detached
just targets-check   # validate the merged model + isolation invariants (no daemon needed)
just targets-down    # tear down (add --volumes to also drop the creds volume)
```

The recipes take `TARGETS_ENV` (falling back to the legacy `DVWA_ENV`, then
`.env.dvwa`), so existing callers keep working; the old `dvwa-up` / `dvwa-down` /
`dvwa-check` names remain as aliases.

### Topology

- **`scan-net`** - one shared, `internal: true` bridge pinned to `172.18.0.0/24`,
  carrying pick and BOTH targets. Targets are published nowhere on the host, so
  scan traffic stays contained on this bridge.
- **`backend-net`** - plain bridge for pick's egress to the Strike48 backend
  (registration + tool requests). No target is attached to it.

Engagement URLs, as reached from pick over scan-net:

| Target | URL |
|--------|-----|
| DVWA | `http://dvwa` |
| Juice Shop | `http://juice-shop:3000` |

### Startup ordering

pick carries `depends_on` entries with `condition: service_healthy` for BOTH
targets, so it starts only after DVWA and Juice Shop each pass their healthcheck
(a PHP probe for DVWA, a `node -e` HTTP probe for Juice Shop; each probe uses an
interpreter guaranteed present in its image, since curl/wget are not guaranteed
in these images). A target that never turns healthy holds pick back rather than
letting it scan a half-up target set.

### Juice Shop state reset

Juice Shop keeps its state (registered users, challenge progress) in an
in-container sqlite file, so leftovers from a previous engagement can confuse
the next one. Reset it by force-recreating just that service:

```bash
docker compose --env-file .env.dvwa \
    -f docker-compose.targets.yml -f targets/dvwa.yml -f targets/juice-shop.yml \
    up -d --force-recreate juice-shop
```

The `--env-file` is required: the compose model has mandatory `${VAR:?}`
interpolations that would otherwise abort the command at parse time.

---

## Troubleshooting

### "Operation not permitted" or WiFi tools don't work

**Cause**: Not running with sudo

**Solution**: Use one of the sudo-enabled commands:
```bash
just run-headless-dev        # Has sudo built-in
./run-pentest.sh headless   # Has sudo built-in
```

### "Failed to read private key: Permission denied (os error 13)"

**Cause**: The connector was previously launched with `sudo`, which wrote the
SDK private key into `~/.strike48/keys/` owned by `root` (mode `0600`). A later
launch as your normal user can no longer read that key, so OTT registration
fails 3 times and the agent stays in `WaitingForApproval`.

**Immediate fix**:
```bash
# Restore ownership of the whole key/credential store to your user
sudo scripts/restore-key-ownership.sh
```

**Prevention** (both are already wired in):

1. The sudo launch paths (`run-pentest.sh`, `just run-headless-sudo`,
   `run-headless-dev`, `run-desktop-sudo`, `run-desktop-release-sudo`) restore
   ownership to `$SUDO_USER` on exit via `scripts/restore-key-ownership.sh`.
2. Grant raw-socket capabilities so most scans need no sudo at all:
   ```bash
   sudo setcap 'cap_net_raw,cap_net_admin+eip' target/debug/pentest-agent
   ```
   Re-apply after each rebuild (the binary is replaced). Note: monitor-mode
   WiFi tools (airmon-ng etc.) still self-escalate.

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

## Comparison

### Complexity Levels

| Method | Complexity | Flexibility | Setup Time |
|--------|-----------|-------------|------------|
| `./run-pentest.sh` | Very simple | Medium | 1 minute |
| `just run-headless-env` | Simple | High | 1 minute |
| Manual env vars | Complex | Full | 0 minutes |

**Recommendation**: Start with `./run-pentest.sh` or `just run-headless-env`

---

## Quick Reference Card

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

## Why Sudo?

**WiFi penetration testing requires direct hardware access:**
- Monitor mode (airmon-ng)
- Packet capture (airodump-ng)
- Packet injection (aireplay-ng)
- Interface scanning (iw)
- Access to /dev/rfkill and /sys/class/net

All the provided methods (`run-pentest.sh`, `just run-*-dev`, `just run-*-sudo`) include sudo automatically.

See [docs/BWRAP_SUDO_EXPLAINED.md](docs/BWRAP_SUDO_EXPLAINED.md) for technical details.

---

## Next Steps

1. **First run**: Use `./run-pentest.sh headless`
2. **Configure**: Edit `.env` file with your Strike48 instance
3. **Create alias** (optional): Add to `~/.bashrc` or `~/.zshrc`:
   ```bash
   alias pick='cd ~/Code/pick && ./run-pentest.sh headless'
   ```
4. **Test WiFi tools**: Try `list_wifi_interfaces` or click "Autopwn"

---



---

## Demo stack (docker compose) — scan targets

The demo stack lives in `docker-compose.targets.yml` (base: pick + networks) plus
one self-contained fragment per scan target under `targets/` (`dvwa.yml`,
`juice-shop.yml`). Drive it with:

```bash
just targets-up      # up --build -d; pick starts only after EVERY target is healthy
just targets-down    # compose down --remove-orphans (stub-env safe)
just targets-check   # no-daemon invariant tripwire: no host ports, scan-net internal, pick gated
```

- `scan-net` is PINNED to `172.18.0.0/24` (`internal: true`) — a collision with an
  existing network fails loudly at network-create time.
- Engagement URLs from pick: `http://dvwa` and `http://juice-shop:3000` (service DNS
  on scan-net; with a shared subnet, subnet-CIDR engagement scoping hits BOTH
  targets — URL scoping is what distinguishes them).
- Juice Shop state (registered users, mutated data) persists in the container layer;
  reset with `up -d --force-recreate juice-shop` (keep the full `-f` file set and
  `--env-file`).
- The juice-shop image is distroless: no shell, and `node` resolves only at the
  absolute entrypoint path `/nodejs/bin/node` — the healthcheck uses that path; a
  bare `node` probe (or `docker exec sh`) fails by design of the image.
- Expected scan-net warnings in juice-shop logs (alchemy.com, localhost:11434 LLM):
  optional web3/LLM challenge integrations that cannot reach the internet from the
  internal bridge. Not a health problem.

### One-time migration note (pre-existing stacks)

Stacks brought up BEFORE the scan-net subnet pin existed have an auto-assigned
subnet. The first `targets-up` recreates the network to apply the pin; containers
that predate that swap can come back with a stale DNS alias (service name SERVFAILs
from peers despite a valid IP). Symptom: `curl http://dvwa` → 000 / "Could not
resolve host" while `docker network inspect pick_scan-net` shows the container.
Fix once, then never again: `up -d --force-recreate dvwa` (or all targets).

---

**Last Updated**: 2026-10-09
