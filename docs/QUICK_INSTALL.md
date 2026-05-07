# Quick Install Guide

Get Pick running in under 5 minutes.

## One-Line Install

```bash
curl -sSL https://raw.githubusercontent.com/Strike48-public/pick/main/install.sh | bash
```

Or clone first:

```bash
git clone https://github.com/Strike48-public/pick.git
cd pick
./install.sh
```

## What Gets Installed

- Rust and Cargo (if needed)
- Build dependencies for your OS
- (Optional) Desktop app dependencies
- (Optional) WiFi scanning tools

## Interactive Prompts

The script will ask:

| Prompt | Recommendation |
|--------|----------------|
| Install desktop dependencies? | Yes if you want the GUI app |
| Install WiFi tools? | Yes if you need penetration testing features |
| Overwrite .env? | No if you already configured it |
| Open .env editor? | Yes for first-time setup |
| Build now? | Yes (takes 5-10 minutes) |
| Run tests? | Yes to verify installation |

## Quick Configuration

Edit `.env` with your Strike48 backend:

```bash
STRIKE48_HOST=wss://your-server.example.com
STRIKE48_TENANT=your-tenant-id
MATRIX_API_URL=https://your-server.example.com
MATRIX_TENANT_ID=your-tenant-id
```

## Run Pick

```bash
# Headless agent (no GUI)
./run-pentest.sh headless dev

# Desktop app (requires sudo for WiFi)
sudo cargo run --package pentest-desktop
```

## Troubleshooting

**Script fails on dependency installation:**
- Check you have sudo/admin privileges
- Verify network connectivity

**Rust not found after install:**
```bash
source $HOME/.cargo/env
```

**Build takes forever:**
- First build compiles all dependencies (5-10 minutes)
- Subsequent builds are much faster

**Connection refused when running:**
- Verify STRIKE48_HOST in .env
- Check if backend is running

## Full Documentation

- [INSTALLATION.md](INSTALLATION.md) - Complete installation guide
- [README.md](../README.md) - Full project documentation
- [UI_FEATURES.md](UI_FEATURES.md) - Customization guide

## Getting Help

- GitHub Issues: [Strike48-public/pick/issues](https://github.com/Strike48-public/pick/issues)
- Full troubleshooting guide: [INSTALLATION.md#troubleshooting](INSTALLATION.md#troubleshooting)
