# Pick Installation Guide

Complete installation guide for the Pick penetration testing connector.

## Table of Contents

- [Quick Install](#quick-install)
- [Manual Installation](#manual-installation)
- [Platform-Specific Guides](#platform-specific-guides)
- [Environment Configuration](#environment-configuration)
- [Troubleshooting](#troubleshooting)

## Quick Install

The automated installation script handles prerequisites, dependencies, and configuration:

```bash
git clone https://github.com/Strike48-public/pick.git
cd pick
./install.sh
```

### What the Script Does

1. Detects your operating system and distribution
2. Installs Rust and Cargo (if not present)
3. Installs platform-specific build dependencies
4. Optionally installs desktop app dependencies
5. Optionally installs WiFi scanning tools
6. Creates `.env` configuration file from template
7. Optionally builds and tests the project

### Interactive Prompts

The script will ask:
- Install desktop app dependencies? (WebKit, GTK)
- Install WiFi scanning tools? (wireless-tools, aircrack-ng)
- Overwrite existing .env file?
- Open .env in editor?
- Build Pick now?
- Run tests?

All prompts default to "No" if you press Enter.

## Manual Installation

### Step 0: Check Dependencies (Optional)

Before installing, you can check if you have all required dependencies:

```bash
./check-deps.sh
```

This script will:
- Check for Rust and Cargo (version 1.70+)
- Verify build tools (gcc/clang, pkg-config)
- Check for OpenSSL development headers
- Report optional dependencies (desktop, WiFi tools)
- Provide specific fix commands for missing dependencies

### Step 1: Install Rust

**Linux / macOS / WSL:**
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

**Windows:**
- Download and run [rustup-init.exe](https://rustup.rs/)
- Or use winget:
  ```powershell
  winget install Rustlang.Rustup
  ```

**Verify:**
```bash
rustc --version  # Should show 1.70 or higher
cargo --version
```

### Step 2: Install Dependencies

See [Platform-Specific Guides](#platform-specific-guides) below.

### Step 3: Clone Repository

```bash
git clone https://github.com/Strike48-public/pick.git
cd pick
```

### Step 4: Configure Environment

```bash
cp .env.example .env
nano .env  # Edit with your Strike48 backend details
```

Required configuration:
- `STRIKE48_HOST` - Strike48 server endpoint
- `STRIKE48_TENANT` - Tenant identifier
- `MATRIX_API_URL` - Matrix API endpoint
- `MATRIX_TENANT_ID` - Matrix tenant identifier

See [Environment Configuration](#environment-configuration) for details.

### Step 5: Build

```bash
# Build headless agent (recommended for first time)
cargo build --package pentest-headless

# Or build all packages
cargo build --all
```

### Step 6: Run

```bash
# Headless agent (no GUI)
./run-pentest.sh headless dev

# Desktop app (requires sudo for WiFi)
sudo cargo run --package pentest-desktop
```

## Platform-Specific Guides

### Linux (Debian/Ubuntu)

```bash
# Update package list
sudo apt update

# Core build tools (required)
sudo apt install -y build-essential pkg-config libssl-dev protobuf-compiler

# Desktop app dependencies (optional)
sudo apt install -y libwebkit2gtk-4.0-dev libgtk-3-dev libayatana-appindicator3-dev

# WiFi scanning tools (optional)
sudo apt install -y wireless-tools aircrack-ng
```

### Linux (Fedora/RHEL/CentOS)

```bash
# Core build tools (required)
sudo dnf install -y gcc gcc-c++ make openssl-devel protobuf-compiler

# Desktop app dependencies (optional)
sudo dnf install -y webkit2gtk3-devel gtk3-devel libappindicator-gtk3-devel

# WiFi scanning tools (optional)
sudo dnf install -y wireless-tools aircrack-ng
```

### macOS

```bash
# Install Xcode Command Line Tools
xcode-select --install

# No additional dependencies needed for basic building
# Desktop app will work out of the box
```

### Windows

**Visual Studio Build Tools:**
1. Download [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022)
2. Select "Desktop development with C++" workload
3. Install

**Or use winget:**
```powershell
winget install Microsoft.VisualStudio.2022.BuildTools
```

## Environment Configuration

### Required Variables

Edit `.env` and set these values:

```bash
# Strike48 Backend
STRIKE48_HOST=wss://your-server.example.com
STRIKE48_TENANT=your-tenant-id

# Matrix API
MATRIX_API_URL=https://your-server.example.com
MATRIX_TENANT_ID=your-tenant-id
```

### Optional Variables

```bash
# Authentication (if not using OTT)
STRIKE48_TOKEN=your_jwt_token_here

# Custom instance ID
STRIKE48_INSTANCE_ID=pick-machine-01

# TLS Configuration
STRIKE48_TLS=true
MATRIX_TLS_INSECURE=false  # Set true for self-signed certs (dev only)

# Logging
RUST_LOG=debug  # trace, debug, info, warn, error

# Gateway Identity
CONNECTOR_NAME=pentest-connector  # Set unique name per host

# Workspace
WORKSPACE_PATH=/custom/workspace/path
```

### Connection Formats

**WebSocket:**
```bash
STRIKE48_HOST=ws://localhost:3030   # HTTP
STRIKE48_HOST=wss://example.com     # HTTPS
```

**gRPC:**
```bash
STRIKE48_HOST=grpc://localhost:50061   # Without TLS
STRIKE48_HOST=grpc://example.com:443   # With TLS (set STRIKE48_TLS=true)
```

### Development vs Production

**Development:**
```bash
STRIKE48_HOST=ws://localhost:3030
STRIKE48_TLS=false
MATRIX_TLS_INSECURE=true
RUST_LOG=debug
```

**Production:**
```bash
STRIKE48_HOST=wss://connectors.example.com
STRIKE48_TLS=true
MATRIX_TLS_INSECURE=false
RUST_LOG=info
```

## Troubleshooting

### Using the Dependency Checker

If you encounter build errors, run the dependency checker first:

```bash
./check-deps.sh
```

It will identify exactly what's missing and provide the fix commands for your OS.

### Rust Installation Issues

**Permission denied during install:**
```bash
# Ensure you can write to ~/.cargo
ls -la ~/.cargo || mkdir -p ~/.cargo
```

**Rust not in PATH after install:**
```bash
source $HOME/.cargo/env
# Or add to ~/.bashrc or ~/.zshrc
echo 'source $HOME/.cargo/env' >> ~/.bashrc
```

### Build Errors

**OpenSSL not found (Linux):**

This is the most common build error. You need both OpenSSL headers AND pkg-config:

```bash
# Debian/Ubuntu
sudo apt update
sudo apt install -y build-essential pkg-config libssl-dev

# Fedora/RHEL
sudo dnf install -y gcc gcc-c++ make openssl-devel

# Arch Linux
sudo pacman -S base-devel openssl pkg-config
```

**pkg-config not found:**

pkg-config is required for the build system to find OpenSSL and other libraries:

```bash
# Debian/Ubuntu
sudo apt install -y pkg-config

# Fedora/RHEL  
sudo dnf install -y pkgconfig

# macOS (via Homebrew)
brew install pkg-config
```

**protoc (Protocol Buffers compiler) not found:**

protoc is required to compile gRPC/protobuf definitions:

```bash
# Debian/Ubuntu
sudo apt install -y protobuf-compiler

# Fedora/RHEL
sudo dnf install -y protobuf-compiler

# Arch Linux
sudo pacman -S protobuf

# macOS (via Homebrew)
brew install protobuf

# Verify installation
protoc --version
```

**WebKit not found (Linux desktop):**
```bash
sudo apt install -y libwebkit2gtk-4.0-dev  # Debian/Ubuntu
sudo dnf install -y webkit2gtk3-devel      # Fedora/RHEL
```

**Linker errors on Windows:**
- Ensure Visual Studio Build Tools with C++ workload is installed
- Restart terminal after installation

### Runtime Issues

**Connection refused:**
- Verify `STRIKE48_HOST` is correct
- Check if Strike48 backend is running
- Verify firewall/network connectivity

**TLS certificate errors:**
- For development: Set `MATRIX_TLS_INSECURE=true`
- For production: Ensure valid certificates or provide CA cert

**WiFi scanning doesn't work:**
- WiFi tools require root privileges
- Run with: `sudo cargo run --package pentest-desktop`
- Or use: `sudo ./run-pentest.sh desktop dev`

**Permission denied on tools:**
- Some penetration testing tools require elevated privileges
- Run Pick with `sudo` when using these features

### First Build is Slow

The first build downloads and compiles all dependencies, which can take 5-10 minutes:

```bash
# Monitor progress with verbose output
cargo build --package pentest-headless --verbose

# Or build in release mode (slower but optimized)
cargo build --package pentest-headless --release
```

### Recommended WiFi Adapter Lost Connection

If you're scanning with your primary WiFi adapter:
- Your adapter enters monitor mode
- You lose internet connection
- Pick disconnects from Strike48

**Solution:** Use an external WiFi adapter for scanning while keeping your primary connection active.

See [Recommended WiFi Adapters](../README.md#recommended-wifi-adapters) in README.

## Next Steps

After successful installation:

1. **Configure environment:** Edit `.env` with your backend details
2. **Build the project:** `cargo build --package pentest-headless`
3. **Run Pick:** `./run-pentest.sh headless dev`
4. **Read the docs:**
   - [README.md](../README.md) - Full documentation
   - [UI_FEATURES.md](UI_FEATURES.md) - UI customization guide
   - [RUNNING.md](RUNNING.md) - Deployment guide (if available)

## Getting Help

- GitHub Issues: [https://github.com/Strike48-public/pick/issues](https://github.com/Strike48-public/pick/issues)
- Documentation: [docs/](.)
- Strike48 Support: Contact your administrator

## Security Notes

- Never commit your `.env` file with real credentials
- Use TLS (`STRIKE48_TLS=true`) in production
- Only use `MATRIX_TLS_INSECURE=true` in development
- WiFi tools require authorization before use on any network
