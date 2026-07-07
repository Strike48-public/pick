# Build Troubleshooting Guide

Common build errors and their solutions when building Pick.

---

## Quick Diagnosis

Run this command to identify your build issue:

```bash
cargo build --package pentest-headless 2>&1 | tee build-error.log
```

Then search this page for your error message.

---

## Table of Contents

- [Rust Version Issues](#rust-version-issues)
- [OpenSSL Errors](#openssl-errors)
- [pkg-config Errors](#pkg-config-errors)
- [protobuf / protoc Errors](#protobuf--protoc-errors)
- [libpcap Errors](#libpcap-errors)
- [Linker Errors](#linker-errors)
- [Platform-Specific Issues](#platform-specific-issues)
- [Clean Build](#clean-build)

---

## Rust Version Issues

### Error: "package requires rustc 1.92 or newer"

**Symptom:**
```
error: package `egui v0.XX.X` cannot be built because it requires rustc 1.92.0 or newer
```

**Cause:** Pick requires Rust 1.92+ due to egui dependency requirements.

**Solution:**
```bash
# Update Rust
rustup update stable

# Verify version
rustc --version
# Should show: rustc 1.92.0 or higher
```

**If rustup update doesn't work:**
```bash
# Install latest stable explicitly
rustup install stable
rustup default stable
```

---

### Error: "edition 2021 is unstable"

**Symptom:**
```
error: edition 2021 is unstable and only available with -Z unstable-options
```

**Cause:** Using an old Rust version that doesn't support Edition 2021.

**Solution:**
```bash
# Update to Rust 1.56+ (Edition 2021 minimum)
rustup update stable
```

---

## OpenSSL Errors

### Error: "Could not find directory of OpenSSL installation"

**Symptom:**
```
error: failed to run custom build command for `openssl-sys v0.X.XX`
Could not find directory of OpenSSL installation
```

**Cause:** OpenSSL development headers not installed or not found.

**Solution (Debian/Ubuntu):**
```bash
sudo apt update
sudo apt install libssl-dev pkg-config
```

**Solution (Fedora/RHEL):**
```bash
sudo dnf install openssl-devel pkg-config
```

**Solution (macOS):**
```bash
brew install openssl@3

# Set environment variable for build
export OPENSSL_DIR=$(brew --prefix openssl@3)
cargo build
```

**Solution (Arch Linux):**
```bash
sudo pacman -S openssl pkg-config
```

---

### Error: "OpenSSL version mismatch"

**Symptom:**
```
error: OpenSSL version 1.1.1 is not supported
note: version 3.0 or later is required
```

**Cause:** System has old OpenSSL version.

**Solution (Ubuntu 22.04+):**
```bash
sudo apt install libssl-dev
# Should install OpenSSL 3.x
```

**Solution (Ubuntu 20.04 or older):**
```bash
# Upgrade to Ubuntu 22.04, or build OpenSSL from source
# Or use vendored OpenSSL:
cargo build --features vendored-openssl
```

---

## pkg-config Errors

### Error: "Could not run `pkg-config`"

**Symptom:**
```
error: failed to run custom build command for `openssl-sys`
pkg-config has not been configured to support cross-compilation
```

**Cause:** `pkg-config` not installed.

**Solution (Debian/Ubuntu):**
```bash
sudo apt install pkg-config
```

**Solution (Fedora/RHEL):**
```bash
sudo dnf install pkgconf-pkg-config
```

**Solution (macOS):**
```bash
brew install pkg-config
```

**Solution (Arch Linux):**
```bash
sudo pacman -S pkgconf
```

---

## protobuf / protoc Errors

### Error: "Could not find `protoc` installation"

**Symptom:**
```
error: failed to run custom build command for `prost-build`
Could not find `protoc` installation
```

**Cause:** Protocol Buffers compiler (protoc) not installed.

**Solution (Debian/Ubuntu):**
```bash
sudo apt install protobuf-compiler
```

**Solution (Fedora/RHEL):**
```bash
sudo dnf install protobuf-compiler
```

**Solution (macOS):**
```bash
brew install protobuf
```

**Solution (Arch Linux):**
```bash
sudo pacman -S protobuf
```

**Verify installation:**
```bash
protoc --version
# Should show: libprotoc 3.x or higher
```

---

### Error: "protoc version too old"

**Symptom:**
```
error: protoc version 2.X is too old, need 3.0 or later
```

**Solution:**
```bash
# Debian/Ubuntu
sudo apt update
sudo apt install --reinstall protobuf-compiler

# macOS
brew upgrade protobuf

# Verify
protoc --version
```

---

## libpcap Errors

### Error: "Could not find library `pcap`"

**Symptom:**
```
error: failed to run custom build command for `pcap-sys`
Could not find library `pcap` required for `libpcap`
```

**Cause:** libpcap development headers not installed (required for packet capture features).

**Solution (Debian/Ubuntu):**
```bash
sudo apt install libpcap-dev
```

**Solution (Fedora/RHEL):**
```bash
sudo dnf install libpcap-devel
```

**Solution (macOS):**
```bash
# Usually pre-installed, but if missing:
brew install libpcap
```

**Solution (Arch Linux):**
```bash
sudo pacman -S libpcap
```

---

## Linker Errors

### Error: "linking with `cc` failed"

**Symptom:**
```
error: linking with `cc` failed: exit status: 1
ld: library not found for -lssl
```

**Cause:** Linker cannot find required libraries.

**Solution:**

1. **Install missing development packages:**
```bash
# Debian/Ubuntu
sudo apt install build-essential libssl-dev libpcap-dev

# Fedora/RHEL
sudo dnf install gcc openssl-devel libpcap-devel

# macOS
xcode-select --install
```

2. **Set library path (macOS):**
```bash
export LIBRARY_PATH=$(brew --prefix)/lib
export CPATH=$(brew --prefix)/include
cargo build
```

---

### Error: "cannot find -lpthread"

**Symptom:**
```
error: linking with `cc` failed
ld: cannot find -lpthread
```

**Cause:** Missing glibc development files.

**Solution (Debian/Ubuntu):**
```bash
sudo apt install build-essential libc6-dev
```

**Solution (Fedora/RHEL):**
```bash
sudo dnf install glibc-devel
```

---

## Platform-Specific Issues

### Linux

#### Error: "failed to load shared library"

**Symptom:**
```
error while loading shared libraries: libssl.so.3: cannot open shared object file
```

**Solution:**
```bash
# Update library cache
sudo ldconfig

# Or install missing library
sudo apt install libssl3  # Debian/Ubuntu
sudo dnf install openssl-libs  # Fedora/RHEL
```

---

### macOS

#### Error: "xcrun: error: invalid active developer path"

**Symptom:**
```
xcrun: error: invalid active developer path
```

**Solution:**
```bash
# Install Xcode command-line tools
xcode-select --install

# If already installed, reset path
sudo xcode-select --reset
```

---

#### Error: "ld: framework 'Security' not found"

**Symptom:**
```
error: linking with `cc` failed
ld: framework 'Security' not found
```

**Solution:**
```bash
# Install Xcode command-line tools
xcode-select --install

# Ensure Xcode is up to date
softwareupdate --all --install --force
```

---

### Windows (WSL)

#### Error: "error: linker `cc` not found"

**Symptom:**
```
error: linker `cc` not found
```

**Solution:**
```bash
# Install build tools in WSL
sudo apt update
sudo apt install build-essential
```

---

#### Error: "could not find native TLS library"

**Solution:**
```bash
# Install OpenSSL in WSL
sudo apt install libssl-dev pkg-config
```

---

### Android

See [ANDROID_BUILD.md](ANDROID_BUILD.md) for Android-specific build issues.

---

## Clean Build

If you encounter persistent build issues, try a clean build:

```bash
# Remove all build artifacts
cargo clean

# Remove Cargo.lock (regenerates dependencies)
rm Cargo.lock

# Clear Cargo registry cache (nuclear option)
rm -rf ~/.cargo/registry/cache
rm -rf ~/.cargo/git/checkouts

# Rebuild
cargo build --package pentest-headless
```

---

## Dependency Issues

### Error: "failed to download dependencies"

**Symptom:**
```
error: failed to download `crate-name v1.0.0`
```

**Cause:** Network issues or corrupted cache.

**Solution:**
```bash
# Update cargo index
cargo update

# If that fails, clear and re-fetch
rm -rf ~/.cargo/registry/index
cargo fetch
```

---

### Error: "version conflict in dependencies"

**Symptom:**
```
error: failed to select a version for `crate-name`
```

**Solution:**
```bash
# Update dependencies
cargo update

# If specific conflict, update Cargo.toml version constraints
# Then:
cargo clean
cargo build
```

---

## Incremental Compilation Issues

### Error: "incremental compilation data is corrupt"

**Symptom:**
```
error: internal compiler error: incremental compilation data is corrupt
```

**Solution:**
```bash
# Remove incremental compilation cache
rm -rf target/debug/incremental
rm -rf target/release/incremental

# Rebuild
cargo build
```

---

## Out of Memory Errors

### Error: "signal: 9, SIGKILL: kill"

**Symptom:**
```
error: could not compile `crate-name`
Caused by: signal: 9, SIGKILL: kill
```

**Cause:** Rust compiler ran out of memory (common on small VMs).

**Solution:**

1. **Reduce parallel compilation:**
```bash
# Build with fewer parallel jobs
cargo build -j 2

# Or set permanently
export CARGO_BUILD_JOBS=2
```

2. **Increase swap:**
```bash
# Check current swap
free -h

# Add swap file (Ubuntu/Debian)
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

3. **Build in release mode (uses less memory):**
```bash
cargo build --release
```

---

## Still Having Issues?

### 1. Check Prerequisites

Ensure all required dependencies are installed:

```bash
# Rust version
rustc --version  # Should be 1.92.0+

# Required tools
pkg-config --version
protoc --version
openssl version
```

### 2. Enable Verbose Output

```bash
# See detailed error messages
cargo build -vv 2>&1 | tee build-error.log
```

### 3. Search GitHub Issues

Check existing issues: https://github.com/Strike48-public/pick/issues

### 4. Ask for Help

- **GitHub Discussions:** https://github.com/Strike48-public/pick/discussions
- **Create an issue:** Include your `build-error.log` file
- **Include:**
  - OS and version (`uname -a`)
  - Rust version (`rustc --version`)
  - Full error output
  - What you've already tried

---

## Common Environment Setup

### Debian/Ubuntu (All Dependencies)

```bash
sudo apt update
sudo apt install -y \
    build-essential \
    libssl-dev \
    pkg-config \
    protobuf-compiler \
    libpcap-dev \
    git \
    curl

# Install Rust if not present
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Update to latest stable
rustup update stable
```

### Fedora/RHEL (All Dependencies)

```bash
sudo dnf install -y \
    gcc \
    openssl-devel \
    pkgconf-pkg-config \
    protobuf-compiler \
    libpcap-devel \
    git \
    curl

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### macOS (All Dependencies)

```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install openssl@3 protobuf libpcap pkg-config

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Set environment for OpenSSL
export OPENSSL_DIR=$(brew --prefix openssl@3)
```

### Arch Linux (All Dependencies)

```bash
sudo pacman -Syu
sudo pacman -S --needed \
    base-devel \
    openssl \
    pkgconf \
    protobuf \
    libpcap \
    git \
    rustup

# Install stable Rust
rustup default stable
```

---

**Last updated:** 2026-05-28
