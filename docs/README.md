# Pick Documentation

Complete documentation for the Pick penetration testing connector.

## Getting Started

- **[Quick Install Guide](QUICK_INSTALL.md)** - Get running in 5 minutes
- **[Installation Guide](INSTALLATION.md)** - Complete installation instructions, troubleshooting, and platform guides
- **[Build Troubleshooting](BUILD_TROUBLESHOOTING.md)** - Fix common build errors (OpenSSL, pkg-config, protoc, linker issues)
- **[Runtime Troubleshooting](RUNTIME_TROUBLESHOOTING.md)** - Fix runtime errors (workspace, resources, connections, permissions)
- **[Main README](../README.md)** - Project overview, features, and architecture

## User Guides

- **[UI Features](UI_FEATURES.md)** - Theme customization, keyboard shortcuts, and visual features
- **[Autopwn Guide](AUTOPWN.md)** - Automated penetration testing workflows
- **[Autopwn Testing](autopwn-testing-guide.md)** - Testing autopwn scenarios

## Technical Documentation

- **[Network Restoration](network-restoration.md)** - WiFi recovery procedures
- **[Token Expiration Fix](token-expiration-fix.md)** - Authentication troubleshooting
- **[CyberChef Drag & Drop](cyberchef-drag-drop-testing.md)** - File analysis testing
- **[E2E Testing Setup](e2e-testing-setup.md)** - End-to-end test configuration

## Product & Planning

- **[Customer Features](PICK_CUSTOMER_FEATURES.md)** - Feature roadmap and customer requests
- **[Competitive Analysis](COMPETITIVE_ANALYSIS_TRIAGE.md)** - Market analysis and positioning

## Quick Reference

### Installation

```bash
# Automated install
./install.sh

# Manual build
cargo build --package pentest-headless

# Run
./run-pentest.sh headless dev
```

### Configuration

Edit `.env`:
```bash
STRIKE48_HOST=wss://your-server.example.com
STRIKE48_TENANT=your-tenant-id
MATRIX_API_URL=https://your-server.example.com
MATRIX_TENANT_ID=your-tenant-id
```

### Common Commands

```bash
# Headless agent
./run-pentest.sh headless dev

# Desktop app (requires sudo)
sudo cargo run --package pentest-desktop

# Web app
cargo run --package pentest-web

# Run tests
cargo test

# Format code
cargo fmt --all

# Lint
cargo clippy -- -D warnings
```

## Platform Support

| Platform | Status | Notes |
|----------|--------|-------|
| Linux | ✓ Full Support | Debian/Ubuntu, Fedora/RHEL |
| macOS | ✓ Full Support | Intel and Apple Silicon |
| Windows | ✓ Via WSL | Native support in progress |
| Android | ⚠ Experimental | Requires cargo-mobile2 |
| iOS | ⚠ Experimental | Requires Xcode |

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Strike48 Backend                             │
│                   (Routes tool requests)                        │
└───────┬─────────────────┬─────────────────┬─────────────────┬───┘
        │                 │                 │                 │
        ▼                 ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│   Desktop     │ │     Web       │ │    Mobile     │ │     TUI       │
│  (dioxus-     │ │  (dioxus-     │ │  (dioxus-     │ │  (dioxus-     │
│   desktop)    │ │   liveview)   │ │   mobile)     │ │   tui)        │
├───────────────┤ ├───────────────┤ ├───────────────┤ ├───────────────┤
│ UI + Tools    │ │ UI + Tools    │ │ UI + Tools    │ │ UI + Tools    │
│ run locally   │ │ run on server │ │ run on device │ │ run locally   │
└───────────────┘ └───────────────┘ └───────────────┘ └───────────────┘
```

Each app IS a connector - it registers with Strike48 and executes tools locally.

## Support

- **GitHub Issues:** [Strike48-public/pick/issues](https://github.com/Strike48-public/pick/issues)
- **Strike48 Support:** Contact your administrator
- **Security Issues:** security@strike48.com

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines (if available).

## License

MIT License - See [LICENSE](../LICENSE) file for details.
