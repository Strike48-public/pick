# Pick

A multiplatform penetration testing connector built with [Dioxus](https://dioxuslabs.com/) and integrated with the [Strike48 Connector SDK](https://github.com/strike48/strike48-rs).

**Pick** connects Strike48 to local penetration testing tools, executing them securely on the machine where it runs.

## Architecture

**Each app IS a connector** - it registers with Strike48 and executes tools locally on the machine where it runs:

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

## Platforms

| Platform | Technology | Tools Execute On |
|----------|------------|------------------|
| **Headless** | dioxus-liveview + axum | Server / StrikeHub IPC |
| **Desktop** | dioxus-desktop | Local machine |
| **Web** | dioxus-liveview + axum | Server hosting the app |
| **Android** | dioxus-mobile | Android device |
| **iOS** | dioxus-mobile | iOS device |
| **TUI** | dioxus-tui | Local machine (terminal) |

## Features

### UI Customization

- **8 Built-in Themes**: Dark, Light, Dracula, Gruvbox, Tokyo Night, Matrix, Cyberpunk, Nord
- **Custom Themes**: Import your own CSS themes with security validation
- **Keyboard Shortcuts**: `Ctrl+Shift+1-8` for instant theme switching
- **Shape Customization**: 5 border radius options (Sharp to Pill)
- **Density Control**: Compact, Normal, or Comfortable spacing
- **Smooth Transitions**: Animated theme changes with 300ms easing
- **Easter Eggs**: Konami code (↑↑↓↓←→←→BA) activates Matrix rain animation

See [`docs/UI_FEATURES.md`](docs/UI_FEATURES.md) for complete customization guide.

### Penetration Testing Tools

Pick integrates **90+ penetration testing tools** across multiple categories:

**Native Tools (24):**
- Network scanning (port_scan, arp_table, ssdp_discover, network_discover)
- WiFi testing (wifi_scan, wifi_scan_detailed, autopwn suite)
- Web vulnerability scanning
- Credential testing and harvesting
- Evidence collection (screenshot, traffic_capture)
- System enumeration and command execution

**External Tool Integrations (70+):**
- **Network:** nmap, masscan, rustscan, unicornscan
- **Web:** nikto, sqlmap, nuclei, ffuf, feroxbuster, gobuster
- **WiFi:** aircrack-ng, bettercap, responder
- **Enumeration:** subfinder, amass, enum4linux, smbmap
- **Exploitation:** hydra, john, hashcat, crackmapexec
- **And many more...**

See [docs/TOOLS.md](docs/TOOLS.md) for the complete tool catalog.

### Three-Agent Validation Pipeline

Evidence quality assurance through specialized agents:
- **Red Team Agent** - Tool execution and evidence generation
- **Validator Agent** - Quality verification and validation
- **Report Agent** - Finding synthesis and reporting

### Recent Features

- **Android Root Detection** (PR #123) - Detect rooted Android devices
- **Agent ERROR Status Detection** (PR #134) - Surface token limit notices
- **Strike48 Default Theme** (PR #120) - Professional default theme
- **Chat Panel Routing** (PR #132) - Fixed LiveView event handling

## Project Structure

```
pick/
├── crates/
│   ├── core/          # Core types, state management, SDK integration
│   ├── platform/      # Platform abstraction (desktop, android, ios)
│   ├── ui/            # Shared Dioxus UI components + LiveView server
│   └── tools/         # Tool implementations
├── apps/
│   ├── headless/      # Headless agent (pentest-agent binary)
│   ├── desktop/       # Desktop app (dioxus-desktop)
│   ├── web/           # Web app (dioxus-liveview + axum)
│   ├── tui/           # Terminal app (dioxus-tui)
│   └── mobile/        # Mobile app (dioxus-mobile)
```

## Building

### Prerequisites

- Rust 1.70+ (with `cargo`)
- For desktop: Native development tools for your OS
- For mobile: `cargo-mobile2` and platform SDKs

### Headless Agent (Pick)

The headless agent (`pentest-agent`) runs without a GUI and serves its workspace
app via Dioxus LiveView over a Unix socket. It can run standalone or be managed
by StrikeHub as the "Pick" connector app.

```bash
# Standalone — connects to Strike48 directly
STRIKE48_HOST=grpc://connectors-studio.example.com:80 \
    STRIKE48_TENANT=non-prod \
    STRIKE48_INSTANCE_ID=pick-local \
    STRIKE48_TLS=false \
    MATRIX_TLS_INSECURE=true \
    cargo run --package pentest-headless

# StrikeHub IPC mode — launched automatically by StrikeHub with
# STRIKEHUB_SOCKET set. No STRIKE48_HOST required (liveview-only).
```

Environment variables (standalone):

| Variable | Description |
|----------|-------------|
| `STRIKE48_HOST` / `STRIKE48_URL` | gRPC/WebSocket endpoint |
| `STRIKE48_TENANT` / `TENANT_ID` | Tenant identifier |
| `STRIKE48_INSTANCE_ID` / `INSTANCE_ID` | Connector instance ID |
| `STRIKE48_TOKEN` | JWT auth token (optional) |
| `STRIKE48_TLS` | `true` or `false` |
| `CONNECTOR_NAME` | Gateway identity name (default: `pentest-connector`). Set a unique name per host to get a dedicated agent view instead of round-robin. |
| `MATRIX_TLS_INSECURE` | Accept self-signed certs |
| `STRIKEHUB_SOCKET` | Unix socket path (set by StrikeHub) |

### Desktop

```bash
# Development (requires sudo for WiFi hardware access)
sudo cargo run --package pentest-desktop

# Release build
cargo build --release --package pentest-desktop
sudo ./target/release/pentest-desktop
```

**Why sudo?** WiFi penetration testing tools (autopwn, wifi_scan, airmon-ng) require direct hardware access to wireless adapters, which needs real root privileges. See [docs/BWRAP_SUDO_EXPLAINED.md](docs/BWRAP_SUDO_EXPLAINED.md) for details.

### Web (Liveview)

```bash
# Development (starts server on http://localhost:3000)
cargo run --package pentest-web

# Release build
cargo build --release --package pentest-web
```

### TUI

```bash
# Development
cargo run --package pentest-tui

# Release build
cargo build --release --package pentest-tui
```

### Mobile (requires additional setup)

```bash
# Install cargo-mobile2
cargo install cargo-mobile2

# Initialize mobile project (first time)
cd apps/mobile
cargo mobile init

# Build for Android
cargo mobile android build

# Build for iOS
cargo mobile ios build
```

## Configuration

The connector connects to a Strike48 backend server. Configuration options:

- **Strike48 Host**: gRPC or WebSocket endpoint (e.g., `grpc://localhost:50061`)
- **Tenant ID**: Strike48 tenant identifier
- **Auth Token**: JWT or One-Time Token (OTT) for authentication

Environment variables:
- `STRIKE48_HOST` / `STRIKE48_URL` - Strike48 server URL
- `STRIKE48_TENANT` / `TENANT_ID` - Tenant ID
- `STRIKE48_INSTANCE_ID` / `INSTANCE_ID` - Connector instance ID
- `CONNECTOR_NAME` - Gateway identity name (default: `pentest-connector`)
- `RUST_LOG` - Logging level (e.g., `pentest=debug`)

## How It Works

1. You run one of the apps (desktop, web, tui, mobile)
2. The app connects to the Strike48 backend and registers as a connector
3. The app presents a UI for manual tool execution
4. Tools can also be triggered remotely via the Strike48 API (e.g., by an AI agent)
5. All tool execution happens locally on the machine running the app

Pick is a native app that is both a UI and a connector - the same architecture proven in production environments.

## Development

### Adding a New Tool

1. Create tool file in `crates/tools/src/`
2. Implement `PentestTool` trait
3. Add to `create_tool_registry()` in `lib.rs`
4. Implement platform-specific functionality in `crates/platform/`

### Adding Platform Support

1. Create platform module in `crates/platform/src/`
2. Implement all platform traits (`NetworkOps`, `SystemInfo`, `CaptureOps`, `CommandExec`)
3. Add feature flag to `Cargo.toml`
4. Update `get_platform()` function

## Recommended WiFi Adapters

For WiFi scanning and pentesting features, we recommend using a dedicated external WiFi adapter. This prevents disconnection issues when your primary adapter enters monitor mode.

### ⚠️ Important: Avoid Connection Loss

If you're connected to the internet via WiFi and try to scan with your built-in adapter:
1. Your adapter enters monitor mode
2. You lose your internet connection
3. Pick disconnects from the Strike48 backend
4. The scan fails

**Solution:** Use an external adapter for scanning while keeping your internet connection active via built-in WiFi or Ethernet.

### Top Recommendations (2025–2026)

#### Best Overall
**Alfa AWUS036ACHM** (MT7610U / MediaTek chipset)
- Dual-band (2.4 & 5 GHz)
- Excellent range/sensitivity
- Reliable monitor mode + packet injection
- Native Linux driver support (mt76 series)
- Plug-and-play on modern Kali
- Compact/mini form factor
- ~$40-50 range

#### Future-Proof Option
**Alfa AWUS036AXML** (MT7921AU / MediaTek WiFi 6E chipset)
- WiFi 6E support (adds 6 GHz)
- Very strong 2025 performance
- Good drivers in recent kernels
- Excellent range on 2.4/5 GHz
- Reliable injection
- ~$60-70 range

#### Budget Dual-Band
**Alfa AWUS036ACS or AWUS036AC** (Realtek RTL8811AU / RTL8812AU)
- Budget-friendly (~$30 range)
- Dual-band (2.4 & 5 GHz)
- Solid out-of-the-box Kali support
- Good for beginners
- Reliable for basic-intermediate aircrack-ng tasks

#### Maximum Range
**Alfa AWUS1900** (Realtek RTL8814AU)
- 4 antennas, very long range
- High power output
- Great for wardriving or distant targets
- Slightly bulkier and more expensive (~$80-100)

### Classic / Budget Options (Still Work Well)

- **Alfa AWUS036NHA** (Atheros AR9271) - Gold standard for years, rock-solid injection, 2.4 GHz only
- **Panda PAU05 / PAU09** - Low-profile, cheap, reliable 2.4 GHz injection
- **TP-Link TL-WN722N v1** (Atheros AR9271) - Very cheap and effective (avoid v2/v3)

## Security Notes

This tool is designed for authorized penetration testing and security research. Features include:

- Network reconnaissance capabilities
- System information gathering
- Traffic interception (requires elevated privileges)
- Command execution

**Always ensure you have proper authorization before using these tools on any system or network.**

## License

MIT License - See LICENSE file for details.

## Credits

- [Dioxus](https://dioxuslabs.com/) - Cross-platform UI framework
- [Strike48 Connector SDK](../strike48-rs) - gRPC/WebSocket connector framework
- Based on [android-pentest-connector](../android-pentest-connector)
