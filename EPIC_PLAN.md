# Dioxus Multiplatform Pentest Connector - Epic Plan

## Project Overview

Create a multiplatform pentest connector application using Dioxus that replicates and extends the functionality of the Android Pentest Connector. The application will target:
- **Web** (WebAssembly)
- **Desktop** (Windows, macOS, Linux)
- **Android** (via Dioxus mobile)
- **iOS** (via Dioxus mobile)
- **TUI** (Terminal UI via dioxus-tui)

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Dioxus UI Layer                              │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐      │
│  │   Web    │ Desktop  │ Android  │   iOS    │   TUI    │      │
│  └────┬─────┴────┬─────┴────┬─────┴────┬─────┴────┬─────┘      │
│       │          │          │          │          │             │
│  ┌────▼──────────▼──────────▼──────────▼──────────▼────┐       │
│  │              Shared UI Components                     │       │
│  │  (Terminal, StatusBar, ToolPanel, ConfigForm)        │       │
│  └────────────────────────┬──────────────────────────────┘       │
└───────────────────────────┼──────────────────────────────────────┘
                            │
┌───────────────────────────┼──────────────────────────────────────┐
│                    Core Library                                  │
│  ┌────────────────────────▼──────────────────────────────┐      │
│  │              State Management (Signals)                │      │
│  │  - ConnectorState, ToolResults, TerminalOutput        │      │
│  └────────────────────────┬──────────────────────────────┘      │
│                           │                                      │
│  ┌────────────────────────▼──────────────────────────────┐      │
│  │              Tool Abstraction Layer                    │      │
│  │  - PentestTool trait                                  │      │
│  │  - Platform-agnostic tool definitions                 │      │
│  └────────────────────────┬──────────────────────────────┘      │
│                           │                                      │
│  ┌────────────────────────▼──────────────────────────────┐      │
│  │           Strike48 Connector SDK Integration             │      │
│  │  - BaseConnector implementation                        │      │
│  │  - gRPC/WebSocket transport                           │      │
│  └───────────────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────────┘
                            │
┌───────────────────────────┼──────────────────────────────────────┐
│              Platform Abstraction Layer                          │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐       │
│  │  Web     │ Desktop  │ Android  │   iOS    │   TUI    │       │
│  │ Platform │ Platform │ Platform │ Platform │ Platform │       │
│  └──────────┴──────────┴──────────┴──────────┴──────────┘       │
│                                                                  │
│  Each platform implements:                                       │
│  - NetworkOps (port scan, ARP, SSDP, mDNS)                      │
│  - SystemInfo (device info, process list)                        │
│  - Capture (screenshot, traffic)                                 │
│  - CommandExec (shell commands where available)                  │
└──────────────────────────────────────────────────────────────────┘
```

## Epic Breakdown

---

### Epic 1: Project Scaffolding & Core Infrastructure

**Goal:** Set up the Dioxus multiplatform project structure with proper workspace configuration.

#### Tasks:

1.1. **Initialize Cargo Workspace**
   - Create `Cargo.toml` workspace with members
   - Configure shared dependencies
   - Set up feature flags for each platform

1.2. **Create Core Library Crate (`crates/core`)**
   - State management types
   - Tool trait definitions
   - Shared utilities

1.3. **Create Platform Abstraction Crate (`crates/platform`)**
   - Define platform traits
   - Feature-gated platform implementations

1.4. **Create UI Components Crate (`crates/ui`)**
   - Dioxus component library
   - Shared styling/theming

1.5. **Create Platform Entry Points**
   - `apps/desktop` - Desktop application
   - `apps/web` - WebAssembly application
   - `apps/mobile` - Android/iOS application
   - `apps/tui` - Terminal UI application

1.6. **Configure Build System**
   - Trunk for web builds
   - cargo-mobile2 for mobile builds
   - Standard cargo for desktop/TUI

---

### Epic 2: Core Library Implementation

**Goal:** Implement the shared core library with state management and tool abstractions.

#### Tasks:

2.1. **State Management**
   ```rust
   // Connection state
   pub enum ConnectorStatus { Disconnected, Connecting, Registered }

   // App state
   pub struct AppState {
       pub status: Signal<ConnectorStatus>,
       pub terminal_output: Signal<Vec<TerminalLine>>,
       pub config: Signal<ConnectorConfig>,
       pub active_tools: Signal<HashMap<String, ToolExecution>>,
   }
   ```

2.2. **Tool Abstraction Layer**
   ```rust
   #[async_trait]
   pub trait PentestTool: Send + Sync {
       fn name(&self) -> &str;
       fn description(&self) -> &str;
       fn schema(&self) -> ToolSchema;
       fn supported_platforms(&self) -> Vec<Platform>;
       async fn execute(&self, params: Value, ctx: &ToolContext) -> ToolResult;
   }
   ```

2.3. **Terminal Output System**
   ```rust
   pub struct TerminalLine {
       pub timestamp: DateTime<Utc>,
       pub level: LogLevel,  // Info, Success, Warning, Error, Debug
       pub message: String,
       pub source: Option<String>,
   }
   ```

2.4. **Configuration Management**
   - Strike48 Host, Tenant ID, Auth Token
   - Platform-specific settings
   - Persistence via platform storage

2.5. **Strike48 Connector SDK Integration**
   - Implement `BaseConnector` for the pentest tools
   - Handle tool registration and execution
   - Manage connection lifecycle

---

### Epic 3: Platform Abstraction Layer

**Goal:** Create platform-specific implementations for all pentest capabilities.

#### Tasks:

3.1. **Define Platform Traits**
   ```rust
   #[async_trait]
   pub trait NetworkOps {
       async fn port_scan(&self, config: ScanConfig) -> Result<ScanResult>;
       async fn get_arp_table(&self) -> Result<Vec<ArpEntry>>;
       async fn ssdp_discover(&self, timeout_ms: u64) -> Result<Vec<SsdpDevice>>;
       async fn mdns_discover(&self, service_type: &str) -> Result<Vec<MdnsService>>;
   }

   #[async_trait]
   pub trait SystemInfo {
       async fn get_device_info(&self) -> Result<DeviceInfo>;
       async fn get_network_interfaces(&self) -> Result<Vec<NetworkInterface>>;
       async fn get_wifi_networks(&self) -> Result<Vec<WifiNetwork>>;
   }

   #[async_trait]
   pub trait CaptureOps {
       async fn capture_screenshot(&self) -> Result<Vec<u8>>;
       async fn start_traffic_capture(&self) -> Result<CaptureHandle>;
       async fn get_captured_packets(&self, limit: usize) -> Result<Vec<PacketInfo>>;
   }

   #[async_trait]
   pub trait CommandExec {
       async fn execute(&self, cmd: &str, args: &[&str], timeout: Duration) -> Result<CommandResult>;
   }
   ```

3.2. **Desktop Platform Implementation**
   - **Port Scanning:** Native TCP socket connections
   - **ARP Table:** Parse `/proc/net/arp` (Linux), `arp -a` (Windows/macOS)
   - **SSDP:** UDP multicast to 239.255.255.250:1900
   - **mDNS:** Use `mdns` or `zeroconf` crate
   - **Device Info:** `sysinfo` crate
   - **Screenshot:** `screenshots` crate or platform-native APIs
   - **Traffic Capture:** `pcap` crate (requires libpcap)
   - **Commands:** `std::process::Command`

3.3. **Web Platform Implementation**
   - **Port Scanning:** Not available (browser sandbox)
   - **ARP Table:** Not available
   - **SSDP/mDNS:** Not available
   - **Device Info:** Limited via `web-sys` (user agent, screen info)
   - **Screenshot:** Canvas capture of web content only
   - **Traffic Capture:** Not available
   - **Commands:** Not available
   - *Note: Web acts as viewer/controller only*

3.4. **Android Platform Implementation**
   - **Port Scanning:** Native TCP via Rust
   - **ARP Table:** Read `/proc/net/arp`
   - **SSDP:** UDP multicast
   - **mDNS:** Via Android NsdManager (JNI)
   - **WiFi Scan:** Via WifiManager (JNI)
   - **Device Info:** Via Android APIs (JNI)
   - **Screenshot:** Via MediaProjection (JNI)
   - **Traffic Capture:** Via VpnService (JNI)
   - **Commands:** Via proot/busybox

3.5. **iOS Platform Implementation**
   - **Port Scanning:** Native TCP
   - **ARP Table:** Limited access
   - **SSDP:** UDP multicast
   - **mDNS:** Via Network framework
   - **Device Info:** Via UIDevice
   - **Screenshot:** Limited due to sandbox
   - **Traffic Capture:** Not available (no VPN API access for capture)
   - **Commands:** Not available (sandbox)

3.6. **TUI Platform Implementation**
   - Same capabilities as Desktop
   - Uses terminal renderer instead of GUI

---

### Epic 4: UI Components Library

**Goal:** Create reusable Dioxus components for the application UI.

#### Tasks:

4.1. **Theme System**
   ```rust
   pub struct Theme {
       pub background: &'static str,      // #1e1e1e
       pub foreground: &'static str,      // #e0e0e0
       pub accent: &'static str,          // #007acc
       pub success: &'static str,         // #4caf50
       pub warning: &'static str,         // #ff9800
       pub error: &'static str,           // #f44336
       pub info: &'static str,            // #00bcd4
       pub font_mono: &'static str,       // "Courier New, monospace"
   }
   ```

4.2. **Terminal Component**
   - Scrollable output area
   - Color-coded log levels
   - Auto-scroll to bottom
   - Copy support
   - Search/filter (optional)

4.3. **Status Indicator Component**
   - Color-changing dot (red/yellow/green)
   - Status text label
   - Pulse animation for connecting state

4.4. **Connection Form Component**
   - Strike48 Host input
   - Tenant ID input
   - Auth Token input (password field)
   - Connect/Disconnect button
   - Validation feedback

4.5. **Tool Panel Component**
   - Tool selection dropdown/tabs
   - Parameter input forms (generated from schema)
   - Execute button
   - Results display

4.6. **Scan Controls Component**
   - Host input
   - Port specification input
   - Progress bar
   - Action buttons (Scan, Clear, Screenshot, Capture)

4.7. **Navigation Component**
   - Platform-appropriate navigation
   - Tab bar for mobile
   - Sidebar for desktop
   - Keyboard shortcuts for TUI

---

### Epic 5: Desktop Application

**Goal:** Build the desktop application targeting Windows, macOS, and Linux.

#### Tasks:

5.1. **Desktop Entry Point**
   - Main window setup
   - System tray integration (optional)
   - Menu bar

5.2. **Desktop-Specific Features**
   - File system access for exports
   - System notifications
   - Clipboard integration
   - Drag-and-drop support

5.3. **Desktop Tool Implementations**
   - Implement all tools using desktop-native APIs
   - Integrate libpcap for packet capture
   - Window/screen capture

5.4. **Desktop Build Configuration**
   - Windows installer (MSI/exe)
   - macOS app bundle (DMG)
   - Linux packages (AppImage, deb, rpm)

---

### Epic 6: Web Application

**Goal:** Build the WebAssembly application for browser deployment.

#### Tasks:

6.1. **Web Entry Point**
   - Trunk configuration
   - Index.html template
   - Asset management

6.2. **Web-Specific Adaptations**
   - WebSocket transport for Strike48 connection
   - Limited tool set (viewer/controller mode)
   - LocalStorage for settings
   - Service Worker for offline support (optional)

6.3. **Web UI Optimizations**
   - Responsive design
   - Touch support
   - PWA manifest

6.4. **Web Build & Deployment**
   - Trunk build pipeline
   - WASM optimization
   - Static hosting configuration

---

### Epic 7: Mobile Applications (Android & iOS)

**Goal:** Build native mobile applications using Dioxus mobile.

#### Tasks:

7.1. **Mobile Project Setup**
   - cargo-mobile2 configuration
   - Shared mobile crate
   - Platform-specific entry points

7.2. **Android Application**
   - JNI bindings for Android APIs
   - Foreground service for background operation
   - Notification channel
   - Permission handling
   - Battery optimization exemption

7.3. **iOS Application**
   - Swift/Objective-C bridge where needed
   - Background modes configuration
   - Permission handling
   - Entitlements configuration

7.4. **Mobile UI Adaptations**
   - Touch-optimized controls
   - Bottom navigation
   - Pull-to-refresh
   - Swipe gestures
   - Safe area handling

7.5. **Mobile Build & Distribution**
   - Android: APK/AAB signing
   - iOS: Code signing, provisioning profiles
   - App store metadata

---

### Epic 8: TUI Application

**Goal:** Build the terminal UI application using dioxus-tui.

#### Tasks:

8.1. **TUI Entry Point**
   - dioxus-tui configuration
   - Terminal size handling
   - Color support detection

8.2. **TUI Component Adaptations**
   - ASCII/Unicode box drawing
   - Keyboard navigation
   - Focus management
   - Modal dialogs

8.3. **TUI-Specific Features**
   - Vim-style keybindings
   - Mouse support (optional)
   - Terminal resize handling
   - 256-color/truecolor support

8.4. **TUI Build**
   - Standard cargo build
   - Cross-compilation for various targets

---

### Epic 9: Tool Implementations

**Goal:** Implement all 9 pentest tools with platform-appropriate backends.

#### Tools to Implement:

9.1. **execute_command**
   - Shell command execution
   - Timeout handling
   - Output streaming
   - Platforms: Desktop, Android, TUI

9.2. **port_scan**
   - TCP connection scanning
   - Concurrent scanning with limits
   - Service name lookup
   - Progress reporting
   - Platforms: All except Web

9.3. **device_info**
   - System information gathering
   - Network configuration
   - Installed applications (where available)
   - Platforms: All (limited on Web)

9.4. **wifi_scan**
   - WiFi network enumeration
   - Signal strength, security type
   - Platforms: Android, iOS, Desktop (with WiFi adapter)

9.5. **arp_table**
   - ARP cache reading
   - MAC address resolution
   - Platforms: Desktop, Android, TUI

9.6. **ssdp_discover**
   - UPnP device discovery
   - Device description fetching
   - Platforms: Desktop, Android, iOS, TUI

9.7. **network_discover (mDNS)**
   - DNS-SD service discovery
   - Service type filtering
   - Platforms: Desktop, Android, iOS, TUI

9.8. **screenshot**
   - Screen/window capture
   - Base64 encoding
   - Platforms: Desktop, Android (with permission), TUI (terminal content)

9.9. **traffic_capture**
   - Packet interception
   - Protocol parsing
   - Filtering
   - Platforms: Desktop (with libpcap), Android (with VPN permission)

---

### Epic 10: Testing & Quality Assurance

**Goal:** Ensure reliability across all platforms.

#### Tasks:

10.1. **Unit Tests**
   - Core library tests
   - Tool logic tests
   - State management tests

10.2. **Integration Tests**
   - Platform abstraction tests
   - Strike48 SDK integration tests
   - End-to-end tool execution tests

10.3. **UI Tests**
   - Component snapshot tests
   - Interaction tests
   - Accessibility tests

10.4. **Platform-Specific Tests**
   - Desktop: Cross-platform CI (Windows, macOS, Linux)
   - Web: Browser compatibility tests
   - Mobile: Emulator tests
   - TUI: Terminal compatibility tests

10.5. **Performance Testing**
   - Memory usage profiling
   - CPU profiling
   - Network performance tests

---

### Epic 11: Documentation & Developer Experience

**Goal:** Create comprehensive documentation and developer tooling.

#### Tasks:

11.1. **User Documentation**
   - Installation guides per platform
   - Feature documentation
   - Tool usage guides

11.2. **Developer Documentation**
   - Architecture overview
   - Contributing guide
   - Platform implementation guide

11.3. **API Documentation**
   - Rustdoc for all public APIs
   - Examples for common patterns

11.4. **Build & Release Documentation**
   - Build instructions per platform
   - Release process
   - CI/CD configuration

---

## Implementation Priority

### Phase 1: Foundation (Epics 1-2)
- Project setup
- Core library
- Basic state management

### Phase 2: Desktop First (Epics 3-5, 9)
- Platform abstraction for desktop
- Desktop app with full tool support
- All tools working on desktop

### Phase 3: Web & TUI (Epics 6, 8)
- Web application (limited tools)
- TUI application (full tools)

### Phase 4: Mobile (Epic 7)
- Android application
- iOS application

### Phase 5: Polish (Epics 10-11)
- Testing
- Documentation
- Performance optimization

---

## File Structure

```
dioxus-connector/
├── Cargo.toml                 # Workspace root
├── EPIC_PLAN.md              # This file
├── README.md
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
├── crates/
│   ├── core/                  # Core library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── state.rs       # State management
│   │       ├── tools.rs       # Tool trait & schemas
│   │       ├── config.rs      # Configuration
│   │       ├── terminal.rs    # Terminal output types
│   │       └── connector.rs   # Strike48 SDK integration
│   ├── platform/              # Platform abstraction
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── traits.rs      # Platform traits
│   │       ├── desktop/       # Desktop implementation
│   │       ├── web/           # Web implementation
│   │       ├── android/       # Android implementation
│   │       ├── ios/           # iOS implementation
│   │       └── tui/           # TUI implementation
│   └── ui/                    # Dioxus UI components
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── theme.rs
│           ├── components/
│           │   ├── terminal.rs
│           │   ├── status.rs
│           │   ├── config_form.rs
│           │   ├── tool_panel.rs
│           │   ├── scan_controls.rs
│           │   └── nav.rs
│           └── layouts/
│               ├── main.rs
│               └── mobile.rs
├── apps/
│   ├── desktop/
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   └── main.rs
│   │   └── assets/
│   ├── web/
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   └── main.rs
│   │   ├── index.html
│   │   └── Trunk.toml
│   ├── mobile/
│   │   ├── Cargo.toml
│   │   ├── src/
│   │   │   └── lib.rs
│   │   ├── android/
│   │   │   └── ...
│   │   └── ios/
│   │       └── ...
│   └── tui/
│       ├── Cargo.toml
│       └── src/
│           └── main.rs
└── tools/                     # Tool implementations
    ├── Cargo.toml
    └── src/
        ├── lib.rs
        ├── port_scan.rs
        ├── device_info.rs
        ├── wifi_scan.rs
        ├── arp_table.rs
        ├── ssdp_discover.rs
        ├── network_discover.rs
        ├── screenshot.rs
        ├── traffic_capture.rs
        └── execute_command.rs
```

---

## Dependencies Overview

### Core Dependencies
- `dioxus = "0.6"` - UI framework
- `tokio` - Async runtime
- `serde`, `serde_json` - Serialization
- `chrono` - Time handling
- `thiserror` - Error handling
- `tracing` - Logging

### Platform-Specific
- Desktop: `sysinfo`, `screenshots`, `pcap`
- Web: `web-sys`, `wasm-bindgen`
- Android: `jni`, `ndk`
- iOS: `objc`, `cocoa`
- TUI: `dioxus-tui`, `crossterm`

### Strike48 SDK
- `strike48-connector` (from `../strike48-rs`)

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Mobile Dioxus stability | Medium | High | Start with desktop, iterate on mobile |
| Platform API differences | High | Medium | Strong abstraction layer |
| Packet capture permissions | High | Medium | Document requirements, graceful degradation |
| Web limitations | Low | Low | Clear documentation of limited features |
| TUI rendering complexity | Medium | Low | Simple, functional UI |

---

## Success Criteria

1. All 9 pentest tools working on Desktop
2. At least 5 tools working on Mobile
3. Web provides functional viewer/controller interface
4. TUI provides full functionality matching Desktop
5. Consistent UI/UX across all platforms
6. Stable Strike48 connector integration
7. Comprehensive test coverage (>70%)
8. Complete documentation
