//! Platform Abstraction Layer
//!
//! This crate provides platform-specific implementations for all pentest capabilities.
//!
//! All apps (desktop, web/liveview, mobile, tui) ARE connectors that execute tools locally.
//! The platform abstraction provides the actual tool implementations.

pub mod common;
pub mod traits;

#[cfg(feature = "desktop")]
pub mod desktop;

#[cfg(feature = "android")]
pub mod android;

#[cfg(feature = "ios")]
pub mod ios;

pub use traits::*;

/// Re-export PtyShell for the current platform
#[cfg(feature = "desktop")]
pub use desktop::pty_shell::PtyShell;

#[cfg(all(feature = "android", not(feature = "desktop")))]
pub use android::pty_shell::PtyShell;

#[cfg(all(feature = "ios", not(feature = "desktop"), not(feature = "android")))]
pub use ios::pty_shell::PtyShell;

/// Re-export sandbox control for desktop
#[cfg(feature = "desktop")]
pub use desktop::{
    is_sandbox_enabled, poll_wsl_install_result, run_wsl_install_blocking,
    sandbox_available_blocking, set_use_sandbox,
};

/// Command sandboxing (bubblewrap/proot) is a desktop-only concept. On
/// non-desktop platforms (mobile) there is no command sandbox, so report it
/// disabled and make toggling it a no-op. Mirrors the `is_pcap_available`
/// fallback below so callers can stay platform-agnostic.
#[cfg(not(feature = "desktop"))]
pub fn is_sandbox_enabled() -> bool {
    false
}

#[cfg(not(feature = "desktop"))]
pub fn set_use_sandbox(_use_sandbox: bool) {}

/// Whether a command-sandbox backend is usable. Desktop probes real backends
/// (bwrap/proot/docker/WSL); non-desktop targets have no host command sandbox,
/// so report unavailable. Lets cross-target UI code (e.g. `WorkspaceApp`) call
/// this without a `#[cfg]` at every call site.
#[cfg(not(feature = "desktop"))]
pub fn sandbox_available_blocking() -> bool {
    false
}

/// Re-export capture session management for desktop
#[cfg(feature = "desktop")]
pub use desktop::{
    get_current_packets, is_capture_active, is_pcap_available, start_current_capture,
    stop_current_capture,
};

/// Pcap is never available on non-desktop platforms
#[cfg(not(feature = "desktop"))]
pub fn is_pcap_available() -> bool {
    false
}

/// Get the platform implementation for the current target
#[cfg(feature = "desktop")]
pub fn get_platform() -> impl PlatformProvider {
    desktop::DesktopPlatform::new()
}

#[cfg(all(feature = "android", not(feature = "desktop")))]
pub fn get_platform() -> impl PlatformProvider {
    android::AndroidPlatform::new()
}

#[cfg(all(feature = "ios", not(feature = "desktop"), not(feature = "android")))]
pub fn get_platform() -> impl PlatformProvider {
    ios::IosPlatform::new()
}
