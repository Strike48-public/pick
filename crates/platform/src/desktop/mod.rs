//! Desktop platform implementation

mod capture;
pub mod clipboard;
pub mod command;
mod network;
pub mod pty_shell;
pub mod sandbox;
pub mod secure;
mod system;
mod wifi_attack;

// Re-export sandbox control functions
pub use command::{is_sandbox_enabled, set_use_sandbox};

// Re-export the OS-credential-store secure token functions so the desktop app
// can register them with `pentest_core::secure_store` (mirrors the iOS/Android
// backends registered from `apps/mobile`).
pub use secure::{secure_delete, secure_get, secure_set};

// Re-export the native clipboard copy so the desktop app can register it with
// `pentest_core::clipboard` (WebView2 has no navigator.clipboard on Windows).
pub use clipboard::copy_text as clipboard_copy_text;

/// Returns all local non-loopback IPv4 addresses (synchronous).
/// Used by connectors to report their host interfaces during registration.
#[cfg(feature = "network-interface")]
pub fn get_local_ipv4_addresses() -> Option<Vec<String>> {
    use network_interface::{NetworkInterface as NI, NetworkInterfaceConfig};

    let interfaces = NI::show().ok()?;
    let ips: Vec<String> = interfaces
        .into_iter()
        .flat_map(|iface| iface.addr)
        .filter_map(|addr| {
            let ip = addr.ip();
            if ip.is_ipv4() && !ip.is_loopback() {
                Some(ip.to_string())
            } else {
                None
            }
        })
        .collect();

    if ips.is_empty() {
        None
    } else {
        Some(ips)
    }
}

#[cfg(not(feature = "network-interface"))]
pub fn get_local_ipv4_addresses() -> Option<Vec<String>> {
    None
}

// Re-export capture session management (single source of truth)
pub use capture::{
    get_current_packets, is_capture_active, is_pcap_available, start_current_capture,
    stop_current_capture,
};

use crate::traits::*;
use async_trait::async_trait;
use pentest_core::error::Result;
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// Wait for a child process to finish and collect its output.
/// Shared by command.rs, bwrap.rs, and proot.rs.
pub(crate) async fn wait_for_child_output(
    mut child: tokio::process::Child,
) -> std::io::Result<(String, String, i32)> {
    const MAX_OUTPUT: usize = 256 * 1024; // 256 KB limit

    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();

    if let Some(mut stdout) = child.stdout.take() {
        stdout.read_to_end(&mut stdout_buf).await?;
        stdout_buf.truncate(MAX_OUTPUT);
    }

    if let Some(mut stderr) = child.stderr.take() {
        stderr.read_to_end(&mut stderr_buf).await?;
        stderr_buf.truncate(MAX_OUTPUT);
    }

    let status = child.wait().await?;
    let exit_code = status.code().unwrap_or(-1);

    let stdout = String::from_utf8_lossy(&stdout_buf).to_string();
    let stderr = String::from_utf8_lossy(&stderr_buf).to_string();

    Ok((stdout, stderr, exit_code))
}

/// Synchronous "is a sandbox backend available?" probe for startup-time UI.
///
/// Run an async future to completion from a synchronous (possibly-already-in-a-
/// runtime) caller, on a DEDICATED thread with its own fresh multi-thread
/// runtime.
///
/// Why a dedicated thread rather than `block_in_place` + `Handle::block_on` on
/// the caller's runtime: these futures spawn `wsl.exe`/`docker` via
/// `tokio::process::Command`, whose child-exit reaping is driven by the runtime
/// that owns the process. Blocking on the Dioxus UI thread's runtime from within
/// itself does not reliably drive that reaper, so `.output()`/`.status()` calls
/// stall until the probe timeout — which made the sandbox look unavailable even
/// when WSL was installed. A separate thread with its own runtime owns the child
/// processes and reaps them promptly. The thread is short-lived (one probe /
/// one install) and joined before returning.
fn run_blocking_on_dedicated_runtime<T, F>(make: F) -> std::result::Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> std::pin::Pin<Box<dyn std::future::Future<Output = T>>> + Send + 'static,
{
    let joined: std::result::Result<std::result::Result<T, String>, _> =
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| format!("failed to build runtime: {e}"))?;
            std::result::Result::<T, String>::Ok(rt.block_on(make()))
        })
        .join();
    match joined {
        Ok(inner) => inner,
        Err(_) => Err("probe thread panicked".to_string()),
    }
}

/// Wraps the async [`sandbox::probe::any_backend_available`] so it can be stored
/// in the cross-target `ConnectorAppConfig` as a `fn() -> bool`. Runs on a
/// dedicated-thread runtime (see [`run_blocking_on_dedicated_runtime`]) so the
/// `wsl.exe`/`docker` child processes it spawns are reaped promptly instead of
/// stalling. If the runtime can't be built we fail OPEN (return `true`) — this
/// only affects the availability *display*; execution stays fail-closed
/// elsewhere.
pub fn sandbox_available_blocking() -> bool {
    match run_blocking_on_dedicated_runtime(|| {
        Box::pin(async {
            let cfg = sandbox::config::SandboxConfig::default();
            sandbox::probe::any_backend_available(&cfg).await
        })
    }) {
        Ok(available) => available,
        Err(e) => {
            tracing::warn!("sandbox_available_blocking: {e}; assuming available");
            true
        }
    }
}

/// Run the guided WSL install synchronously, for the cross-target UI banner.
///
/// Stored in the cross-target `ConnectorAppConfig` as a
/// `fn() -> pentest_core::WslInstallStatus`, so `pentest-ui` never touches the
/// desktop-only `wsl_install` module directly. The flow: check elevation; if
/// NOT elevated, launch a UAC-elevating relaunch (the elevated helper does the
/// feature-enable + kernel-update out of process) and report
/// [`WslInstallStatus::ElevationLaunched`]; if already elevated, run the guided
/// install inline and map its [`wsl_install::InstallOutcome`] onto the
/// cross-target [`WslInstallStatus`].
///
/// Runs on a dedicated-thread runtime (see [`run_blocking_on_dedicated_runtime`])
/// so the `powershell.exe`/`wsl.exe` child processes it spawns are reaped
/// promptly instead of stalling on a nested runtime.
pub fn run_wsl_install_blocking() -> pentest_core::WslInstallStatus {
    use pentest_core::WslInstallStatus;

    // Async body: decide elevation, then either relaunch or install inline.
    async fn drive() -> WslInstallStatus {
        use sandbox::wsl_install::{
            is_elevated, relaunch_elevated, run_guided_install, InstallOutcome,
        };
        if is_elevated().await {
            match run_guided_install().await {
                InstallOutcome::Completed => WslInstallStatus::Completed,
                InstallOutcome::RebootRequired => WslInstallStatus::RebootRequired,
                // Already elevated, so this should not happen; treat as failure.
                InstallOutcome::NeedsElevation => {
                    WslInstallStatus::Failed("elevation lost mid-install".into())
                }
                InstallOutcome::Failed(msg) => WslInstallStatus::Failed(msg),
            }
        } else {
            // Not elevated: launch the UAC-elevating helper which finishes the
            // install out-of-process. The user must reboot afterwards.
            match relaunch_elevated() {
                Ok(()) => WslInstallStatus::ElevationLaunched,
                Err(e) => WslInstallStatus::Failed(e),
            }
        }
    }

    match run_blocking_on_dedicated_runtime(|| Box::pin(drive())) {
        Ok(status) => status,
        Err(e) => WslInstallStatus::Failed(e),
    }
}

/// Poll for the outcome of a previously-launched ELEVATED WSL install.
///
/// After [`run_wsl_install_blocking`] returns [`WslInstallStatus::ElevationLaunched`],
/// the actual feature-enable + kernel-update runs in a separate elevated
/// process. That child writes its result to a marker file; this reads (and
/// consumes) it. Returns `None` while the elevated run is still in flight (or if
/// the user dismissed the UAC prompt so nothing ran) — the UI should keep
/// polling for a bounded window. `Some(RebootRequired)`/`Some(Failed)` is the
/// terminal outcome. Stored in `ConnectorAppConfig` as an optional
/// `fn() -> Option<WslInstallStatus>` so `pentest-ui` never touches the
/// desktop-only `wsl_install` module directly.
pub fn poll_wsl_install_result() -> Option<pentest_core::WslInstallStatus> {
    use pentest_core::WslInstallStatus;
    use sandbox::wsl_install::{poll_install_result, InstallOutcome};
    match poll_install_result() {
        None => None,
        Some(InstallOutcome::RebootRequired) => Some(WslInstallStatus::RebootRequired),
        Some(InstallOutcome::Completed) => Some(WslInstallStatus::Completed),
        Some(InstallOutcome::Failed(msg)) => Some(WslInstallStatus::Failed(msg)),
        // The elevated marker only ever carries RebootRequired/Failed, but map
        // NeedsElevation defensively rather than silently dropping it.
        Some(InstallOutcome::NeedsElevation) => Some(WslInstallStatus::Failed(
            "elevation lost mid-install".into(),
        )),
    }
}

/// Desktop platform provider
pub struct DesktopPlatform;

impl DesktopPlatform {
    pub fn new() -> Self {
        Self
    }
}

impl Default for DesktopPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetworkOps for DesktopPlatform {
    async fn port_scan(&self, config: ScanConfig) -> Result<ScanResult> {
        network::port_scan(config).await
    }

    async fn get_arp_table(&self) -> Result<Vec<ArpEntry>> {
        network::get_arp_table().await
    }

    async fn ssdp_discover(&self, timeout_ms: u64) -> Result<Vec<SsdpDevice>> {
        network::ssdp_discover(timeout_ms).await
    }

    async fn mdns_discover(&self, service_type: &str, timeout_ms: u64) -> Result<Vec<MdnsService>> {
        network::mdns_discover(service_type, timeout_ms).await
    }
}

#[async_trait]
impl SystemInfo for DesktopPlatform {
    async fn get_device_info(&self) -> Result<DeviceInfo> {
        system::get_device_info().await
    }

    async fn get_network_interfaces(&self) -> Result<Vec<NetworkInterface>> {
        system::get_network_interfaces().await
    }

    async fn get_wifi_networks(&self, interface: Option<String>) -> Result<Vec<WifiNetwork>> {
        system::get_wifi_networks(interface).await
    }

    async fn check_wifi_connection_status(
        &self,
        selected_adapter: Option<String>,
    ) -> Result<WifiConnectionStatus> {
        system::check_wifi_connection_status(selected_adapter).await
    }
}

#[async_trait]
impl CaptureOps for DesktopPlatform {
    async fn capture_screenshot(&self) -> Result<Vec<u8>> {
        capture::capture_screenshot().await
    }

    async fn start_traffic_capture(&self) -> Result<CaptureHandle> {
        capture::start_traffic_capture().await
    }

    async fn get_captured_packets(
        &self,
        handle: &CaptureHandle,
        limit: usize,
    ) -> Result<Vec<PacketInfo>> {
        capture::get_captured_packets(handle, limit).await
    }

    async fn stop_traffic_capture(&self, handle: CaptureHandle) -> Result<()> {
        capture::stop_traffic_capture(handle).await
    }
}

#[async_trait]
impl CommandExec for DesktopPlatform {
    async fn execute_command(
        &self,
        cmd: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandResult> {
        command::execute_command(cmd, args, timeout).await
    }

    async fn execute_command_in_dir(
        &self,
        cmd: &str,
        args: &[&str],
        timeout: Duration,
        working_dir: Option<&std::path::Path>,
    ) -> Result<CommandResult> {
        command::execute_command_in_dir(cmd, args, timeout, working_dir).await
    }
}

impl PlatformProvider for DesktopPlatform {}
