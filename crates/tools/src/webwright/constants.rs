//! Named constants and path helpers for the Webwright tool.
//!
//! Everything that used to be a magic literal scattered across the webwright
//! submodules lives here. Two categories:
//!
//! - **Tuning constants** (`pub const`) — chosen for a reason, documented inline.
//!   User-facing schema defaults (like the `timeout` tool parameter) are *not*
//!   redefined here; they live in the tool schema where agents discover them.
//! - **Path helpers** (`pub fn`) — every place that needs the sandbox rootfs,
//!   the proot binary, or the embedded sidecar script reads it through these
//!   helpers so we have one place to change the layout. The helpers honor
//!   `$HOME` with a `.` fallback (matching pre-existing behavior).

use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Networking
// ---------------------------------------------------------------------------

/// Default port for Pick's local LLM proxy.
///
/// Callers should prefer reading the `PICK_LLM_PROXY_PORT` env var (set by the
/// connector at startup) and only fall back to this constant when the env var
/// is unset or unparseable. Keeping it here makes the fallback discoverable in
/// one place.
pub const DEFAULT_LLM_PROXY_PORT: u16 = 9100;

/// String form of [`DEFAULT_LLM_PROXY_PORT`] for use in shell command
/// templates and env-var fallbacks that need a `String`.
pub const DEFAULT_LLM_PROXY_PORT_STR: &str = "9100";

// ---------------------------------------------------------------------------
// Sidecar process
// ---------------------------------------------------------------------------

/// Capacity of the broadcast channel that fans out [`SidecarEvent`]s to
/// subscribers (the executor loop and any live-progress watchers).
///
/// One sidecar emits a step-or-finding event roughly each second of agent
/// reasoning. A backlog of 100 means a slow subscriber has ~100 events of
/// headroom before the broadcast lags it.
///
/// [`SidecarEvent`]: super::sidecar::SidecarEvent
pub const SIDECAR_EVENT_CHANNEL_CAPACITY: usize = 100;

/// How long to wait for the sidecar's `ready` event after spawning the
/// process. The sidecar imports webwright + Playwright on startup, which
/// dominates this budget; ten seconds is comfortably above the observed p99.
pub const SIDECAR_READY_TIMEOUT_SECS: u64 = 10;

/// Polling cadence used while waiting for sidecar readiness. Kept short so
/// the happy path returns quickly without burning CPU.
pub const SIDECAR_READY_POLL_INTERVAL_MS: u64 = 100;

/// Grace period given to the sidecar to flush stdout and exit cleanly after
/// receiving the `Shutdown` command, before we send `SIGKILL`.
pub const SIDECAR_SHUTDOWN_GRACE_MS: u64 = 500;

/// Floor for the post-subtraction effective timeout (see
/// `mod::effective_timeout_secs`). If an agent supplies a tiny `timeout`, we
/// still need enough budget for proot to come up and Playwright to launch
/// before we can usefully report anything back.
pub const MIN_EFFECTIVE_TIMEOUT_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Progress / live-state
// ---------------------------------------------------------------------------

/// Maximum number of log entries retained in
/// [`WebwrightProgress::log`](super::live_state::WebwrightProgress). Older
/// entries are dropped FIFO. Twenty is enough for a human to see what the
/// agent did recently in the live widget without ballooning socket frames.
pub const MAX_LIVE_LOG_ENTRIES: usize = 20;

/// Maximum number of base64-encoded screenshots retained in
/// [`WebwrightProgress::screenshots`](super::live_state::WebwrightProgress).
/// Each entry is hundreds of KB; uncapped this is a memory leak on long runs.
/// Matches [`MAX_LIVE_LOG_ENTRIES`] so the widget gallery and step log scroll
/// at the same rate.
pub const MAX_LIVE_SCREENSHOTS: usize = 20;

/// Deferred prune delay for [`live_state::complete`](super::live_state::complete).
/// Subscribers (UI widgets) get this long to read the final `running: false`
/// state before the task's channel and bindings are removed. Sixty seconds is
/// well above the widget poll cadence and short enough not to leak.
pub const LIVE_STATE_PURGE_DELAY_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Output truncation
// ---------------------------------------------------------------------------

/// Maximum bytes of webwright stdout returned in the tool result. Anything
/// longer is truncated with a `... (truncated, N bytes total)` suffix.
///
/// Webwright can produce tens of megabytes of debug output; without this cap
/// we blow past the WebSocket frame limit on the connector channel.
pub const STDOUT_TRUNCATION_THRESHOLD_BYTES: usize = 4000;

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Relative path inside `$HOME` that contains the BlackArch rootfs we proot
/// into.
const ROOTFS_REL: &str = ".local/share/pentest-sandbox/blackarch-rootfs";

/// Relative path inside `$HOME` of the bundled `proot` binary.
const PROOT_BIN_REL: &str = ".local/share/pentest-sandbox/bin/proot";

/// Filename of the embedded Python sidecar script, written into the rootfs
/// `/tmp` before each spawn. Inside the sandbox it is invoked as
/// `python3 /tmp/<this filename>`.
pub const SIDECAR_SCRIPT_FILENAME: &str = "webwright_sidecar_server.py";

/// Directory (inside the proot rootfs view) that holds per-task workspaces.
/// The same path is also a valid host path when joined under
/// [`rootfs_dir`].
pub const SANDBOX_WORKSPACE_ROOT: &str = "/tmp/webwright";

/// Read the home directory the way the existing webwright code expects: from
/// `$HOME`, with `.` as the fallback when the variable is unset.
fn home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_string()))
}

/// Absolute path to the BlackArch rootfs directory.
pub fn rootfs_dir() -> PathBuf {
    home().join(ROOTFS_REL)
}

/// Absolute path to the bundled `proot` binary.
pub fn proot_binary_path() -> PathBuf {
    home().join(PROOT_BIN_REL)
}

/// Absolute *host* path to the location where the sidecar script must be
/// written so that it appears at `/tmp/<filename>` inside the proot view.
pub fn sidecar_server_script_path() -> PathBuf {
    rootfs_dir().join("tmp").join(SIDECAR_SCRIPT_FILENAME)
}

/// Absolute *sandbox* path (as seen from inside proot) the sidecar script
/// will be invoked from.
pub fn sidecar_server_sandbox_path() -> String {
    format!("/tmp/{}", SIDECAR_SCRIPT_FILENAME)
}

/// Absolute *sandbox* path of a task's workspace directory.
pub fn sandbox_task_workspace(task_id: &str) -> String {
    format!("{}/{}", SANDBOX_WORKSPACE_ROOT, task_id)
}

/// Absolute *host* path of a task's workspace directory (the rootfs view of
/// [`sandbox_task_workspace`]).
pub fn host_task_workspace(task_id: &str) -> PathBuf {
    rootfs_dir().join("tmp").join("webwright").join(task_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_port_string_matches_numeric() {
        assert_eq!(
            DEFAULT_LLM_PROXY_PORT_STR.parse::<u16>().unwrap(),
            DEFAULT_LLM_PROXY_PORT
        );
    }

    #[test]
    fn rootfs_dir_ends_with_expected_suffix() {
        let dir = rootfs_dir();
        assert!(
            dir.ends_with("blackarch-rootfs"),
            "rootfs_dir should end with blackarch-rootfs: {:?}",
            dir
        );
    }

    #[test]
    fn proot_binary_ends_with_proot() {
        let bin = proot_binary_path();
        assert!(
            bin.ends_with("proot"),
            "proot path should end with 'proot': {:?}",
            bin
        );
    }

    #[test]
    fn sidecar_script_host_path_is_inside_rootfs() {
        let p = sidecar_server_script_path();
        assert!(p.starts_with(rootfs_dir()));
        assert_eq!(
            p.file_name().and_then(|s| s.to_str()),
            Some(SIDECAR_SCRIPT_FILENAME)
        );
    }

    #[test]
    fn sandbox_paths_use_fixed_root() {
        assert!(sandbox_task_workspace("abc").starts_with(SANDBOX_WORKSPACE_ROOT));
        assert!(sandbox_task_workspace("abc").ends_with("/abc"));
        assert_eq!(
            sidecar_server_sandbox_path(),
            format!("/tmp/{}", SIDECAR_SCRIPT_FILENAME),
        );
    }

    #[test]
    fn host_task_workspace_mirrors_sandbox_layout() {
        let host = host_task_workspace("task-xyz");
        assert!(host.starts_with(rootfs_dir()));
        assert!(
            host.to_string_lossy().contains("/tmp/webwright/task-xyz"),
            "host_task_workspace should contain /tmp/webwright/task-xyz: {:?}",
            host
        );
    }
}
