//! Interactive PTY shell for desktop
//!
//! Spawns a native or sandboxed shell session via portable-pty.

use super::sandbox::config::SandboxBackend;
use pentest_core::config::ShellMode;
use pentest_core::error::{Error, Result};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// An interactive PTY shell session.
pub struct PtyShell {
    pair: portable_pty::PtyPair,
    child: Box<dyn portable_pty::Child + Send + Sync>,
}

/// Return true if a `portable_pty` spawn error was caused by `EACCES`
/// (`Permission denied`, os error 13).
///
/// `portable_pty` returns `anyhow::Error`; on Unix the underlying cause when a
/// spawn is rejected is a `std::io::Error`, so we downcast through the error
/// chain and inspect `io::ErrorKind::PermissionDenied` precisely. We deliberately
/// do NOT fall back to substring-matching the message: a message that merely
/// mentions "Permission denied" for an unrelated reason must not silently swap
/// the sandbox backend under the user. If no typed `io::Error` is present, we
/// treat it as "not EACCES" and surface the original error instead of guessing.
fn spawn_err_is_permission_denied(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io_err| io_err.kind() == std::io::ErrorKind::PermissionDenied)
}

/// Given the backend whose spawn just failed and the error, return the *other*
/// namespace backend to retry with — or `None` if no retry applies.
///
/// The #238 failure mode is a healthy sandbox backend that `portable_pty` can't
/// spawn in this process context, surfacing as `EACCES`. bwrap and proot are
/// interchangeable for the unprivileged interactive shell (both give a fake-root
/// BlackArch shell), so on an EACCES spawn we retry with the sibling backend:
///
/// - proot spawn hits EACCES -> retry **bwrap**
/// - bwrap spawn hits EACCES -> retry **proot**
///
/// WSL and Docker have no namespace sibling to swap to, so they never qualify.
/// Only EACCES qualifies: a missing binary or bad rootfs would fail identically
/// under the sibling and must surface as-is. The caller still confirms the
/// sibling is actually available before retrying. Pure function so the decision
/// is unit-testable without a live PTY.
fn fallback_backend_for(backend: SandboxBackend, err: &anyhow::Error) -> Option<SandboxBackend> {
    if !spawn_err_is_permission_denied(err) {
        return None;
    }
    match backend {
        SandboxBackend::Proot => Some(SandboxBackend::Bwrap),
        SandboxBackend::Bwrap => Some(SandboxBackend::Proot),
        SandboxBackend::Wsl | SandboxBackend::Docker => None,
    }
}

impl PtyShell {
    /// Spawn a new interactive shell using the system default program.
    /// If `cwd` is provided, the shell will start in that directory.
    /// When `shell_mode` is `Proot`, spawns inside a sandboxed BlackArch rootfs
    /// using bwrap (preferred) or proot (fallback).
    pub async fn spawn(
        cols: u16,
        rows: u16,
        _progress: Option<tokio::sync::mpsc::Sender<String>>,
        cwd: Option<&Path>,
        shell_mode: ShellMode,
    ) -> Result<Self> {
        tracing::info!("PtyShell::spawn called with mode={:?}", shell_mode);

        if shell_mode == ShellMode::Proot {
            return Self::spawn_sandboxed(cols, rows, cwd).await;
        }

        tracing::info!("Spawning native shell");

        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| Error::ToolExecution(format!("Failed to open PTY: {e}")))?;

        #[cfg(windows)]
        let mut cmd = CommandBuilder::new("powershell.exe");
        #[cfg(not(windows))]
        let mut cmd = CommandBuilder::new_default_prog();
        if let Some(dir) = cwd {
            cmd.cwd(dir);
        }

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| Error::ToolExecution(format!("Failed to spawn shell: {e}")))?;

        Ok(Self { pair, child })
    }

    /// Spawn a sandboxed interactive shell using bwrap, proot, or WSL.
    async fn spawn_sandboxed(cols: u16, rows: u16, cwd: Option<&Path>) -> Result<Self> {
        use super::sandbox::get_sandbox_manager;

        tracing::info!("[PtyShell::spawn_sandboxed] Starting sandboxed shell spawn");

        tracing::debug!("[PtyShell::spawn_sandboxed] Getting sandbox manager...");
        let manager = get_sandbox_manager().await.map_err(|e| {
            tracing::error!("[PtyShell::spawn_sandboxed] Sandbox init failed: {}", e);
            Error::ToolExecution(format!("Sandbox init failed: {e}"))
        })?;

        tracing::debug!("[PtyShell::spawn_sandboxed] Ensuring rootfs ready...");
        manager.ensure_ready().await.map_err(|e| {
            tracing::error!(
                "[PtyShell::spawn_sandboxed] Sandbox rootfs setup failed: {}",
                e
            );
            Error::ToolExecution(format!("Sandbox rootfs setup failed: {e}"))
        })?;

        let config = manager.config();
        let backend = manager.backend();
        tracing::info!(
            "[PtyShell::spawn_sandboxed] Sandbox ready — backend={}, rootfs={}",
            backend,
            config.rootfs_dir().display()
        );

        // bwrap/proot-specific rootfs pre-creation — WSL manages its own filesystem
        if backend != SandboxBackend::Wsl {
            // Ensure mount-point directories exist in the rootfs before launching
            // bwrap.  The rootfs is bind-mounted read-only, so bwrap cannot create
            // new directories inside it at runtime.  Creating them on the real
            // filesystem beforehand means the directory already exists when bwrap
            // applies the read-only overlay.
            let rootfs = config.rootfs_dir();
            let _ = std::fs::create_dir_all(rootfs.join("workspace"));
            let _ = std::fs::create_dir_all(rootfs.join("root"));
            let _ = std::fs::create_dir_all(rootfs.join("etc/pacman.d/gnupg"));

            // Fix pacman.conf for bwrap user namespace compatibility (mirrors
            // the Android proot fix in android/proot/pacman.rs).
            //
            // Inside a bwrap user namespace only uid 0 is mapped, so:
            // - DownloadUser must be commented out (setting to empty fails with
            //   "user does not exist")
            // - SigLevel set to Never (keyring is not writable on ro-bind rootfs)
            // - DisableSandboxFilesystem + DisableSandboxSyscalls enabled
            // - Stale lock file removed from previous crashed sessions
            let pacman_conf = rootfs.join("etc/pacman.conf");
            if pacman_conf.exists() {
                if let Ok(mut content) = std::fs::read_to_string(&pacman_conf) {
                    let mut changed = false;

                    // Comment out DownloadUser entirely — do NOT set to empty
                    if content.contains("\nDownloadUser") && !content.contains("\n#DownloadUser") {
                        content = content.replace("\nDownloadUser", "\n#DownloadUser");
                        changed = true;
                    }

                    // Disable signature checking (keyring can't be initialised on
                    // a read-only rootfs in a user namespace)
                    if content.contains("SigLevel    = Required DatabaseOptional") {
                        content = content.replace(
                            "SigLevel    = Required DatabaseOptional",
                            "SigLevel    = Never",
                        );
                        changed = true;
                    }

                    // Uncomment sandbox disable options
                    if content.contains("#DisableSandboxFilesystem") {
                        content = content
                            .replace("#DisableSandboxFilesystem", "DisableSandboxFilesystem");
                        changed = true;
                    }
                    if content.contains("#DisableSandboxSyscalls") {
                        content =
                            content.replace("#DisableSandboxSyscalls", "DisableSandboxSyscalls");
                        changed = true;
                    }

                    // Older pacman (6.x) — add DisableSandbox if no sandbox options exist
                    if !content.contains("DisableSandbox") {
                        content = content.replace("[options]\n", "[options]\nDisableSandbox\n");
                        changed = true;
                    }

                    // Disable CheckSpace — fails in sandboxed environments with
                    // "not enough free disk space" or "partition mounted read only"
                    if content.contains("\nCheckSpace") && !content.contains("\n#CheckSpace") {
                        content = content.replace("\nCheckSpace", "\n#CheckSpace");
                        changed = true;
                    }

                    if changed {
                        let _ = std::fs::write(&pacman_conf, content);
                    }
                }
            }
            let lock_file = rootfs.join("var/lib/pacman/db.lck");
            if lock_file.exists() {
                let _ = std::fs::remove_file(&lock_file);
            }
        }

        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| Error::ToolExecution(format!("Failed to open PTY: {e}")))?;

        let cmd = Self::build_cmd_for_backend(backend, config, cwd).await?;

        let child = match pair.slave.spawn_command(cmd) {
            Ok(child) => child,
            Err(e) => {
                // Graceful symmetric fallback: a namespace backend (bwrap/proot)
                // can fail to spawn under portable-pty with EACCES depending on
                // the host process context (see #238), even when its binary and
                // rootfs are healthy. bwrap and proot are interchangeable for the
                // unprivileged interactive shell, so on EACCES we retry with the
                // sibling backend instead of hard-failing.
                let sibling = fallback_backend_for(backend, &e);
                if let Some(fallback) = sibling {
                    if Self::backend_is_available(fallback, config).await {
                        // Log the failure at warn (not error): it is expected and
                        // recoverable here; a preemptive error would read as a hard
                        // failure even on the successful retry path.
                        tracing::warn!(
                            "[PtyShell::spawn_sandboxed] {backend:?} spawn hit EACCES ({e}); falling back to {fallback:?}"
                        );

                        // Open a *fresh* PTY for the retry. portable_pty does not
                        // guarantee a slave is reusable after a failed spawn (the
                        // controlling-terminal / TIOCSCTTY state may be left
                        // partially applied by a half-forked child), so we drop
                        // the old pair rather than spawn into it twice.
                        drop(pair);
                        let retry_pair = pty_system
                            .openpty(PtySize {
                                rows,
                                cols,
                                pixel_width: 0,
                                pixel_height: 0,
                            })
                            .map_err(|e2| {
                                Error::ToolExecution(format!(
                                    "Failed to open PTY for {fallback:?} fallback: {e2} (original {backend:?} error: {e})"
                                ))
                            })?;

                        let fallback_cmd =
                            Self::build_cmd_for_backend(fallback, config, cwd).await?;
                        let child = retry_pair.slave.spawn_command(fallback_cmd).map_err(|e2| {
                            tracing::error!(
                                "[PtyShell::spawn_sandboxed] {fallback:?} fallback also failed: {e2} (original {backend:?} error: {e})"
                            );
                            Error::ToolExecution(format!(
                                "Failed to spawn sandboxed shell ({backend:?} spawn failed: {e}; {fallback:?} fallback also failed: {e2})"
                            ))
                        })?;

                        tracing::info!(
                            "Sandboxed shell spawned successfully ({fallback:?} fallback after {backend:?} EACCES)"
                        );
                        return Ok(Self {
                            pair: retry_pair,
                            child,
                        });
                    }
                }

                tracing::error!(
                    "[PtyShell::spawn_sandboxed] spawn_command failed: {e} (backend={backend:?})"
                );
                return Err(Error::ToolExecution(format!(
                    "Failed to spawn sandboxed shell: {e}"
                )));
            }
        };

        tracing::info!("Sandboxed shell spawned successfully");

        Ok(Self { pair, child })
    }

    /// Build the interactive-shell `CommandBuilder` for a specific backend.
    ///
    /// Shared by the primary spawn and the symmetric EACCES fallback so both
    /// paths construct commands identically. proot needs an async binary-path
    /// lookup, hence the `async` signature.
    async fn build_cmd_for_backend(
        backend: SandboxBackend,
        config: &super::sandbox::config::SandboxConfig,
        cwd: Option<&Path>,
    ) -> Result<CommandBuilder> {
        use super::sandbox::proot::ProotExecutor;

        let cmd = match backend {
            SandboxBackend::Bwrap => {
                tracing::info!("Building bwrap command for PTY shell");
                Self::build_bwrap_cmd(config, cwd)
            }
            SandboxBackend::Proot => {
                let proot_path = ProotExecutor::get_proot_path(config)
                    .await
                    .map_err(|e| Error::ToolExecution(format!("Proot binary not found: {e}")))?;
                #[cfg(unix)]
                let is_executable = std::fs::metadata(&proot_path)
                    .map(|m| m.permissions().mode() & 0o111 != 0)
                    .unwrap_or(false);
                // Windows: SandboxBackend::Proot is not a runtime target here (no proot
                // binary is shipped), but this branch must still compile. Fall back to a
                // plain existence probe rather than re-implementing an executable check
                // via Windows-specific APIs.
                #[cfg(not(unix))]
                let is_executable = proot_path.exists();
                tracing::info!(
                    "[PtyShell] proot binary: path={} exists={} executable={}",
                    proot_path.display(),
                    proot_path.exists(),
                    is_executable,
                );
                Self::build_proot_cmd(config, &proot_path, cwd)
            }
            SandboxBackend::Wsl => {
                tracing::info!("Building WSL command for PTY shell");
                Self::build_wsl_cmd(config, cwd)
            }
            SandboxBackend::Docker => {
                tracing::info!("Building Docker command for PTY shell");
                Self::build_docker_cmd(config, cwd)
            }
        };

        Ok(cmd)
    }

    /// Check whether a given backend is currently usable, used to gate the
    /// EACCES fallback retry before we commit to swapping backends.
    async fn backend_is_available(
        backend: SandboxBackend,
        config: &super::sandbox::config::SandboxConfig,
    ) -> bool {
        use super::sandbox::{bwrap::BwrapExecutor, proot::ProotExecutor};

        match backend {
            SandboxBackend::Bwrap => BwrapExecutor::is_available().await,
            SandboxBackend::Proot => ProotExecutor::is_available(config).await,
            // Only bwrap/proot are valid fallback targets (see
            // `fallback_backend_for`); other backends never reach here.
            SandboxBackend::Wsl | SandboxBackend::Docker => false,
        }
    }

    /// Build a `CommandBuilder` for a bwrap interactive shell.
    pub(crate) fn build_bwrap_cmd(
        config: &super::sandbox::config::SandboxConfig,
        cwd: Option<&Path>,
    ) -> CommandBuilder {
        let rootfs = config.rootfs_dir();
        let rootfs_str = rootfs.to_string_lossy().into_owned();

        let mut cmd = CommandBuilder::new("bwrap");

        // Mount rootfs as writable for package installation
        cmd.arg("--bind");
        cmd.arg(rootfs_str.as_str());
        cmd.arg("/");

        // Make /var writable for tool installation
        let rootfs_var = rootfs.join("var");
        if rootfs_var.exists() {
            cmd.arg("--bind");
            cmd.arg(rootfs_var.to_string_lossy().as_ref());
            cmd.arg("/var");
        }

        // Make /etc/pacman.d writable for keyring init (pacman-key --init)
        let rootfs_pacman_d = rootfs.join("etc/pacman.d");
        if rootfs_pacman_d.exists() {
            cmd.arg("--bind");
            cmd.arg(rootfs_pacman_d.to_string_lossy().as_ref());
            cmd.arg("/etc/pacman.d");
        }

        // System directories
        cmd.args(["--dev", "/dev"]);
        cmd.args(["--proc", "/proc"]);

        // DNS resolution
        cmd.args(["--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"]);

        // Run as root (uid 0) inside the sandbox
        cmd.args(["--unshare-user", "--uid", "0", "--gid", "0"]);

        // Network access
        if config.network_access {
            cmd.arg("--share-net");
        } else {
            cmd.arg("--unshare-net");
        }

        // Mount workspace
        let workspace = cwd.or(config.workspace_dir.as_deref());
        if let Some(ws) = workspace {
            if ws.exists() {
                cmd.arg("--bind");
                cmd.arg(ws.to_string_lossy().as_ref());
                cmd.arg("/workspace");
            }
        }

        // Working directory
        cmd.args([
            "--chdir",
            if workspace.is_some() {
                "/workspace"
            } else {
                "/root"
            },
        ]);

        // Die when parent dies
        cmd.arg("--die-with-parent");

        // Environment variables
        for (key, value) in &config.env_vars {
            cmd.args(["--setenv", key, value]);
        }

        // Interactive login shell
        cmd.args(["/bin/bash", "-l", "-i"]);

        cmd
    }

    /// Build a `CommandBuilder` for a proot interactive shell.
    pub(crate) fn build_proot_cmd(
        config: &super::sandbox::config::SandboxConfig,
        proot_binary: &Path,
        cwd: Option<&Path>,
    ) -> CommandBuilder {
        let rootfs = config.rootfs_dir();
        let rootfs_str = rootfs.to_string_lossy().into_owned();

        let mut cmd = CommandBuilder::new(proot_binary);

        // Fake root (uid/gid 0)
        cmd.arg("-0");

        // Set rootfs
        cmd.arg("-r");
        cmd.arg(rootfs_str.as_str());

        // Bind directories
        cmd.args(["-b", "/dev"]);
        cmd.args(["-b", "/proc"]);
        cmd.args(["-b", "/sys"]);
        cmd.args(["-b", "/etc/resolv.conf"]);

        // Mount workspace
        let workspace = cwd.or(config.workspace_dir.as_deref());
        if let Some(ws) = workspace {
            if ws.exists() {
                let bind_spec = format!("{}:/workspace", ws.to_string_lossy());
                cmd.arg("-b");
                cmd.arg(bind_spec.as_str());
            }
        }

        // Working directory
        cmd.args([
            "-w",
            if workspace.is_some() {
                "/workspace"
            } else {
                "/root"
            },
        ]);

        // Environment variables (proot uses process env)
        for (key, value) in &config.env_vars {
            cmd.env(key, value);
        }

        // Interactive login shell
        cmd.args(["/bin/bash", "-l", "-i"]);

        cmd
    }

    /// Build a `CommandBuilder` for a WSL2 interactive shell.
    pub(crate) fn build_wsl_cmd(
        config: &super::sandbox::config::SandboxConfig,
        cwd: Option<&Path>,
    ) -> CommandBuilder {
        let distro_name = config.wsl_distro_name();

        let mut cmd = CommandBuilder::new("wsl.exe");

        cmd.arg("-d");
        cmd.arg(distro_name);

        // Set working directory via --cd if a workspace is provided
        let workspace = cwd.or(config.workspace_dir.as_deref());
        if let Some(ws) = workspace {
            let wsl_path =
                super::sandbox::wsl::WslExecutor::windows_to_wsl_path(&ws.to_string_lossy());
            cmd.arg("--cd");
            cmd.arg(wsl_path.as_str());
        }

        cmd.arg("--");

        // Set environment variables inline via env command
        cmd.arg("env");
        for (key, value) in &config.env_vars {
            cmd.arg(format!("{}={}", key, value));
        }

        // Interactive login shell
        cmd.args(["/bin/bash", "-l", "-i"]);

        cmd
    }

    /// Build a `CommandBuilder` for a Docker interactive shell.
    pub(crate) fn build_docker_cmd(
        config: &super::sandbox::config::SandboxConfig,
        cwd: Option<&Path>,
    ) -> CommandBuilder {
        let mut cmd = CommandBuilder::new("docker");

        cmd.args(["run", "--rm", "-it"]);

        // Pin platform for Apple Silicon compatibility (BlackArch is x86_64 only)
        cmd.args(["--platform", "linux/amd64"]);

        // Security: drop all capabilities, only grant what pentest tools need
        cmd.args(["--cap-drop=ALL", "--cap-add=NET_RAW"]);
        cmd.args(["--security-opt", "no-new-privileges"]);

        // Network access
        if !config.network_access {
            cmd.arg("--network=none");
        }

        // Mount workspace
        let workspace = cwd.or(config.workspace_dir.as_deref());
        if let Some(ws) = workspace {
            if ws.exists() {
                let mount_spec = format!("{}:/workspace", ws.to_string_lossy());
                cmd.arg("-v");
                cmd.arg(mount_spec.as_str());
                cmd.args(["-w", "/workspace"]);
            }
        }

        // Environment variables
        for (key, value) in &config.env_vars {
            cmd.arg("-e");
            cmd.arg(format!("{}={}", key, value));
        }

        // Image and interactive login shell
        cmd.arg("pentest-blackarch:latest");
        cmd.args(["/bin/bash", "-l", "-i"]);

        cmd
    }

    /// Resize the PTY.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        self.pair
            .master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| Error::ToolExecution(format!("PTY resize failed: {e}")))
    }

    /// Clone a reader for the PTY output.
    pub fn try_clone_reader(&self) -> Result<Box<dyn Read + Send>> {
        self.pair
            .master
            .try_clone_reader()
            .map_err(|e| Error::ToolExecution(format!("Failed to clone PTY reader: {e}")))
    }

    /// Take a writer for the PTY input.
    pub fn take_writer(&self) -> Result<Box<dyn Write + Send>> {
        self.pair
            .master
            .take_writer()
            .map_err(|e| Error::ToolExecution(format!("Failed to take PTY writer: {e}")))
    }

    /// Check if the child process has exited.
    pub fn try_wait(&mut self) -> Result<Option<portable_pty::ExitStatus>> {
        self.child
            .try_wait()
            .map_err(|e| Error::ToolExecution(format!("Failed to check child status: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::super::sandbox::config::SandboxConfig;
    use super::*;
    use std::ffi::OsStr;
    use std::path::PathBuf;

    /// Helper: convert a CommandBuilder's argv to a Vec<&str> for easy assertions.
    fn argv_strs(cmd: &CommandBuilder) -> Vec<String> {
        cmd.get_argv()
            .iter()
            .map(|os| os.to_string_lossy().into_owned())
            .collect()
    }

    // ------------------------------------------------------------------
    // EACCES detection for the proot -> bwrap fallback (#238)
    // ------------------------------------------------------------------

    #[test]
    fn permission_denied_detected_from_io_error_source() {
        let io_err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let wrapped = anyhow::Error::new(io_err).context("spawn_command");
        assert!(spawn_err_is_permission_denied(&wrapped));
    }

    #[test]
    fn permission_denied_detected_deep_in_error_chain() {
        // The io::Error may be several context layers down; the chain walk must
        // still find it.
        let io_err = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let wrapped = anyhow::Error::new(io_err)
            .context("spawn_command")
            .context("PtyShell::spawn_sandboxed");
        assert!(spawn_err_is_permission_denied(&wrapped));
    }

    #[test]
    fn message_only_permission_denied_is_not_flagged() {
        // No typed io::Error in the chain: we must NOT guess from the message
        // string (that could wrongly swap a user's chosen backend). Treat it as
        // not-EACCES and let the caller surface the original error.
        let err = anyhow::anyhow!("Permission denied (os error 13)");
        assert!(!spawn_err_is_permission_denied(&err));
    }

    #[test]
    fn non_permission_error_is_not_flagged() {
        let io_err = std::io::Error::from(std::io::ErrorKind::NotFound);
        let wrapped = anyhow::Error::new(io_err).context("spawn_command");
        assert!(!spawn_err_is_permission_denied(&wrapped));

        let other = anyhow::anyhow!("no such file or directory");
        assert!(!spawn_err_is_permission_denied(&other));
    }

    // ------------------------------------------------------------------
    // Symmetric fallback-decision predicate (#238): bwrap <-> proot on EACCES
    // ------------------------------------------------------------------

    fn eacces() -> anyhow::Error {
        anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
    }

    #[test]
    fn proot_eacces_falls_back_to_bwrap() {
        assert_eq!(
            fallback_backend_for(SandboxBackend::Proot, &eacces()),
            Some(SandboxBackend::Bwrap)
        );
    }

    #[test]
    fn bwrap_eacces_falls_back_to_proot() {
        // The prefer-bwrap default means bwrap is the common primary backend; a
        // runtime EACCES on a host where bwrap passed is_available() but can't
        // spawn must degrade to proot rather than hard-failing the shell.
        assert_eq!(
            fallback_backend_for(SandboxBackend::Bwrap, &eacces()),
            Some(SandboxBackend::Proot)
        );
    }

    #[test]
    fn no_fallback_for_non_eacces() {
        // A non-permission failure (e.g. binary missing, bad rootfs) would fail
        // identically under the sibling, so surface it as-is rather than swapping.
        let not_found = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::NotFound));
        assert_eq!(
            fallback_backend_for(SandboxBackend::Proot, &not_found),
            None
        );
        assert_eq!(
            fallback_backend_for(SandboxBackend::Bwrap, &not_found),
            None
        );
    }

    #[test]
    fn no_fallback_for_backends_without_a_namespace_sibling() {
        // WSL and Docker have no bwrap/proot sibling to swap to.
        assert_eq!(fallback_backend_for(SandboxBackend::Wsl, &eacces()), None);
        assert_eq!(
            fallback_backend_for(SandboxBackend::Docker, &eacces()),
            None
        );
    }

    /// Build a SandboxConfig pointing at a temporary directory with a fake
    /// rootfs so that the path-existence checks in `build_bwrap_cmd` pass.
    fn test_config(tmp: &std::path::Path) -> SandboxConfig {
        let data_dir = tmp.join("data");
        // Create rootfs dirs so the bind-mount branches are exercised
        std::fs::create_dir_all(data_dir.join("blackarch-rootfs").join("var")).unwrap();
        std::fs::create_dir_all(data_dir.join("blackarch-rootfs").join("etc/pacman.d")).unwrap();
        SandboxConfig {
            data_dir,
            workspace_dir: None,
            preferred_backend: None,
            network_access: true,
            env_vars: vec![
                ("TERM".to_string(), "xterm-256color".to_string()),
                ("HOME".to_string(), "/root".to_string()),
            ],
        }
    }

    // ------------------------------------------------------------------
    // bwrap command builder
    // ------------------------------------------------------------------

    #[test]
    fn test_bwrap_cmd_without_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());

        let cmd = PtyShell::build_bwrap_cmd(&config, None);
        let argv = argv_strs(&cmd);

        // First arg must be the bwrap binary
        assert_eq!(argv[0], "bwrap");

        // Must contain --bind <rootfs> / (writable for package installation)
        let rootfs_str = config.rootfs_dir().to_string_lossy().into_owned();
        assert!(argv.windows(3).any(|w| w == ["--bind", &rootfs_str, "/"]));

        // Must contain --bind <rootfs>/var /var (because we created it)
        let rootfs_var = config
            .rootfs_dir()
            .join("var")
            .to_string_lossy()
            .into_owned();
        assert!(argv
            .windows(3)
            .any(|w| w == ["--bind", &rootfs_var, "/var"]));

        // System dirs
        assert!(argv.windows(2).any(|w| w == ["--dev", "/dev"]));
        assert!(argv.windows(2).any(|w| w == ["--proc", "/proc"]));

        // DNS
        assert!(argv
            .windows(3)
            .any(|w| w == ["--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf"]));

        // User namespace — run as root inside sandbox
        assert!(argv
            .windows(4)
            .any(|w| w == ["--unshare-user", "--uid", "0", "--gid"]));
        assert!(argv.contains(&"0".to_string())); // --gid 0

        // Network
        assert!(argv.contains(&"--share-net".to_string()));

        // Without workspace the chdir should default to /root
        assert!(argv.windows(2).any(|w| w == ["--chdir", "/root"]));

        // Must NOT contain /workspace anywhere (no workspace given)
        assert!(
            !argv.iter().any(|a| a == "/workspace"),
            "unexpected /workspace without cwd"
        );

        // Must end with the shell invocation
        let tail: Vec<_> = argv.iter().rev().take(3).collect();
        assert_eq!(*tail[0], "-i");
        assert_eq!(*tail[1], "-l");
        assert_eq!(*tail[2], "/bin/bash");

        // --die-with-parent must be present
        assert!(argv.contains(&"--die-with-parent".to_string()));

        // Environment variables via --setenv
        assert!(argv
            .windows(3)
            .any(|w| w == ["--setenv", "TERM", "xterm-256color"]));
        assert!(argv.windows(3).any(|w| w == ["--setenv", "HOME", "/root"]));
    }

    #[test]
    fn test_bwrap_cmd_with_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());

        // Create a fake workspace dir so the exists() check passes
        let ws = tmp.path().join("my_workspace");
        std::fs::create_dir_all(&ws).unwrap();

        let cmd = PtyShell::build_bwrap_cmd(&config, Some(ws.as_path()));
        let argv = argv_strs(&cmd);

        let ws_str = ws.to_string_lossy().into_owned();

        // Should mount the workspace
        assert!(
            argv.windows(3)
                .any(|w| w == ["--bind", &ws_str, "/workspace"]),
            "workspace bind mount missing"
        );

        // chdir should be /workspace
        assert!(argv.windows(2).any(|w| w == ["--chdir", "/workspace"]));
    }

    #[test]
    fn test_bwrap_cmd_no_network() {
        let tmp = tempfile::tempdir().unwrap();
        let mut config = test_config(tmp.path());
        config.network_access = false;

        let cmd = PtyShell::build_bwrap_cmd(&config, None);
        let argv = argv_strs(&cmd);

        assert!(argv.contains(&"--unshare-net".to_string()));
        assert!(!argv.contains(&"--share-net".to_string()));
    }

    // ------------------------------------------------------------------
    // proot command builder
    // ------------------------------------------------------------------

    #[test]
    fn test_proot_cmd_without_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let proot_bin = PathBuf::from("/usr/bin/proot");

        let cmd = PtyShell::build_proot_cmd(&config, &proot_bin, None);
        let argv = argv_strs(&cmd);

        // First arg is the proot binary
        assert_eq!(argv[0], "/usr/bin/proot");

        // Fake root
        assert!(argv.contains(&"-0".to_string()));

        // Rootfs via -r
        let rootfs_str = config.rootfs_dir().to_string_lossy().into_owned();
        assert!(argv.windows(2).any(|w| w == ["-r", &rootfs_str]));

        // Bound dirs
        assert!(argv.windows(2).any(|w| w == ["-b", "/dev"]));
        assert!(argv.windows(2).any(|w| w == ["-b", "/proc"]));
        assert!(argv.windows(2).any(|w| w == ["-b", "/sys"]));
        assert!(argv.windows(2).any(|w| w == ["-b", "/etc/resolv.conf"]));

        // Without workspace, working dir defaults to /root
        assert!(argv.windows(2).any(|w| w == ["-w", "/root"]));

        // Shell invocation
        let tail: Vec<_> = argv.iter().rev().take(3).collect();
        assert_eq!(*tail[0], "-i");
        assert_eq!(*tail[1], "-l");
        assert_eq!(*tail[2], "/bin/bash");

        // Environment variables should be set via cmd.env(), not as args.
        // Verify they are NOT in argv:
        assert!(!argv.contains(&"--setenv".to_string()));
        // But they should be accessible through get_env:
        assert_eq!(cmd.get_env("TERM"), Some(OsStr::new("xterm-256color")));
        assert_eq!(cmd.get_env("HOME"), Some(OsStr::new("/root")));
    }

    #[test]
    fn test_proot_cmd_with_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let proot_bin = PathBuf::from("/usr/bin/proot");

        let ws = tmp.path().join("project");
        std::fs::create_dir_all(&ws).unwrap();

        let cmd = PtyShell::build_proot_cmd(&config, &proot_bin, Some(ws.as_path()));
        let argv = argv_strs(&cmd);

        let expected_bind = format!("{}:/workspace", ws.to_string_lossy());
        assert!(
            argv.windows(2).any(|w| w == ["-b", &expected_bind]),
            "workspace bind spec missing"
        );

        // Working dir
        assert!(argv.windows(2).any(|w| w == ["-w", "/workspace"]));
    }

    #[test]
    fn test_proot_cmd_workspace_from_config() {
        let tmp = tempfile::tempdir().unwrap();
        let ws = tmp.path().join("config_ws");
        std::fs::create_dir_all(&ws).unwrap();

        let mut config = test_config(tmp.path());
        config.workspace_dir = Some(ws.clone());

        let proot_bin = PathBuf::from("proot");

        // cwd=None should fall back to config.workspace_dir
        let cmd = PtyShell::build_proot_cmd(&config, &proot_bin, None);
        let argv = argv_strs(&cmd);

        let expected_bind = format!("{}:/workspace", ws.to_string_lossy());
        assert!(
            argv.windows(2).any(|w| w == ["-b", &expected_bind]),
            "config workspace bind spec missing"
        );
        assert!(argv.windows(2).any(|w| w == ["-w", "/workspace"]));
    }

    // ------------------------------------------------------------------
    // WSL command builder
    // ------------------------------------------------------------------

    #[test]
    fn test_wsl_cmd_without_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());

        let cmd = PtyShell::build_wsl_cmd(&config, None);
        let argv = argv_strs(&cmd);

        // First arg must be wsl.exe
        assert_eq!(argv[0], "wsl.exe");

        // Must contain -d <distro_name>
        assert!(argv
            .windows(2)
            .any(|w| w == ["-d", config.wsl_distro_name()]));

        // Must NOT contain --cd (no workspace)
        assert!(
            !argv.contains(&"--cd".to_string()),
            "unexpected --cd without workspace"
        );

        // Must contain -- separator
        assert!(argv.contains(&"--".to_string()));

        // Must contain env command with env vars
        assert!(argv.contains(&"env".to_string()));
        assert!(argv.iter().any(|a| a == "TERM=xterm-256color"));
        assert!(argv.iter().any(|a| a == "HOME=/root"));

        // Must end with shell invocation
        let tail: Vec<_> = argv.iter().rev().take(3).collect();
        assert_eq!(*tail[0], "-i");
        assert_eq!(*tail[1], "-l");
        assert_eq!(*tail[2], "/bin/bash");
    }

    #[test]
    fn test_wsl_cmd_with_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());

        // Create a fake workspace dir so the exists() check passes
        let ws = tmp.path().join("my_project");
        std::fs::create_dir_all(&ws).unwrap();

        let cmd = PtyShell::build_wsl_cmd(&config, Some(ws.as_path()));
        let argv = argv_strs(&cmd);

        // Should have --cd with the WSL-translated path
        assert!(
            argv.contains(&"--cd".to_string()),
            "missing --cd for workspace"
        );

        // The path after --cd should be a WSL-style path
        let cd_idx = argv.iter().position(|a| a == "--cd").unwrap();
        let wsl_path = &argv[cd_idx + 1];
        // On Linux the path won't have a drive letter, so it stays as-is
        assert!(
            wsl_path.starts_with('/'),
            "WSL path should be unix-style: {}",
            wsl_path
        );
    }

    // ------------------------------------------------------------------
    // Workspace dir pre-creation (the bwrap mkdir fix)
    // ------------------------------------------------------------------

    #[test]
    fn test_rootfs_mount_point_dirs_can_be_precreated() {
        // Verifies the logic that spawn_sandboxed uses: creating /workspace
        // and /root inside the rootfs directory before bwrap starts.
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(tmp.path());
        let rootfs = config.rootfs_dir();

        // Directories should not exist yet (only var was created in test_config)
        assert!(!rootfs.join("workspace").exists());
        // /root may or may not exist; the important thing is create_dir_all succeeds

        // This mirrors what spawn_sandboxed does
        let _ = std::fs::create_dir_all(rootfs.join("workspace"));
        let _ = std::fs::create_dir_all(rootfs.join("root"));

        assert!(rootfs.join("workspace").exists());
        assert!(rootfs.join("root").exists());
    }

    #[tokio::test]
    #[ignore]
    async fn test_bwrap_install_package() {
        use super::super::sandbox::{config::SandboxBackend, get_sandbox_manager};
        use std::process::Stdio;
        use tokio::process::Command;

        println!("\n=== Testing bwrap package installation ===");

        let manager = get_sandbox_manager()
            .await
            .expect("Failed to get sandbox manager");
        println!(
            "Sandbox manager initialized: backend={:?}",
            manager.backend()
        );

        if manager.backend() != SandboxBackend::Bwrap {
            println!(
                "Skipping test - bwrap not available, got: {:?}",
                manager.backend()
            );
            return;
        }

        manager
            .ensure_ready()
            .await
            .expect("Failed to ensure rootfs");
        let rootfs = manager.config().rootfs_dir();
        println!("Rootfs ready: {:?}", rootfs);

        // Build base bwrap arguments (need owned strings for lifetime)
        let rootfs_str = rootfs.to_str().unwrap();

        let bwrap_args = vec![
            "--bind",
            rootfs_str,
            "/",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "--ro-bind",
            "/etc/resolv.conf",
            "/etc/resolv.conf",
            "--unshare-user",
            "--uid",
            "0",
            "--gid",
            "0",
            "--share-net",
            "--chdir",
            "/root",
            "--setenv",
            "HOME",
            "/root",
            "--setenv",
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        ];

        // Test 1: Simple echo command
        println!("\n=== Test 1: Simple command ===");
        let output = Command::new("bwrap")
            .args(&bwrap_args)
            .args(["/bin/bash", "-c", "echo BWRAP_WORKS"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .expect("Failed to execute bwrap");

        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("Output: {}", stdout);
        assert!(stdout.contains("BWRAP_WORKS"), "Basic command failed");
        println!("✓ Basic command works");

        // Test 2: Check pacman is available
        println!("\n=== Test 2: Pacman version ===");
        let output = Command::new("bwrap")
            .args(&bwrap_args)
            .args(["/bin/bash", "-c", "pacman --version 2>&1"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .expect("Failed to execute bwrap");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("Stdout: {}", stdout.lines().next().unwrap_or(""));
        println!("Stderr: {}", stderr);
        assert!(
            stdout.contains("Pacman")
                || stdout.contains("pacman")
                || stderr.contains("Pacman")
                || stderr.contains("pacman"),
            "Pacman not found"
        );
        println!("✓ Pacman is available");

        // Test 3: Check /var is writable
        println!("\n=== Test 3: Check /var is writable ===");
        let output = Command::new("bwrap")
            .args(&bwrap_args)
            .args(["/bin/bash", "-c", "touch /var/test_writable && rm /var/test_writable && echo VAR_WRITABLE || echo VAR_READONLY"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .expect("Failed to execute bwrap");

        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("Output: {}", stdout);
        assert!(stdout.contains("VAR_WRITABLE"), "/var is not writable!");
        println!("✓ /var is writable");

        // Test 4: Install/verify which package
        println!("\n=== Test 4: Install which package ===");
        let output = Command::new("bwrap")
            .args(&bwrap_args)
            .args(["/bin/bash", "-c", "pacman -S --noconfirm --needed which 2>&1 && echo INSTALL_SUCCESS || echo INSTALL_FAILED"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .expect("Failed to execute bwrap");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        println!("Stdout:\n{}", stdout);
        println!("Stderr:\n{}", stderr);

        let combined_output = format!("{}{}", stdout, stderr);
        assert!(
            combined_output.contains("INSTALL_SUCCESS")
                || combined_output.contains("reinstalling")
                || combined_output.contains("up-to-date")
                || combined_output.contains("up to date")
                || combined_output.contains("there is nothing to do"),
            "Package installation failed!\nOutput: {}",
            combined_output
        );
        println!("✓ Package installation succeeded");

        // Test 5: Verify package is in database
        println!("\n=== Test 5: Verify which is in package database ===");
        let output = Command::new("bwrap")
            .args(&bwrap_args)
            .args([
                "/bin/bash",
                "-c",
                "pacman -Q which 2>&1 && echo PACKAGE_FOUND || echo PACKAGE_NOT_FOUND",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .expect("Failed to execute bwrap");

        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("Output: {}", stdout);
        assert!(
            stdout.contains("PACKAGE_FOUND") && stdout.contains("which"),
            "Package not found in database"
        );
        println!("✓ Package is tracked in pacman database");

        println!("\n✅ ALL TESTS PASSED - Bwrap can install packages!");
    }

    #[tokio::test]
    #[ignore]
    async fn test_proot_pty_spawn_real() {
        use super::super::sandbox::{config::SandboxBackend, get_sandbox_manager};
        use portable_pty::{native_pty_system, PtySize};
        use std::io::Read;

        println!("\n=== Testing real proot PTY spawn ===");

        let manager = get_sandbox_manager()
            .await
            .expect("Failed to get sandbox manager");
        println!(
            "Sandbox manager initialized: backend={:?}",
            manager.backend()
        );

        if manager.backend() != SandboxBackend::Proot {
            println!(
                "Skipping test - proot not available, got: {:?}",
                manager.backend()
            );
            return;
        }

        manager
            .ensure_ready()
            .await
            .expect("Failed to ensure rootfs");
        println!("Rootfs ready: {:?}", manager.config().rootfs_dir());

        let proot_path =
            super::super::sandbox::proot::ProotExecutor::get_proot_path(manager.config())
                .await
                .expect("Failed to get proot path");
        println!("Proot binary: {:?}", proot_path);

        let cmd = PtyShell::build_proot_cmd(manager.config(), &proot_path, None);

        println!("\nCommand args:");
        for (i, arg) in cmd.get_argv().iter().enumerate() {
            println!("  [{}] {:?}", i, arg);
        }

        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: 24,
                cols: 80,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("Failed to open PTY");

        println!("\nPTY opened, attempting to spawn command...");

        let spawn_result = pair.slave.spawn_command(cmd);

        match spawn_result {
            Ok(mut child) => {
                println!("✓ Command spawned successfully!");

                let mut reader = pair
                    .master
                    .try_clone_reader()
                    .expect("Failed to clone reader");
                let mut writer = pair.master.take_writer().expect("Failed to take writer");
                let mut buf = [0u8; 2048];

                println!("\nWaiting for initial prompt (2s)...");
                std::thread::sleep(std::time::Duration::from_secs(2));

                if let Ok(n) = reader.read(&mut buf) {
                    if n > 0 {
                        println!("Initial output: {:?}", String::from_utf8_lossy(&buf[..n]));
                    }
                }

                writer
                    .write_all(b"echo TEST_SUCCESS\n")
                    .expect("Failed to write");
                writer.flush().expect("Failed to flush");

                std::thread::sleep(std::time::Duration::from_secs(1));

                buf = [0u8; 2048];
                let mut output = String::new();
                if let Ok(n) = reader.read(&mut buf) {
                    output = String::from_utf8_lossy(&buf[..n]).to_string();
                    println!("Command output: {:?}", output);
                }

                assert!(output.contains("TEST_SUCCESS"), "Command execution failed");

                writer.write_all(b"exit\n").expect("Failed to write");
                writer.flush().expect("Failed to flush");
                std::thread::sleep(std::time::Duration::from_millis(500));
                let _ = child.try_wait();

                println!("✓ Proot shell works!");
            }
            Err(e) => {
                panic!("Proot PTY spawn failed: {:?}", e);
            }
        }
    }
}
