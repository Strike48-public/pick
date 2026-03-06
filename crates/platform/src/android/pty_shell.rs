//! Interactive PTY shell via proot + raw libc PTY
//!
//! Spawns a real PTY session inside the proot BlackArch environment.
//! Uses raw libc openpty + tokio::process::Command to avoid portable-pty's
//! fork handler which triggers Android's seccomp filter with proot.

use super::proot::{ensure_binaries, ensure_pacman_compatible, ensure_rootfs_with_progress};
use pentest_core::config::ShellMode;
use pentest_core::error::{Error, Result};
use std::io::{Read, Write};
use std::os::unix::io::{FromRawFd, RawFd};
use std::path::{Path, PathBuf};
use tokio::process::Child;

/// An interactive PTY shell session running inside proot.
pub struct PtyShell {
    master_fd: RawFd,
    child: Child,
}

/// Prepare the proot rootfs with fake /proc entries, SELinux neutralisation,
/// /dev/shm mapping, and the link2symlink metadata directory.
///
/// Returns `(proot_binary_path, rootfs_path)`.
fn ensure_proot_environment(data_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let (proot, _) = ensure_binaries()?;
    let rootfs = data_dir.to_path_buf();

    // Create fake /proc entries that programs expect
    let proc_dir = rootfs.join("proc");
    std::fs::create_dir_all(&proc_dir).ok();
    std::fs::write(proc_dir.join(".loadavg"), "0.12 0.07 0.02 2/165 765\n").ok();
    std::fs::write(
        proc_dir.join(".stat"),
        "cpu  1050008 127632 898432 43828767 37203 63 99244 0 0 0\n",
    )
    .ok();
    std::fs::write(proc_dir.join(".uptime"), "10000.00 40000.00\n").ok();
    std::fs::write(
        proc_dir.join(".version"),
        "Linux version 6.2.0-PRoot-Distro (proot@localhost) (gcc 12.2.0) #1 SMP PREEMPT_DYNAMIC\n",
    )
    .ok();
    std::fs::write(
        proc_dir.join(".vmstat"),
        "nr_free_pages 15717\nnr_zone_active_anon 27773\nnr_zone_inactive_anon 7914\n",
    )
    .ok();

    // Neutralize SELinux
    let selinux_dir = rootfs.join("sys/.empty");
    std::fs::create_dir_all(&selinux_dir).ok();

    // Ensure /dev/shm mapped to tmp
    let shm_dir = rootfs.join("tmp");
    std::fs::create_dir_all(&shm_dir).ok();

    // link2symlink metadata dir
    let l2s_dir = rootfs.join(".l2s");
    std::fs::create_dir_all(&l2s_dir).ok();

    Ok((proot, rootfs))
}

/// Open a PTY pair via `openpty` and set the initial terminal size.
///
/// Returns `(master_fd, slave_fd)`.
fn create_pty_pair(cols: u16, rows: u16) -> Result<(RawFd, RawFd)> {
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;
    // SAFETY: openpty() allocates a new pseudoterminal pair and writes valid file
    // descriptors into `master` and `slave`. We pass null for the name, termios,
    // and winsize arguments (all optional). The return value is checked immediately
    // below — if openpty fails (ret != 0), we return an error and never use the
    // uninitialised fd values. If the invariant that openpty returns 0 only when
    // both fds are valid were violated, subsequent read/write/ioctl on those fds
    // would produce undefined behaviour or EBADF.
    let ret = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ret != 0 {
        return Err(Error::ToolExecution(format!(
            "openpty failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Set initial window size
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: master is a valid PTY master fd returned by the successful openpty()
    // call above. TIOCSWINSZ is the standard ioctl for setting terminal window
    // size and expects a pointer to a fully-initialised `winsize` struct, which
    // `ws` is. If master were an invalid fd, ioctl would return -1/EBADF; we
    // intentionally ignore the return value here because a window-size failure is
    // non-fatal (the terminal simply keeps its default dimensions).
    unsafe { libc::ioctl(master, libc::TIOCSWINSZ, &ws) };

    Ok((master, slave))
}

/// Build the proot argument list: root emulation, bind mounts, working
/// directory, and the login shell invocation.
fn build_proot_args(
    proot: &Path,
    rootfs: &Path,
    _data_dir: &Path,
    working_dir: &str,
    cwd: Option<&Path>,
) -> Vec<String> {
    let rootfs_str = rootfs.to_string_lossy().to_string();

    let mut args: Vec<String> = vec![
        "-0".into(),             // fake root
        "--link2symlink".into(), // hardlink emulation (essential on Android)
        "--kill-on-exit".into(), // clean up child processes
        "--sysvipc".into(),      // emulate System V IPC (required for pacman locking)
        "-r".into(),
        rootfs_str.clone(),
        "-b".into(),
        "/dev".into(),
        "-b".into(),
        "/proc".into(),
        "-b".into(),
        "/sys".into(),
        "-b".into(),
        "/dev/urandom:/dev/random".into(),
        "-b".into(),
        "/proc/self/fd:/dev/fd".into(),
        "-b".into(),
        "/proc/self/fd/0:/dev/stdin".into(),
        "-b".into(),
        "/proc/self/fd/1:/dev/stdout".into(),
        "-b".into(),
        "/proc/self/fd/2:/dev/stderr".into(),
    ];

    // Bind fake /proc entries (programs read these)
    for entry in &[".loadavg", ".stat", ".uptime", ".version", ".vmstat"] {
        let host = format!("{}/proc/{}", rootfs_str, entry);
        let guest = format!("/proc/{}", &entry[1..]); // strip leading dot
        args.push("-b".into());
        args.push(format!("{}:{}", host, guest));
    }

    // Neutralize SELinux
    args.push("-b".into());
    args.push(format!("{}/sys/.empty:/sys/fs/selinux", rootfs_str));

    // /dev/shm -> rootfs tmp
    args.push("-b".into());
    args.push(format!("{}/tmp:/dev/shm", rootfs_str));

    // If workspace provided, bind-mount it to /workspace inside proot
    if let Some(workspace) = cwd {
        let ws_str = workspace.to_string_lossy();
        args.push("-b".into());
        args.push(format!("{}:/workspace", ws_str));
    }

    args.extend([
        "-w".into(),
        working_dir.to_string(),
        // Termux proot handles syscall translation (dup2->dup3, etc.) at the
        // ptrace level, so no LD_PRELOAD shim is needed inside the guest.
        "/bin/bash".into(),
        "-l".into(),
        "-i".into(),
    ]);

    args
}

impl PtyShell {
    /// Spawn a new interactive shell.
    /// - ShellMode::Proot: Runs inside the proot BlackArch environment
    /// - ShellMode::Native: Runs directly on the Android device (limited functionality)
    /// If a progress sender is provided, setup status messages are sent through it.
    /// If `cwd` is provided, the workspace will be bind-mounted to `/workspace` inside proot.
    pub async fn spawn(
        cols: u16,
        rows: u16,
        progress: Option<tokio::sync::mpsc::Sender<String>>,
        cwd: Option<&Path>,
        shell_mode: ShellMode,
    ) -> Result<Self> {
        match shell_mode {
            ShellMode::Native => Self::spawn_native(cols, rows, cwd).await,
            ShellMode::Proot => Self::spawn_proot(cols, rows, progress, cwd).await,
        }
    }

    /// Spawn a native shell directly on Android (limited functionality)
    async fn spawn_native(cols: u16, rows: u16, cwd: Option<&Path>) -> Result<Self> {
        let (master, slave) = create_pty_pair(cols, rows)?;

        // Build simple shell command
        let mut cmd = tokio::process::Command::new("/system/bin/sh");
        cmd.arg("-l");
        if let Some(dir) = cwd {
            cmd.current_dir(dir);
        } else {
            cmd.current_dir("/data/local/tmp");
        }
        cmd.env("TERM", "xterm-256color");
        cmd.env("PATH", "/system/bin:/system/xbin");

        // PTY child setup
        let slave_fd = slave;
        // SAFETY: pre_exec registers a closure that runs in the forked child
        // process between fork() and exec(). The closure is unsafe because it
        // must only call async-signal-safe functions (all libc calls below
        // qualify). The operations and their safety justifications:
        //
        // - setsid(): Creates a new session and detaches from the parent's
        //   controlling terminal. Safe because this is a freshly forked child
        //   that is not yet a session leader.
        //
        // - dup2(slave_fd, 0/1/2): Redirects stdin/stdout/stderr to the PTY
        //   slave. slave_fd is a valid fd obtained from openpty() in the parent
        //   and inherited across fork. If slave_fd were invalid, dup2 would
        //   return -1/EBADF but would not cause UB.
        //
        // - close(3..1024): Closes all file descriptors >= 3 to prevent
        //   inherited Android fds from leaking into the child. The bounded
        //   range (3..1024) ensures we never pass a negative fd. Closing an
        //   already-closed fd harmlessly returns EBADF.
        //
        // - ioctl(0, TIOCSCTTY, 0): Makes fd 0 (the PTY slave after dup2) the
        //   controlling terminal. Safe because setsid() was called above, so
        //   the process has no controlling terminal yet. If this failed, the
        //   shell would still work but job control signals (Ctrl-C) would not
        //   be delivered.
        unsafe {
            cmd.pre_exec(move || {
                libc::setsid();
                libc::dup2(slave_fd, 0);
                libc::dup2(slave_fd, 1);
                libc::dup2(slave_fd, 2);
                for fd in 3..1024 {
                    libc::close(fd);
                }
                libc::ioctl(0, libc::TIOCSCTTY, 0);
                Ok(())
            });
        }

        let child = cmd
            .spawn()
            .map_err(|e| Error::ToolExecution(format!("Failed to spawn native shell: {e}")))?;

        // SAFETY: slave is a valid fd returned by openpty() via create_pty_pair().
        // The parent process only needs the master side of the PTY; the slave side
        // has been inherited by the child via fork (inside Command::spawn). Closing
        // it here prevents an fd leak in the parent and ensures the child sees EOF
        // on the slave when the master is eventually closed. Closing an already-
        // closed fd would return EBADF but not cause UB.
        unsafe { libc::close(slave) };

        Ok(Self {
            master_fd: master,
            child,
        })
    }

    /// Spawn a shell inside the proot BlackArch environment.
    ///
    /// This is a thin orchestrator that delegates to [`ensure_proot_environment`],
    /// [`create_pty_pair`], and [`build_proot_args`], then configures and spawns
    /// the child process.
    async fn spawn_proot(
        cols: u16,
        rows: u16,
        progress: Option<tokio::sync::mpsc::Sender<String>>,
        cwd: Option<&Path>,
    ) -> Result<Self> {
        // --- 1. Ensure rootfs is downloaded & environment directories exist ---
        let rootfs = ensure_rootfs_with_progress(progress).await?;

        // Always fix pacman.conf compatibility (DownloadUser, stale locks)
        if let Err(e) = ensure_pacman_compatible().await {
            tracing::warn!("Failed to fix pacman config: {}", e);
        }

        let (proot, rootfs) = ensure_proot_environment(&rootfs)?;

        tracing::info!("PTY: proot={}, exists={}", proot.display(), proot.exists());
        tracing::info!(
            "PTY: rootfs={}, exists={}",
            rootfs.display(),
            rootfs.exists()
        );

        // proot needs a writable temp dir; Android doesn't always expose /tmp
        let tmp_dir = rootfs.parent().unwrap_or(&rootfs).join("proot-tmp");
        std::fs::create_dir_all(&tmp_dir).ok();

        // --- 2. Create PTY pair ---
        let (master, slave) = create_pty_pair(cols, rows)?;
        tracing::info!("PTY: openpty succeeded, master={}, slave={}", master, slave);

        // --- 3. Build proot argument list ---
        let working_dir = if cwd.is_some() { "/workspace" } else { "/root" };
        let proot_args = build_proot_args(&proot, &rootfs, &rootfs, working_dir, cwd);

        // --- 4. Configure and spawn the Command ---
        // Termux proot needs libtalloc.so (patched via patchelf at build time from libtalloc.so.2)
        // We run proot directly from jniLibs (LD_LIBRARY_PATH points there for libtalloc)
        let lib_dir = proot
            .parent()
            .ok_or_else(|| Error::ToolExecution("proot has no parent directory".to_string()))?;

        tracing::info!(
            "PTY: using proot: {}, lib_dir: {}",
            proot.display(),
            lib_dir.display()
        );

        let mut cmd = tokio::process::Command::new(&proot);
        cmd.args(&proot_args);
        cmd.current_dir("/");
        cmd.env("HOME", "/root");
        cmd.env("USER", "root");
        cmd.env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        );
        cmd.env("TERM", "xterm-256color");
        cmd.env("COLORTERM", "truecolor");
        cmd.env("PROOT_TMP_DIR", &tmp_dir);
        cmd.env("TMPDIR", &tmp_dir);

        let l2s_dir = rootfs.join(".l2s");
        cmd.env("PROOT_L2S_DIR", l2s_dir.to_string_lossy().as_ref());

        // Point to loader in jniLibs
        let loader = lib_dir.join("libproot_loader.so");
        if loader.exists() {
            cmd.env("PROOT_LOADER", &loader);
        }
        // LD_LIBRARY_PATH tells the linker where to find libtalloc.so (patched from .so.2)
        cmd.env("LD_LIBRARY_PATH", lib_dir);
        // NOTE: do NOT set PROOT_NO_SECCOMP=1. With it set, proot intercepts
        // ALL syscalls via ptrace and its handlers return ENOSYS for dup2/dup3,
        // breaking bash redirects and pipes.

        // Proper PTY child setup via pre_exec:
        // 1. Create new session
        // 2. Set slave as stdin/stdout/stderr
        // 3. Close ALL inherited fds (Android app has 200+ open fds from
        //    WebView, goldfish, sockets -- if they leak to proot, its fd
        //    management breaks and dup2/dup3 returns ENOSYS)
        // 4. Set controlling terminal
        let slave_fd = slave;
        // SAFETY: pre_exec registers a closure that runs in the forked child
        // process between fork() and exec(). The closure is unsafe because it
        // must only call async-signal-safe functions (all libc calls below
        // qualify). The operations and their safety justifications:
        //
        // - setsid(): Creates a new session so the child is no longer associated
        //   with the parent's controlling terminal. Safe because this is a freshly
        //   forked child that is not a session leader yet.
        //
        // - dup2(slave_fd, 0/1/2): Redirects stdin/stdout/stderr to the PTY
        //   slave end. slave_fd is a valid fd obtained from openpty() in the
        //   parent and inherited across fork. If slave_fd were invalid, dup2
        //   would return -1/EBADF without causing UB.
        //
        // - close(3..1024): Closes every fd >= 3 to prevent the 200+ Android
        //   inherited fds (WebView, goldfish, sockets) from leaking into proot,
        //   which would break its internal fd management. The bounded range
        //   (3..1024) avoids passing negative fds. Closing an already-closed fd
        //   harmlessly returns EBADF. This must happen *after* dup2 so that
        //   fds 0/1/2 already point to the slave PTY.
        //
        // - ioctl(0, TIOCSCTTY, 0): Acquires fd 0 (the PTY slave) as the
        //   controlling terminal. Safe because setsid() was called above, so the
        //   process currently has no controlling terminal. Without this, job-
        //   control signals (SIGINT on Ctrl-C, SIGTSTP on Ctrl-Z) would not be
        //   delivered to the proot process group.
        unsafe {
            cmd.pre_exec(move || {
                // New session, detach from parent's controlling terminal
                libc::setsid();

                // Set slave as stdin/stdout/stderr
                libc::dup2(slave_fd, 0);
                libc::dup2(slave_fd, 1);
                libc::dup2(slave_fd, 2);

                // Close ALL fds >= 3 -- prevents Android's 200+ inherited fds
                // from leaking into proot. This must happen after dup2 above
                // (which ensures 0/1/2 are the slave PTY) but before exec.
                for fd in 3..1024 {
                    libc::close(fd);
                }

                // Make this the controlling terminal
                libc::ioctl(0, libc::TIOCSCTTY, 0);

                Ok(())
            });
        }

        tracing::info!("PTY: spawning proot via tokio::process::Command...");
        let child = cmd
            .spawn()
            .map_err(|e| Error::ToolExecution(format!("Failed to spawn proot shell: {e}")))?;

        // SAFETY: slave is a valid fd returned by openpty() via create_pty_pair().
        // The parent process only communicates through the master side; the slave
        // has been inherited by the child via fork (inside Command::spawn). Closing
        // it here prevents an fd leak and ensures proper EOF semantics when the
        // master is closed later. Closing an already-closed fd would return EBADF
        // but would not cause undefined behaviour.
        unsafe {
            libc::close(slave);
        }

        tracing::info!("PTY: proot spawned, pid={:?}", child.id());

        Ok(Self {
            master_fd: master,
            child,
        })
    }

    /// Resize the PTY.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<()> {
        let ws = libc::winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: self.master_fd is a valid PTY master fd that was obtained from
        // openpty() during construction and has not been closed (Drop has not run).
        // TIOCSWINSZ expects a pointer to a fully-initialised `winsize` struct,
        // which `ws` is. If master_fd were somehow invalid (e.g., double-close
        // from misuse), ioctl would return -1/EBADF, which we check below.
        let ret = unsafe { libc::ioctl(self.master_fd, libc::TIOCSWINSZ, &ws) };
        if ret != 0 {
            Err(Error::ToolExecution(format!(
                "PTY resize failed: {}",
                std::io::Error::last_os_error()
            )))
        } else {
            Ok(())
        }
    }

    /// Clone a reader for the PTY output (dup the master fd).
    pub fn try_clone_reader(&self) -> Result<Box<dyn Read + Send>> {
        // SAFETY: self.master_fd is a valid PTY master fd obtained from openpty()
        // during construction. dup() duplicates it, returning a new fd that
        // independently references the same open file description. If master_fd
        // were invalid, dup would return -1, which we check immediately below.
        let fd = unsafe { libc::dup(self.master_fd) };
        if fd < 0 {
            return Err(Error::ToolExecution(format!(
                "Failed to dup PTY master for reader: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: fd is a valid, open file descriptor — we just verified it is
        // non-negative (success from dup). from_raw_fd takes ownership, so the
        // File will close fd when dropped. We never use this raw fd again, so
        // there is no double-close risk.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        Ok(Box::new(file))
    }

    /// Clone a writer for the PTY input (dup the master fd).
    pub fn take_writer(&self) -> Result<Box<dyn Write + Send>> {
        // SAFETY: self.master_fd is a valid PTY master fd obtained from openpty()
        // during construction. dup() duplicates it, returning a new independent fd.
        // If master_fd were invalid, dup would return -1, which we check below.
        let fd = unsafe { libc::dup(self.master_fd) };
        if fd < 0 {
            return Err(Error::ToolExecution(format!(
                "Failed to dup PTY master for writer: {}",
                std::io::Error::last_os_error()
            )));
        }
        // SAFETY: fd is a valid, open file descriptor — we just verified it is
        // non-negative (success from dup). from_raw_fd takes ownership, so the
        // File will close fd when dropped. We never use this raw fd again, so
        // there is no double-close risk.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        Ok(Box::new(file))
    }

    /// Check if the child process has exited.
    pub fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>> {
        self.child
            .try_wait()
            .map_err(|e| Error::ToolExecution(format!("Failed to check child status: {e}")))
    }
}

impl Drop for PtyShell {
    fn drop(&mut self) {
        // SAFETY: self.master_fd is a valid PTY master fd that was obtained from
        // openpty() during construction and stored for the lifetime of PtyShell.
        // Drop runs exactly once, so there is no double-close. Any duplicated fds
        // (created by try_clone_reader/take_writer via dup()) are independently
        // owned by their respective File objects, so closing master_fd here does
        // not affect them. After this close, the kernel tears down the PTY master
        // end, which delivers EOF/SIGHUP to the child process.
        unsafe { libc::close(self.master_fd) };
    }
}
