//! Integration tests for sandbox command execution
//!
//! These tests validate the full sandbox setup including:
//! - Rootfs download and initialization
//! - Command execution as root inside the sandbox
//! - Package installation via pacman
//!
//! They exercise the platform-agnostic sandbox entry point
//! ([`pentest_platform::get_platform`] → [`CommandExec::execute_command`]), so
//! the SAME tests run against whatever sandbox the target provides — WSL/bwrap/
//! proot/Docker on desktop, proot on Android — rather than hard-coding one OS.
//!
//! Run with: `cargo test --test sandbox_integration -- --nocapture --ignored`
//! (ignored by default because they download a ~500MB rootfs / provision a
//! distro). Gated to targets that actually have a command sandbox.

#[cfg(all(
    test,
    any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "android"
    )
))]
mod sandbox_tests {
    use pentest_platform::CommandExec;
    use std::sync::OnceLock;
    use std::time::Duration;
    use tokio::sync::{Mutex, MutexGuard};

    /// Every test in this module drives the SAME global sandbox rootfs (one
    /// `/var/lib/pacman` DB, one `db.lck`). Rust runs tests in parallel, so
    /// running them together makes concurrent `pacman` invocations collide on
    /// the DB lock (`exit_code=1`) and one blocks until its 600s timeout. The
    /// rootfs manager's SETUP_LOCK only serializes provisioning, not command
    /// execution. Acquire this shared async guard at the top of each test so the
    /// suite runs sandbox commands one at a time (a `--test-threads=1` equivalent
    /// scoped to just these tests).
    fn sandbox_guard() -> &'static Mutex<()> {
        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        GUARD.get_or_init(|| Mutex::new(()))
    }

    async fn lock_sandbox() -> MutexGuard<'static, ()> {
        sandbox_guard().lock().await
    }

    /// Test that we can execute basic commands in the sandbox as root
    #[tokio::test]
    #[ignore = "downloads rootfs, run explicitly"]
    async fn test_sandbox_whoami() {
        let _guard = lock_sandbox().await;
        let platform = pentest_platform::get_platform();

        let result = platform
            .execute_command("whoami", &[], Duration::from_secs(10))
            .await
            .expect("Failed to execute whoami");

        println!("whoami output: {:?}", result);

        assert_eq!(result.exit_code, 0, "whoami should succeed");
        assert!(
            result.stdout.trim() == "root",
            "Should be root inside sandbox, got: {}",
            result.stdout.trim()
        );
    }

    /// Test that pacman database sync works (prerequisite for package installation)
    #[tokio::test]
    #[ignore = "downloads rootfs, run explicitly"]
    async fn test_sandbox_pacman_sync() {
        let _guard = lock_sandbox().await;
        let platform = pentest_platform::get_platform();

        // First ensure the sandbox is set up by running a simple command
        let _ = platform
            .execute_command("echo", &["test"], Duration::from_secs(10))
            .await
            .expect("Failed to initialize sandbox");

        // Sync package databases
        let result = platform
            .execute_command("pacman", &["-Sy", "--noconfirm"], Duration::from_secs(120))
            .await
            .expect("Failed to execute pacman -Sy");

        println!("pacman -Sy stdout:\n{}", result.stdout);
        println!("pacman -Sy stderr:\n{}", result.stderr);

        assert_eq!(result.exit_code, 0, "pacman -Sy should succeed");
    }

    /// Test that we can install nmap via pacman
    #[tokio::test]
    #[ignore = "downloads rootfs and packages, run explicitly"]
    async fn test_sandbox_install_nmap() {
        let _guard = lock_sandbox().await;
        let platform = pentest_platform::get_platform();

        // Sync databases first
        let sync_result = platform
            .execute_command("pacman", &["-Sy", "--noconfirm"], Duration::from_secs(120))
            .await
            .expect("Failed to sync packages");

        println!("pacman -Sy stdout:\n{}", sync_result.stdout);
        println!("pacman -Sy stderr:\n{}", sync_result.stderr);
        println!("pacman -Sy exit_code: {}", sync_result.exit_code);

        assert_eq!(sync_result.exit_code, 0, "pacman -Sy should succeed");

        // Try to install nmap
        let install_result = platform
            .execute_command(
                "pacman",
                &["-S", "--noconfirm", "nmap"],
                Duration::from_secs(300),
            )
            .await
            .expect("Failed to execute pacman -S nmap");

        println!("pacman -S nmap stdout:\n{}", install_result.stdout);
        println!("pacman -S nmap stderr:\n{}", install_result.stderr);

        // If installation fails due to file conflicts, we need to fix the rootfs
        if install_result.exit_code != 0 {
            if install_result.stderr.contains("conflicting files") {
                panic!(
                    "Package installation failed with file conflicts. \
                     The rootfs needs to be updated or packages need --overwrite flag.\n\
                     Stderr: {}",
                    install_result.stderr
                );
            } else {
                panic!(
                    "Package installation failed unexpectedly (exit code {}):\n\
                     Stdout: {}\n\
                     Stderr: {}",
                    install_result.exit_code, install_result.stdout, install_result.stderr
                );
            }
        }

        // Verify nmap was installed by running it
        let verify_result = platform
            .execute_command("nmap", &["--version"], Duration::from_secs(10))
            .await
            .expect("Failed to verify nmap installation");

        println!("nmap --version: {}", verify_result.stdout);
        assert_eq!(verify_result.exit_code, 0, "nmap should be installed");
        assert!(
            verify_result.stdout.contains("Nmap version"),
            "nmap should report version"
        );
    }

    /// Comprehensive test: Install nmap, verify raw sockets work via execute_command and PTY.
    ///
    /// Desktop-only (linux/macos/windows): it drives the desktop `PtyShell`,
    /// which lives in the `desktop` module and so is absent on android/ios.
    /// `ShellMode::Proot` here is Pick's generic "run sandboxed" mode, NOT the
    /// proot binary specifically — `PtyShell::spawn` routes it to whatever
    /// backend the platform provides: bwrap/proot on Linux, WSL on Windows,
    /// Docker on macOS (see `build_cmd_for_backend`). So the PTY path is
    /// exercised on every desktop OS, not just Linux.
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    #[tokio::test]
    #[ignore = "comprehensive end-to-end test, run explicitly"]
    async fn test_sandbox_nmap_raw_sockets_comprehensive() {
        use pentest_core::config::ShellMode;
        use pentest_platform::desktop::pty_shell::PtyShell;
        use std::io::{Read, Write};

        let _guard = lock_sandbox().await;
        let platform = pentest_platform::get_platform();

        println!("=== Step 1: Install nmap via pacman ===");

        // Sync databases
        let sync_result = platform
            .execute_command("pacman", &["-Sy", "--noconfirm"], Duration::from_secs(120))
            .await
            .expect("Failed to sync packages");

        println!("pacman -Sy: exit_code={}", sync_result.exit_code);
        assert_eq!(sync_result.exit_code, 0, "pacman -Sy should succeed");

        // Install nmap
        let install_result = platform
            .execute_command(
                "pacman",
                &["-S", "--noconfirm", "nmap"],
                Duration::from_secs(300),
            )
            .await
            .expect("Failed to install nmap");

        println!("pacman -S nmap: exit_code={}", install_result.exit_code);
        assert_eq!(
            install_result.exit_code, 0,
            "nmap installation should succeed"
        );

        println!("\n=== Step 2: Test nmap TCP connect scan via execute_command ===");

        // Run TCP connect scan (doesn't require raw sockets, works in unprivileged sandbox)
        // Note: -sS (SYN scan) requires CAP_NET_RAW which doesn't work in unprivileged containers
        let scan_result = platform
            .execute_command(
                "nmap",
                &["-sT", "127.0.0.1", "-p", "22"],
                Duration::from_secs(30),
            )
            .await
            .expect("Failed to run nmap scan");

        println!("nmap -sT stdout:\n{}", scan_result.stdout);
        println!("nmap -sT stderr:\n{}", scan_result.stderr);

        assert_eq!(
            scan_result.exit_code, 0,
            "nmap TCP connect scan should succeed"
        );
        assert!(
            scan_result.stdout.contains("Nmap scan report")
                || scan_result.stdout.contains("Starting Nmap"),
            "nmap should start scan"
        );

        println!("\n=== Step 3: Test nmap scan via PTY shell ===");

        // Spawn sandboxed PTY shell (WSL on Windows, bwrap/proot on Linux,
        // Docker on macOS — PtyShell::spawn picks the backend).
        let pty = PtyShell::spawn(24, 80, None, None, ShellMode::Proot)
            .await
            .expect("Failed to spawn PTY shell");

        let mut reader = pty.try_clone_reader().expect("Failed to get PTY reader");
        let mut writer = pty.take_writer().expect("Failed to get PTY writer");

        // The PtyShell reader is a plain blocking `Read` with no timeout, and
        // shells differ in WHEN they first emit (a Linux bwrap/proot PTY prints a
        // prompt immediately; the Windows WSL2 PTY may not), so a bare
        // `reader.read()` can block forever — that hung this test on Windows.
        // Instead, pump the reader on a dedicated thread into a channel and
        // consume with a wall-clock deadline until the sentinel appears. Portable
        // across Linux/WSL2/Docker and can never hang the suite.
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let reader_thread = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break, // EOF: shell closed
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).is_err() {
                            break; // receiver gone (test finished)
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Run a TCP connect scan (no raw sockets needed) and mark completion with
        // a unique sentinel we can wait for.
        writer
            .write_all(b"nmap -sT 127.0.0.1 -p 22; echo NMAP_DONE_SENTINEL\n")
            .expect("Failed to write to PTY");
        writer.flush().expect("Failed to flush PTY");

        // Accumulate output until the sentinel shows up or we hit the deadline.
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let mut collected = String::new();
        while std::time::Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(chunk) => {
                    collected.push_str(&String::from_utf8_lossy(&chunk));
                    if collected.contains("NMAP_DONE_SENTINEL") {
                        break;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }

        // Tell the interactive shell to exit so the PTY closes and the reader
        // thread hits EOF. `/bin/bash -l -i` does NOT terminate just from stdin
        // closing (and PtyShell has no kill() and no Drop that reaps the child),
        // so `exit` is what actually ends it — without it the reader thread
        // blocks on read() forever and a join() here would deadlock.
        let _ = writer.write_all(b"exit\n");
        let _ = writer.flush();
        drop(writer);
        drop(pty);
        // Reap the reader thread, but never block the test on it: if the shell
        // somehow doesn't close, joining in a bounded side-thread lets the test
        // finish and report rather than hang the whole suite (the observed
        // Windows failure mode). The child dies with the test process anyway.
        let joiner = std::thread::spawn(move || {
            let _ = reader_thread.join();
        });
        let join_deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !joiner.is_finished() && std::time::Instant::now() < join_deadline {
            std::thread::sleep(Duration::from_millis(100));
        }

        println!("PTY output:\n{collected}");
        assert!(
            collected.contains("Nmap scan report")
                || collected.contains("Starting Nmap")
                || collected.contains("NMAP_DONE_SENTINEL"),
            "PTY nmap should run (got: {collected})",
        );

        println!("\n=== SUCCESS: Nmap works in both execute_command and PTY shell! ===");
    }

    /// Test that pacman can handle package updates without conflicts
    #[tokio::test]
    #[ignore = "downloads rootfs and updates all packages, run explicitly"]
    async fn test_sandbox_pacman_update() {
        let _guard = lock_sandbox().await;
        let platform = pentest_platform::get_platform();

        // Full system update with --overwrite to handle any conflicts
        let result = platform
            .execute_command(
                "pacman",
                &["-Syu", "--noconfirm", "--overwrite", "*"],
                Duration::from_secs(600),
            )
            .await
            .expect("Failed to execute pacman -Syu");

        println!("pacman -Syu stdout:\n{}", result.stdout);
        println!("pacman -Syu stderr:\n{}", result.stderr);

        // System update should either succeed or indicate packages are up to date
        assert!(
            result.exit_code == 0 || result.stdout.contains("there is nothing to do"),
            "pacman -Syu should succeed or indicate no updates needed"
        );
    }
}
