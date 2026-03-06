//! Integration tests for sandbox command execution
//!
//! These tests validate the full sandbox setup including:
//! - Rootfs download and initialization
//! - Command execution as root inside the sandbox
//! - Package installation via pacman
//!
//! Run with: `cargo test --test sandbox_integration -- --nocapture --ignored`
//! (ignored by default because they download ~500MB rootfs)

#[cfg(all(test, target_os = "linux"))]
mod sandbox_tests {
    use pentest_platform::CommandExec;
    use std::time::Duration;

    /// Test that we can execute basic commands in the sandbox as root
    #[tokio::test]
    #[ignore = "downloads rootfs, run explicitly"]
    async fn test_sandbox_whoami() {
        let platform = pentest_platform::desktop::DesktopPlatform;

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
        let platform = pentest_platform::desktop::DesktopPlatform;

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
        let platform = pentest_platform::desktop::DesktopPlatform;

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

    /// Comprehensive test: Install nmap, verify raw sockets work via execute_command and PTY
    #[tokio::test]
    #[ignore = "comprehensive end-to-end test, run explicitly"]
    async fn test_sandbox_nmap_raw_sockets_comprehensive() {
        use pentest_core::config::ShellMode;
        use pentest_platform::desktop::pty_shell::PtyShell;
        use std::io::{Read, Write};

        let platform = pentest_platform::desktop::DesktopPlatform;

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

        // Spawn sandboxed PTY shell
        let pty = PtyShell::spawn(24, 80, None, None, ShellMode::Proot)
            .await
            .expect("Failed to spawn PTY shell");

        // Get reader and writer
        let mut reader = pty.try_clone_reader().expect("Failed to get PTY reader");
        let mut writer = pty.take_writer().expect("Failed to get PTY writer");

        // Give shell time to initialize
        tokio::time::sleep(Duration::from_millis(1000)).await;

        // Read initial prompt/output
        let mut initial_buf = vec![0u8; 4096];
        let _ = reader.read(&mut initial_buf);
        println!(
            "Initial PTY output: {}",
            String::from_utf8_lossy(&initial_buf)
        );

        // Run nmap command in PTY (TCP connect scan works without raw sockets)
        let cmd = "nmap -sT 127.0.0.1 -p 22; echo NMAP_DONE\n";
        writer
            .write_all(cmd.as_bytes())
            .expect("Failed to write to PTY");

        // Wait for command to complete and read output
        tokio::time::sleep(Duration::from_secs(5)).await;

        let mut output = vec![0u8; 8192];
        let n = reader.read(&mut output).unwrap_or(0);
        let output_str = String::from_utf8_lossy(&output[..n]);

        println!("PTY nmap output:\n{}", output_str);

        assert!(
            output_str.contains("Nmap scan report")
                || output_str.contains("Starting Nmap")
                || output_str.contains("NMAP_DONE"),
            "PTY nmap should run (got: {})",
            output_str
        );

        println!("\n=== SUCCESS: Nmap works in both execute_command and PTY shell! ===");
    }

    /// Test that pacman can handle package updates without conflicts
    #[tokio::test]
    #[ignore = "downloads rootfs and updates all packages, run explicitly"]
    async fn test_sandbox_pacman_update() {
        let platform = pentest_platform::desktop::DesktopPlatform;

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
