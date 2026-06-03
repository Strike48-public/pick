//! Empirical smoke tests for each sandbox backend on the current machine.
//!
//! Each test reports clearly whether its backend is available AND whether basic
//! exec + PTY spawn work. They're `#[ignore]` so CI doesn't fail when bwrap or
//! proot aren't installed.
//!
//! Run on your machine with:
//!   cargo test -p pentest-platform --test backend_smoke -- --ignored --nocapture
//!
//! Read the output to know empirically which backend(s) work for you.

#![cfg(all(test, target_os = "linux"))]

use std::path::PathBuf;
use std::process::Command;

/// Helper: did the given binary respond to `--version` (or equivalent)?
fn binary_available(bin: &str) -> Option<String> {
    let out = Command::new(bin).arg("--version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()?
            .to_string(),
    )
}

/// Resolve the downloaded proot path (the one Pick uses when system proot is absent).
fn downloaded_proot_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(format!("{}/.local/share/pentest-sandbox/bin/proot", home))
}

/// Path to the BlackArch rootfs Pick downloaded.
fn rootfs_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(format!(
        "{}/.local/share/pentest-sandbox/blackarch-rootfs",
        home
    ))
}

/// Verify each backend's binary is discoverable, before any spawn attempts.
#[test]
#[ignore = "machine-specific, run with --ignored"]
fn discover_backends() {
    println!("\n=== Backend availability ===");
    let bwrap = binary_available("bwrap");
    let proot_system = binary_available("proot");
    let proot_downloaded = if downloaded_proot_path().exists() {
        binary_available(downloaded_proot_path().to_str().unwrap())
    } else {
        None
    };
    let rootfs_exists = rootfs_path().exists();

    println!("  bwrap                : {:?}", bwrap);
    println!("  proot (system PATH)  : {:?}", proot_system);
    println!("  proot (downloaded)   : {:?}", proot_downloaded);
    println!("  rootfs dir exists    : {}", rootfs_exists);
    println!("  rootfs path          : {}", rootfs_path().display());
}

// ---------------------------------------------------------------------------
// Direct backend exec — no PTY. Verifies the sandbox executor's command path.
// ---------------------------------------------------------------------------

/// Native: just run a command directly with std::process::Command. Should always work.
#[test]
#[ignore = "machine-specific, run with --ignored"]
fn native_exec_works() {
    let out = Command::new("/usr/bin/env")
        .args(["echo", "hello-native"])
        .output()
        .expect("native exec");
    let stdout = String::from_utf8_lossy(&out.stdout);
    println!("native exit={} stdout={:?}", out.status, stdout);
    assert!(out.status.success());
    assert!(stdout.contains("hello-native"));
}

/// Bwrap: spawn a no-rootfs command (just exposes / read-only) to verify bwrap itself
/// runs in this environment. Doesn't need the BlackArch rootfs.
#[test]
#[ignore = "machine-specific, run with --ignored"]
fn bwrap_exec_works() {
    if binary_available("bwrap").is_none() {
        println!(
            "bwrap not installed — SKIPPING (this is the failure mode for users who chose proot)"
        );
        return;
    }
    let out = Command::new("bwrap")
        .args([
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--unshare-user",
            "--uid",
            "0",
            "--gid",
            "0",
            "/usr/bin/env",
            "echo",
            "hello-bwrap",
        ])
        .output()
        .expect("bwrap spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    println!(
        "bwrap exit={} stdout={:?} stderr={:?}",
        out.status, stdout, stderr
    );
    assert!(out.status.success(), "bwrap stderr: {}", stderr);
    assert!(stdout.contains("hello-bwrap"));
}

/// Proot: spawn a command inside the BlackArch rootfs. Requires the downloaded
/// proot binary AND the rootfs to be present.
#[test]
#[ignore = "machine-specific, run with --ignored"]
fn proot_exec_works() {
    let proot = downloaded_proot_path();
    if !proot.exists() {
        println!("proot not downloaded ({}) — SKIPPING", proot.display());
        return;
    }
    let rootfs = rootfs_path();
    if !rootfs.exists() {
        println!("rootfs not present ({}) — SKIPPING", rootfs.display());
        return;
    }
    let out = Command::new(&proot)
        .args([
            "-0",
            "-r",
            rootfs.to_str().unwrap(),
            "-b",
            "/dev",
            "-b",
            "/proc",
            "-b",
            "/sys",
            "-b",
            "/etc/resolv.conf",
            "-w",
            "/root",
            "/bin/echo",
            "hello-proot",
        ])
        .output()
        .expect("proot spawn");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    println!(
        "proot exit={} stdout={:?} stderr={:?}",
        out.status, stdout, stderr
    );
    assert!(out.status.success(), "proot stderr: {}", stderr);
    assert!(stdout.contains("hello-proot"));
}

// ---------------------------------------------------------------------------
// PTY spawn — this is the path that fails for the user's proot setup.
// Uses portable_pty exactly like crates/platform/src/desktop/pty_shell.rs does.
// ---------------------------------------------------------------------------

fn try_pty_spawn(label: &str, mut build: impl FnMut(&mut portable_pty::CommandBuilder)) {
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");
    let mut cmd = CommandBuilder::new("/bin/sh"); // placeholder, build will replace
    build(&mut cmd);
    let result = pair.slave.spawn_command(cmd);
    match result {
        Ok(mut child) => {
            // Don't wait for the shell to actually exit; just confirm spawn succeeded.
            let _ = child.kill();
            println!("[{}] PTY spawn: OK", label);
        }
        Err(e) => {
            println!("[{}] PTY spawn: FAILED — {:#}", label, e);
        }
    }
}

/// Native: PTY spawning a plain /bin/sh. Should always work.
#[test]
#[ignore = "machine-specific, run with --ignored"]
fn pty_spawn_native_works() {
    try_pty_spawn("native", |cmd| {
        *cmd = portable_pty::CommandBuilder::new("/bin/sh");
        cmd.args(["-c", "true"]);
    });
}

/// Bwrap: PTY spawning bwrap. Should work for users who have bwrap.
#[test]
#[ignore = "machine-specific, run with --ignored"]
fn pty_spawn_bwrap_works() {
    if binary_available("bwrap").is_none() {
        println!("bwrap not installed — SKIPPING");
        return;
    }
    try_pty_spawn("bwrap", |cmd| {
        *cmd = portable_pty::CommandBuilder::new("bwrap");
        cmd.args([
            "--ro-bind",
            "/",
            "/",
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--unshare-user",
            "--uid",
            "0",
            "--gid",
            "0",
            "/bin/sh",
            "-c",
            "true",
        ]);
    });
}

/// Proot: PTY spawning proot — this is the path that returns EACCES for the user.
/// Use the same args as `crates/platform/src/desktop/pty_shell.rs::build_proot_cmd`.
#[test]
#[ignore = "machine-specific, run with --ignored"]
fn pty_spawn_proot_works() {
    let proot = downloaded_proot_path();
    if !proot.exists() {
        println!("proot not downloaded — SKIPPING");
        return;
    }
    let rootfs = rootfs_path();
    if !rootfs.exists() {
        println!("rootfs not present — SKIPPING");
        return;
    }
    let proot_str = proot.to_string_lossy().to_string();
    let rootfs_str = rootfs.to_string_lossy().to_string();
    try_pty_spawn("proot", move |cmd| {
        *cmd = portable_pty::CommandBuilder::new(&proot_str);
        cmd.arg("-0");
        cmd.arg("-r");
        cmd.arg(&rootfs_str);
        cmd.args(["-b", "/dev"]);
        cmd.args(["-b", "/proc"]);
        cmd.args(["-b", "/sys"]);
        cmd.args(["-b", "/etc/resolv.conf"]);
        cmd.arg("-w");
        cmd.arg("/root");
        cmd.args(["/bin/sh", "-c", "true"]);
    });
}

/// Same as `pty_spawn_proot_works` but with `set_controlling_tty(false)`.
/// If THIS one works while the other fails, the bug is in TIOCSCTTY — and a
/// one-liner in `build_proot_cmd` (`cmd.set_controlling_tty(false)`) is the fix.
#[test]
#[ignore = "machine-specific, run with --ignored"]
fn pty_spawn_proot_works_without_controlling_tty() {
    let proot = downloaded_proot_path();
    if !proot.exists() {
        println!("proot not downloaded — SKIPPING");
        return;
    }
    let rootfs = rootfs_path();
    if !rootfs.exists() {
        println!("rootfs not present — SKIPPING");
        return;
    }
    let proot_str = proot.to_string_lossy().to_string();
    let rootfs_str = rootfs.to_string_lossy().to_string();
    try_pty_spawn("proot+no-ctty", move |cmd| {
        *cmd = portable_pty::CommandBuilder::new(&proot_str);
        cmd.set_controlling_tty(false);
        cmd.arg("-0");
        cmd.arg("-r");
        cmd.arg(&rootfs_str);
        cmd.args(["-b", "/dev"]);
        cmd.args(["-b", "/proc"]);
        cmd.args(["-b", "/sys"]);
        cmd.args(["-b", "/etc/resolv.conf"]);
        cmd.arg("-w");
        cmd.arg("/root");
        cmd.args(["/bin/sh", "-c", "true"]);
    });
}
