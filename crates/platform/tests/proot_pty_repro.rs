//! Progressive reproducer for the proot PTY-spawn EACCES bug observed in Pick.
//!
//! Each test adds one piece of Pick's runtime state to a baseline proot PTY spawn,
//! looking for the condition that triggers EACCES. Run them in order; the first one
//! to FAIL is the trigger.
//!
//! Run on your machine with:
//!   cargo test -p pentest-platform --test proot_pty_repro -- --ignored --nocapture --test-threads=1
//!
//! All tests are #[ignore] because they need the BlackArch rootfs + downloaded proot.

#![cfg(all(test, target_os = "linux"))]

use std::path::PathBuf;
use std::process::{Command as StdCommand, Stdio};
use std::time::Duration;

fn proot_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(format!("{}/.local/share/pentest-sandbox/bin/proot", home))
}

fn rootfs_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(format!(
        "{}/.local/share/pentest-sandbox/blackarch-rootfs",
        home
    ))
}

fn require_proot_and_rootfs() -> Option<(PathBuf, PathBuf)> {
    let p = proot_path();
    let r = rootfs_path();
    if !p.exists() || !r.exists() {
        println!("proot or rootfs missing — SKIPPING");
        return None;
    }
    Some((p, r))
}

/// Build the same CommandBuilder pty_shell::build_proot_cmd builds, then spawn through
/// portable_pty. Returns Ok if spawn succeeded.
fn try_pty_spawn_proot(label: &str) -> Result<(), String> {
    use portable_pty::{native_pty_system, CommandBuilder, PtySize};

    let (proot, rootfs) = match require_proot_and_rootfs() {
        Some(v) => v,
        None => return Err("setup missing".into()),
    };

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("openpty: {e}"))?;

    let mut cmd = CommandBuilder::new(&proot);
    cmd.arg("-0");
    cmd.arg("-r");
    cmd.arg(rootfs.to_str().unwrap());
    cmd.args(["-b", "/dev"]);
    cmd.args(["-b", "/proc"]);
    cmd.args(["-b", "/sys"]);
    cmd.args(["-b", "/etc/resolv.conf"]);
    cmd.arg("-w");
    cmd.arg("/root");
    cmd.args(["/bin/bash", "-l", "-i"]);

    match pair.slave.spawn_command(cmd) {
        Ok(mut child) => {
            let _ = child.kill();
            println!("[{label}] PTY spawn: OK");
            Ok(())
        }
        Err(e) => {
            let msg = format!("{e:#}");
            println!("[{label}] PTY spawn: FAILED — {msg}");
            Err(msg)
        }
    }
}

/// Baseline: bare process, fresh fork, try PTY spawn. Should match `backend_smoke`.
#[test]
#[ignore = "machine-specific, run with --ignored"]
fn level_0_baseline() {
    assert!(try_pty_spawn_proot("L0 baseline").is_ok());
}

/// Spawn a long-lived proot child first (simulating a webwright sidecar), THEN try
/// to PTY-spawn another proot. If EACCES happens here, two concurrent proots conflict.
#[test]
#[ignore = "machine-specific, run with --ignored"]
fn level_1_with_running_proot_child() {
    let (proot, rootfs) = match require_proot_and_rootfs() {
        Some(v) => v,
        None => return,
    };

    // Spawn a proot child that just sleeps. Mirrors what webwright's sidecar does.
    let mut child = StdCommand::new(&proot)
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
            "/tmp",
            "/bin/sleep",
            "5",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sleeper proot");

    // Give it a moment to actually be running.
    std::thread::sleep(Duration::from_millis(200));

    let result = try_pty_spawn_proot("L1 with-running-proot");

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        result.is_ok(),
        "PTY spawn failed while another proot child is running: {result:?}"
    );
}

/// Spawn 8 concurrent proot children (matches user's 8 parallel webwright invocations),
/// then PTY-spawn another. Tests whether FD/process-count saturation breaks PTY.
#[test]
#[ignore = "machine-specific, run with --ignored"]
fn level_2_with_eight_running_proot_children() {
    let (proot, rootfs) = match require_proot_and_rootfs() {
        Some(v) => v,
        None => return,
    };

    let mut kids = Vec::new();
    for i in 0..8 {
        let c = StdCommand::new(&proot)
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
                "/tmp",
                "/bin/sleep",
                "10",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn child {i}: {e}"));
        kids.push(c);
    }
    std::thread::sleep(Duration::from_millis(300));

    let result = try_pty_spawn_proot("L2 eight-running-proots");

    for mut c in kids {
        let _ = c.kill();
        let _ = c.wait();
    }

    assert!(result.is_ok(), "PTY spawn failed with 8 concurrent proots");
}

/// Run inside a multi-threaded tokio runtime (matches Pick) and try the PTY spawn.
#[test]
#[ignore = "machine-specific, run with --ignored"]
fn level_3_inside_tokio_runtime() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("tokio runtime");

    let result = rt.block_on(async {
        tokio::task::spawn_blocking(|| try_pty_spawn_proot("L3 tokio-rt")).await
    });
    assert!(result.is_ok(), "join failed: {result:?}");
    assert!(
        result.unwrap().is_ok(),
        "PTY spawn failed inside tokio runtime"
    );
}

/// Same as L3, but with a webwright sidecar (tokio::process::Command::new(proot))
/// running in another task. Mirrors Pick's actual pattern more closely.
#[test]
#[ignore = "machine-specific, run with --ignored"]
fn level_4_tokio_with_concurrent_tokio_proot_child() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("tokio runtime");

    let result = rt.block_on(async {
        let (proot, rootfs) = match require_proot_and_rootfs() {
            Some(v) => v,
            None => return Ok(()),
        };

        // Spawn the "sidecar" with tokio::process::Command (matches sidecar.rs)
        let sidecar = tokio::process::Command::new(&proot)
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
                "/tmp",
                "/bin/sleep",
                "5",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn();

        let mut sidecar = match sidecar {
            Ok(c) => c,
            Err(e) => return Err(format!("spawn sidecar: {e}")),
        };

        tokio::time::sleep(Duration::from_millis(200)).await;

        // Now try the PTY spawn from spawn_blocking (portable_pty is sync)
        let r = tokio::task::spawn_blocking(|| try_pty_spawn_proot("L4 tokio-sidecar+pty"))
            .await
            .map_err(|e| format!("join: {e}"))?;

        let _ = sidecar.kill().await;
        r
    });

    assert!(result.is_ok(), "L4 result: {result:?}");
}

/// With several open TCP listeners + lots of background tokio tasks (simulating
/// the LLM proxy server's FD footprint). No axum, just primitives.
#[test]
#[ignore = "machine-specific, run with --ignored"]
fn level_5_with_open_sockets_and_tasks() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("tokio runtime");

    let result = rt.block_on(async {
        // Bind a bunch of listeners to consume FDs and create network state.
        let mut listeners = Vec::new();
        for _ in 0..16 {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            listeners.push(l);
        }
        // Spawn a few accept loops so the runtime is actively scheduling I/O.
        let mut accept_handles = Vec::new();
        for l in &listeners {
            let local = l.local_addr().unwrap();
            let h = tokio::spawn(async move {
                let l = tokio::net::TcpListener::bind(local).await;
                if let Ok(l) = l {
                    let _ = l.accept().await;
                }
            });
            accept_handles.push(h);
        }
        // Also spawn a bunch of background sleeping tasks for scheduler pressure.
        let mut sleep_handles = Vec::new();
        for _ in 0..32 {
            sleep_handles.push(tokio::spawn(async {
                tokio::time::sleep(Duration::from_secs(30)).await;
            }));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;

        let r = tokio::task::spawn_blocking(|| try_pty_spawn_proot("L5 sockets+tasks"))
            .await
            .map_err(|e| format!("join: {e}"))?;

        for h in accept_handles {
            h.abort();
        }
        for h in sleep_handles {
            h.abort();
        }
        drop(listeners);
        r
    });

    assert!(result.is_ok(), "L5 result: {result:?}");
}

/// Maximum simulation: tokio runtime + 8 tokio-spawned proot sidecars + open sockets +
/// PTY spawn. Closest in-test approximation of Pick at the moment shell tab is clicked.
#[test]
#[ignore = "machine-specific, run with --ignored"]
fn level_6_full_pick_simulation() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(8)
        .enable_all()
        .build()
        .expect("tokio runtime");

    let result = rt.block_on(async {
        let (proot, rootfs) = match require_proot_and_rootfs() {
            Some(v) => v,
            None => return Ok(()),
        };

        // Open sockets
        let mut listeners = Vec::new();
        for _ in 0..16 {
            listeners.push(
                tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind"),
            );
        }

        // 8 concurrent tokio::process proot sidecars
        let mut sidecars = Vec::new();
        for i in 0..8 {
            let c = tokio::process::Command::new(&proot)
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
                    "/tmp",
                    "/bin/sleep",
                    "15",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .spawn()
                .unwrap_or_else(|e| panic!("spawn sidecar {i}: {e}"));
            sidecars.push(c);
        }

        tokio::time::sleep(Duration::from_millis(500)).await;

        let r = tokio::task::spawn_blocking(|| try_pty_spawn_proot("L6 full-sim"))
            .await
            .map_err(|e| format!("join: {e}"))?;

        for mut c in sidecars {
            let _ = c.kill().await;
        }
        drop(listeners);
        r
    });

    assert!(result.is_ok(), "L6 result: {result:?}");
}
