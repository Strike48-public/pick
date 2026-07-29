//! Real-backend sandbox harness. `#[ignore]`d because it touches the OS
//! (wsl.exe / bwrap / docker) and possibly the network. Run explicitly:
//!   cargo test -p pentest-platform --features desktop -- --ignored sandbox
//! CI runs this in per-OS matrix jobs, each asserting the backend(s) it
//! provisioned are Working and tolerating the rest as Unavailable.

use pentest_platform::desktop::sandbox::config::SandboxConfig;
use pentest_platform::desktop::sandbox::probe::{any_backend_available, probe_all, BackendStatus};
use pentest_platform::desktop::sandbox::SandboxManager;
use std::time::Duration;

#[tokio::test]
#[ignore = "touches OS backends; run with --ignored"]
async fn probe_all_reports_every_os_backend() {
    let reports = probe_all(&SandboxConfig::default()).await;
    assert!(!reports.is_empty());
    for r in &reports {
        // Print so a human/CI log can see the per-backend verdict.
        println!("{:?} -> {:?}", r.backend, r.status);
    }
}

#[tokio::test]
#[ignore = "requires a provisioned backend; run with --ignored on a set-up host"]
async fn at_least_one_backend_is_working_on_a_provisioned_host() {
    let reports = probe_all(&SandboxConfig::default()).await;
    let working = reports
        .iter()
        .any(|r| matches!(r.status, BackendStatus::Working { .. }));
    assert!(
        working,
        "no Working backend; provision one (WSL distro / bwrap / docker) before running this test. Reports: {reports:?}"
    );
}

#[tokio::test]
#[ignore = "runs a real command in a provisioned sandbox; run with --ignored on a set-up host"]
async fn working_backend_executes_and_reports_host_arch() {
    let cfg = SandboxConfig::default();

    // No-op when nothing is provisioned, so this is safe to run anywhere. The
    // check is import-only (see probe.rs) — it never downloads or imports.
    if !any_backend_available(&cfg).await {
        eprintln!("no working backend on this host; skipping exec-sanity check");
        return;
    }

    // First run may build the image / import the distro — allow generous time.
    let mgr = SandboxManager::new(cfg)
        .await
        .expect("build sandbox manager");
    let out = mgr
        .execute("uname -m", Duration::from_secs(900), None)
        .await
        .expect("a Working sandbox must execute a command, not Exec-format-error");

    // The guest arch must equal the host arch. A wrong-arch rootfs (e.g. the old
    // x86_64 image on arm64) fails here: the command aborts with `Exec format
    // error`, leaving stdout empty. Docker/WSL/bwrap/proot all run a guest of the
    // host arch (Docker on Apple Silicon runs arm64 natively; on Intel, amd64 ==
    // x86_64, which `uname -m` reports as `x86_64`).
    let reported = out.stdout.trim();
    assert_eq!(
        reported,
        std::env::consts::ARCH,
        "sandbox `uname -m` should equal host arch {}; got stdout={:?} stderr={:?}",
        std::env::consts::ARCH,
        out.stdout,
        out.stderr
    );
}
