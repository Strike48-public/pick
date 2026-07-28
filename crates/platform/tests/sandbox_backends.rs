//! Real-backend sandbox harness. `#[ignore]`d because it touches the OS
//! (wsl.exe / bwrap / docker) and possibly the network. Run explicitly:
//!   cargo test -p pentest-platform --features desktop -- --ignored sandbox
//! CI runs this in per-OS matrix jobs, each asserting the backend(s) it
//! provisioned are Working and tolerating the rest as Unavailable.

use pentest_platform::desktop::sandbox::config::SandboxConfig;
use pentest_platform::desktop::sandbox::probe::{probe_all, BackendStatus};

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
