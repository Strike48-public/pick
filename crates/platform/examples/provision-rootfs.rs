//! Provision a desktop sandbox rootfs with the REAL first-boot code path
//! (`RootfsManager::ensure_rootfs`): pinned download, tar extraction,
//! keyring init, BlackArch strap, mirrors, initial system update, tool caps.
//!
//! Not committed — a local verification harness for the #625 bootstrap cut
//! bump. Run with:
//!   PICK_PROVISION_DIR=/tmp/pick-prov-test cargo run -p pentest-platform --example provision-rootfs

use pentest_platform::desktop::sandbox::config::SandboxConfig;

fn init_logging() {
    // tracing-subscriber is a dev-dependency of this crate so the harness
    // can surface ensure_rootfs's internal info/warn tracing (the pacman
    // steps tolerate failures by design — without logs they are invisible).
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}
use pentest_platform::desktop::sandbox::rootfs::RootfsManager;

#[tokio::main]
async fn main() {
    init_logging();
    let data_dir = std::path::PathBuf::from(
        std::env::var("PICK_PROVISION_DIR").expect("set PICK_PROVISION_DIR to a fresh dir"),
    );
    println!("provisioning rootfs in {}", data_dir.display());
    let mgr = RootfsManager::new(SandboxConfig {
        data_dir,
        ..Default::default()
    });
    let rootfs = mgr
        .ensure_rootfs()
        .await
        .expect("ensure_rootfs failed — see tracing output above");
    println!("ROOTFS READY at {}", rootfs.display());
}
