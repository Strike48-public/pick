//! Host facts for the diagnostics bundle (pick#476).
//!
//! Everything here is read-only and cheap: the static `sysinfo` OS queries
//! (no process refresh, no hostname), the sandbox switches, a peek at the
//! sandbox backend that never initializes the manager, and the rootfs version
//! marker.

use pentest_core::diagnostics::{PlatformFacts, SandboxFacts};
use sysinfo::System;

use super::command::{is_sandbox_disabled_by_env, is_sandbox_enabled};
use super::sandbox::{config::SandboxConfig, current_backend};

/// Marker the rootfs manager writes after a successful install.
const ROOTFS_VERSION_MARKER: &str = ".rootfs_version";

/// Longest rootfs version kept, so a damaged marker cannot pad the bundle.
const MAX_ROOTFS_VERSION_CHARS: usize = 64;

pub fn diagnostic_facts() -> PlatformFacts {
    PlatformFacts {
        os_name: System::name(),
        os_version: System::long_os_version().or_else(System::os_version),
        kernel_version: System::kernel_version(),
        sandbox: SandboxFacts {
            enabled: is_sandbox_enabled(),
            disabled_by_env: is_sandbox_disabled_by_env(),
            backend: current_backend().map(|b| b.to_string()),
            rootfs_version: rootfs_version(),
        },
    }
}

fn rootfs_version() -> Option<String> {
    let marker = SandboxConfig::default()
        .rootfs_dir()
        .join(ROOTFS_VERSION_MARKER);
    let version = std::fs::read_to_string(marker).ok()?;
    let version: String = version
        .trim()
        .chars()
        .take(MAX_ROOTFS_VERSION_CHARS)
        .collect();
    (!version.is_empty()).then(|| pentest_core::provenance::redact(&version))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facts_report_the_host_os() {
        let facts = diagnostic_facts();
        assert!(facts.os_name.is_some(), "{facts:?}");
        assert!(facts.kernel_version.is_some(), "{facts:?}");
    }
}
