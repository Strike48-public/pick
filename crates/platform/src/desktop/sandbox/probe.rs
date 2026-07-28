//! Side-effect-free probing of sandbox backends for availability reporting.
//!
//! Unlike `detect_backend` (which SELECTS a backend to use and may download
//! proot), this only reports what each backend's state is WITHOUT importing or
//! downloading anything. Used by the Settings availability gate, the Windows
//! install banner, and the ignored test harness.

use super::config::{SandboxBackend, SandboxConfig};
use super::{bwrap, docker, proot, wsl};
use serde::Serialize;

/// The state of a single sandbox backend on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum BackendStatus {
    /// Available and a smoke command succeeded (or is trivially usable).
    Working { detail: String },
    /// Prerequisites exist but the backend is not usable right now.
    Broken { reason: String },
    /// Not applicable/installed on this machine.
    Unavailable { reason: String },
}

/// A backend paired with its probed status.
#[derive(Debug, Clone, Serialize)]
pub struct BackendReport {
    pub backend: SandboxBackend,
    pub status: BackendStatus,
}

/// Backends that could conceivably run on this target_os, in preference order.
fn os_backends() -> Vec<SandboxBackend> {
    #[cfg(target_os = "windows")]
    {
        vec![SandboxBackend::Wsl, SandboxBackend::Docker]
    }
    #[cfg(target_os = "linux")]
    {
        vec![
            SandboxBackend::Bwrap,
            SandboxBackend::Proot,
            SandboxBackend::Docker,
        ]
    }
    #[cfg(target_os = "macos")]
    {
        vec![SandboxBackend::Docker]
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    {
        Vec::new()
    }
}

/// Probe a single backend WITHOUT importing/downloading anything heavy:
/// availability check only. A backend whose prerequisites exist but whose
/// rootfs/distro is not yet set up reports `Unavailable` (probing must never
/// trigger `ensure_distro`/`download_proot`).
pub async fn probe_backend(cfg: &SandboxConfig, b: SandboxBackend) -> BackendReport {
    let status = match b {
        SandboxBackend::Bwrap => {
            if bwrap::BwrapExecutor::is_available().await {
                BackendStatus::Working {
                    detail: "bwrap namespaces available".into(),
                }
            } else {
                BackendStatus::Unavailable {
                    reason: "bwrap not available (Linux-only / no namespaces)".into(),
                }
            }
        }
        SandboxBackend::Proot => {
            if proot::ProotExecutor::is_available(cfg).await {
                BackendStatus::Working {
                    detail: "proot binary present".into(),
                }
            } else {
                BackendStatus::Unavailable {
                    reason: "proot not present (not downloaded)".into(),
                }
            }
        }
        SandboxBackend::Docker => {
            if docker::DockerExecutor::is_available().await {
                BackendStatus::Working {
                    detail: "docker daemon reachable".into(),
                }
            } else {
                BackendStatus::Unavailable {
                    reason: "docker not installed or daemon not running".into(),
                }
            }
        }
        SandboxBackend::Wsl => {
            if !wsl::WslExecutor::is_available().await {
                BackendStatus::Unavailable {
                    reason: "WSL not installed (wsl.exe --status failed)".into(),
                }
            } else {
                let exec = wsl::WslExecutor::new(cfg.clone());
                if !exec.is_distro_imported().await {
                    BackendStatus::Unavailable {
                        reason: "WSL installed but distro not imported yet".into(),
                    }
                } else if !exec.is_setup_complete().await {
                    BackendStatus::Unavailable {
                        reason: "WSL distro imported but not set up yet".into(),
                    }
                } else {
                    BackendStatus::Working {
                        detail: "WSL distro ready".into(),
                    }
                }
            }
        }
    };
    BackendReport { backend: b, status }
}

/// Probe every backend valid for this target_os. Skips (reports `Unavailable`)
/// backends that can't run here; never errors for "not available".
pub async fn probe_all(cfg: &SandboxConfig) -> Vec<BackendReport> {
    let mut out = Vec::new();
    for b in os_backends() {
        out.push(probe_backend(cfg, b).await);
    }
    out
}

/// True iff at least one backend is `Working`. Drives the Settings toggle
/// gating and the Windows install banner. Cheap and side-effect free.
pub async fn any_backend_available(cfg: &SandboxConfig) -> bool {
    for r in probe_all(cfg).await {
        if matches!(r.status, BackendStatus::Working { .. }) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::desktop::sandbox::config::SandboxConfig;

    #[tokio::test]
    async fn probe_all_returns_a_report_per_os_backend_and_never_panics() {
        let cfg = SandboxConfig::default();
        let reports = probe_all(&cfg).await;
        assert!(!reports.is_empty(), "must probe at least one backend");
        // Every report has a concrete status; unavailable backends are reported,
        // not panicked on.
        for r in &reports {
            match &r.status {
                BackendStatus::Working { detail } => assert!(!detail.is_empty()),
                BackendStatus::Broken { reason } => assert!(!reason.is_empty()),
                BackendStatus::Unavailable { reason } => assert!(!reason.is_empty()),
            }
        }
    }

    #[test]
    fn status_serializes_to_tagged_json() {
        let s = BackendStatus::Broken {
            reason: "no nested virt".into(),
        };
        let j = serde_json::to_string(&s).unwrap();
        assert!(j.contains("Broken") && j.contains("no nested virt"));
    }
}
