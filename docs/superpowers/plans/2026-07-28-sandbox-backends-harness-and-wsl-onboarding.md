# Sandbox Backends: Harness + Windows WSL Onboarding — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a sandbox-backend probe + test harness, gate the Settings Sandboxed/Native toggle on backend availability, and add a Windows "install WSL" onboarding banner with a guided installer; fix the WSL1 DNS bug that breaks unattended distro setup.

**Architecture:** One side-effect-free `probe`/`any_backend_available` routine in `pentest-platform` underpins three consumers: an ignored cargo integration harness, the Settings toggle gating, and a Windows install banner. `detect_backend` and the fail-closed execution path (issue #256) are unchanged. `setup_distro` is hardened so a fresh WSL1 import works without manual DNS fixes.

**Tech Stack:** Rust, `pentest-platform` (desktop feature), Dioxus 0.7 UI (`pentest-ui`), `pentest-core` settings, Windows `wsl.exe`/`dism`/PowerShell + `ShellExecuteW` for UAC.

## Global Constraints

- Sandbox execution must remain **fail-closed** (issue #256): a sandbox init/exec failure returns `Err`, never a silent host run. Do not add a host fallback.
- The Settings control stays **abstract**: "Sandboxed" vs "Native (host)". No backend picker in the product UI. `ShellMode` enum values (`Native`, `Proot`) are unchanged for serialization compatibility; `Proot` means "sandboxed".
- On Windows with no working backend, the user **cannot select Sandboxed** — the option is disabled with explanatory helper text.
- The install banner shows **only** on `target_os = "windows"` AND no backend available; it is dismissable, and dismissal persists. Once a backend is Working the banner never shows.
- Probe is **side-effect free**: it must NOT trigger `ensure_distro`/`download_proot`/image pulls. A backend whose prerequisites exist but whose rootfs/distro is not set up reports `Unavailable`, not `Working`.
- No auto-reboot; prompt the user. UAC elevation via a minimal helper invocation, not by elevating the whole app.
- CI: `cargo clippy --all-targets -- -D warnings` and `cargo fmt` must pass. Real-backend tests are `#[ignore]`d.
- Commits: conventional-commit format, no attribution/emoji/em-dash, no secrets/tenant names.

---

### Task 1: Backend probe + report types

**Files:**
- Create: `crates/platform/src/desktop/sandbox/probe.rs`
- Modify: `crates/platform/src/desktop/sandbox/mod.rs` (add `pub mod probe;`)
- Test: unit tests inside `probe.rs`

**Interfaces:**
- Consumes: `SandboxConfig`, `SandboxBackend` (from `sandbox/config.rs`); each executor's existing `is_available()` (`BwrapExecutor::is_available()`, `ProotExecutor::is_available(&cfg)`, `WslExecutor::is_available()`, `DockerExecutor::is_available()`), `WslExecutor::is_distro_imported()`, `WslExecutor::is_setup_complete()`.
- Produces:
  - `enum BackendStatus { Working { detail: String }, Broken { reason: String }, Unavailable { reason: String } }` (derive `Debug, Clone, PartialEq, Eq, serde::Serialize`)
  - `struct BackendReport { backend: SandboxBackend, status: BackendStatus }` (derive `Debug, Clone, serde::Serialize`)
  - `async fn probe_backend(cfg: &SandboxConfig, b: SandboxBackend) -> BackendReport`
  - `async fn probe_all(cfg: &SandboxConfig) -> Vec<BackendReport>`
  - `async fn any_backend_available(cfg: &SandboxConfig) -> bool`

- [ ] **Step 1: Write the failing test**

Add to `probe.rs`:

```rust
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
        let s = BackendStatus::Broken { reason: "no nested virt".into() };
        let j = serde_json::to_string(&s).unwrap();
        assert!(j.contains("Broken") && j.contains("no nested virt"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-platform --features desktop probe 2>&1 | tail`
Expected: FAIL — `probe_all`/`BackendStatus` not defined.

- [ ] **Step 3: Write minimal implementation**

```rust
//! Side-effect-free probing of sandbox backends for availability reporting.
//!
//! Unlike `detect_backend` (which SELECTS a backend to use and may download
//! proot), this only reports what each backend's state is WITHOUT importing or
//! downloading anything. Used by the Settings availability gate, the Windows
//! install banner, and the ignored test harness.

use super::config::{SandboxBackend, SandboxConfig};
use super::{bwrap, docker, proot, wsl};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum BackendStatus {
    /// Available and a smoke command succeeded (or is trivially usable).
    Working { detail: String },
    /// Prerequisites exist but the backend is not usable right now.
    Broken { reason: String },
    /// Not applicable/installed on this machine.
    Unavailable { reason: String },
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendReport {
    pub backend: SandboxBackend,
    pub status: BackendStatus,
}

/// Backends that could conceivably run on this target_os, in preference order.
fn os_backends() -> Vec<SandboxBackend> {
    #[cfg(target_os = "windows")]
    { vec![SandboxBackend::Wsl, SandboxBackend::Docker] }
    #[cfg(target_os = "linux")]
    { vec![SandboxBackend::Bwrap, SandboxBackend::Proot, SandboxBackend::Docker] }
    #[cfg(target_os = "macos")]
    { vec![SandboxBackend::Docker] }
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    { Vec::new() }
}

pub async fn probe_backend(cfg: &SandboxConfig, b: SandboxBackend) -> BackendReport {
    let status = match b {
        SandboxBackend::Bwrap => {
            if bwrap::BwrapExecutor::is_available().await {
                BackendStatus::Working { detail: "bwrap namespaces available".into() }
            } else {
                BackendStatus::Unavailable { reason: "bwrap not available (Linux-only / no namespaces)".into() }
            }
        }
        SandboxBackend::Proot => {
            if proot::ProotExecutor::is_available(cfg).await {
                BackendStatus::Working { detail: "proot binary present".into() }
            } else {
                BackendStatus::Unavailable { reason: "proot not present (not downloaded)".into() }
            }
        }
        SandboxBackend::Docker => {
            if docker::DockerExecutor::is_available().await {
                BackendStatus::Working { detail: "docker daemon reachable".into() }
            } else {
                BackendStatus::Unavailable { reason: "docker not installed or daemon not running".into() }
            }
        }
        SandboxBackend::Wsl => {
            if !wsl::WslExecutor::is_available().await {
                BackendStatus::Unavailable { reason: "WSL not installed (wsl.exe --status failed)".into() }
            } else {
                let exec = wsl::WslExecutor::new(cfg.clone());
                if !exec.is_distro_imported().await {
                    BackendStatus::Unavailable { reason: "WSL installed but distro not imported yet".into() }
                } else if !exec.is_setup_complete().await {
                    BackendStatus::Unavailable { reason: "WSL distro imported but not set up yet".into() }
                } else {
                    BackendStatus::Working { detail: "WSL distro ready".into() }
                }
            }
        }
    };
    BackendReport { backend: b, status }
}

pub async fn probe_all(cfg: &SandboxConfig) -> Vec<BackendReport> {
    let mut out = Vec::new();
    for b in os_backends() {
        out.push(probe_backend(cfg, b).await);
    }
    out
}

pub async fn any_backend_available(cfg: &SandboxConfig) -> bool {
    for r in probe_all(cfg).await {
        if matches!(r.status, BackendStatus::Working { .. }) {
            return true;
        }
    }
    false
}
```

Add `pub mod probe;` to `sandbox/mod.rs` beside the other `pub mod` lines.

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo test -p pentest-platform --features desktop probe 2>&1 | tail`
Expected: PASS (2 tests).

- [ ] **Step 5: Clippy + fmt + commit**

```bash
nix develop --command cargo clippy -p pentest-platform --features desktop -- -D warnings
nix develop --command cargo fmt --all
git add crates/platform/src/desktop/sandbox/probe.rs crates/platform/src/desktop/sandbox/mod.rs
git commit -m "feat(sandbox): side-effect-free backend probe + report"
```

---

### Task 2: Ignored integration harness for real backends

**Files:**
- Create: `crates/platform/tests/sandbox_backends.rs`

**Interfaces:**
- Consumes: `pentest_platform::desktop::sandbox::probe::{probe_all, any_backend_available, BackendStatus}`, `SandboxConfig`. Requires these to be re-exported: ensure `sandbox` module path is reachable as `pentest_platform::desktop::sandbox` (it is `pub mod sandbox`).

- [ ] **Step 1: Write the ignored harness tests**

```rust
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
    let working = reports.iter().any(|r| matches!(r.status, BackendStatus::Working { .. }));
    assert!(
        working,
        "no Working backend; provision one (WSL distro / bwrap / docker) before running this test. Reports: {reports:?}"
    );
}
```

- [ ] **Step 2: Verify it compiles and the tests are collected but skipped by default**

Run: `nix develop --command cargo test -p pentest-platform --features desktop --test sandbox_backends 2>&1 | tail`
Expected: compiles; `2 ignored`.

- [ ] **Step 3: (Optional local) run ignored on this Linux host**

Run: `nix develop --command cargo test -p pentest-platform --features desktop --test sandbox_backends -- --ignored 2>&1 | tail`
Expected: `probe_all_reports_every_os_backend` prints bwrap/proot/docker verdicts. `at_least_one_backend...` passes iff a backend is set up locally.

- [ ] **Step 4: Commit**

```bash
git add crates/platform/tests/sandbox_backends.rs
git commit -m "test(sandbox): ignored real-backend probe harness"
```

---

### Task 3: Harden `setup_distro` (WSL1 DNS + pacman overwrite)

**Files:**
- Modify: `crates/platform/src/desktop/sandbox/wsl.rs` (the `setup_script` string in `setup_distro`)

**Interfaces:**
- No signature change. Behavior change only.

- [ ] **Step 1: Write a unit test asserting the setup script content**

Add to `wsl.rs` `#[cfg(test)] mod tests`:

```rust
#[test]
fn setup_script_forces_working_dns_and_overwrite() {
    // The embedded setup script must (a) disable WSL's resolv.conf regeneration,
    // (b) pin a working nameserver unconditionally, and (c) use --overwrite so
    // the ArchWSL gcc-libs file conflict does not abort the transaction.
    let script = super::WSL_SETUP_SCRIPT;
    assert!(script.contains("generateResolvConf = false"));
    assert!(script.contains("nameserver 8.8.8.8"));
    assert!(script.contains("--overwrite"));
    // resolv.conf must be written unconditionally, not guarded by "if missing".
    assert!(!script.contains("if [ ! -f /etc/resolv.conf ]"));
}
```

To make the script testable, extract the current inline `setup_script` literal in `setup_distro` into a module-level `pub(crate) const WSL_SETUP_SCRIPT: &str = r#"..."#;` and reference it.

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-platform --features desktop setup_script 2>&1 | tail`
Expected: FAIL (current script guards resolv.conf and lacks wsl.conf/`--overwrite`).

- [ ] **Step 3: Rewrite `WSL_SETUP_SCRIPT`**

Replace the resolv.conf block and pacman calls. New script (keep mirror/keyring/BlackArch sections):

```bash
#!/bin/bash
set -e

# WSL1 auto-generates a resolv.conf pointing at an unreachable nameserver
# (it mirrors NetBird-polluted Windows DNS), so ALWAYS take control of DNS.
cat > /etc/wsl.conf << 'WSLCONF'
[network]
generateResolvConf = false
WSLCONF
rm -f /etc/resolv.conf
cat > /etc/resolv.conf << 'RESOLV'
nameserver 8.8.8.8
nameserver 1.1.1.1
RESOLV

# ... (unchanged mirrorlist, pacman.conf CheckSpace/DownloadUser/DisableSandbox,
#      SigLevel=Never, pacman-key init/populate, [blackarch] repo append) ...

# --overwrite '*' clears the ArchWSL gcc-libs / libstdc++ file conflict.
pacman -Syu --noconfirm --overwrite '*' 2>&1 || true
pacman -Sy --noconfirm 2>&1 || true

touch /root/.pentest-setup-complete
echo "WSL distro setup complete"
```

Keep `setup_distro` writing this const to the temp file and executing it as before.

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo test -p pentest-platform --features desktop setup_script 2>&1 | tail`
Expected: PASS.

- [ ] **Step 5: Clippy + commit**

```bash
nix develop --command cargo clippy -p pentest-platform --features desktop -- -D warnings
git add crates/platform/src/desktop/sandbox/wsl.rs
git commit -m "fix(sandbox): WSL1 setup forces working DNS and pacman --overwrite"
```

---

### Task 4: Persist banner-dismissal in settings

**Files:**
- Modify: `crates/core/src/config.rs` (the `AppSettings` struct)
- Test: unit test in `config.rs`

**Interfaces:**
- Produces: `AppSettings.wsl_banner_dismissed: bool` (serde default false).

- [ ] **Step 1: Write the failing test**

Add to `config.rs` tests:

```rust
#[test]
fn app_settings_defaults_wsl_banner_not_dismissed() {
    let s = AppSettings::default();
    assert!(!s.wsl_banner_dismissed);
}

#[test]
fn app_settings_deserializes_without_wsl_banner_field() {
    // Older settings.json lacks the field; must default, not fail.
    let s: AppSettings = serde_json::from_str("{}").unwrap();
    assert!(!s.wsl_banner_dismissed);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-core wsl_banner 2>&1 | tail`
Expected: FAIL — field missing.

- [ ] **Step 3: Add the field**

In `AppSettings`:

```rust
    /// Whether the user dismissed the Windows "install WSL for better scanning"
    /// banner. Re-shown logic still hides it once a backend is available.
    #[serde(default)]
    pub wsl_banner_dismissed: bool,
```

Ensure `AppSettings` `Default` derive (or manual impl) covers it (serde default handles deserialization; add to any manual `Default`).

- [ ] **Step 4: Run test to verify it passes**

Run: `nix develop --command cargo test -p pentest-core wsl_banner 2>&1 | tail`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/core/src/config.rs
git commit -m "feat(settings): persist WSL install banner dismissal"
```

---

### Task 5: Windows guided WSL installer (platform)

**Files:**
- Create: `crates/platform/src/desktop/sandbox/wsl_install.rs`
- Modify: `crates/platform/src/desktop/sandbox/mod.rs` (`pub mod wsl_install;`)

**Interfaces:**
- Produces:
  - `enum InstallStep { EnableFeatures, UpdateKernel, RebootRequired, Done }`
  - `enum InstallOutcome { Completed, RebootRequired, NeedsElevation, Failed(String) }` (derive `Debug, Clone, PartialEq, Serialize`)
  - `async fn is_elevated() -> bool` (Windows: check process token elevation; non-Windows: `false`)
  - `async fn run_guided_install() -> InstallOutcome` — enables `Microsoft-Windows-Subsystem-Linux` + `VirtualMachinePlatform` (via `dism`/PowerShell args constructed programmatically) then `wsl --update`; returns `RebootRequired` on success, `NeedsElevation` if not elevated, `Failed` otherwise.
  - `fn relaunch_elevated() -> Result<(), String>` — Windows `ShellExecuteW` `runas` of a minimal elevated helper command that runs the same steps and writes a result marker file; non-Windows returns `Err("elevation only on Windows")`.

- [ ] **Step 1: Write unit tests for the non-OS logic**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn non_windows_install_is_not_applicable() {
        #[cfg(not(target_os = "windows"))]
        {
            assert!(!is_elevated().await);
            assert!(matches!(run_guided_install().await, InstallOutcome::Failed(_)));
            assert!(relaunch_elevated().is_err());
        }
    }

    #[test]
    fn outcome_serializes() {
        let o = InstallOutcome::RebootRequired;
        assert!(serde_json::to_string(&o).unwrap().contains("RebootRequired"));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `nix develop --command cargo test -p pentest-platform --features desktop wsl_install 2>&1 | tail`
Expected: FAIL — module not defined.

- [ ] **Step 3: Implement `wsl_install.rs`**

Implement the interface above. Windows specifics:
- `is_elevated`: use `windows`/`winapi` token check, or shell `net session` exit code as a fallback; prefer a token API already in the dependency tree (check `windows` crate availability; if absent, run `whoami /groups` and look for the elevation SID, or shell PowerShell `([Security.Principal.WindowsPrincipal]...).IsInRole(...)`).
- `run_guided_install`: build `Command::new("dism.exe")` (or `powershell.exe -Command Enable-WindowsOptionalFeature ...`) with args as a `Vec`, run for both features with `-NoRestart`, then `Command::new("wsl.exe").arg("--update")`. Map success → `RebootRequired`.
- `relaunch_elevated`: `ShellExecuteW(null, "runas", "powershell.exe", args_to_run_install_and_write_marker, ...)`. The elevated child writes `%LOCALAPPDATA%\pentest-sandbox\.wsl-install-result` which the caller polls.
- All non-Windows arms: return the not-applicable variants so the crate builds on Linux/macOS.

Guard OS-specific bodies with `#[cfg(target_os = "windows")]` / `#[cfg(not(...))]`.

- [ ] **Step 4: Run tests + build on Linux**

Run: `nix develop --command cargo test -p pentest-platform --features desktop wsl_install 2>&1 | tail`
Expected: PASS (non-windows arms exercised).

- [ ] **Step 5: Clippy + commit**

```bash
nix develop --command cargo clippy -p pentest-platform --features desktop -- -D warnings
git add crates/platform/src/desktop/sandbox/wsl_install.rs crates/platform/src/desktop/sandbox/mod.rs
git commit -m "feat(sandbox): Windows guided WSL installer (features + kernel + UAC)"
```

---

### Task 6: Surface availability to the UI

**Files:**
- Modify: `crates/ui/src/connector_app.rs`
- Modify: `crates/ui/src/lib.rs` if a shared signal/type export is needed

**Interfaces:**
- Consumes: `pentest_platform::desktop::sandbox::probe::any_backend_available` (desktop) — but `pentest-ui` is cross-target. Add a thin indirection: a `fn sandbox_available() -> bool` the app layer can call, provided via `ConnectorAppConfig` like `set_sandbox`, OR a `use_resource` that calls the platform probe only under `#[cfg(feature = "desktop")]` and returns `true` elsewhere (mobile always has its sandbox path). Prefer a `ConnectorAppConfig` field `sandbox_available: Option<fn() -> bool>` set by the desktop app, mirroring `set_sandbox`.
- Produces: a reactive `Signal<bool>` `sandbox_available` in `connector_app` that children (settings toggle, banner) read.

- [ ] **Step 1: Add the config hook**

In `ConnectorAppConfig` add:

```rust
    /// Returns whether a sandbox backend is currently available. `None` (mobile)
    /// is treated as `true` — mobile always has its proot path.
    pub sandbox_available: Option<fn() -> bool>,
```

Desktop `DESKTOP_CONFIG` sets `sandbox_available: Some(pentest_platform::sandbox_available_blocking)` — add a small blocking wrapper in `pentest-platform` that runs `any_backend_available` on a tokio runtime handle (or caches the last async probe). Mobile/other configs set `None`.

- [ ] **Step 2: Compute the signal in `connector_app`**

```rust
let sandbox_available = use_signal(|| cfg.sandbox_available.map(|f| f()).unwrap_or(true));
```

(Later tasks read this. Keep it a plain signal; a background refresh is optional and out of scope.)

- [ ] **Step 3: Build**

Run: `nix develop --command cargo check -p pentest-desktop 2>&1 | tail`
Expected: compiles.

- [ ] **Step 4: Commit**

```bash
git add crates/ui/src/connector_app.rs crates/ui/src/lib.rs crates/platform/src/lib.rs apps/desktop/src/main.rs
git commit -m "feat(ui): surface sandbox backend availability to the app"
```

---

### Task 7: Gate the Settings Sandboxed toggle

**Files:**
- Modify: `crates/ui/src/components/settings_page.rs`
- Modify: `crates/ui/src/connector_app.rs` (pass `sandbox_available` into the settings page props)

**Interfaces:**
- Consumes: `sandbox_available: bool` signal from Task 6; existing `settings_shell_mode: ShellMode` + `on_shell_mode_change` props.

- [ ] **Step 1: Add `sandbox_available` to the settings page props and gate the control**

- Add `sandbox_available: bool` to the settings page props struct.
- In the Shell Mode card: when `!sandbox_available`, render the "Sandboxed" option disabled (add a `disabled` attribute + a muted class), and show helper text: `"No sandbox available — install WSL for isolated scanning"`. When disabled, force the selection to Native visually and ignore clicks on Sandboxed.
- When `sandbox_available`, behavior is unchanged.

- [ ] **Step 2: Guard the change handler**

In `on_shell_mode_change` wiring in `connector_app.rs`, ignore a request to switch to `ShellMode::Proot` when `!sandbox_available()` (defense in depth; the UI already disables it).

- [ ] **Step 3: Build + clippy**

Run: `nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings 2>&1 | tail`
Expected: no warnings.

- [ ] **Step 4: Commit**

```bash
git add crates/ui/src/components/settings_page.rs crates/ui/src/connector_app.rs
git commit -m "feat(ui): gate Sandboxed shell mode on backend availability"
```

---

### Task 8: Windows install banner component

**Files:**
- Create: `crates/ui/src/components/wsl_install_banner.rs`
- Modify: `crates/ui/src/components/mod.rs` (declare module) — confirm the components module path
- Modify: `crates/ui/src/connector_app.rs` (render banner conditionally)
- Modify: a CSS file under `crates/ui/src/components/css/` or `styles/` for banner styling (Sage tokens)

**Interfaces:**
- Consumes: `sandbox_available: bool`, `wsl_banner_dismissed` from settings, `pentest_core::settings::{load_settings,save_settings}`, and the install flow via `ConnectorAppConfig` hooks: add `run_wsl_install: Option<fn() -> ()>` OR call an async spawn that invokes `pentest_platform` install (desktop-only) — mirror the `sandbox_available` indirection so `pentest-ui` stays cross-target.
- Produces: `#[component] pub fn WslInstallBanner(props: WslInstallBannerProps) -> Element`.

- [ ] **Step 1: Build the banner component**

Props: `visible: bool` (computed by parent = `cfg(windows) && !sandbox_available && !dismissed`), `on_dismiss: EventHandler<()>`, `on_install: EventHandler<()>`.

Render (Sage-styled): title "Install WSL for better scanning", body copy from the spec, buttons: **Install** (fires `on_install`), **How** (opens docs URL via `pentest_core::matrix::open_url_in_browser`), **Dismiss** (fires `on_dismiss`). During install show a progress state and, on `RebootRequired`, a "Restart required" message with a Restart button.

- [ ] **Step 2: Wire into `connector_app`**

- Compute `let show_banner = cfg!(target_os = "windows") && !sandbox_available() && !settings.read().wsl_banner_dismissed;`
- Render `WslInstallBanner` at the top of the easy-mode home + workspace shells when `show_banner`.
- `on_dismiss`: set `wsl_banner_dismissed = true` and `save_settings`.
- `on_install`: spawn the platform install (desktop hook); on `NeedsElevation`, call `relaunch_elevated`; on `RebootRequired`, show the restart affordance.

- [ ] **Step 3: Build + clippy (desktop) and confirm mobile still builds**

Run:
```
nix develop --command cargo clippy -p pentest-ui --features "desktop,connector" -- -D warnings
nix develop --command cargo check -p pentest-desktop
```
Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add crates/ui/src/components/wsl_install_banner.rs crates/ui/src/components/mod.rs crates/ui/src/connector_app.rs crates/ui/src/components/css/*
git commit -m "feat(ui): Windows install-WSL banner with guided install"
```

---

### Task 9: Full verification pass

**Files:** none (verification only)

- [ ] **Step 1: Workspace check + clippy + fmt**

```bash
nix develop --command cargo check --all-targets
nix develop --command cargo clippy --all-targets -- -D warnings
nix develop --command cargo fmt --all --check
```
Expected: all clean.

- [ ] **Step 2: Unit + lib tests**

```bash
nix develop --command cargo test --lib --bins
```
Expected: pass (probe unit tests, setup_script test, settings test, wsl_install non-windows tests).

- [ ] **Step 3: Confirm ignored harness compiles**

```bash
nix develop --command cargo test -p pentest-platform --features desktop --test sandbox_backends 2>&1 | tail
```
Expected: compiles; ignored.

- [ ] **Step 4: On the Windows box (manual):** relaunch Pick, confirm (a) with WSL present the banner does NOT show and Sandboxed is selectable and scans run in WSL; (b) simulate no-backend (rename distro) → banner shows, Sandboxed disabled, install flow reaches the reboot prompt.
