# Sandbox Backends: Test Harness + Windows WSL Onboarding — Design

**Date:** 2026-07-28
**Status:** Approved (design); ready for implementation plan
**Branch:** `feat/easy-mode-phase1` (or a fresh `feat/sandbox-onboarding` off it)

## Problem

Pick executes pentest tools (`nmap`, etc.) inside a sandboxed BlackArch Linux
environment. The backend is chosen per-platform by
`crates/platform/src/desktop/sandbox/mod.rs::detect_backend`:

- **Linux:** bwrap (preferred) → proot → docker
- **macOS:** docker
- **Windows:** WSL2 → (WSL1 fallback on no nested-virt) → docker

Two gaps surfaced while running Pick on a Windows VM:

1. **No coverage** of the backend-selection + execution paths. WSL1 vs WSL2
   selection, proot vs bwrap fallback, and the "no backend" fail-closed path
   are all untested, so regressions ship silently. (The WSL1 fallback and the
   DNS-in-WSL1 bug below were both found by hand, not by a test.)
2. **No onboarding.** On Windows with no WSL installed, `detect_backend`
   returns `NoBackendAvailable`, tool execution fails closed (issue #256), and
   the agent silently degrades to Pick's native `port_scan`. The user is given
   no explanation and no path to fix it. Installing WSL by hand today required:
   enabling two Windows optional features, `wsl --update`, importing a distro,
   working around no-nested-virt (WSL1), and fixing broken WSL1 DNS.

## Goals

- A **test harness** that exercises every sandbox backend the current machine
  supports, running a real command through each, and cleanly **skips + reports**
  backends the machine can't run (no single machine has all of
  WSL1+WSL2+proot+bwrap+docker).
- A Settings **Sandboxed vs Native** toggle that stays abstract (no backend
  picker); Pick auto-detects the backend. On Windows with no backend, the user
  **cannot select Sandboxed** — it is disabled with an explanation.
- A dismissable **"install WSL for better scanning"** banner on Windows when no
  sandbox backend is available, with a **guided installer** that automates what
  it can (UAC-elevated) and instructs the rest (reboot, nested-virt caveats).
- Fix the **WSL1 DNS bug** in `setup_distro` so a fresh import works unattended.

## Non-Goals

- No explicit backend picker in the product UI (testing forces backends via the
  harness / env, not the UI).
- No attempt to enable nested virtualization from inside the guest (impossible);
  WSL1 is the documented fallback.
- No auto-reboot without user consent.

## Architecture

Three coupled components, all keyed off one detect/probe routine.

### Component 1: Backend probe + report (core of everything)

Add a structured probe to `crates/platform/src/desktop/sandbox/`:

```rust
// sandbox/probe.rs
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum BackendStatus {
    /// Backend is available and a smoke command ran successfully.
    Working { detail: String },      // e.g. "WSL1 distro pentest-blackarch: uname ok"
    /// Backend's prerequisites exist but a smoke command failed.
    Broken { reason: String },       // e.g. "WSL2 import: HCS_E_HYPERV_NOT_INSTALLED"
    /// Backend is not applicable/installed on this machine.
    Unavailable { reason: String },  // e.g. "bwrap: Linux-only" / "wsl.exe --status failed"
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendReport {
    pub backend: SandboxBackend,     // Bwrap | Proot | Wsl | Docker
    pub status: BackendStatus,
}

/// Probe a single backend WITHOUT importing/downloading anything heavy:
/// availability check + (if available and cheap) a smoke command through it.
pub async fn probe_backend(cfg: &SandboxConfig, b: SandboxBackend) -> BackendReport;

/// Probe every backend valid for this target_os. Skips (Unavailable) the ones
/// that can't run here; never errors for "not available".
pub async fn probe_all(cfg: &SandboxConfig) -> Vec<BackendReport>;

/// True iff at least one backend is Working. Drives Settings toggle gating and
/// the Windows install banner.
pub async fn any_backend_available(cfg: &SandboxConfig) -> bool;
```

Notes:

- `probe_backend` reuses each executor's existing `is_available()` and, for a
  *already-imported/ready* backend, runs a cheap smoke command (`id -u` — no
  network). It must NOT trigger the heavy `ensure_distro`/`download_proot`
  paths; probing is read-only. If a backend is available but its rootfs/distro
  is not yet set up, report `Unavailable { reason: "not set up yet" }` rather
  than downloading during a probe.
- `any_backend_available` is what the UI calls; it is cheap and side-effect free.

### Component 2: Settings — abstract Sandboxed vs Native, gated

Current model (`crates/core/src/config.rs`): `ShellMode { Native, Proot }`
(default `Proot`). "Proot" is a historical misnomer — it means "run sandboxed",
and `detect_backend` picks the real backend. Keep the enum values for
serialization compatibility but treat the toggle as **Sandboxed (`Proot`) vs
Native**.

- The Settings shell-mode control (`components/settings_page.rs`) shows a
  two-way toggle: **Sandboxed** / **Native (host)**.
- **Gating:** when `any_backend_available()` is false, the **Sandboxed** option
  is disabled (greyed) with helper text: *"No sandbox available — install WSL
  for isolated scanning"* linking to the banner/installer. The user cannot
  select Sandboxed with no backend.
- If Sandboxed was already selected and the backend later disappears, execution
  **fails closed** (unchanged issue-#256 behavior in `command.rs`) and the
  banner appears. We do NOT auto-fallback to Native.

### Component 3: Windows install banner + guided installer

- **Trigger:** `target_os = "windows"` AND `any_backend_available() == false`.
  Dismissable; dismissal persisted in `AppSettings` (e.g.
  `wsl_banner_dismissed: bool`) so it doesn't nag. Re-evaluated each launch —
  once a backend is Working, the banner never shows again regardless of the
  dismiss flag.
- **Copy:** "Install WSL for better scanning — Pick runs security tools like
  nmap inside an isolated Linux sandbox. On Windows that needs WSL. [Install]
  [How] [Dismiss]".
- **Guided installer** (new `crates/platform/src/desktop/sandbox/wsl_install.rs`):
  1. **Check elevation.** If not elevated, relaunch the install step elevated
     via `ShellExecuteW`/`runas` (UAC prompt). The elevated helper does the
     feature-enable + `wsl --update` and writes a result marker the main process
     polls.
  2. **Enable features:** `Enable-WindowsOptionalFeature -Online -NoRestart` for
     `Microsoft-Windows-Subsystem-Linux` and `VirtualMachinePlatform` (via a
     bundled `dism`/PowerShell invocation, not a shelled script string —
     construct args programmatically).
  3. **`wsl --update`** to install the kernel (Store WSL).
  4. **Prompt reboot** with a Restart button (the features require it); do not
     auto-reboot.
  5. After reboot + next launch, Pick's existing `ensure_distro` imports
     `pentest-blackarch`. If WSL2 import fails with `HCS_E_HYPERV_NOT_INSTALLED`
     (VM, no nested virt), the existing WSL1 fallback (`wsl.rs:135`) handles it.
- **Progress + honesty:** show each step's status; when a step needs a reboot or
  can't be automated (e.g. nested virt for WSL2), say so explicitly. This is the
  "run what we can, instruct the rest" contract.

### Fold-in fix: WSL1 DNS in `setup_distro`

`crates/platform/src/desktop/sandbox/wsl.rs::setup_distro` currently writes
`/etc/resolv.conf` only if missing/empty. On WSL1 the auto-generated
`resolv.conf` exists but points at an unreachable nameserver (it mirrors
NetBird-polluted Windows DNS), so pacman fails with "Could not resolve host".
Fix the setup script to **always**:

1. Write `/etc/wsl.conf` with `[network]\ngenerateResolvConf = false`.
2. Overwrite `/etc/resolv.conf` with working resolvers (`8.8.8.8`, `1.1.1.1`).
3. (Keep the existing mirror/keyring/BlackArch/`-Syu` steps, adding
   `--overwrite '*'` to the pacman calls to clear the ArchWSL gcc-libs
   file-conflict seen in practice.)

This makes a fresh unattended `ensure_distro` succeed instead of stranding on
DNS the way it did during manual setup.

## Test Harness (Component 1 consumer)

`crates/platform/tests/sandbox_backends.rs` — `#[ignore]`d integration tests
(they touch the OS/network), run with `cargo test -p pentest-platform --
--ignored`, matching the existing evidence-buffer / WSL-lifecycle ignored-test
pattern.

- `probe_all_reports_every_backend_for_os` — asserts `probe_all` returns a
  report for each `target_os`-valid backend, each with a status, and never
  panics on an unavailable backend.
- `at_least_the_expected_backend_works_when_configured` — on a machine where a
  backend is set up, assert exactly that one is `Working` and a real command
  (`id -u` → `0`) ran through it.
- `no_backend_is_fail_closed_not_host_escape` — with all backends forced
  unavailable (mock/empty config), `any_backend_available()` is false and
  `command.rs` execution returns `Err`, never a host result (guards #256).
- Backend-selection unit tests (non-ignored, run everywhere) for the pure
  decision logic: WSL2-preferred-then-WSL1-fallback string handling, and
  `preferred_backend_for` (already exists — extend).

CI: the ignored tests run in a Windows-WSL matrix job and a Linux
bwrap/proot/docker job; each job asserts the backend(s) it's provisioned for are
`Working` and tolerates the rest as `Unavailable`.

## Data Flow

```
launch
  └─ probe_all(cfg)                     [cheap, side-effect free]
       ├─ any_backend_available()? ──── false + windows ──► show install banner
       │                                              └─ [Install] ─► wsl_install (UAC) ─► reboot prompt
       ├─ Settings: gate "Sandboxed" option on availability
       └─ detect_backend (unchanged)  ─► execute tool (fail closed if none)
```

## Files

- **Create** `crates/platform/src/desktop/sandbox/probe.rs` — probe + report.
- **Create** `crates/platform/src/desktop/sandbox/wsl_install.rs` — guided
  installer (feature-enable, `wsl --update`, UAC elevation, reboot prompt).
- **Create** `crates/platform/tests/sandbox_backends.rs` — ignored harness.
- **Modify** `crates/platform/src/desktop/sandbox/mod.rs` — expose probe;
  register submodules.
- **Modify** `crates/platform/src/desktop/sandbox/wsl.rs` — always write
  wsl.conf + resolv.conf; `--overwrite '*'` in setup.
- **Modify** `crates/core/src/settings.rs` / `config.rs` — add
  `wsl_banner_dismissed`; document the Sandboxed/Native meaning.
- **Modify** `crates/ui/src/components/settings_page.rs` — gate the Sandboxed
  toggle on availability + helper text.
- **Create** `crates/ui/src/components/wsl_install_banner.rs` — dismissable
  banner + install flow UI, shown from the easy-mode home + workspace shells.
- **Modify** `crates/ui/src/connector_app.rs` — surface `any_backend_available`
  to children; wire the banner.

## Risks / Open Questions

- **UAC relaunch UX in a webview app:** ShellExecute `runas` from a Dioxus
  desktop process pops a standard UAC dialog; the elevated child must be a
  minimal helper (not the full app). Confirm we can spawn `powershell`/`dism`
  elevated and poll a result file rather than IPC.
- **Probe cost:** `wsl.exe --status` can be slow on a cold WSL; run the probe
  off the UI thread and cache the result per launch.
- **Docker on Windows:** if Docker Desktop is present, a backend IS available →
  no banner. Correct per "Windows + no sandbox backend available" trigger.
