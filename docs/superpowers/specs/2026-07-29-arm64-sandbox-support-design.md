# Arch-Aware Desktop Sandbox (arm64 support) — Design

**Date:** 2026-07-29
**Status:** Approved (design); ready for implementation plan
**Branch:** `josh/catching-up` (or a fresh `feat/arch-aware-sandbox`)

## Problem

Pick's **desktop** sandbox — all three backends (Windows WSL, Linux bwrap/proot, macOS Docker) — hardcodes an **x86_64** guest, so it is non-functional or needlessly emulated on arm64 hosts:

- WSL: `ARCHWSL_ROOTFS_URL` (`wsl.rs:19`) = yuk7/ArchWSL-FS's single x86_64 `rootfs.tar.gz`.
- Linux bwrap/proot: `ARCH_BOOTSTRAP_URL(_GZ)` (`rootfs.rs:15,19`) = `archlinux-bootstrap-*-x86_64`; the mirrorlist is `geo.mirror.pkgbuild.com` (x86_64-only); `pacman-key --populate archlinux` (`rootfs.rs:215`).
- macOS Docker: `DOCKER_PLATFORM = "linux/amd64"` + `FROM --platform=linux/amd64 archlinux:latest` (`docker.rs:20,24`) — forces amd64-under-emulation on Apple Silicon instead of running arm64 containers natively (see Key facts correction).

On **native arm64 Windows** (verified on 10.10.0.38 — genuine ARM64, Win11 24H2) the x86_64 WSL rootfs imports but every command fails `execvpe(/bin/sh): Exec format error`. The same class of failure would hit arm64 Linux bwrap/proot. On **Apple Silicon** the amd64 Docker image still runs, but only under slow QEMU/Rosetta emulation when it could run natively. Pick's *build* now works on arm64 (commit `1685fe0` fixed the rquickjs-sys bindgen gap); only tool execution is broken/emulated.

**Android is already arch-aware and is the reference implementation.**
`crates/platform/src/android/proot/rootfs.rs` selects the rootfs by runtime
`std::env::consts::ARCH` (separate `ARCH_ROOTFS_AARCH64` / `ARCH_ROOTFS_X86_64`
Termux proot-distro tarballs), maps arch → pacman-arch (`aarch64`/`armv7h`/
`x86_64`), and even exposes a `PROOT_ROOTFS_URL` override. That's why the
Android proot shell works on both x64 and arm. The desktop path never got the
same treatment — this design brings desktop up to Android's arch-awareness.

Two distinct defects:

1. **No arch-aware rootfs/base-image/mirror/keyring selection on desktop** (WSL, Linux bwrap/proot, AND macOS Docker). arm64 needs an aarch64 rootfs / arm64 base image + ALARM mirrors + `pacman-key --populate archlinuxarm`.
2. **The probe can't detect "imports but can't execute."** `probe.rs` was changed (this session) to report `Working` when the distro/rootfs is merely *present*, dropping the exec smoke-check (it cold-started the distro and stalled UI startup). So a broken sandbox reads as `Working`, and the ignored harness — which only asserts the probe's verdict — would pass it. On .38 `at_least_one_backend_is_working` failed only incidentally (WSL2 unavailable + no distro), not because it detected the exec failure.

## Goals

1. Make the **desktop** sandbox arch-aware across all three backends — **WSL (Windows)**, **bwrap/proot (Linux)**, AND **Docker (macOS)** — selecting an aarch64 rootfs/base-image + arch-appropriate mirrors/keyring on arm64 — mirroring the pattern Android already uses.
2. Keep **x86_64** behavior (Windows/Linux/macOS Intel) byte-for-byte unchanged.
3. Add a **real execution sanity check** to the ignored harness tests (NOT the startup probe) that runs a command through each `Working` backend and asserts output — catching "imports but can't exec" (the arm64 Exec-format bug) on x64 AND arm, per platform. Keep it out of the startup probe to avoid the UI-thread stall that caused the smoke-check's removal.

## Non-Goals

- Changing the fast startup probe to run commands (that stall risk is why the smoke-check was removed). The exec check lives in tests only.
- Android changes — it's already arch-aware; it's the model, not a target. (We DO add an Android sanity test — see Goal 3.)
- Kali. The user wants **BlackArch**, which publishes an aarch64 repo (verified below).

## Key facts (verified 2026-07-29)

- **Android proot is already arch-aware** — `android/proot/rootfs.rs`: `get_rootfs_url()`/`get_pacman_arch()` switch on `std::env::consts::ARCH` (aarch64/armv7h/x86_64) with Termux proot-distro tarballs. Copy this pattern for desktop.
- **BlackArch aarch64 repo exists**: `https://blackarch.org/blackarch/$repo/os/aarch64/blackarch.db` → HTTP 200. The `[blackarch]` repo entries (both `wsl.rs` and `rootfs.rs`) already use `$repo/os/$arch`, so inside an aarch64 guest `$arch` resolves correctly — the repo append needs no change.
- **ArchWSL-FS has no arm64 rootfs** (single x86_64 `rootfs.tar.gz`). arm64 WSL must use a different base.
- **ArchLinuxARM** publishes aarch64 images: `http://os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz` (HTTP 200, plain tar.gz → WSL `--import`-compatible). Its mirrors are `mirror.archlinuxarm.org/$arch/$repo` (NOT `geo.mirror.pkgbuild.com`), and its keyring is `archlinuxarm` (not `archlinux`). So both the WSL setup script AND the Linux `rootfs.rs` need arch-aware mirrorlist + keyring, not just the rootfs URL.
- **macOS Docker is an arch target, NOT a no-op (spec correction 2026-07-29).** The official `archlinux` Docker image is **amd64-only** — `docker run --platform linux/arm64 archlinux:latest` fails with `no matching manifest for linux/arm64`. `docker.rs` pins `--platform linux/amd64` + `FROM --platform=linux/amd64 archlinux:latest` (`docker.rs:20,24`), which means on a **native Apple Silicon Mac** it forces the amd64 BlackArch container to run under **emulation** (QEMU/Rosetta) even though the host can run arm64 containers natively. That is wasteful (slow) and inconsistent with the WSL/Linux arm64 fix. Verified on the real arm64 Mac (10.10.0.8): `docker run --platform linux/arm64 menci/archlinuxarm:latest uname -m` → `aarch64` runs **natively** (no emulation); `lopsided/archlinux:latest` arm64 also → `aarch64`. **`menci/archlinuxarm`** is the chosen arm64 base — it's ArchLinuxARM-based, so it pairs with the SAME ALARM mirrors + `archlinuxarm` keyring the WSL/Linux arm64 paths use. So Docker joins the shared arch helper: on amd64 hosts (Intel Macs) → `linux/amd64` + `archlinux` + pkgbuild mirrors + `archlinux` keyring (unchanged); on arm64 hosts (Apple Silicon) → `linux/arm64` + `menci/archlinuxarm` + ALARM mirrors + `archlinuxarm` keyring, running natively.
  - Note: the earlier assumption that "macOS gets an x86_64 guest via emulation and needs NO change" was **wrong** and is superseded. Docker gets the same arch-awareness as the other two backends.
  - Unrelated-to-arch caveat that still holds: **Docker is macOS's ONLY backend** (no proot/bwrap — proot is a Linux ELF), so "Docker not installed/running" → `NoBackendAvailable` with a clear "install Docker Desktop/OrbStack/colima" error. The exec-sanity test (Goal 3) covers the macOS Docker backend when Docker is present.

## Architecture

### 1. Arch-aware rootfs selection (`wsl.rs`)

Replace the single `ARCHWSL_ROOTFS_URL` const with a function that returns the rootfs URL for the host arch:

```rust
/// Rootfs download URL for the current host architecture.
/// x86_64 → yuk7/ArchWSL-FS (flat, WSL-ready). aarch64 → ArchLinuxARM aarch64
/// rootfs (the x86_64 ArchWSL image can't exec on arm64 — Exec format error).
fn wsl_rootfs_url() -> &'static str {
    #[cfg(target_arch = "aarch64")]
    { "http://os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz" }
    #[cfg(not(target_arch = "aarch64"))]
    { "https://github.com/yuk7/ArchWSL-FS/releases/download/25030400/rootfs.tar.gz" }
}
```

`ensure_distro` calls `wsl_rootfs_url()` instead of the const. `cfg!(target_arch)` is correct here because the connector binary's arch matches the WSL guest arch it can run (arm64 Windows → arm64 WSL).

### 2. Arch-aware setup script (`wsl.rs::WSL_SETUP_SCRIPT`)

The setup script (already a `pub(crate) const` from the WSL1-DNS task) hardcodes the x86_64 pacman mirrorlist:

```
Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch    # x86_64 ONLY
Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch
```

`geo.mirror.pkgbuild.com` has no aarch64 packages. On arm64 the mirrorlist must use ArchLinuxARM's mirrors:

```
Server = http://mirror.archlinuxarm.org/$arch/$repo
```

Approach: keep `WSL_SETUP_SCRIPT` for x86_64 and add `WSL_SETUP_SCRIPT_AARCH64` (identical except the mirrorlist block + ALARM keyring init — `pacman-key --populate archlinuxarm` instead of `archlinux`). `setup_distro` picks the script by `cfg!(target_arch = "aarch64")`. The `[blackarch]` repo append is unchanged (its `$arch` resolves correctly). Everything else (DNS/wsl.conf fix, `--overwrite '*'`, `nmap` install, `.pentest-setup-complete` marker) is identical.

ALARM specifics to verify during implementation: the aarch64 rootfs ships as a plain `.tar.gz` (WSL `--import` compatible), extracts to a flat FS, and its pacman is usable after `pacman-key --init && pacman-key --populate archlinuxarm`. BlackArch's `strap.sh` may assume x86_64 — prefer appending the `[blackarch]` repo directly (as the script already does) over running `strap.sh`.

### 3. Arch-aware Linux bwrap/proot rootfs (`rootfs.rs`)

The Linux desktop path (`RootfsManager`) has the SAME x86_64 hardcoding and needs the SAME arch-awareness (this is the piece the user explicitly wants, not deferred):

- `ARCH_BOOTSTRAP_URL` / `ARCH_BOOTSTRAP_URL_GZ` (`rootfs.rs:15,19`) are `archlinux-bootstrap-*-x86_64`. On aarch64, use the ArchLinuxARM aarch64 rootfs instead (same base as WSL — `os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz`). Wrap in a `bootstrap_url()` fn gated on `cfg!(target_arch)`, mirroring Android's `get_rootfs_url()`.
- The extracted-dir name `root.x86_64` (`rootfs.rs:178`) is arch-specific — ArchLinuxARM extracts differently (no `root.<arch>` wrapper dir). Detect the extracted top-level dir rather than hardcoding, or branch by arch.
- The mirrorlist write (`rootfs.rs:~288`, `geo.mirror.pkgbuild.com`) and `pacman-key --populate archlinux` (`rootfs.rs:215`) must be arch-aware exactly like the WSL setup script — ALARM mirrors + `archlinuxarm` keyring on aarch64.
- The `[blackarch]` repo append is unchanged (`$arch` resolves).

Prefer factoring the arch→(rootfs URL, mirror server, keyring name) mapping into ONE shared helper (e.g. in `sandbox/config.rs` or a small `sandbox/arch.rs`) that ALL THREE desktop backends (`wsl.rs`, `rootfs.rs`, `docker.rs`) consume, so they can't drift. Android keeps its own (Termux-based) mapping — its rootfs source differs — but the desktop helper should read like Android's for consistency.

Note: this is testable locally on Linux x86_64 (must stay unchanged) but the aarch64 Linux path can only be exercised on an arm64 Linux host (none currently available) — so arm64 Linux is implement-and-review-carefully, verify-later, like the Windows arm arms were.

### 3b. Arch-aware Docker (`docker.rs`) — macOS (and any Docker host)

The Docker backend hardcodes amd64 in three spots and must become arch-aware exactly like WSL/Linux (this is the spec correction — macOS is NOT a no-op):

- `DOCKER_PLATFORM` (`docker.rs:20`) = `"linux/amd64"`, used for BOTH `docker build` (line 133) and `docker run` (line 176). Replace with a `docker_platform()` that returns `"linux/arm64"` on aarch64 hosts, `"linux/amd64"` otherwise. Runs the container **natively** on Apple Silicon instead of under emulation.
- `DOCKERFILE_CONTENTS` (`docker.rs:24-49`) hardcodes `FROM --platform=linux/amd64 archlinux:latest` and the x86_64 pkgbuild mirrorlist + `pacman-key --populate archlinux`. The official `archlinux` image has **no arm64 manifest** (verified: `no matching manifest for linux/arm64`), so arm64 needs a different base. Build the Dockerfile from the shared arch helper: on arm64 → `FROM --platform=linux/arm64 menci/archlinuxarm:latest` (verified `uname -m` → `aarch64` natively on 10.10.0.8) + ALARM mirrorlist (`http://mirror.archlinuxarm.org/$arch/$repo`) + `pacman-key --populate archlinuxarm`; on amd64 → the current `archlinux:latest` + pkgbuild mirrors + `archlinux` keyring, byte-for-byte unchanged.
- The `[blackarch]` repo / `strap.sh` step: `$arch` inside an arm64 container resolves to `aarch64`, so BlackArch's aarch64 repo is selected automatically. As with WSL/Linux, prefer appending the `[blackarch]` repo directly over `strap.sh` if `strap.sh` assumes x86_64 (verify during implementation — the current Docker path uses `strap.sh`; check it works on aarch64 or switch to a direct repo append there too).
- Everything else in `docker.rs` (cap-drop, no-new-privileges, network flags, workspace mount, timeout) is arch-independent — unchanged.

`cfg!(target_arch = "aarch64")` is correct here: Docker Desktop/colima/OrbStack run a Linux VM whose native arch matches the Mac host, so an arm64 Mac runs arm64 containers natively. (An Intel Mac stays on amd64.) The shared helper's arch→(base image, mirror, keyring) mapping serves Docker; the rootfs-URL field is WSL/Linux-only, so the helper exposes both a "base image name" (Docker) and a "rootfs tarball URL" (WSL/Linux) keyed off the same arch.

This IS verifiable now on the real arm64 Mac (10.10.0.8, Apple Silicon) — the arm64 native path and the exec-sanity test both run there. That makes macOS the one arm64 desktop backend we can fully validate today (WSL-arm on .38 is WSL1-only; arm64 Linux has no box).

### 4. Harness execution sanity check (`tests/sandbox_backends.rs`)

Add a THIRD ignored test that, for each backend reported `Working`, actually runs a command through it and asserts real output — this is what would have caught the arm64 `Exec format error`:

```rust
#[tokio::test]
#[ignore = "runs a real command in the sandbox; run with --ignored on a provisioned host"]
async fn working_backend_can_execute_a_command() {
    // For any backend the probe calls Working, a trivial command must actually
    // run and return the expected output. Catches "imports but can't exec"
    // (e.g. an x86_64 rootfs on arm64 -> Exec format error) that the probe's
    // import-only check misses by design.
    let cfg = SandboxConfig::default();
    let mgr = SandboxManager::new(cfg).await.expect("manager");
    // gate on availability so this is a no-op when nothing is provisioned
    if !any_backend_available(&SandboxConfig::default()).await { return; }
    let out = mgr.execute("id -u", Duration::from_secs(60), None).await
        .expect("a Working sandbox must execute a command, not Exec-format-error");
    assert_eq!(out.stdout.trim(), "0", "expected root uid from the sandbox; got {out:?}");
}
```

This keeps the startup probe light (Goal: no UI stall) while giving CI/manual a real exec assertion. On arm64 with a working aarch64 rootfs it passes; with the old x86_64 rootfs it would fail loudly with the Exec-format error — exactly the missing coverage.

The desktop harness exercises whichever backend the host provides (WSL on
Windows-arm/x64, bwrap/proot on Linux-arm/x64, Docker on macOS-arm/Intel), so
running it on each box gives the per-arch coverage. Since a given machine only
has its own arch, the "both x64 and arm" guarantee comes from running the same
ignored test on an x64 box AND an arm box (CI matrix / the .37 x64 + .38 arm
Windows boxes + the 10.10.0.8 arm64 Mac for Docker), not from one run.

### 5. Android exec sanity check

The user recalls the Android proot shell working and wants a test that PROVES
it on both x64 and arm Android. Android's rootfs/exec lives in
`crates/platform/src/android/proot/` (not the desktop `sandbox` module), so its
test belongs there. Add an ignored integration test (or a `#[cfg(target_os =
"android")]` gated one) that provisions/uses the proot rootfs and runs a trivial
command (`id -u` / `uname -m`), asserting it executes and the reported machine
matches the device arch (`aarch64` on arm, `x86_64` on x64 emulator). This
mirrors the desktop exec check and locks in the arch-aware behavior Android
already has, so a future regression (e.g. a bad rootfs URL) is caught. Runs on a
device/emulator only — `#[ignore]`, invoked in the Android CI/dev path.

## Files

- **Create** `crates/platform/src/desktop/sandbox/arch.rs` (or add to `config.rs`): shared `SandboxArch`/helper mapping host arch → (rootfs tarball URL [WSL/Linux], Docker base image name [Docker], pacman mirror server, keyring name). Consumed by `wsl.rs`, `rootfs.rs`, AND `docker.rs` so they can't drift.
- **Modify** `crates/platform/src/desktop/sandbox/wsl.rs`: use the shared helper for the rootfs URL; add `WSL_SETUP_SCRIPT_AARCH64` (ALARM mirrorlist + `archlinuxarm` keyring) selected by arch in `setup_distro`.
- **Modify** `crates/platform/src/desktop/sandbox/rootfs.rs`: use the shared helper for the bootstrap URL, mirrorlist, and keyring; make the extracted-dir detection arch-agnostic (don't hardcode `root.x86_64`).
- **Modify** `crates/platform/src/desktop/sandbox/docker.rs`: replace `DOCKER_PLATFORM` const with a `docker_platform()` (arm64→`linux/arm64`, else `linux/amd64`); build `DOCKERFILE_CONTENTS` from the shared helper (arm64 → `menci/archlinuxarm` base + ALARM mirrors + `archlinuxarm` keyring; amd64 → current `archlinux` + pkgbuild + `archlinux`, unchanged). Keep all security/network flags unchanged.
- **Modify** `crates/platform/tests/sandbox_backends.rs`: add the `working_backend_can_execute_a_command` ignored exec-sanity test (covers WSL on Windows, bwrap/proot on Linux, AND Docker on macOS).
- **Create/Modify** an Android proot test under `crates/platform/src/android/proot/` (or `crates/platform/tests/`): ignored exec-sanity test asserting a command runs and the arch matches the device.

## Risks / Open Questions

- **ALARM WSL compatibility:** ArchLinuxARM's rootfs is built for real ARM devices, not WSL specifically. It should import (`wsl --import` just untars), but init quirks (systemd expectations, `/etc/resolv.conf`, first-boot pacman-key) need real testing on .38. The DNS/wsl.conf fix already in the script covers resolv.conf.
- **BlackArch aarch64 tool coverage:** BlackArch's aarch64 repo has fewer packages than x86_64. `nmap` (the smoke tool) is in core and will be there; exotic tools may not. Acceptable — the goal is a functional sandbox, not 100% tool parity, on arm64.
- **Verification requires .38** (the only arm64 box) with WSL — but .38 has **no nested virt → WSL1 only**. WSL1 on arm64 runs aarch64 binaries (confirmed: aarch64 Alpine ran, kernel `4.4.0-*-Microsoft aarch64`), so the aarch64 ArchLinuxARM rootfs should exec under WSL1. WSL2-on-arm64 remains untested (no nested-virt arm box available).
- `cfg!(target_arch)` gates the guest rootfs to the host arch — correct for WSL (guest arch = host arch) but would be wrong if we ever cross-provisioned; documented as a WSL-only assumption.
- **macOS is a real arm64 exec-sanity target** (10.10.0.8, Apple Silicon; Docker installed via colima 2026-07-29) — running the desktop exec-sanity test there proves the arm64-**native** Docker path executes on arm (`--platform linux/arm64` + `menci/archlinuxarm`, verified `uname -m` → `aarch64` natively). That plus the .38 arm64 WSL path and the x64 boxes gives cross-arch coverage across all three desktop backends (Docker/WSL/bwrap-proot). Note the .8 Mac is a nested-virt-disabled guest so colima runs under QEMU-TCG — but the *container* arch is still arm64-native to the VM (no amd64 emulation layer), which is what the test exercises.
- **Docker `menci/archlinuxarm` BlackArch compatibility:** the arm64 base is ArchLinuxARM, not vanilla Arch. Its pacman needs `pacman-key --populate archlinuxarm`, and BlackArch's `strap.sh` may assume x86_64 — verify the `[blackarch]` repo append works on aarch64 (prefer a direct repo append over `strap.sh` if it balks), same open question as the WSL/Linux paths.
- **No qemu emulation of the sandbox for tests (decided).** We considered running the aarch64 path on x86_64 Linux via qemu-user, but the sandbox uses bwrap (namespaces) / proot (ptrace), which do not nest reliably inside qemu-user — it would test qemu quirks, not our code. Decision: **verify on real arm hardware** (the .38 arm64 box for Windows/WSL; a real arm64 Linux host when one exists) — consistent with how everything else this session was validated. The exec-sanity tests stay `#[ignore]`d / real-hardware-only; do NOT add a qemu emulation harness.
