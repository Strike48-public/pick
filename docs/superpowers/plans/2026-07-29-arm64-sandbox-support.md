# Arch-Aware Desktop Sandbox (arm64 support) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Pick's desktop sandbox provision an arch-appropriate BlackArch guest on all three backends (WSL, Linux bwrap/proot, macOS Docker) so tools execute natively on arm64 instead of failing with `Exec format error` (WSL/Linux) or running under emulation (Docker).

**Architecture:** Introduce one shared arch helper (`sandbox/arch.rs`) that maps host arch → (pacman mirrorlist, pacman keyring, ALARM rootfs URL, Docker base image, Docker platform). All three backends consume it, so they can't drift. On x86_64 every backend keeps its current base source and produces byte-for-byte-identical provisioning; on aarch64 they select ArchLinuxARM (ALARM) + ALARM mirrors + the `archlinuxarm` keyring, plus BlackArch's aarch64 repo (whose `$arch` resolves automatically). A new ignored exec-sanity test runs a real command through the provisioned backend and asserts the guest arch matches the host — the coverage that would have caught the arm64 Exec-format bug.

**Tech Stack:** Rust (async/tokio), `cfg!(target_arch)`, pacman/BlackArch, WSL (`wsl.exe`), bwrap/proot, Docker CLI. Crate: `pentest-platform`, module `crates/platform/src/desktop/sandbox/`.

## Global Constraints

- **Keep x86_64 behavior byte-for-byte unchanged** on Windows/Linux/macOS-Intel. The x86_64 render of every builder must equal the current hardcoded text/URLs.
- **BlackArch, not Kali.** BlackArch publishes an aarch64 repo; the `[blackarch]` `$repo/os/$arch` entry resolves `$arch` to `aarch64` inside an arm64 guest, so the repo line itself is unchanged.
- **Use ArchLinuxARM (ALARM) on arm64.** WSL/Linux use the ALARM aarch64 rootfs tarball `http://os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz`; Docker uses the ALARM-based image `menci/archlinuxarm:latest`. arm64 needs ALARM mirrors (`http://mirror.archlinuxarm.org/$arch/$repo`) + `pacman-key --populate archlinuxarm`.
- **One shared arch helper** (`sandbox/arch.rs`) consumed by `wsl.rs`, `rootfs.rs`, AND `docker.rs`. Android keeps its own (Termux-based) mapping — do not touch Android's rootfs source.
- **Do NOT add an exec check to the startup probe** (`probe.rs`). Probing stays import-only/fast to avoid the UI-thread stall that caused the smoke-check's removal. The exec-sanity check lives in the ignored test harness only.
- **Exec-sanity tests are `#[ignore]`d and verified on real hardware only.** No qemu emulation harness. arm64 Linux has no available box → its path is implement-and-review-carefully, verify-later.
- **Selection uses `cfg!(target_arch = "aarch64")`** (connector binary arch == host arch == guest arch on desktop). Pure mapping fns take the arch as a `bool` param so both branches are unit-testable on any host.
- CI runs clippy with `-D warnings`; run `cargo clippy -p pentest-platform --features desktop -- -D warnings` before every commit. Use `pentest_core::error::{Error, Result}` where the surrounding code does (Android).

---

## File Structure

- **Create** `crates/platform/src/desktop/sandbox/arch.rs` — pure arch→provisioning mapping. No I/O. The single source of truth for all three backends.
- **Modify** `crates/platform/src/desktop/sandbox/mod.rs` — declare `mod arch;`.
- **Modify** `crates/platform/src/desktop/sandbox/wsl.rs` — arch-aware rootfs URL; convert `WSL_SETUP_SCRIPT` const into a `wsl_setup_script()` builder that interpolates the shared mirror + keyring.
- **Modify** `crates/platform/src/desktop/sandbox/rootfs.rs` — arch-aware bootstrap URL, extract path (flat ALARM vs `root.x86_64`), mirrorlist, keyring.
- **Modify** `crates/platform/src/desktop/sandbox/docker.rs` — arch-aware `docker_platform()` + `dockerfile_contents()` builder (FROM/platform/mirror/keyring/blackarch-step).
- **Modify** `crates/platform/tests/sandbox_backends.rs` — add the ignored exec-sanity test (covers WSL/bwrap/proot/Docker on whatever the host provides).
- **Modify** `crates/platform/src/android/proot/mod.rs` — add an ignored, android-gated exec-sanity test asserting proot runs and reports the device arch.

---

### Task 1: Shared arch helper (`arch.rs`)

**Files:**
- Create: `crates/platform/src/desktop/sandbox/arch.rs`
- Modify: `crates/platform/src/desktop/sandbox/mod.rs:7-14` (module declarations block)

**Interfaces:**
- Produces (all `pub(super)`, in module `super::arch`):
  - `const ALARM_AARCH64_ROOTFS: &str`
  - `fn is_aarch64() -> bool`
  - `fn keyring_for(aarch64: bool) -> &'static str` and `fn pacman_keyring() -> &'static str`
  - `fn mirrorlist_for(aarch64: bool) -> &'static str` and `fn pacman_mirrorlist() -> &'static str`
  - `fn docker_platform_for(aarch64: bool) -> &'static str` and `fn docker_platform() -> &'static str`
  - `fn docker_base_image_for(aarch64: bool) -> &'static str` and `fn docker_base_image() -> &'static str`

- [ ] **Step 1: Create `arch.rs` with the mapping and its tests**

```rust
//! Host-architecture → sandbox provisioning parameters.
//!
//! The desktop sandbox provisions a BlackArch (Arch-based) guest. On x86_64
//! hosts that guest is vanilla Arch Linux; on aarch64 hosts vanilla Arch has no
//! ARM port, so the guest is ArchLinuxARM (ALARM) — a different mirror set and a
//! different pacman keyring. This module centralizes that arch → (mirror,
//! keyring, rootfs source, Docker base image, Docker platform) mapping so all
//! three desktop backends (WSL, bwrap/proot, Docker) stay consistent.
//!
//! Selection uses `cfg!(target_arch = "aarch64")`: the connector binary's
//! compile arch equals the host arch equals the guest arch it can execute
//! (an arm64 Windows host runs arm64 WSL; an Apple Silicon Mac runs arm64
//! containers natively). The `*_for(bool)` helpers take the arch as a param so
//! both branches are unit-testable on any host.

/// ArchLinuxARM aarch64 root filesystem tarball. Plain `.tar.gz`, accepted by
/// both `wsl --import` (WSL backend) and `tar -xzf` (Linux bwrap/proot backend),
/// so the two share this single source and never drift. The `os.archlinuxarm.org`
/// host 302-redirects to a geographic mirror; `reqwest` follows redirects.
pub(super) const ALARM_AARCH64_ROOTFS: &str =
    "http://os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz";

/// True when provisioning an aarch64 guest (host is aarch64).
pub(super) fn is_aarch64() -> bool {
    cfg!(target_arch = "aarch64")
}

/// pacman keyring to populate: ArchLinuxARM on aarch64, Arch on x86_64.
pub(super) fn keyring_for(aarch64: bool) -> &'static str {
    if aarch64 {
        "archlinuxarm"
    } else {
        "archlinux"
    }
}

/// pacman keyring for the current host arch.
pub(super) fn pacman_keyring() -> &'static str {
    keyring_for(is_aarch64())
}

/// pacman mirrorlist `Server` line(s) for the guest arch, with a trailing
/// newline so it drops straight into a mirrorlist file/heredoc. ALARM uses
/// `$arch/$repo` ordering; Arch uses `$repo/os/$arch`. `$repo`/`$arch` are
/// pacman variables (resolved inside the guest), not shell/Rust interpolation.
pub(super) fn mirrorlist_for(aarch64: bool) -> &'static str {
    if aarch64 {
        "Server = http://mirror.archlinuxarm.org/$arch/$repo\n"
    } else {
        "Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch\n\
         Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch\n"
    }
}

/// pacman mirrorlist for the current host arch.
pub(super) fn pacman_mirrorlist() -> &'static str {
    mirrorlist_for(is_aarch64())
}

/// Docker `--platform` value: arm64 runs natively on Apple Silicon, amd64 on
/// Intel. (The official `archlinux` image is amd64-only; arm64 uses an ALARM
/// base image — see `docker_base_image_for`.)
pub(super) fn docker_platform_for(aarch64: bool) -> &'static str {
    if aarch64 {
        "linux/arm64"
    } else {
        "linux/amd64"
    }
}

/// Docker platform for the current host arch.
pub(super) fn docker_platform() -> &'static str {
    docker_platform_for(is_aarch64())
}

/// Docker base image: vanilla Arch on amd64, an ArchLinuxARM image on arm64
/// (the official `archlinux` image has no arm64 manifest).
pub(super) fn docker_base_image_for(aarch64: bool) -> &'static str {
    if aarch64 {
        "menci/archlinuxarm:latest"
    } else {
        "archlinux:latest"
    }
}

/// Docker base image for the current host arch.
pub(super) fn docker_base_image() -> &'static str {
    docker_base_image_for(is_aarch64())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyring_matches_distro_family() {
        assert_eq!(keyring_for(false), "archlinux");
        assert_eq!(keyring_for(true), "archlinuxarm");
    }

    #[test]
    fn x86_64_mirrorlist_is_pkgbuild_unchanged() {
        let m = mirrorlist_for(false);
        assert!(m.contains("geo.mirror.pkgbuild.com/$repo/os/$arch"));
        assert!(m.contains("mirror.rackspace.com/archlinux/$repo/os/$arch"));
        assert!(!m.contains("archlinuxarm"));
        assert!(m.ends_with('\n'));
    }

    #[test]
    fn aarch64_mirrorlist_is_alarm() {
        let m = mirrorlist_for(true);
        assert!(m.contains("mirror.archlinuxarm.org/$arch/$repo"));
        assert!(!m.contains("pkgbuild.com"));
        assert!(m.ends_with('\n'));
    }

    #[test]
    fn docker_platform_and_base_image_track_arch() {
        assert_eq!(docker_platform_for(false), "linux/amd64");
        assert_eq!(docker_platform_for(true), "linux/arm64");
        assert_eq!(docker_base_image_for(false), "archlinux:latest");
        assert_eq!(docker_base_image_for(true), "menci/archlinuxarm:latest");
    }

    #[test]
    fn alarm_rootfs_is_a_plain_targz() {
        assert!(ALARM_AARCH64_ROOTFS.ends_with(".tar.gz"));
        assert!(ALARM_AARCH64_ROOTFS.contains("archlinuxarm.org"));
    }
}
```

- [ ] **Step 2: Declare the module in `mod.rs`**

In `crates/platform/src/desktop/sandbox/mod.rs`, add `mod arch;` to the module block (lines 7-14). Result:

```rust
pub mod bwrap;
pub mod config;
mod arch;
pub mod docker;
pub mod probe;
pub mod proot;
pub mod rootfs;
pub mod wsl;
pub mod wsl_install;
```

(`mod arch;` is private to the `sandbox` module; sibling backend modules reach it via `super::arch`, and its `pub(super)` items are visible within `sandbox`.)

- [ ] **Step 3: Run the tests to verify they pass**

Run: `cargo test -p pentest-platform --features desktop arch:: -- --nocapture`
Expected: 5 tests pass (`keyring_matches_distro_family`, `x86_64_mirrorlist_is_pkgbuild_unchanged`, `aarch64_mirrorlist_is_alarm`, `docker_platform_and_base_image_track_arch`, `alarm_rootfs_is_a_plain_targz`).

- [ ] **Step 4: Clippy + build**

Run: `cargo clippy -p pentest-platform --features desktop -- -D warnings`
Expected: no warnings. (The `*_for(true)` branches are compiled on x86_64 because they are runtime `if`s over a `bool` param, not `#[cfg]` — no dead-code warnings.)

- [ ] **Step 5: Commit**

```bash
git add crates/platform/src/desktop/sandbox/arch.rs crates/platform/src/desktop/sandbox/mod.rs
git commit -m "feat(sandbox): add shared arch helper for arm64 provisioning"
```

---

### Task 2: WSL arch-awareness (`wsl.rs`)

**Files:**
- Modify: `crates/platform/src/desktop/sandbox/wsl.rs:17-88` (rootfs const + setup-script const), `wsl.rs:288` (setup-script write site), `wsl.rs:355-378` (rootfs URL use site), `wsl.rs:566-581` (existing setup-script test)

**Interfaces:**
- Consumes: `super::arch::{is_aarch64, ALARM_AARCH64_ROOTFS, mirrorlist_for, keyring_for}`.
- Produces (module-private): `fn wsl_rootfs_url() -> &'static str`, `fn wsl_setup_script() -> String`, `fn wsl_setup_script_for(aarch64: bool) -> String`. Replaces `const WSL_SETUP_SCRIPT`.

- [ ] **Step 1: Write the failing tests**

Replace the existing `setup_script_forces_working_dns_and_overwrite` test (wsl.rs:570-581) with these three tests in the same `#[cfg(test)] mod tests` block:

```rust
    #[test]
    fn setup_script_forces_working_dns_and_overwrite() {
        // The built setup script must (a) disable WSL's resolv.conf regeneration,
        // (b) pin a working nameserver unconditionally, and (c) use --overwrite so
        // the ArchWSL gcc-libs file conflict does not abort the transaction.
        // These invariants hold on BOTH arches.
        for aarch64 in [false, true] {
            let script = super::wsl_setup_script_for(aarch64);
            assert!(script.contains("generateResolvConf = false"), "arch={aarch64}");
            assert!(script.contains("nameserver 8.8.8.8"), "arch={aarch64}");
            assert!(script.contains("--overwrite"), "arch={aarch64}");
            // resolv.conf must be written unconditionally, not guarded by "if missing".
            assert!(!script.contains("if [ ! -f /etc/resolv.conf ]"), "arch={aarch64}");
            // BlackArch repo line is arch-agnostic ($arch resolves in-guest).
            assert!(script.contains("[blackarch]"), "arch={aarch64}");
        }
    }

    #[test]
    fn x86_64_setup_script_uses_arch_mirrors_and_keyring() {
        let s = super::wsl_setup_script_for(false);
        assert!(s.contains("geo.mirror.pkgbuild.com/$repo/os/$arch"));
        assert!(s.contains("pacman-key --populate archlinux"));
        assert!(!s.contains("archlinuxarm"));
    }

    #[test]
    fn aarch64_setup_script_uses_alarm_mirrors_and_keyring() {
        let s = super::wsl_setup_script_for(true);
        assert!(s.contains("mirror.archlinuxarm.org/$arch/$repo"));
        assert!(s.contains("pacman-key --populate archlinuxarm"));
        assert!(!s.contains("pkgbuild.com"));
    }

    #[test]
    fn wsl_rootfs_url_selects_alarm_only_on_aarch64() {
        // On the x86_64 build host the URL must be the ArchWSL-FS release.
        let url = super::wsl_rootfs_url();
        #[cfg(target_arch = "aarch64")]
        assert!(url.contains("archlinuxarm.org"));
        #[cfg(not(target_arch = "aarch64"))]
        assert!(url.contains("yuk7/ArchWSL-FS"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p pentest-platform --features desktop --lib wsl::tests -- --nocapture`
Expected: FAIL to compile — `wsl_setup_script_for`, `wsl_rootfs_url` not defined.

- [ ] **Step 3: Replace the rootfs const with an arch-aware selector**

Keep `ARCHWSL_ROOTFS_URL` (wsl.rs:19-20) as the x86_64 source. Add below it (after line 20):

```rust
/// Rootfs download URL for the current host architecture. x86_64 uses the
/// pre-built ArchWSL-FS release (flat, WSL-ready). aarch64 uses the ArchLinuxARM
/// aarch64 rootfs — the x86_64 ArchWSL image imports on arm64 WSL but every
/// command then fails `execvpe(/bin/sh): Exec format error`.
fn wsl_rootfs_url() -> &'static str {
    if super::arch::is_aarch64() {
        super::arch::ALARM_AARCH64_ROOTFS
    } else {
        ARCHWSL_ROOTFS_URL
    }
}
```

- [ ] **Step 4: Convert the setup-script const into an arch-aware builder**

Delete `pub(crate) const WSL_SETUP_SCRIPT` (wsl.rs:30-88) and replace it with the builder below. The DNS fix, pacman.conf tweaks, `[blackarch]` repo, `--overwrite`, and marker are unchanged; only the mirrorlist and `pacman-key --populate <keyring>` are interpolated from the shared helper. (The raw template contains no `{`/`}` other than the two `{mirrors}`/`{keyring}` placeholders, so `format!` is safe.)

```rust
/// Build the setup script executed inside the freshly-imported WSL distro.
///
/// On WSL1 (used when the host lacks nested virtualisation) WSL auto-generates
/// an `/etc/resolv.conf` pointing at an unreachable nameserver, so pacman fails
/// with "Could not resolve host" for every mirror. This script therefore always
/// takes control of DNS (disabling WSL's regeneration and pinning public
/// resolvers) and passes pacman `--overwrite '*'` to clear the ArchWSL
/// gcc-libs / libstdc++ file conflict that would otherwise abort the transaction.
///
/// The mirrorlist and keyring are arch-specific (Arch vs ArchLinuxARM); every
/// other line is identical across arches.
pub(crate) fn wsl_setup_script() -> String {
    wsl_setup_script_for(super::arch::is_aarch64())
}

fn wsl_setup_script_for(aarch64: bool) -> String {
    format!(
        r#"#!/bin/bash
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

# Configure mirrors — $repo and $arch are pacman variables, not shell
cat > /etc/pacman.d/mirrorlist << 'MIRRORS'
{mirrors}MIRRORS

# Fix pacman.conf for WSL
sed -i 's/^CheckSpace/#CheckSpace/' /etc/pacman.conf 2>/dev/null || true
sed -i 's/^DownloadUser/#DownloadUser/' /etc/pacman.conf 2>/dev/null || true
sed -i 's/^#DisableSandbox/DisableSandbox/' /etc/pacman.conf 2>/dev/null || true

# Add DisableSandbox if not present (pacman 7.0+)
if ! grep -q 'DisableSandbox' /etc/pacman.conf 2>/dev/null; then
    sed -i '/^\[options\]/a DisableSandbox' /etc/pacman.conf
fi

# Set SigLevel to Never (avoids keyring issues)
sed -i 's/^SigLevel.*/SigLevel = Never/' /etc/pacman.conf 2>/dev/null || true

# Initialize pacman keyring
pacman-key --init 2>/dev/null || true
pacman-key --populate {keyring} 2>/dev/null || true

# Add BlackArch repository if not present
if ! grep -q '\[blackarch\]' /etc/pacman.conf 2>/dev/null; then
    cat >> /etc/pacman.conf << 'BLACKARCH'

[blackarch]
Server = https://blackarch.org/blackarch/$repo/os/$arch
SigLevel = Never
BLACKARCH
fi

# System update — --overwrite '*' clears the ArchWSL gcc-libs / libstdc++
# file conflict that would otherwise abort the transaction.
pacman -Syu --noconfirm --overwrite '*' 2>&1 || true

# Sync package databases
pacman -Sy --noconfirm --overwrite '*' 2>&1 || true

# Mark setup as complete
touch /root/.pentest-setup-complete
echo "WSL distro setup complete"
"#,
        mirrors = super::arch::mirrorlist_for(aarch64),
        keyring = super::arch::keyring_for(aarch64),
    )
}
```

- [ ] **Step 5: Update the two use sites**

At `wsl.rs:288`, change the setup-script write from the const to the builder:

```rust
        tokio::fs::write(&script_path, wsl_setup_script()).await?;
```

At `wsl.rs:377`, change the rootfs download to use the selector (also update the two log/comment references at lines 357-359 and 374 that say "ArchWSL"):

```rust
                .download_file(wsl_rootfs_url(), &rootfs_path)
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cargo test -p pentest-platform --features desktop --lib wsl::tests -- --nocapture`
Expected: all `wsl::tests` pass (the 4 new/updated arch tests plus the existing path/decode tests).

- [ ] **Step 7: Clippy**

Run: `cargo clippy -p pentest-platform --features desktop -- -D warnings`
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/platform/src/desktop/sandbox/wsl.rs
git commit -m "feat(sandbox): arch-aware WSL rootfs and setup script"
```

---

### Task 3: Linux bwrap/proot arch-awareness (`rootfs.rs`)

**Files:**
- Modify: `crates/platform/src/desktop/sandbox/rootfs.rs:14-20` (bootstrap URL consts), `rootfs.rs:116-202` (download/extract), `rootfs.rs:205-216` (keyring), `rootfs.rs:283-295` (mirrorlist)

**Interfaces:**
- Consumes: `super::arch::{is_aarch64, ALARM_AARCH64_ROOTFS, pacman_mirrorlist, pacman_keyring}`.
- Produces (module-private): `fn bootstrap_url() -> &'static str`, `fn extracted_subdir_for(aarch64: bool) -> Option<&'static str>`.

**Note:** No arm64 Linux box is available, so the aarch64 extract path is verify-later. The x86_64 path must stay byte-for-byte; the automated guard is the pure `extracted_subdir_for` unit test plus x86_64 compile/clippy.

- [ ] **Step 1: Write the failing test**

Add a `#[cfg(test)] mod tests` block at the end of `rootfs.rs` (the file currently has none):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_bootstrap_archive_has_wrapper_dir_aarch64_is_flat() {
        // The x86_64 Arch bootstrap tarball extracts into a `root.x86_64/`
        // wrapper dir that must then be moved up. The ALARM aarch64 tarball
        // extracts flat (no wrapper), so no move is needed.
        assert_eq!(extracted_subdir_for(false), Some("root.x86_64"));
        assert_eq!(extracted_subdir_for(true), None);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p pentest-platform --features desktop --lib rootfs::tests`
Expected: FAIL to compile — `extracted_subdir_for` not defined.

- [ ] **Step 3: Add the arch selectors**

Below `ARCH_BOOTSTRAP_URL_GZ` (rootfs.rs:20), add `use super::arch;` near the top imports (after line 5) and these helpers:

```rust
/// Base rootfs URL for the current host arch. x86_64 uses the Arch bootstrap
/// tarball; aarch64 uses the ArchLinuxARM aarch64 rootfs (vanilla Arch has no
/// ARM port).
fn bootstrap_url() -> &'static str {
    if arch::is_aarch64() {
        arch::ALARM_AARCH64_ROOTFS
    } else {
        ARCH_BOOTSTRAP_URL
    }
}

/// Name of the wrapper directory the base archive extracts into, if any. The
/// x86_64 Arch bootstrap archive nests everything under `root.x86_64/`; the
/// ALARM aarch64 tarball extracts flat, so there is no wrapper to move.
fn extracted_subdir_for(aarch64: bool) -> Option<&'static str> {
    if aarch64 {
        None
    } else {
        Some("root.x86_64")
    }
}
```

- [ ] **Step 4: Make the extract path arch-aware**

Replace `download_and_extract_rootfs` (rootfs.rs:117-202) so aarch64 downloads the ALARM `.tar.gz` and untars it flat into `rootfs`, while x86_64 keeps the exact existing zst/gz + `root.x86_64` behavior. Full replacement:

```rust
    /// Download and extract the base Arch rootfs
    async fn download_and_extract_rootfs(&self, rootfs: &Path) -> SandboxResult<()> {
        tokio::fs::create_dir_all(rootfs).await?;

        // aarch64: ArchLinuxARM ships a flat .tar.gz that untars directly into
        // the rootfs dir (no `root.<arch>` wrapper like the x86_64 bootstrap).
        if arch::is_aarch64() {
            let tarball_path = self.config.data_dir.join("alarm-rootfs.tar.gz");
            if !tarball_path.exists() {
                tracing::info!("Downloading ArchLinuxARM aarch64 rootfs...");
                self.download_file(bootstrap_url(), &tarball_path).await?;
            }
            tracing::info!("Extracting ALARM rootfs...");
            let status = Command::new("tar")
                .args([
                    "-xzf",
                    &tarball_path.to_string_lossy(),
                    "-C",
                    &rootfs.to_string_lossy(),
                    "--no-same-owner",
                ])
                .status()
                .await
                .map_err(|e| {
                    SandboxError::RootfsSetupFailed(format!("Failed to extract ALARM rootfs: {e}"))
                })?;
            if !status.success() {
                tracing::warn!(
                    "ALARM tar extraction exit code {} (usually harmless symlink perms)",
                    status.code().unwrap_or(-1)
                );
            }
            tokio::fs::remove_file(&tarball_path).await.ok();

            if !rootfs.join("bin").join("bash").exists()
                && !rootfs.join("usr").join("bin").join("bash").exists()
            {
                return Err(SandboxError::RootfsSetupFailed(
                    "ALARM rootfs extraction incomplete - bash not found".to_string(),
                ));
            }
            if !rootfs.join("usr").join("bin").join("pacman").exists() {
                return Err(SandboxError::RootfsSetupFailed(
                    "ALARM rootfs extraction incomplete - pacman not found".to_string(),
                ));
            }
            tracing::info!("ALARM rootfs extraction completed successfully");
            return Ok(());
        }

        let tarball_path = self.config.data_dir.join("arch-bootstrap.tar.zst");

        if !tarball_path.exists() {
            tracing::info!("Downloading Arch bootstrap...");
            if self
                .download_file(bootstrap_url(), &tarball_path)
                .await
                .is_err()
            {
                tracing::info!("Trying gzip fallback...");
                let gz_path = self.config.data_dir.join("arch-bootstrap.tar.gz");
                self.download_file(ARCH_BOOTSTRAP_URL_GZ, &gz_path).await?;
                tokio::fs::rename(&gz_path, &tarball_path).await?;
            }
        }

        tracing::info!("Extracting rootfs...");

        let tarball_str = tarball_path.to_string_lossy();
        let extract_result = if tarball_str.ends_with(".zst") {
            Command::new("tar")
                .args([
                    "--zstd",
                    "-xf",
                    &tarball_str,
                    "-C",
                    &self.config.data_dir.to_string_lossy(),
                    "--no-same-owner",
                ])
                .status()
                .await
        } else {
            Command::new("tar")
                .args([
                    "-xzf",
                    &tarball_str,
                    "-C",
                    &self.config.data_dir.to_string_lossy(),
                    "--no-same-owner",
                ])
                .status()
                .await
        };

        match extract_result {
            Ok(status) => {
                if !status.success() {
                    tracing::warn!("Tar extraction completed with warnings (exit code {}), this is usually due to permission issues with symlinks that don't affect functionality", status.code().unwrap_or(-1));
                }
            }
            Err(e) => {
                return Err(SandboxError::RootfsSetupFailed(format!(
                    "Failed to extract rootfs: {}",
                    e
                )));
            }
        }

        // The archive extracts to a subdirectory, move contents up
        if let Some(subdir) = extracted_subdir_for(false) {
            let extracted_dir = self.config.data_dir.join(subdir);
            if extracted_dir.exists() && extracted_dir != *rootfs {
                if rootfs.exists() {
                    tokio::fs::remove_dir_all(rootfs).await.ok();
                }
                tokio::fs::rename(&extracted_dir, rootfs).await?;
            }
        }

        tokio::fs::remove_file(&tarball_path).await.ok();

        // Verify essential components were extracted
        if !rootfs.join("bin").join("bash").exists() {
            return Err(SandboxError::RootfsSetupFailed(
                "Rootfs extraction incomplete - /bin/bash not found".to_string(),
            ));
        }
        if !rootfs.join("usr").join("bin").join("pacman").exists() {
            return Err(SandboxError::RootfsSetupFailed(
                "Rootfs extraction incomplete - /usr/bin/pacman not found".to_string(),
            ));
        }

        tracing::info!("Rootfs extraction completed successfully");
        Ok(())
    }
```

(Note: `tokio::fs::create_dir_all(rootfs)` moved to the top so both branches share it; the x86_64 branch previously created it mid-function — behavior is identical.)

- [ ] **Step 5: Make the keyring arch-aware**

In `init_pacman_keyring` (rootfs.rs:212-216), change the populate line to use the helper:

```rust
        let init_script = format!(
            "set -e\npacman-key --init\npacman-key --populate {}\n",
            arch::pacman_keyring()
        );
```

Then update the call at rootfs.rs:218 to pass `&init_script` (it is now a `String`):

```rust
        match self.run_in_rootfs(rootfs, &init_script).await {
```

- [ ] **Step 6: Make the mirrorlist arch-aware**

In `sync_packages` (rootfs.rs:286-292), replace the hardcoded write with the helper:

```rust
        let mirrorlist = rootfs.join("etc/pacman.d/mirrorlist");
        tokio::fs::write(&mirrorlist, arch::pacman_mirrorlist()).await?;
```

- [ ] **Step 7: Run tests + clippy**

Run: `cargo test -p pentest-platform --features desktop --lib rootfs::tests`
Expected: PASS (`x86_64_bootstrap_archive_has_wrapper_dir_aarch64_is_flat`).
Run: `cargo clippy -p pentest-platform --features desktop -- -D warnings`
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/platform/src/desktop/sandbox/rootfs.rs
git commit -m "feat(sandbox): arch-aware Linux bwrap/proot rootfs"
```

---

### Task 4: Docker arch-awareness (`docker.rs`)

**Files:**
- Modify: `crates/platform/src/desktop/sandbox/docker.rs:17-49` (platform + Dockerfile consts), `docker.rs:124` (Dockerfile write), `docker.rs:127-137` (build platform), `docker.rs:171-183` (run platform)

**Interfaces:**
- Consumes: `super::arch::{docker_platform, docker_base_image_for, keyring_for, mirrorlist_for, is_aarch64}`.
- Produces (module-private): `fn dockerfile_contents() -> String`, `fn dockerfile_contents_for(aarch64: bool) -> String`. Removes `const DOCKER_PLATFORM` and `const DOCKERFILE_CONTENTS`.

- [ ] **Step 1: Write the failing tests**

Add to the existing `#[cfg(test)] mod tests` block in docker.rs (after the two existing tests). The x86_64 golden string is today's `DOCKERFILE_CONTENTS` verbatim — this asserts x86_64 output is byte-for-byte unchanged.

```rust
    // Today's x86_64 Dockerfile, verbatim — regression guard so the arch-aware
    // builder produces byte-for-byte-identical output on x86_64.
    const DOCKERFILE_X86_64_GOLDEN: &str = r#"FROM --platform=linux/amd64 archlinux:latest

# Configure mirrors
RUN echo 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch' > /etc/pacman.d/mirrorlist && \
    echo 'Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch' >> /etc/pacman.d/mirrorlist

# Fix pacman.conf for container usage
RUN sed -i 's/^CheckSpace/#CheckSpace/' /etc/pacman.conf 2>/dev/null || true && \
    sed -i 's/^DownloadUser/#DownloadUser/' /etc/pacman.conf 2>/dev/null || true

# Initialize pacman keyring and system update
RUN pacman-key --init && \
    pacman-key --populate archlinux && \
    pacman -Syu --noconfirm --overwrite '*'

# Add BlackArch repository and import its key
RUN curl -sL https://blackarch.org/strap.sh -o /tmp/strap.sh && \
    chmod +x /tmp/strap.sh && \
    /tmp/strap.sh && \
    rm /tmp/strap.sh

# Sync package databases
RUN pacman -Sy --noconfirm

WORKDIR /root
"#;

    #[test]
    fn x86_64_dockerfile_is_byte_for_byte_unchanged() {
        assert_eq!(dockerfile_contents_for(false), DOCKERFILE_X86_64_GOLDEN);
    }

    #[test]
    fn aarch64_dockerfile_uses_alarm_base_mirrors_and_keyring() {
        let d = dockerfile_contents_for(true);
        assert!(d.contains("FROM --platform=linux/arm64 menci/archlinuxarm:latest"));
        assert!(d.contains("mirror.archlinuxarm.org/$arch/$repo"));
        assert!(d.contains("pacman-key --populate archlinuxarm"));
        // ALARM: append the BlackArch repo directly rather than strap.sh (which
        // assumes an x86_64 bootstrap). $arch resolves to aarch64 in-container.
        assert!(d.contains("[blackarch]"));
        assert!(d.contains("https://blackarch.org/blackarch/$repo/os/$arch"));
        assert!(!d.contains("strap.sh"));
        assert!(!d.contains("archlinux:latest"));
        assert!(!d.contains("pkgbuild.com"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p pentest-platform --features desktop --lib docker::tests`
Expected: FAIL to compile — `dockerfile_contents_for` not defined.

- [ ] **Step 3: Replace the platform + Dockerfile consts with arch-aware builders**

Delete `const DOCKER_PLATFORM` (docker.rs:17-20) and `const DOCKERFILE_CONTENTS` (docker.rs:22-49). Keep `const DOCKER_IMAGE` (docker.rs:15). Add in their place:

```rust
/// Build the embedded Dockerfile for the current host arch. On x86_64 this is
/// byte-for-byte the original (vanilla Arch + strap.sh); on aarch64 it uses an
/// ArchLinuxARM base image (the official `archlinux` image has no arm64
/// manifest), ALARM mirrors + keyring, and appends the BlackArch aarch64 repo
/// directly (strap.sh assumes an x86_64 bootstrap).
fn dockerfile_contents() -> String {
    dockerfile_contents_for(super::arch::is_aarch64())
}

fn dockerfile_contents_for(aarch64: bool) -> String {
    let from = format!(
        "FROM --platform={} {}",
        super::arch::docker_platform_for(aarch64),
        super::arch::docker_base_image_for(aarch64),
    );
    let mirror_block = if aarch64 {
        "RUN echo 'Server = http://mirror.archlinuxarm.org/$arch/$repo' > /etc/pacman.d/mirrorlist".to_string()
    } else {
        "RUN echo 'Server = https://geo.mirror.pkgbuild.com/$repo/os/$arch' > /etc/pacman.d/mirrorlist && \\\n    echo 'Server = https://mirror.rackspace.com/archlinux/$repo/os/$arch' >> /etc/pacman.d/mirrorlist".to_string()
    };
    let keyring = super::arch::keyring_for(aarch64);
    let blackarch_block = if aarch64 {
        "RUN printf '\\n[blackarch]\\nServer = https://blackarch.org/blackarch/$repo/os/$arch\\nSigLevel = Never\\n' >> /etc/pacman.conf".to_string()
    } else {
        "RUN curl -sL https://blackarch.org/strap.sh -o /tmp/strap.sh && \\\n    chmod +x /tmp/strap.sh && \\\n    /tmp/strap.sh && \\\n    rm /tmp/strap.sh".to_string()
    };
    format!(
        r#"{from}

# Configure mirrors
{mirror_block}

# Fix pacman.conf for container usage
RUN sed -i 's/^CheckSpace/#CheckSpace/' /etc/pacman.conf 2>/dev/null || true && \
    sed -i 's/^DownloadUser/#DownloadUser/' /etc/pacman.conf 2>/dev/null || true

# Initialize pacman keyring and system update
RUN pacman-key --init && \
    pacman-key --populate {keyring} && \
    pacman -Syu --noconfirm --overwrite '*'

# Add BlackArch repository and import its key
{blackarch_block}

# Sync package databases
RUN pacman -Sy --noconfirm

WORKDIR /root
"#
    )
}
```

(On x86_64: `from` = `FROM --platform=linux/amd64 archlinux:latest`, `mirror_block` reproduces the two-echo block, `keyring` = `archlinux`, `blackarch_block` reproduces the strap.sh block — so the render equals `DOCKERFILE_X86_64_GOLDEN` exactly. The `\\n`/`\\\n` in the block strings are ordinary Rust escapes producing a literal `\n` for `printf` and a backslash-newline for Dockerfile line-continuation respectively.)

- [ ] **Step 4: Update the Dockerfile write site**

At docker.rs:124, use the builder:

```rust
        tokio::fs::write(&dockerfile_path, dockerfile_contents()).await?;
```

- [ ] **Step 5: Update the build `--platform`**

In `ensure_image`, the `docker build` args (docker.rs:128-136) pass `DOCKER_PLATFORM`. Replace with `super::arch::docker_platform()`:

```rust
            .args([
                "build",
                "--platform",
                super::arch::docker_platform(),
                "-t",
                DOCKER_IMAGE,
                "-f",
                &dockerfile_path.to_string_lossy(),
                &dockerfile_dir.to_string_lossy(),
            ])
```

- [ ] **Step 6: Update the run `--platform`**

In `execute`, the run args build a `Vec<String>` (docker.rs:171-183). Replace the `DOCKER_PLATFORM.to_string()` entry (docker.rs:176) with:

```rust
            super::arch::docker_platform().to_string(),
```

Also update the two comments that say "Apple Silicon compatibility / Rosetta / QEMU emulation" (docker.rs:18-19 comment is deleted with the const; the inline comments at docker.rs:174 "Pin platform for Apple Silicon compatibility" and docker.rs:126 "pin platform to linux/amd64 for BlackArch compatibility") to reflect arch-aware selection, e.g. "Select platform for the host arch (arm64 native on Apple Silicon, amd64 on Intel)".

- [ ] **Step 7: Run tests + clippy**

Run: `cargo test -p pentest-platform --features desktop --lib docker::tests`
Expected: PASS — including `x86_64_dockerfile_is_byte_for_byte_unchanged` and `aarch64_dockerfile_uses_alarm_base_mirrors_and_keyring`.
Run: `cargo clippy -p pentest-platform --features desktop -- -D warnings`
Expected: no warnings.

- [ ] **Step 8: Commit**

```bash
git add crates/platform/src/desktop/sandbox/docker.rs
git commit -m "feat(sandbox): arch-aware Docker platform, base image, and mirrors"
```

---

### Task 5: Desktop exec-sanity harness test (`tests/sandbox_backends.rs`)

**Files:**
- Modify: `crates/platform/tests/sandbox_backends.rs:7-8` (imports), append new test.

**Interfaces:**
- Consumes: `pentest_platform::desktop::sandbox::SandboxManager`, `probe::any_backend_available`, `config::SandboxConfig`.

- [ ] **Step 1: Add the exec-sanity test**

Update the imports (sandbox_backends.rs:7-8) to add `any_backend_available` and `SandboxManager`:

```rust
use pentest_platform::desktop::sandbox::config::SandboxConfig;
use pentest_platform::desktop::sandbox::probe::{any_backend_available, probe_all, BackendStatus};
use pentest_platform::desktop::sandbox::SandboxManager;
use std::time::Duration;
```

Append this test to the file:

```rust
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
```

- [ ] **Step 2: Verify it compiles and is collected (but skipped by default)**

Run: `cargo test -p pentest-platform --features desktop --test sandbox_backends`
Expected: compiles; the new test shows as `ignored` (not run without `--ignored`).

- [ ] **Step 3: Clippy on the test target**

Run: `cargo clippy -p pentest-platform --features desktop --tests -- -D warnings`
Expected: no warnings.

- [ ] **Step 4: Commit**

```bash
git add crates/platform/tests/sandbox_backends.rs
git commit -m "test(sandbox): exec-sanity check that a Working backend runs and matches host arch"
```

- [ ] **Step 5: (Manual, real-hardware) Record verification**

This is not a code step — note it in the progress ledger for the reviewer. Run on the arm64 Mac (10.10.0.8, Docker provisioned) and, when available, the arm64 Windows box (10.10.0.38, WSL) and an x64 box:

```bash
cargo test -p pentest-platform --features desktop --test sandbox_backends -- --ignored working_backend_executes_and_reports_host_arch --nocapture
```

Expected on arm64 Mac: passes with `uname -m` == `aarch64` (arm64-native container, no emulation). Record pass/fail per box; do not block the branch on boxes that are unavailable, but log which arches were actually exercised.

---

### Task 6: Android exec-sanity test (`android/proot/mod.rs`)

**Files:**
- Modify: `crates/platform/src/android/proot/mod.rs` (append an android-gated test module).

**Interfaces:**
- Consumes: `execute_in_proot(cmd: &str, args: &[&str], timeout: Duration) -> Result<CommandResult>` (already public in this module).

**Note:** This compiles only under an Android target and runs only on a device/emulator with a provisioned proot rootfs. Verification here is compile-check under both Android targets; the run is device-only/manual. Android is already arch-aware (`get_rootfs_url`/`detect_arch`) — this test locks that in against regression.

- [ ] **Step 1: Add the android-gated ignored test**

Append to `crates/platform/src/android/proot/mod.rs`:

```rust
#[cfg(all(test, target_os = "android"))]
mod arch_sanity {
    use super::*;
    use std::time::Duration;

    // Proves the proot shell actually executes and the guest arch matches the
    // device — the same coverage the desktop exec-sanity test gives. Android is
    // already arch-aware (see rootfs::get_rootfs_url / detect_arch); this guards
    // against a future regression (e.g. a bad rootfs URL) that would reintroduce
    // an Exec-format-error like the desktop arm64 bug. Device/emulator only.
    #[tokio::test]
    #[ignore = "requires a provisioned proot rootfs on-device; run with --ignored on a device/emulator"]
    async fn proot_executes_and_reports_device_arch() {
        let out = execute_in_proot("uname", &["-m"], Duration::from_secs(900))
            .await
            .expect("proot must execute uname, not Exec-format-error");
        assert_eq!(
            out.stdout.trim(),
            std::env::consts::ARCH,
            "proot `uname -m` should equal device arch {}; got {:?}",
            std::env::consts::ARCH,
            out
        );
    }
}
```

- [ ] **Step 2: Compile-check under both Android targets**

The nix dev shell provides the Android targets (see project memory). Run:

```bash
cargo check -p pentest-platform --features android --target aarch64-linux-android
cargo check -p pentest-platform --features android --target x86_64-linux-android
```

Expected: both compile. (If the environment lacks the Android NDK/targets, record that the compile-check could not run here and must run in the Android CI path — do not fake it.)

- [ ] **Step 3: Clippy (android feature, aarch64 target)**

```bash
cargo clippy -p pentest-platform --features android --target aarch64-linux-android -- -D warnings
```

Expected: no warnings. (Skip only if the Android toolchain is unavailable; record that.)

- [ ] **Step 4: Commit**

```bash
git add crates/platform/src/android/proot/mod.rs
git commit -m "test(android): exec-sanity check that proot runs and matches device arch"
```

- [ ] **Step 5: (Manual, device) Record verification**

Note in the ledger: on an arm64 device and an x86_64 emulator, run the ignored test and record `uname -m` == device arch. Not a blocker for boxes/devices unavailable now.

---

## Self-Review

**1. Spec coverage** (against `docs/superpowers/specs/2026-07-29-arm64-sandbox-support-design.md`):
- Goal 1 (arch-aware WSL + Linux + Docker): Tasks 1-4. ✓
- Goal 2 (x86_64 byte-for-byte): golden-string test (Task 4), `wsl_rootfs_url`/x86_64 script keeps ArchWSL + pkgbuild (Task 2), `extracted_subdir_for(false)` + unchanged x86_64 extract branch (Task 3). ✓
- Goal 3 (real exec-sanity in tests, not the probe): Task 5 (desktop) + Task 6 (Android); probe.rs untouched. ✓
- Shared helper consumed by all three backends: `arch.rs` (Task 1) used in Tasks 2/3/4. ✓
- ALARM mirrors + `archlinuxarm` keyring on arm64; `[blackarch]` `$arch` unchanged: Tasks 2/3/4. ✓
- Docker: `menci/archlinuxarm` + `linux/arm64` native + direct blackarch repo append on arm64: Task 4. ✓
- macOS is a verifiable arm64 target: Task 5 Step 5. ✓

**2. Placeholder scan:** No TBD/TODO/"handle edge cases"/"similar to Task N". Every code step shows full code. ✓

**3. Type consistency:** `is_aarch64`, `keyring_for`, `mirrorlist_for`, `docker_platform`/`docker_platform_for`, `docker_base_image_for`, `pacman_keyring`, `pacman_mirrorlist`, `ALARM_AARCH64_ROOTFS` — names identical across Tasks 1-4. `wsl_setup_script`/`wsl_setup_script_for`, `wsl_rootfs_url`, `bootstrap_url`, `extracted_subdir_for`, `dockerfile_contents`/`dockerfile_contents_for` — each defined once and referenced consistently. `execute_in_proot`/`SandboxManager::execute` signatures match the source read. ✓

**Known limitation (called out, not a gap):** the arm64 *Linux* bwrap/proot extract path (Task 3) has no available test hardware; its automated guard is the pure `extracted_subdir_for` test + x86_64 compile. Verify on real arm64 Linux when a box exists. arm64 *Windows* WSL2 also remains untested (only WSL1-capable arm box available). Both are documented in the spec's Risks.
