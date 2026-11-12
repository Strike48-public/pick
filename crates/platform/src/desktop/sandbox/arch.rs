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

/// ArchLinuxARM aarch64 root filesystem tarball. Generic aarch64 build (NOT a
/// board-specific `-rpi-`/`-chromebook-` image): the sandbox runs this userland
/// on the host's existing kernel (WSL / Docker VM / Linux), so it only depends
/// on the CPU instruction set (aarch64), never on board/kernel specifics. Plain
/// `.tar.gz`, accepted by both `wsl --import` (WSL backend) and `tar -xzf`
/// (Linux bwrap/proot backend), so the two share this single source and never
/// drift. `os.archlinuxarm.org` 302-redirects to a geographic mirror; `reqwest`
/// follows redirects.
///
/// Pinned aarch64 sandbox rootfs, self-hosted under the `alarm-aarch64-v1`
/// release tag on Strike48-public/pick (tarball + `.sha256` sidecar).
///
/// Upstream (os.archlinuxarm.org) serves this image over plaintext HTTP only
/// (its HTTPS cert doesn't match the host) and publishes ONLY a rolling
/// `-latest` — nothing versioned to pin — so we freeze a copy as a release
/// asset and verify every download against [`ALARM_AARCH64_ROOTFS_SHA256`]
/// before extraction (same refuse-unverified contract as the proot binaries in
/// `proot.rs`). This closes the "KNOWN LIMITATION (integrity)" that used to
/// live here; see #624.
///
/// Republish (when a newer ALARM cut is wanted): download
/// `http://os.archlinuxarm.org/os/ArchLinuxARM-aarch64-latest.tar.gz`, vet it,
/// upload it + its sha256 sidecar under a NEW tag (`alarm-aarch64-v2`), then
/// bump both constants here. Extraction still fails closed: a corrupt/hostile
/// rootfs that lacks `bash`/`pacman` is rejected by the post-extract checks.
pub(super) const ALARM_AARCH64_ROOTFS: &str =
    "https://github.com/Strike48-public/pick/releases/download/alarm-aarch64-v1/alarm-aarch64.tar.gz";

/// Lowercase hex SHA-256 of [`ALARM_AARCH64_ROOTFS`], verified after download
/// and before the tarball is used; empty = refuse (unverifiable).
pub(super) const ALARM_AARCH64_ROOTFS_SHA256: &str = "42a4eeaa038994ffd31fa173256ef2f0ef511358eeb41b9ea1f8626391b9b319";

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
    fn alarm_rootfs_is_a_pinned_plain_targz() {
        // #624: the ALARM rootfs is a self-hosted, pinned release asset (the
        // upstream host is plaintext-HTTP-only). It must stay a plain
        // .tar.gz — extraction uses `tar -xzf`.
        assert!(ALARM_AARCH64_ROOTFS.ends_with(".tar.gz"));
        assert!(ALARM_AARCH64_ROOTFS.contains(
            "github.com/Strike48-public/pick/releases/download/alarm-aarch64-v1/"
        ));
    }
}
