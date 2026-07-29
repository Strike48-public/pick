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

#![allow(dead_code)] // Task 1: helpers unused until Tasks 2-4 wire backends

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
