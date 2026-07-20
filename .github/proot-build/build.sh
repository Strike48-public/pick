#!/usr/bin/env bash
# Build a static, openat2-capable proot from termux/proot (#248/#252).
#
# Runs INSIDE a debian:bookworm container (see build-proot.yml), with the repo
# bind-mounted at /work. Reads $TERMUX_PROOT_REF and $ARCH from the env.
# Recipe verified A/B during the #248 spike:
#   - glibc-static (musl fails on `struct rlimit64`)
#   - let the makefile auto-detect the lld-only `--rosegment` flag: its src/GNUmakefile
#     probe test-links with `-Wl,--rosegment` and only enables it if the linker
#     accepts it, so on GNU ld (which rejects it) it is skipped automatically.
#     Do NOT sed it out — the flag's only literal occurrence is inside that probe,
#     so editing it breaks detection and forces `--rosegment` onto the real link
#     line, which GNU ld then rejects (the loader/loader link fails).
#   - stub <linux/ashmem.h> so the Android-only ashmem_memfd extension compiles
#     (do NOT delete the object — cli/proot.c references ashmem_memfd_callback)
set -euo pipefail

: "${TERMUX_PROOT_REF:?TERMUX_PROOT_REF must be set}"
: "${ARCH:?ARCH must be set}"

apt-get update
apt-get install -y --no-install-recommends \
  git ca-certificates build-essential libc6-dev \
  pkg-config uthash-dev libtalloc-dev python3 gzip file

git clone https://github.com/termux/proot /src
cd /src
git checkout "$TERMUX_PROOT_REF"

# NOTE: no --rosegment patch. The makefile's own probe (src/GNUmakefile) disables
# the flag on GNU ld automatically; sed-ing it out corrupts that probe and forces
# the flag on, breaking the loader link (#252, first live run of this workflow).

# Patch: install the committed linux/ashmem.h stub.
mkdir -p /usr/include/linux
cp /work/.github/proot-build/ashmem.h /usr/include/linux/ashmem.h

# Static glibc build.
#
# LDFLAGS via the ENVIRONMENT, not as a make argument: `make LDFLAGS=-static` is
# a command-line assignment that OVERRIDES the makefile's
# `LDFLAGS += -ltalloc -Wl,-z,noexecstack` (src/GNUmakefile:19), dropping
# -ltalloc and failing the final link with `undefined reference to _talloc_*`.
# In the environment, the makefile's `+=` appends, so both -static and -ltalloc
# reach the link. (GNU make: env vars have lower precedence than `+=`.)
#
# HAS_LOADER_32BIT= (command-line, empty) disables the 32-bit compat loader. The
# makefile derives it from arch.h and, on aarch64, tries to build loader-m32 with
# `cc -m32` — which the aarch64 toolchain has no notion of (`unrecognized
# command-line option '-m32'`). The sandbox only runs native-arch tools, so the
# 32-bit guest loader is dead weight; disable it on every arch for a uniform,
# reproducible build. (GNU make: a command-line `VAR=` overrides the makefile's
# `:=`, and `ifdef` on the resulting empty value is false.)
LDFLAGS="-static" make -C src HAS_LOADER_32BIT= V=1
/src/src/proot --version

cp /src/src/proot "/work/proot-${ARCH}"
file "/work/proot-${ARCH}"
