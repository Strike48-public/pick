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

# Static glibc build. Pass LDFLAGS through the ENVIRONMENT, not as a make
# argument: `make LDFLAGS=-static` is a command-line assignment that OVERRIDES
# the makefile's `LDFLAGS += -ltalloc -Wl,-z,noexecstack` (src/GNUmakefile:19),
# dropping -ltalloc and failing the final link with `undefined reference to
# _talloc_*`. Setting it in the environment lets the makefile's `+=` append, so
# both -static and -ltalloc reach the link. (Verified: GNU make gives env vars
# lower precedence than `+=`, command-line vars higher.)
LDFLAGS="-static" make -C src V=1
/src/src/proot --version

cp /src/src/proot "/work/proot-${ARCH}"
file "/work/proot-${ARCH}"
