#!/usr/bin/env bash
# Build a static, openat2-capable proot from termux/proot (#248/#252).
#
# Runs INSIDE a debian:bookworm container (see build-proot.yml), with the repo
# bind-mounted at /work. Reads $TERMUX_PROOT_REF and $ARCH from the env.
# Recipe verified A/B during the #248 spike:
#   - glibc-static (musl fails on `struct rlimit64`)
#   - strip the lld-only `--rosegment` linker flag (GNU ld rejects it)
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

# Patch 1: strip the lld-only --rosegment flag (GNU ld rejects it).
if grep -rl -- "--rosegment" . >/dev/null 2>&1; then
  grep -rl -- "--rosegment" . | xargs sed -i "s/-Wl,--rosegment//g"
fi

# Patch 2: install the committed linux/ashmem.h stub.
mkdir -p /usr/include/linux
cp /work/.github/proot-build/ashmem.h /usr/include/linux/ashmem.h

# Static glibc build.
make -C src LDFLAGS="-static" V=1
/src/src/proot --version

cp /src/src/proot "/work/proot-${ARCH}"
file "/work/proot-${ARCH}"
