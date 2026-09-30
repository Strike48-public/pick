#!/usr/bin/env bash
# Run the Pick workspace build/test inside a Linux container (Colima or Docker
# Desktop), mirroring the CI Linux lane, so compilation and test execution run
# in Linux instead of on a developer's host. Two reasons to prefer it locally:
#
#   1. Endpoint security (EDR) on some managed macOS hosts terminates and
#      quarantines test binaries that spawn adversarial argv - Pick's
#      command-injection *defense* fixtures - deleting the binary mid-run. In
#      the VM those processes are invisible to the host agent and run normally.
#   2. It matches CI's Linux OS, catching Linux-only failures that a macOS host
#      would miss.
#
# Usage (anything after the script name is passed straight to `cargo`):
#   ./docker/dev-test/test.sh                        # full CI test line (default)
#   ./docker/dev-test/test.sh test -p pentest-core --locked <filter>
#   ./docker/dev-test/test.sh check --workspace --locked --features pentest-platform/desktop-pcap
#   ./docker/dev-test/test.sh clippy --workspace --locked --features pentest-platform/desktop-pcap -- -D warnings
#
# With no args, runs the exact ci.yml `test` job command. With args, they are
# passed verbatim to cargo - supply your own --features when you scope a run.
#
# Env:
#   PICK_DIR   pick workspace to mount   (default: repo root of this script)
#   PLATFORM   linux/amd64 for x86_64 (CI arch) parity via qemu - SLOW
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PICK_DIR="${PICK_DIR:-$(git -C "$HERE" rev-parse --show-toplevel 2>/dev/null || (cd "$HERE/../.." && pwd))}"
IMAGE="pick-ci:local"
PLATFORM="${PLATFORM:-}"

# --- preflight -------------------------------------------------------------
command -v docker >/dev/null 2>&1 || { echo "docker not found on PATH." >&2; exit 1; }
docker info >/dev/null 2>&1 || {
  echo "docker daemon not reachable. On macOS start a Linux backend, e.g.: colima start" >&2; exit 1; }
[ -f "$PICK_DIR/Cargo.toml" ] || {
  echo "PICK_DIR='$PICK_DIR' is not the pick workspace root. Set PICK_DIR." >&2; exit 1; }

# --- default command mirrors ci.yml `test` job exactly ---------------------
if [ "$#" -eq 0 ]; then
  set -- test --workspace --locked --no-fail-fast --features pentest-platform/desktop-pcap
fi

PLAT_ARGS=()
[ -n "$PLATFORM" ] && PLAT_ARGS=(--platform "$PLATFORM")

# --- build image (fast when the Dockerfile layer cache is warm) ------------
echo ">> building $IMAGE ${PLATFORM:+($PLATFORM)}" >&2
docker build "${PLAT_ARGS[@]}" -t "$IMAGE" "$HERE" >&2

# --- run -------------------------------------------------------------------
# Named volumes keep the registry cache and target dir INSIDE the VM, so the
# host's target/ is never touched and builds cache across runs. Source is
# bind-mounted; artifacts land on the /target volume via CARGO_TARGET_DIR.
echo ">> cargo $*" >&2
exec docker run --rm "${PLAT_ARGS[@]}" \
  -v "$PICK_DIR":/work -w /work \
  -v pick-ci-registry:/usr/local/cargo/registry \
  -v pick-ci-target:/target \
  -e CARGO_TARGET_DIR=/target \
  -e DISABLE_SANDBOX=true \
  -e CARGO_TERM_COLOR=always \
  -e CARGO_BUILD_JOBS \
  "$IMAGE" \
  cargo "$@"
# CARGO_BUILD_JOBS is forwarded only when set (unset = full parallelism). A full
# `cargo test --workspace` does full codegen for the whole graph, including the
# heavy desktop UI crate (lucide-dioxus all-icons); at high job counts its peak
# RAM can exceed a small VM and the Linux OOM killer SIGKILLs rustc. If that
# happens, cap it, e.g.  CARGO_BUILD_JOBS=3 ./docker/dev-test/test.sh
