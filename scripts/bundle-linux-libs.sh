#!/usr/bin/env bash
# Bundle RUNTIME shared libraries into a release tarball's lib/ directory.
#
# The release Package steps (desktop, web, headless) each ship their small
# host libraries plus the transitive closure of each bundled library under
# lib/, resolved via the $ORIGIN/lib rpath baked into the binaries at link
# time. Sourcing from the RUNTIME packages (libpcap0.8, not libpcap-dev)
# keeps the real versioned .so files, not the -dev symlinks.
#
# One shared implementation here so the three jobs cannot drift (the
# libXdo/libxdo case bug was exactly such a drift: the soname on jammy is
# lowercase — verify any (package, soname) pair with
# `dpkg -L <pkg> | grep -E "/<soname>$"` before adding it).
#
# Usage: bundle-linux-libs.sh <dest-lib-dir> <package:soname>...
set -euo pipefail

dest=${1:?usage: bundle-linux-libs.sh <dest-lib-dir> <package:soname>...}
shift
[ $# -gt 0 ] || { echo "no libraries given" >&2; exit 2; }
command -v dpkg >/dev/null || { echo "dpkg not found (bundle-linux-libs runs on the ubuntu runner)" >&2; exit 2; }

install -d "$dest"

bundle_lib() {
    local pkg=$1 soname=$2 f
    f=$(dpkg -L "$pkg" 2>/dev/null | grep -E "/$soname$" | head -1 || true)
    if [ -z "$f" ] || [ ! -f "$f" ]; then
        echo "bundled source library not found: $pkg ($soname)" >&2
        exit 1
    fi
    cp "$f" "$dest/"
}

for spec in "$@"; do
    case "$spec" in
        *:*) ;;
        *)
            echo "bad spec (want package:soname): $spec" >&2
            exit 2
            ;;
    esac
    bundle_lib "${spec%%:*}" "${spec#*:}"
    echo "bundled ${spec#*:} from ${spec%%:*}"
done
