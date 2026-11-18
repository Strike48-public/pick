#!/bin/sh
# Pick desktop launcher — the entry point of the Linux release tarball.
#
# The real binary (pentest-connector-bin, next to this script) resolves
# the host libraries bundled in ./lib (libpcap, libxcb, libxdo, OpenSSL
# and the transitive closure of each) through its $ORIGIN/lib rpath, so
# no LD_LIBRARY_PATH juggling is needed. The only host-provided stack
# the tarball deliberately leaves to the host is WebKit2GTK *and its
# package dependencies* — the GTK/X11 web engine, 50MB+ with its helper
# processes, for which the strikehub AppImage is the shipping vehicle
# (strikehub#102 precedent). Installing libwebkit2gtk-4.1-0 pulls that
# whole closure (libgtk-3, libgdk-3, libcairo, libsoup-3.0, libX11, ...)
#
# Because the binary links WebKit2GTK as a NEEDED library, a host
# without it dies inside the dynamic loader — before any of Pick's own
# code, logging or error handling can run (silent death). This launcher
# probes for that gap up front and turns it into an actionable error.
set -u

# CDPATH= is a deliberate guard: a user-set CDPATH would turn `cd` into a
# glob-expanding cd that prints the target dir and breaks the path.
# readlink -f resolves $0 through symlinks (ln -s .../pentest-connector
# ~/.local/bin/pick must still find the binary next to the REAL launcher,
# the way the pre-PR bare ELF found its $ORIGIN via /proc/self/exe).
self=$(readlink -f -- "$0" 2>/dev/null) || self=$0
# shellcheck disable=SC1007
here=$(CDPATH= cd -- "$(dirname -- "$self")" && pwd)
bin="$here/pentest-connector-bin"

if [ ! -x "$bin" ]; then
    echo "pick: cannot find the desktop binary at $bin" >&2
    echo "pick: extract the tarball as-is — pentest-connector, pentest-connector-bin and lib/ must stay together" >&2
    exit 127
fi

# ldd ships with glibc, so the probe works on every supported host. On
# the rare system without ldd, fall through and let the loader speak.
if command -v ldd >/dev/null 2>&1; then
    missing=$(ldd "$bin" 2>/dev/null | grep '=> not found' || true)
    if [ -n "$missing" ]; then
        {
            echo "pick: cannot start the desktop app: shared libraries are missing from this system:"
            printf '%s\n' "$missing" | sed 's/^[[:space:]]*/  /'
            echo ""
            echo "The Linux tarball bundles libpcap, libxcb, libxdo, OpenSSL"
            echo "and the transitive closure of each under lib/."
            case "$missing" in
                *libwebkit2gtk*)
                    echo "WebKit2GTK (the web engine behind the UI) and its"
                    echo "package dependencies (the GTK/X11 stack) are the one"
                    echo "host-provided stack; install it and re-run:"
                    echo ""
                    echo "  Debian/Ubuntu:  sudo apt install libwebkit2gtk-4.1-0"
                    echo "  Fedora:         sudo dnf install webkit2gtk4.1"
                    echo "  Arch:           sudo pacman -S webkit2gtk-4.1"
                    ;;
                *)
                    echo "The tarball does not provide these libraries. Install the"
                    echo "distribution packages that provide them, then re-run."
                    ;;
            esac
        } >&2
        exit 127
    fi
fi

exec "$bin" "$@"
