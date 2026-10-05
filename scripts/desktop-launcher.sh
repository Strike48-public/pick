#!/bin/sh
# Pick desktop launcher — the entry point of the Linux release tarball.
#
# The real binary (pentest-connector-bin, next to this script) resolves
# the small host libraries bundled in ./lib through its $ORIGIN/lib
# rpath, so no LD_LIBRARY_PATH juggling is needed. The ONE library the
# tarball deliberately does not bundle is WebKit2GTK — the web engine
# behind the UI, 50MB+ with its helper processes, for which the
# strikehub AppImage is the shipping vehicle (strikehub#102 precedent).
#
# Because the binary links WebKit2GTK as a NEEDED library, a host
# without it dies inside the dynamic loader — before any of Pick's own
# code, logging or error handling can run (silent death). This launcher
# probes for that gap up front and turns it into an actionable error.
set -u

# CDPATH= is a deliberate guard: a user-set CDPATH would turn `cd` into a
# glob-expanding cd that prints the target dir and breaks the path.
# shellcheck disable=SC1007
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
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
            echo "The Linux tarball bundles libpcap, libxcb and libXdo under lib/."
            case "$missing" in
                *libwebkit2gtk*)
                    echo "WebKit2GTK (the web engine behind the UI) is the one"
                    echo "host-provided dependency; install it and re-run:"
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
