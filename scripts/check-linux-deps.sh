#!/usr/bin/env bash
# Fail if an extracted Pick Linux release tarball references a shared
# library that is neither bundled in its lib/ directory nor present in
# the supported host environment. Companion to check-glibc-floor.sh:
# that script enforces the glibc/GLIBCXX *version* floor; this one
# enforces that there are no unresolved ("not found") NEEDED entries at
# all, so a release cannot silently depend on a host package nobody
# documented (field incident: a released agent died on NixOS with
# `error while loading shared libraries: libpcap.so.0.8` and its stderr
# was discarded by the supervisor).
#
# ldd resolves against the machine running the check (CI: the
# ubuntu-22.04 runner, where every build-time host library is
# installed), so "not found" there means the artifact references a
# library the supported build environment does not provide — which no
# supported host will either, and bundling cannot express.
#
# One exception is allowed on purpose: the desktop app does not bundle
# WebKit2GTK (50MB+ with its helper processes; the strikehub AppImage
# is the vehicle that bundles webkit). Pass --allow-missing per
# soname for an intentionally host-provided library; the docs must name
# the matching package for every allowed soname.
#
# The script also asserts the rpath invariant: when a tarball ships a
# lib/ directory, every executable ELF in it (i.e. outside lib/) must
# carry an RPATH/RUNPATH entry pointing at lib/ relative to the
# binary's own directory (root-level binary -> $ORIGIN/lib,
# bin/x -> $ORIGIN/../lib), or the bundled libraries would sit in the
# archive unused.
#
# Usage: check-linux-deps.sh <extracted-tarball-dir>
#                [--allow-missing SONAME]... [--glibc FLOOR] [--glibcxx FLOOR]
set -euo pipefail

ROOT=${1:?usage: check-linux-deps.sh <extracted-tarball-dir> [--allow-missing SONAME]... [--glibc FLOOR] [--glibcxx FLOOR]}
shift

ALLOW_MISSING=()
GLIBC_FLOOR=2.35
GLIBCXX_FLOOR=3.4.30
while [ $# -gt 0 ]; do
    case "$1" in
        --allow-missing)
            ALLOW_MISSING+=("${2:?--allow-missing requires a soname}")
            shift 2
            ;;
        --glibc)
            GLIBC_FLOOR=${2:?--glibc requires a version}
            shift 2
            ;;
        --glibcxx)
            GLIBCXX_FLOOR=${2:?--glibcxx requires a version}
            shift 2
            ;;
        *)
            echo "unknown argument: $1" >&2
            exit 2
            ;;
    esac
done

[ -d "$ROOT" ] || { echo "not a directory: $ROOT" >&2; exit 2; }
command -v ldd >/dev/null || { echo "ldd not found on this machine" >&2; exit 2; }

# True when SONAME $1 is in the allow list.
allowed() {
    local a
    for a in "${ALLOW_MISSING[@]:-}"; do
        [ -n "$a" ] && [ "$a" = "$1" ] && return 0
    done
    return 1
}

# The RPATH/RUNPATH entry that must point at ROOT/lib from the
# directory containing FILE (FILE relative to ROOT).
want_rpath() {
    local rel=$1
    local rel_to_lib=lib
    local noslash
    noslash=${rel//\//}
    local depth=$(( ${#rel} - ${#noslash} ))
    local i=0
    while [ "$i" -lt "$depth" ]; do
        rel_to_lib="../$rel_to_lib"
        i=$((i + 1))
    done
    # Literal $ORIGIN is intended in the emitted rpath token.
    # shellcheck disable=SC2016
    printf '$ORIGIN/%s' "$rel_to_lib"
}

BAD=0
CHECKED=0
ALLOWED_SEEN=0
while IFS= read -r -d '' f; do
    file -b "$f" 2>/dev/null | grep -q '^ELF' || continue
    CHECKED=$((CHECKED + 1))
    rel=${f#"$ROOT"/}

    # ldd prints "  <lib> => not found" per unresolved NEEDED entry and
    # (independently of its exit code) we report every gap at once.
    out=$(ldd "$f" 2>&1) || true
    missing=$(printf '%s\n' "$out" | grep '=> not found' | sed -E 's/^[[:space:]]+([^[:space:]]+).*/\1/' || true)
    if [ -n "$missing" ]; then
        while IFS= read -r lib; do
            [ -n "$lib" ] || continue
            if allowed "$lib"; then
                ALLOWED_SEEN=$((ALLOWED_SEEN + 1))
                echo "host-provided (allowed): $lib (in $rel)"
            else
                echo "MISSING shared library: $lib (in $rel)"
                BAD=1
            fi
        done <<< "$missing"
    fi

    # rpath invariant: an artifact that ships lib/ must point its
    # executables at it.
    case "$rel" in
        lib/*) : ;;
        *)
            if [ -d "$ROOT/lib" ]; then
                want=$(want_rpath "$rel")
                if readelf -d "$f" 2>/dev/null | grep -E '\((RPATH|RUNPATH)\)' | grep -qF "$want"; then
                    :
                else
                    echo "no $want rpath on $rel while the tarball ships lib/"
                    BAD=1
                fi
            fi
            ;;
    esac
done < <(find "$ROOT" -type f -print0)

[ "$CHECKED" -gt 0 ] || { echo "no ELF files found under $ROOT" >&2; exit 1; }
[ "$BAD" -eq 0 ] || {
    echo "release artifact(s) reference shared libraries that are neither bundled nor host-guaranteed" >&2
    exit 1
}

# The version-floor guard still applies (bundled libs included).
echo "all $CHECKED ELF files resolve their shared libraries (host-provided: $ALLOWED_SEEN)"
scripts_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
"$scripts_dir/check-glibc-floor.sh" "$ROOT" "$GLIBC_FLOOR" "$GLIBCXX_FLOOR"
