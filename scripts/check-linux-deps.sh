#!/usr/bin/env bash
# Fail if an extracted Pick Linux release tarball is not self-contained.
#
# Companion to check-glibc-floor.sh: that script pins the glibc/GLIBCXX
# *version* floor; this one enforces that the artifact ships every shared
# library it needs. Every release artifact verified by this script must:
#
#   1. ship its bundled libraries in lib/ — a tarball without lib/ is the
#      field-incident shape (a bare ELF that dies in the dynamic loader on
#      any host missing one package: NixOS, minimal containers), so the
#      absence of lib/ is itself a failure;
#   2. carry the $ORIGIN/...-to-lib/ rpath entry on every executable ELF
#      outside lib/ (whole-entry compare of the ':'-separated
#      RPATH/RUNPATH list, so $ORIGIN/libexec or /opt/x$ORIGIN/lib cannot
#      masquerade as $ORIGIN/lib) — otherwise the bundled libraries would
#      sit in the archive unused;
#   3. resolve every NEEDED entry (per ldd) to one of:
#        - a file under <root>/lib  (bundled),
#        - a base-system library    (the glibc/libgcc/libstdc++ floor),
#        - an explicitly allowed soname (--allow-missing / --allow-missing-file),
#      and never to "not found" unless explicitly allowed.
#
# Rule 3 is deliberately strict because of WHERE the check runs: the
# release runner is a SUPERSET of the supported hosts — every build-time
# library is installed there, so a bare "=> not found" test can never go
# red on the runner and an unbundled dependency silently resolves from
# /lib. Comparing every resolution path against the artifact's own lib/
# is what makes the step fail on the runner for exactly the failures that
# would kill a minimal host (and makes dropping a bundled library, or a
# new unexpected NEEDED, fail the release at package time).
#
# Intentionally host-provided stacks are allowed per soname. The desktop
# app does not bundle WebKit2GTK (50MB+ with its helper processes; the
# strikehub AppImage is the vehicle that bundles webkit, strikehub#102) —
# its whole GTK/X11/web-engine package closure is documented as the one
# host-provided line and allowlisted from the runner's package metadata
# (see the release.yml Verify step), not hardcoded here. For every
# allowed soname the docs must name the matching host package.
#
# Usage: check-linux-deps.sh <extracted-tarball-dir>
#                [--allow-missing SONAME]...
#                [--allow-missing-file FILE]
#                [--expect-file NAME]...
#                [--glibc FLOOR] [--glibcxx FLOOR]
set -euo pipefail

ROOT=${1:?usage: check-linux-deps.sh <extracted-tarball-dir> [--allow-missing SONAME]... [--allow-missing-file FILE] [--expect-file NAME]... [--glibc FLOOR] [--glibcxx FLOOR]}
shift

ALLOW_MISSING=()
ALLOW_MISSING_FILE=""
EXPECT_FILES=()
GLIBC_FLOOR=2.35
GLIBCXX_FLOOR=3.4.30
while [ $# -gt 0 ]; do
    case "$1" in
        --allow-missing)
            ALLOW_MISSING+=("${2:?--allow-missing requires a soname}")
            shift 2
            ;;
        --allow-missing-file)
            ALLOW_MISSING_FILE=${2:?--allow-missing-file requires a file}
            shift 2
            ;;
        --expect-file)
            EXPECT_FILES+=("${2:?--expect-file requires a file name}")
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

ROOT=$(cd "$ROOT" && pwd)
[ -d "$ROOT" ] || { echo "not a directory: $ROOT" >&2; exit 2; }
for tool in ldd readelf file; do
    command -v "$tool" >/dev/null || { echo "$tool not found on this machine" >&2; exit 2; }
done
if [ -n "$ALLOW_MISSING_FILE" ]; then
    [ -r "$ALLOW_MISSING_FILE" ] || { echo "cannot read allowlist: $ALLOW_MISSING_FILE" >&2; exit 2; }
fi

# Entry points the tarball must ship (name relative to the tarball root),
# present and executable. The desktop tarball's entry point is a shell
# launcher, not an ELF — nothing else in this script would ever look at
# it, so a tarball with a missing/broken launcher must fail here.
for name in ${EXPECT_FILES[@]+"${EXPECT_FILES[@]}"}; do
    if [ ! -f "$ROOT/$name" ]; then
        echo "expected entry point missing from tarball: $name" >&2
        exit 1
    elif [ ! -x "$ROOT/$name" ]; then
        echo "expected entry point not executable: $name" >&2
        exit 1
    fi
done

# Base-system sonames every supported host provides: the glibc family
# (libm/libdl/libpthread/librt are merged into libc since glibc 2.34; the
# separate names stay for hosts that still resolve them that way), the
# dynamic loaders (x86-64 + arm64), libgcc_s, the vDSO, and libstdc++
# (its version floor is enforced by check-glibc-floor.sh below).
base_system() {
    case "$1" in
        ld-linux-x86-64.so.2|ld-linux-aarch64.so.1|libc.so.6|libm.so.6|libdl.so.2|libpthread.so.0|librt.so.1|libgcc_s.so.1|linux-vdso.so.1|libstdc++.so.6)
            return 0
            ;;
    esac
    return 1
}

# True when soname $1 is explicitly allowed (intentionally host-provided).
allowed() {
    local a
    for a in ${ALLOW_MISSING[@]+"${ALLOW_MISSING[@]}"}; do
        if [ "$a" = "$1" ]; then return 0; fi
    done
    if [ -n "$ALLOW_MISSING_FILE" ]; then
        grep -qxF "$1" "$ALLOW_MISSING_FILE" && return 0
    fi
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

# The first RPATH or RUNPATH value of FILE, or empty.
actual_rpath() {
    readelf -d "$1" 2>/dev/null \
        | sed -nE 's/^[[:space:]]*0x[0-9a-fA-F]+[[:space:]]+\((RPATH|RUNPATH)\)[[:space:]].*\[(.+)\][[:space:]]*$/\2/p' \
        | head -1 || true
}

# Rule 1: the bundled library directory must exist.
if [ ! -d "$ROOT/lib" ]; then
    echo "tarball ships no lib/ directory — release artifacts must bundle their shared libraries" >&2
    exit 1
fi

BAD=0
CHECKED=0
BUNDLED_SEEN=0
HOST_SEEN=0
ALLOWED_SEEN=0
while IFS= read -r -d '' f; do
    file -b "$f" 2>/dev/null | grep -q '^ELF' || continue
    CHECKED=$((CHECKED + 1))
    rel=${f#"$ROOT"/}

    # ldd prints one line per resolved NEEDED entry:
    #   "<soname> => <path> (0x...)"   or   "<soname> => not found"
    # plus direct mappings without "=>" (e.g. linux-vdso.so.1).
    # For ELFs inside lib/, ldd in isolation would lose the executable's
    # $ORIGIN/lib DT_RPATH context (its own NEEDEDs would then resolve
    # from the runner's /lib, exactly the blind spot this script exists
    # to close). LD_LIBRARY_PATH="$ROOT/lib" emulates that context for
    # the check: anything it cannot resolve from lib/ there, the
    # executable's rpath cannot resolve at runtime either.
    if [ "${rel#lib/}" != "$rel" ]; then
        out=$(LD_LIBRARY_PATH="$ROOT/lib" ldd "$f" 2>&1) || true
    else
        out=$(ldd "$f" 2>&1) || true
    fi
    while IFS= read -r line; do
        line=${line#"${line%%[![:space:]]*}"}
        case "$line" in
            *" => "*)
                soname=${line%% *}
                rest=${line#* => }
                case "$rest" in
                    "not found")
                        if allowed "$soname"; then
                            ALLOWED_SEEN=$((ALLOWED_SEEN + 1))
                            echo "host-provided (allowed, missing here): $soname (in $rel)"
                        else
                            echo "MISSING shared library: $soname (in $rel)"
                            BAD=1
                        fi
                        ;;
                    "$ROOT/lib"/*)
                        BUNDLED_SEEN=$((BUNDLED_SEEN + 1))
                        ;;
                    *)
                        path=${rest%% *}
                        if base_system "$soname"; then
                            HOST_SEEN=$((HOST_SEEN + 1))
                        elif allowed "$soname"; then
                            ALLOWED_SEEN=$((ALLOWED_SEEN + 1))
                            echo "host-provided (allowed): $soname (in $rel)"
                        else
                            echo "UNBUNDLED host dependency: $soname resolves to $path (in $rel) — bundle it under lib/ or document + allow it"
                            BAD=1
                        fi
                        ;;
                esac
                ;;
        esac
    done <<< "$out"

    # Rule 2 (unconditional): an executable ELF outside lib/ must point
    # its rpath at lib/, whole-entry, or the bundled libraries are dead
    # weight (and the pre-PR bare-ELF shape would sail through).
    case "$rel" in
        lib/*) : ;;
        *)
            want=$(want_rpath "$rel")
            rpath=$(actual_rpath "$f")
            have=0
            if [ -n "$rpath" ]; then
                old_ifs=$IFS
                IFS=':'
                # shellcheck disable=SC2206
                entries=($rpath)
                IFS=$old_ifs
                for e in ${entries[@]+"${entries[@]}"}; do
                    if [ "$e" = "$want" ]; then
                        have=1
                        break
                    fi
                done
            fi
            if [ "$have" -ne 1 ]; then
                echo "no whole-entry $want rpath on $rel (rpath: ${rpath:-<none>}) while the tarball ships lib/"
                BAD=1
            fi
            ;;
    esac
done < <(find "$ROOT" -type f -print0)

[ "$CHECKED" -gt 0 ] || { echo "no ELF files found under $ROOT" >&2; exit 1; }
[ "$BAD" -eq 0 ] || {
    echo "release artifact(s) reference shared libraries that are neither bundled nor host-guaranteed" >&2
    exit 1
}

echo "all $CHECKED ELF files resolve every NEEDED entry to lib/ ($BUNDLED_SEEN), base system ($HOST_SEEN) or an allowed host library ($ALLOWED_SEEN)"

# The version-floor guard still applies (bundled libs included).
scripts_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
"$scripts_dir/check-glibc-floor.sh" "$ROOT" "$GLIBC_FLOOR" "$GLIBCXX_FLOOR"
