#!/usr/bin/env bash
# Fail if any ELF file in an extracted Pick release tarball needs a newer
# glibc or libstdc++ than the supported floor. Neither library is bundled,
# so these floors decide which distros can run Pick at all; a runner image
# upgrade raised the glibc floor silently once (GLIBC_2.38 from a
# ubuntu-latest build broke Ubuntu 22.04/Debian 12, QA-verified). Ported
# from Strike48-public/strikehub PR #90.
#
# Defaults match Ubuntu 22.04 (glibc 2.35, GCC 12 libstdc++ = GLIBCXX 3.4.30),
# which also covers Debian 12 — the minimum distros Pick targets.
#
# Usage: check-glibc-floor.sh <extracted-tarball-dir> [glibc-floor] [glibcxx-floor]
set -euo pipefail

ROOT=${1:?usage: check-glibc-floor.sh <extracted-tarball-dir> [glibc-floor] [glibcxx-floor]}
GLIBC_FLOOR=${2:-2.35}
GLIBCXX_FLOOR=${3:-3.4.30}

# Highest version of symbol PREFIX_x.y that FILE requires, or empty.
highest() {
    objdump -T "$2" 2>/dev/null | grep -oE "\b$1_[0-9.]+" | sed "s/^$1_//" | sort -uV | tail -1 || true
}

# True when version $1 is newer than floor $2.
newer_than() {
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

BAD=0
CHECKED=0
while IFS= read -r -d '' f; do
    file -b "$f" | grep -q '^ELF' || continue
    CHECKED=$((CHECKED + 1))
    rel=${f#"$ROOT"/}
    need=$(highest GLIBC "$f")
    if [ -n "$need" ] && newer_than "$need" "$GLIBC_FLOOR"; then
        echo "needs glibc $need (floor $GLIBC_FLOOR): $rel"
        BAD=1
    fi
    need=$(highest GLIBCXX "$f")
    if [ -n "$need" ] && newer_than "$need" "$GLIBCXX_FLOOR"; then
        echo "needs GLIBCXX $need (floor $GLIBCXX_FLOOR): $rel"
        BAD=1
    fi
done < <(find "$ROOT" -type f -print0)

[ "$CHECKED" -gt 0 ] || { echo "no ELF files found under $ROOT"; exit 1; }
[ "$BAD" -eq 0 ] || { echo "release artifact(s) require a newer glibc/libstdc++ than the supported floor"; exit 1; }
echo "all $CHECKED ELF files need glibc <= $GLIBC_FLOOR and GLIBCXX <= $GLIBCXX_FLOOR"
