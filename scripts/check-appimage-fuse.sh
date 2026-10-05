#!/usr/bin/env bash
# check-appimage-fuse.sh — assert an AppImage's embedded runtime does NOT
# require libfuse.so.2 (FUSE 2).
#
# Why this exists: the legacy AppImageKit type-2 runtime resolves FUSE 2 at
# launch — it dlopens libfuse.so.2, a library stock Ubuntu 24.04+ no longer
# ships (FUSE 3 only). The AppImage then dies at launch with
#     dlopen(): error loading libfuse.so.2
# and when launched from a desktop app grid the failure is silent (the error
# only reaches the journal) — Strike48/project-management#377 finding 2
# (BLOCKER), resolved by project-management#382 with the static FUSE-3
# type2-runtime (github.com/AppImage/type2-runtime, built -static -lfuse3:
# no host libfuse at all, only fusermount3, which 24.04+ provides).
#
# The check is on the RUNTIME SECTION of the AppImage (the embedded ELF
# before the squashfs payload), not on the payload: the payload's libraries
# are already covered by the usual ldd/glibc-floor guards, and FUSE is a
# property of the container runtime, not of the payload.
#
# Usage:
#   check-appimage-fuse.sh <file.AppImage>   verify one AppImage
#   check-appimage-fuse.sh --self-test       hermetic mutation test (needs cc)
#
# Checks, on the runtime section [0, payload_offset):
#   1. byte scan: no "libfuse.so.2" reference anywhere in the runtime.
#      (The legacy runtime dlopens FUSE 2 — it has NO NEEDED entry for it,
#      so this scan is the decisive check; it catches the exact field
#      string "dlopen(): error loading libfuse.so.2".)
#   2. dynamic segment (readelf -d): no NEEDED libfuse* entry — catches
#      runtimes that link FUSE 2 as a regular dependency.
#   3. the runtime is a statically linked ELF — a static runtime cannot
#      acquire host library requirements at load time (the legacy runtime
#      is dynamically linked; the type2-runtime is static-pie).
#
# payload_offset is found WITHOUT executing the AppImage (no FUSE, no
# fusermount needed): the embedded runtime is a plain ELF, so parse its
# section headers (end of the last non-NOBITS section) and take the first
# squashfs magic ("hsqs") at or after that point — the same boundary the
# runtime itself uses (`--appimage-offset`).

set -euo pipefail

fail() { echo "FAIL: $*" >&2; exit 1; }

# runtime_boundary <file>
# Prints the byte offset where the squashfs payload starts (== the runtime
# section's end). Pure file parsing; never executes the AppImage.
runtime_boundary() {
    python3 - "$1" <<'PY'
import struct, sys

path = sys.argv[1]
data = open(path, "rb").read()
if data[:4] != b"\x7fELF":
    sys.exit("not an ELF (not an AppImage?)")

ei_class = data[4]  # 1 = 32-bit, 2 = 64-bit
if ei_class == 2:
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)
    off_fmt, size_fmt = "<Q", "<Q"
    sh_type_off, sh_off_off, sh_size_off = 0x04, 0x18, 0x20
elif ei_class == 1:
    e_shoff, = struct.unpack_from("<I", data, 0x20)
    e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x2E)
    off_fmt, size_fmt = "<I", "<I"
    sh_type_off, sh_off_off, sh_size_off = 0x04, 0x10, 0x14
else:
    sys.exit("unsupported ELF class")

end = 0
for i in range(e_shnum):
    off = e_shoff + i * e_shentsize
    (sh_type,) = struct.unpack_from("<I", data, off + sh_type_off)
    if sh_type == 8:  # SHT_NOBITS (.bss): in-memory only, not in the file
        continue
    (sh_offset,) = struct.unpack_from(off_fmt, data, off + sh_off_off)
    (sh_size,) = struct.unpack_from(size_fmt, data, off + sh_size_off)
    end = max(end, sh_offset + sh_size)

# The payload (squashfs) starts with "hsqs" at or just after the ELF;
# locate it within a bounded window (packers may leave a small gap).
payload = data.find(b"hsqs", end, end + 1 << 26)
print(payload if payload != -1 else end)
PY
}

# check_appimage <file.AppImage>
check_appimage() {
    local ai="$1"
    [ -f "$ai" ] || fail "file not found: $ai"
    local size
    size=$(wc -c < "$ai")
    [ "$size" -gt 4 ] || fail "file too small to be an AppImage: $ai"

    local magic
    magic=$(head -c4 "$ai" | od -An -tx1 | tr -d ' \n')
    [ "$magic" = "7f454c46" ] || fail "not an ELF/AppImage (bad magic): $ai"

    local offset
    offset=$(runtime_boundary "$ai") || fail "could not determine runtime boundary: $ai"
    case "$offset" in
        ''|*[!0-9]*) fail "non-numeric runtime boundary: $offset" ;;
    esac
    [ "$offset" -gt 64 ] || fail "implausibly small runtime section ($offset bytes)"
    [ "$offset" -lt "$size" ] || fail "runtime boundary ($offset) >= file size ($size)"

    local tmp rt
    tmp=$(mktemp -d)
    rt="$tmp/runtime"
    head -c "$offset" "$ai" > "$rt"

    local failures=0

    # 1. Byte scan for any libfuse.so.2 reference in the runtime section.
    local hits
    hits=$(LC_ALL=C grep -a -c -F 'libfuse.so.2' "$rt" || true)
    if [ "${hits:-0}" -gt 0 ]; then
        echo "  runtime section references libfuse.so.2 ($hits line(s)):" >&2
        LC_ALL=C strings "$rt" 2>/dev/null | grep -F 'libfuse.so.2' | head -3 | sed 's/^/    /' >&2 || true
        failures=$((failures + 1))
    fi

    # 2. Dynamic segment: no NEEDED libfuse* (covers link-time FUSE 2 deps,
    #    which the byte scan would also catch but which deserve their own
    #    failure line for diagnostics).
    if command -v readelf >/dev/null 2>&1; then
        if readelf -d "$rt" 2>/dev/null | grep '(NEEDED)' | grep -E 'Shared library: \[libfuse' ; then
            echo "  runtime NEEDEDs a libfuse shared library:" >&2
            readelf -d "$rt" 2>/dev/null | grep '(NEEDED)' | grep -E 'Shared library: \[libfuse' | sed 's/^/    /' >&2
            failures=$((failures + 1))
        fi
    fi

    # 3. The runtime must be statically linked (the legacy FUSE-2 runtime is
    #    dynamically linked; the static FUSE-3 type2-runtime is static-pie).
    local kind
    kind=$(file -b "$rt")
    if ! printf '%s' "$kind" | grep -Eq 'statically linked|static-pie linked'; then
        echo "  runtime is not statically linked: $kind" >&2
        failures=$((failures + 1))
    fi

    rm -rf "$tmp"

    if [ "$failures" -ne 0 ]; then
        echo "AppImage REQUIRES FUSE 2 (runtime section of $ai):" >&2
        [ "${hits:-0}" -gt 0 ] && echo "  - runtime references libfuse.so.2 (the legacy AppImageKit runtime; stock Ubuntu 24.04+ has FUSE 3 only)" >&2 || true
        echo "  - fix: package with the static FUSE-3 type2-runtime (github.com/AppImage/type2-runtime)" >&2
        exit 1
    fi

    echo "OK: $ai"
    echo "  runtime section: 0..$offset of $size bytes"
    echo "  libfuse.so.2 references in runtime: 0"
    echo "  runtime link type: static ($kind)"
}

# self-test: hermetic mutation suite. Builds synthetic AppImages (runtime ELF
# + "hsqs" payload marker) and asserts the guard's verdict on each. Needs a
# C compiler (cc); no network, no FUSE, no real AppImage required.
self_test() {
    command -v cc >/dev/null 2>&1 || fail "--self-test requires a C compiler (cc)"
    command -v python3 >/dev/null 2>&1 || fail "--self-test requires python3"

    local tmp=""
    trap '[ -n "${tmp:-}" ] && rm -rf "$tmp"' EXIT
    tmp=$(mktemp -d)
    local pass=0
    expect() { # expect <ok|bad> <file> <label>
        local want="$1" f="$2" label="$3" rc=0
        # Subshell: check_appimage exits the shell on verdicts (fail/exit 1);
        # we want the code, not the death, in self-test mode.
        ( check_appimage "$f" ) >/dev/null 2>&1 || rc=$?
        if [ "$want" = ok ] && [ $rc -eq 0 ]; then
            echo "  self-test PASS (accepted as expected): $label"; pass=$((pass + 1))
        elif [ "$want" = bad ] && [ $rc -ne 0 ]; then
            echo "  self-test PASS (rejected as expected): $label"; pass=$((pass + 1))
        else
            echo "  self-test MISMATCH (want=$want rc=$rc): $label" >&2
        fi
    }
    make_appimage() { # make_appimage <runtime-elf> <out>
        cat "$1" > "$2"; printf 'hsqs' >> "$2"; head -c 1024 /dev/zero >> "$2"
    }

    echo "self-test: building synthetic runtimes..."
    printf 'int main(void){return 0;}\n' > "$tmp/hello.c"
    local good="$tmp/good" dyn="$tmp/dyn"
    if cc -static -o "$good" "$tmp/hello.c" 2>/dev/null; then
        echo "  (good case: cc -static)"
    else
        # No static C library (e.g. NixOS glibc): fall back to any existing
        # statically linked ELF on the system.
        good=""
        local cand
        for cand in $(compgen -c 2>/dev/null | sort -u | head -200); do
            local p
            p=$(command -v "$cand" 2>/dev/null) || continue
            if file -b "$p" 2>/dev/null | grep -Eq 'statically linked|static-pie linked'; then
                good="$p"; echo "  (good case: existing static binary $p)"; break
            fi
        done
        [ -n "$good" ] || fail "--self-test needs a statically linked ELF (cc -static failed and no static binary found)"
    fi
    make_appimage "$good" "$tmp/good.AppImage"

    # bad-1: FUSE-2 dlopen reference (the legacy runtime's failure mode:
    # no NEEDED entry, the soname lives in the runtime's byte image).
    cp "$good" "$tmp/bad-dlopen"
    printf '\nlibfuse.so.2\ndlopen(): error loading libfuse.so.2\n' >> "$tmp/bad-dlopen"
    make_appimage "$tmp/bad-dlopen" "$tmp/bad-dlopen.AppImage"

    # bad-2: FUSE 2 as a link-time NEEDED dependency (fake libfuse.so.2).
    # The link-time file is libfuse.so (what -lfuse looks for); its soname is
    # libfuse.so.2, so the resulting NEEDED entry is libfuse.so.2.
    printf 'int fuse_stub(void){return 0;}\n' > "$tmp/fuse.c"
    cc -shared -Wl,-soname,libfuse.so.2 -o "$tmp/libfuse.so" "$tmp/fuse.c"
    printf 'extern int fuse_stub(void);int main(void){return fuse_stub();}\n' > "$tmp/need.c"
    (cd "$tmp" && cc -o need need.c -L. -lfuse)
    make_appimage "$tmp/need" "$tmp/bad-needed.AppImage"

    # bad-3: dynamically linked runtime with no FUSE at all (still the wrong
    # class: host-dependent).
    cc -o "$dyn" "$tmp/hello.c"
    make_appimage "$dyn" "$tmp/bad-dynamic.AppImage"

    echo "self-test: running guard against synthetic AppImages..."
    expect ok  "$tmp/good.AppImage"        "static runtime, no FUSE-2"
    expect bad "$tmp/bad-dlopen.AppImage"  "runtime references libfuse.so.2 (legacy dlopen class)"
    expect bad "$tmp/bad-needed.AppImage"  "runtime NEEDEDs libfuse.so.2 (link-time class)"
    expect bad "$tmp/bad-dynamic.AppImage" "dynamically linked runtime (host-dependent class)"

    if [ "$pass" -eq 4 ]; then
        echo "self-test: all 4 cases behaved as expected"
    else
        fail "self-test: $pass/4 cases behaved as expected"
    fi
}

case "${1:-}" in
    --self-test) self_test ;;
    '')
        echo "usage: $0 <file.AppImage> | --self-test" >&2
        exit 2
        ;;
    *) check_appimage "$1" ;;
esac
