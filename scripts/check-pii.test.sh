#!/usr/bin/env bash
# check-pii.test.sh - Regression tests for scripts/check-pii.sh.
#
# Focus (#336 review blocker): operator-supplied names are matched as LITERAL
# fixed strings, never as regexes. A name containing an ERE metacharacter must
# not (a) corrupt the scan into a silent no-op that passes while scanning
# nothing, nor (b) introduce false positives. Baseline detection and the
# whole-word boundary are also pinned so the fix does not regress behavior.
#
# Hermetic: each case supplies its own $PII_NAMES, so no repository secret is
# needed and this runs in CI on every PR (including fork PRs).

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly SCANNER="${SCRIPT_DIR}/check-pii.sh"
readonly LOCAL_NAMES_FILE="${SCRIPT_DIR}/../.pii-names.local"

fail=0

# assert_exit <description> <expected-exit> <PII_NAMES> <input-text>
assert_exit() {
    local desc="$1" expected="$2" names="$3" input="$4" actual
    printf '%s\n' "$input" | PII_NAMES="$names" PII_NAMES_FILE="" "$SCANNER" >/dev/null 2>&1
    actual=$?
    if [[ "$actual" == "$expected" ]]; then
        printf 'ok   - %s (exit %s)\n' "$desc" "$actual"
    else
        printf 'FAIL - %s (expected exit %s, got %s)\n' "$desc" "$expected" "$actual"
        fail=1
    fi
}

# --- The blocker this guards: names with regex metacharacters ---

# An unbalanced paren must still be DETECTED literally, not silently turned into
# a broken regex that errors out and passes while scanning nothing.
assert_exit "unbalanced-paren name is detected literally" 1 'foo(bar' 'leak: foo(bar here'

# A malformed name must not corrupt matching of a second, valid name in the list.
assert_exit "one metachar name does not disable the whole list" 1 $'foo(bar\nacme' 'this mentions acme only'

# A '.' in a name must match literally, NOT as regex "any character".
assert_exit "dot in name does not false-positive on any char" 0 'a.c' 'the axc token'
assert_exit "dot in name still matches the literal" 1 'a.c' 'contains a.c literally'

# --- Baseline behavior preserved ---
assert_exit "plain name is detected" 1 'acme' 'built for acme corp'
assert_exit "whole-word boundary avoids substring hit" 0 'acme' 'the acmecorp release'
assert_exit "clean input passes" 0 'acme' 'no customer names here'

# fail-loud on an empty list - only assert when no ambient local list can supply
# names (the scanner falls back to .pii-names.local, which exists on some dev
# checkouts but never in CI).
if [[ ! -f "$LOCAL_NAMES_FILE" ]]; then
    assert_exit "empty name list fails loud (exit 2)" 2 '' 'anything'
else
    printf 'skip - empty-list fail-loud (.pii-names.local present locally)\n'
fi

if [[ "$fail" -ne 0 ]]; then
    echo "PII scanner regression tests FAILED" >&2
    exit 1
fi
echo "All PII scanner regression tests passed."
