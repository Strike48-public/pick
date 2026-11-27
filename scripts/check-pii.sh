#!/usr/bin/env bash
# check-pii.sh - Scan text for customer names that must never appear in public artifacts.
#
# Usage:
#   scripts/check-pii.sh [file ...]           # Scan one or more files
#   echo "text" | scripts/check-pii.sh        # Scan stdin
#   scripts/check-pii.sh --text "some text"   # Scan inline text
#
# Exit codes:
#   0 - No PII found
#   1 - PII found (one or more customer names detected)
#   2 - Usage or configuration error (no name list available)
#
# The banned-name list is loaded at runtime from OUTSIDE this repository so the
# customer names themselves never live in a public artifact. Sources, in order:
#
#   1. $PII_NAMES       - newline- or comma-separated names (used by CI, fed
#                         from a repository secret/variable).
#   2. $PII_NAMES_FILE  - path to a file with one name per line.
#   3. .pii-names.local - a gitignored file at the repo root (local dev default).
#
# Lines beginning with '#' and blank lines in the file/variable are ignored.
# If no source yields at least one name, the scanner FAILS LOUD (exit 2) rather
# than silently passing - a scanner with an empty list protects nothing.
#
# Set PII_REDACT=1 (CI does this) to print only the location of a hit and never
# the matched text, so customer names never reach a public CI log. Unset (local
# dev) the offending line is shown so the developer can find and fix it.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT
readonly LOCAL_NAMES_FILE="${REPO_ROOT}/.pii-names.local"
readonly REDACT="${PII_REDACT:-0}"

# Populate PII_NAMES from the first available source. Returns non-zero if none
# of the sources provided any names.
load_names() {
    local raw=""

    if [[ -n "${PII_NAMES:-}" ]]; then
        raw="$PII_NAMES"
    elif [[ -n "${PII_NAMES_FILE:-}" && -f "${PII_NAMES_FILE}" ]]; then
        raw="$(cat "${PII_NAMES_FILE}")"
    elif [[ -f "${LOCAL_NAMES_FILE}" ]]; then
        raw="$(cat "${LOCAL_NAMES_FILE}")"
    else
        return 1
    fi

    # Split on newlines and commas; trim whitespace; drop blanks and comments.
    NAMES=()
    local line name
    while IFS= read -r line; do
        line="${line//,/$'\n'}"
        while IFS= read -r name; do
            name="${name#"${name%%[![:space:]]*}"}"  # ltrim
            name="${name%"${name##*[![:space:]]}"}"  # rtrim
            [[ -z "$name" || "$name" == \#* ]] && continue
            NAMES+=("$name")
        done <<< "$line"
    done <<< "$raw"

    [[ ${#NAMES[@]} -gt 0 ]]
}

# Match the banned names against the stream on this function's stdin.
#
# Matching is FIXED-STRING (grep -F), not regex: a customer name may contain
# regex metacharacters (an unbalanced '(' or '[', a '+', a '.'), and folding it
# raw into an alternation would corrupt the pattern - grep would error and, if
# that error were mistaken for "no match", the scanner would silently pass every
# name. Fixed strings are immune to that, and grep errors (exit >= 2) FAIL LOUD.
#
# Reads the named file, or this function's stdin when no file is given.
# Returns 0 if a name was found, 1 if clean; exits 2 on a grep error.
match_stream() {
    local label="$1" file="${2:-}"
    local out rc=0
    # -F fixed strings, -i case-insensitive, -w whole-word, -n line numbers.
    if [[ -n "$file" ]]; then
        out="$(grep -Fiwn -f "$NAMES_FILE" -- "$file" 2>/dev/null)" || rc=$?
    else
        out="$(grep -Fiwn -f "$NAMES_FILE" 2>/dev/null)" || rc=$?
    fi
    case "$rc" in
        0) : ;;          # match(es) found - fall through to report
        1) return 0 ;;   # no match = clean
        *)
            echo "ERROR: PII scanner grep failed (exit $rc) while scanning ${label}." >&2
            exit 2 ;;
    esac

    # A name was found. Emit locations on stderr (diagnostic). In redact mode
    # print only the line number so the name never reaches a public CI log.
    local m lineno
    while IFS= read -r m; do
        lineno="${m%%:*}"
        if [[ "$REDACT" == "1" ]]; then
            printf '%s:%s: [PII match redacted]\n' "$label" "$lineno" >&2
        else
            printf '%s:%s\n' "$label" "$m" >&2
        fi
    done <<< "$out"
    return 1
}

main() {
    if ! load_names; then
        echo "ERROR: no PII name list available." >&2
        echo "Provide names via \$PII_NAMES (CI secret), \$PII_NAMES_FILE, or ${LOCAL_NAMES_FILE}." >&2
        echo "See scripts/check-pii.sh header for the format." >&2
        exit 2
    fi

    # Materialize the names as a fixed-string pattern file for grep -F -f.
    NAMES_FILE="$(mktemp)"
    trap 'rm -f "$NAMES_FILE"' EXIT
    printf '%s\n' "${NAMES[@]}" > "$NAMES_FILE"

    local found=0

    if [[ $# -eq 0 ]]; then
        # stdin mode. Empty input is valid (nothing to scan = no PII).
        local input
        input="$(cat)"
        if [[ -n "$input" ]]; then
            match_stream "stdin" <<< "$input" || found=1
        fi
    elif [[ "$1" == "--text" ]]; then
        if [[ $# -lt 2 ]]; then
            echo "Error: --text requires an argument" >&2
            exit 2
        fi
        match_stream "text" <<< "$2" || found=1
    else
        # File mode
        for file in "$@"; do
            if [[ ! -f "$file" ]]; then
                echo "Warning: $file is not a regular file, skipping" >&2
                continue
            fi
            match_stream "$file" "$file" || found=1
        done
    fi

    if [[ $found -eq 1 ]]; then
        echo "" >&2
        echo "ERROR: Customer names (PII) detected in the content above." >&2
        # Do NOT echo the name list here - this output reaches public CI logs.
        echo "Replace with neutral placeholders like '<tenant-id>' or 'customer tenant'." >&2
        exit 1
    fi

    exit 0
}

main "$@"
