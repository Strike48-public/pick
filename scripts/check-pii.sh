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

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT
readonly LOCAL_NAMES_FILE="${REPO_ROOT}/.pii-names.local"

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

# Build a single case-insensitive regex: \b(name1|name2|...)\b
# Word boundaries prevent false positives on substrings.
build_pattern() {
    local pattern="" sep=""
    for name in "${NAMES[@]}"; do
        pattern+="${sep}${name}"
        sep="|"
    done
    printf '\\b(%s)\\b' "$pattern"
}

# Scan stdin or arguments, print matches with file:line prefix, return status.
scan() {
    local source_label="$1"
    local input="$2"
    # -E extended regex, -i case-insensitive, -n line numbers, -H label prefix
    if echo "$input" | grep -EHin --label="$source_label" --color=never -- "$PATTERN"; then
        return 1
    fi
    return 0
}

main() {
    if ! load_names; then
        echo "ERROR: no PII name list available." >&2
        echo "Provide names via \$PII_NAMES (CI secret), \$PII_NAMES_FILE, or ${LOCAL_NAMES_FILE}." >&2
        echo "See scripts/check-pii.sh header for the format." >&2
        exit 2
    fi

    PATTERN="$(build_pattern)"

    local found=0

    if [[ $# -eq 0 ]]; then
        # stdin mode. Empty input is valid (nothing to scan = no PII).
        local input
        input="$(cat)"
        if [[ -n "$input" ]]; then
            scan "stdin" "$input" || found=1
        fi
    elif [[ "$1" == "--text" ]]; then
        if [[ $# -lt 2 ]]; then
            echo "Error: --text requires an argument" >&2
            exit 2
        fi
        scan "text" "$2" || found=1
    else
        # File mode
        for file in "$@"; do
            if [[ ! -f "$file" ]]; then
                echo "Warning: $file is not a regular file, skipping" >&2
                continue
            fi
            if grep -EHin --color=never -- "$PATTERN" "$file"; then
                found=1
            fi
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
