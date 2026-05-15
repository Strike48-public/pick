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
#   2 - Usage error
#
# The list of banned names is defined in PII_NAMES below. Add new customer
# names there when onboarding new tenants.

set -euo pipefail

# Banned customer names (case-insensitive). Add new names here.
PII_NAMES=(
    "talion"
    "maidar"
    "hotwire"
    "deepseas"
)

# Build a single case-insensitive regex: \b(name1|name2|...)\b
# Word boundaries prevent false positives on substrings.
build_pattern() {
    local pattern=""
    local sep=""
    for name in "${PII_NAMES[@]}"; do
        pattern+="${sep}${name}"
        sep="|"
    done
    printf '\\b(%s)\\b' "$pattern"
}

PATTERN="$(build_pattern)"

# Scan stdin or arguments, print matches with file:line prefix, return status.
scan() {
    local source_label="$1"
    local input="$2"
    # -E extended regex, -i case-insensitive, -n line numbers, -w word boundary
    if echo "$input" | grep -EHin --label="$source_label" --color=never -- "$PATTERN"; then
        return 1
    fi
    return 0
}

main() {
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
        echo "Banned names: ${PII_NAMES[*]}" >&2
        echo "Replace with neutral placeholders like '<tenant-id>' or 'customer tenant'." >&2
        exit 1
    fi

    exit 0
}

main "$@"
