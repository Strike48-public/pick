#!/usr/bin/env bash
# Screenshot capture runner
#
# Usage:
#   ./screenshots/capture.sh           — capture all screenshots
#   ./screenshots/capture.sh login     — capture one by name
#   ./screenshots/capture.sh --list    — list available manifests
#   ./screenshots/capture.sh --open    — open all captures in eog

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PKG="com.strike48.pentest_connector"

toml_get() {
    grep -E "^${2}\s*=" "$1" | head -1 | sed -E 's/^[^=]+=\s*"?([^"]*)"?\s*$/\1/'
}

wait_for_app() {
    for _ in $(seq 1 20); do
        if adb shell "dumpsys activity activities" 2>/dev/null | grep -q "topResumedActivity.*${PKG}"; then
            sleep 3
            return 0
        fi
        sleep 0.5
    done
    echo "    WARNING: app not in foreground after 10s"
}

run_section() {
    local file="$1" section="$2"
    local tmpfile="/tmp/pick-capture-cmds.$$"

    sed -n "/^\[${section}\]/,/^\[/p" "$file" \
        | grep -E '^\s+"' \
        | sed -E 's/^\s*"([^"]*)".*/\1/' \
        > "$tmpfile" 2>/dev/null || true

    local has_start=false
    while IFS= read -r cmd; do
        [ -z "$cmd" ] && continue
        echo "    \$ $cmd"
        bash -c "$cmd" </dev/null >/dev/null 2>&1 || true
        [[ "$cmd" == *"am start"* ]] && has_start=true
    done < "$tmpfile"
    rm -f "$tmpfile"

    if $has_start; then
        echo "    waiting for app..."
        wait_for_app
    else
        local ms
        ms=$(sed -n "/^\[${section}\]/,/^\[/p" "$file" | grep -E '^wait_ms' | head -1 | grep -oE '[0-9]+' || echo "1000")
        sleep "$(echo "scale=3; $ms / 1000" | bc)"
    fi
}

run_manifest() {
    local manifest="$1"
    local name output desc
    name=$(toml_get "$manifest" "name")
    output=$(toml_get "$manifest" "output")
    desc=$(toml_get "$manifest" "description")

    echo "==> [$name] $desc"

    run_section "$manifest" "setup"

    if grep -q '^\[setup\.then\]' "$manifest"; then
        run_section "$manifest" 'setup\.then'
    fi

    local outpath="$SCRIPT_DIR/$output"
    mkdir -p "$(dirname "$outpath")"
    adb exec-out screencap -p > "$outpath"
    echo "    saved: $outpath"
}

case "${1:-}" in
    --list)
        for f in "$SCRIPT_DIR"/*.toml; do
            [ -f "$f" ] || continue
            echo "  $(toml_get "$f" "name") — $(toml_get "$f" "description")"
        done ;;
    --open)
        for f in "$SCRIPT_DIR"/captures/*.png; do [ -f "$f" ] && eog "$f" & done ;;
    "")
        echo "Capturing all screenshots..."
        for f in "$SCRIPT_DIR"/*.toml; do
            [ -f "$f" ] || continue
            run_manifest "$f"; echo ""
        done
        echo "Done." ;;
    *)
        for f in "$SCRIPT_DIR"/*.toml; do
            [ -f "$f" ] || continue
            if [ "$(toml_get "$f" "name")" = "$1" ]; then
                run_manifest "$f"; exit 0
            fi
        done
        echo "Error: no manifest '$1'" >&2; exit 1 ;;
esac
