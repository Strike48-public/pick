#!/usr/bin/env bash
# Screenshot capture runner
#
# Usage:
#   ./screenshots/capture.sh                  — capture all, both themes (default)
#   ./screenshots/capture.sh --theme dark      — capture all, dark only
#   ./screenshots/capture.sh --theme light     — capture all, light only
#   ./screenshots/capture.sh login             — capture one by name, both themes
#   ./screenshots/capture.sh login --theme dark
#   ./screenshots/capture.sh --list            — list available manifests
#   ./screenshots/capture.sh --open            — open all captures in eog
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CAPTURES_DIR="$SCRIPT_DIR/captures"

PKG="com.strike48.pentest_connector"

# --- arg parsing ---
TARGET=""
THEMES="dark light"
ACTION="capture"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --theme)  THEMES="$2"; shift 2 ;;
        --list)   ACTION="list"; shift ;;
        --open)   ACTION="open"; shift ;;
        *)        TARGET="$1"; shift ;;
    esac
done

# --- helpers ---

toml_get() {
    local file="$1" key="$2"
    grep -E "^${key}\s*=" "$file" | head -1 | sed -E 's/^[^=]+=\s*"?([^"]*)"?\s*$/\1/'
}

set_theme() {
    local theme="$1"
    # Kill the app first — changing uimode triggers an activity restart
    adb shell am force-stop "$PKG" >/dev/null 2>&1 || true
    if [ "$theme" = "dark" ]; then
        adb shell cmd uimode night yes >/dev/null 2>&1
    else
        adb shell cmd uimode night no >/dev/null 2>&1
    fi
    sleep 2
}

run_commands() {
    local file="$1" section="$2"
    # Extract commands from the section
    local in_section=0
    local in_commands=0
    while IFS= read -r line; do
        if [[ "$line" =~ ^\[${section}\] ]]; then
            in_section=1; continue
        fi
        if [[ $in_section -eq 1 && "$line" =~ ^\[ && ! "$line" =~ ^\[${section} ]]; then
            break
        fi
        if [[ $in_section -eq 1 && "$line" =~ ^commands ]]; then
            in_commands=1; continue
        fi
        if [[ $in_commands -eq 1 && "$line" =~ ^\] ]]; then
            in_commands=0; continue
        fi
        if [[ $in_commands -eq 1 ]]; then
            local cmd
            cmd=$(echo "$line" | sed -E 's/^\s*"([^"]*)".*/\1/')
            if [ -n "$cmd" ]; then
                echo "    \$ $cmd"
                eval "$cmd" >/dev/null 2>&1 || true
            fi
        fi
    done < "$file"
}

get_wait_ms() {
    local file="$1" section="$2"
    sed -n "/^\[${section}\]/,/^\[/p" "$file" | grep -E '^wait_ms\s*=' | head -1 | sed -E 's/.*=\s*([0-9]+).*/\1/' || echo "2000"
}

wait_for() {
    local ms="$1"
    if [ -n "$ms" ] && [ "$ms" -gt 0 ] 2>/dev/null; then
        echo "    waiting ${ms}ms..."
        sleep "$(echo "scale=3; $ms / 1000" | bc)"
    fi
}

run_manifest() {
    local manifest="$1" theme="$2"
    local name output desc

    name=$(toml_get "$manifest" "name")
    output=$(toml_get "$manifest" "output")
    output="${output//\{theme\}/$theme}"
    desc=$(toml_get "$manifest" "description")

    echo "==> [$name] ($theme) $desc"

    # Run [setup] commands
    run_commands "$manifest" "setup"
    wait_for "$(get_wait_ms "$manifest" "setup")"

    # Run [setup.then] commands if present
    if grep -q '^\[setup\.then\]' "$manifest"; then
        run_commands "$manifest" "setup\\.then"
        wait_for "$(get_wait_ms "$manifest" "setup\\.then")"
    fi

    # Capture
    local outpath="$SCRIPT_DIR/$output"
    mkdir -p "$(dirname "$outpath")"
    adb exec-out screencap -p > "$outpath"
    echo "    saved: $outpath"
}

# --- actions ---

if [ "$ACTION" = "list" ]; then
    for f in "$SCRIPT_DIR"/*.toml; do
        [ -f "$f" ] || continue
        name=$(toml_get "$f" "name")
        desc=$(toml_get "$f" "description")
        echo "  $name — $desc"
    done
    exit 0
fi

if [ "$ACTION" = "open" ]; then
    for f in "$CAPTURES_DIR"/*/*.png; do
        [ -f "$f" ] && eog "$f" &
    done
    exit 0
fi

# --- capture ---

for theme in $THEMES; do
    echo "==== Theme: $theme ===="
    set_theme "$theme"

    if [ -n "$TARGET" ]; then
        for f in "$SCRIPT_DIR"/*.toml; do
            [ -f "$f" ] || continue
            name=$(toml_get "$f" "name")
            if [ "$name" = "$TARGET" ]; then
                run_manifest "$f" "$theme"
                break
            fi
        done
    else
        for f in "$SCRIPT_DIR"/*.toml; do
            [ -f "$f" ] || continue
            run_manifest "$f" "$theme"
            echo ""
        done
    fi
    echo ""
done

# Restore dark mode as default
set_theme "dark"

echo "Done. Screenshots in: $CAPTURES_DIR"
