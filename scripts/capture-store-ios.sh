#!/usr/bin/env bash
# Capture App Store store-listing screenshots from a booted iOS Simulator.
#
# App Store Connect requires screenshots at specific device sizes. A booted
# modern iPhone simulator produces a native-resolution frame that satisfies the
# 6.9"/6.7"/6.5" iPhone display classes (App Store Connect accepts one of these
# and can reuse it for the others). `xcrun simctl io booted screenshot` grabs
# the exact simulator framebuffer — no scaling.
#
# MUST run on the macOS host with Xcode + a BOOTED simulator running Pick. This
# is a MANUAL, interactive capture tool: you drive the app to each screen in the
# Simulator, press <Enter> in this terminal to snap. Screenshots are NOT
# committed; default output is outside the repo tree.
#
# Usage (on the Mac):
#   scripts/capture-store-ios.sh
#   scripts/capture-store-ios.sh -o ~/pick-store/ios
#   scripts/capture-store-ios.sh -u <UDID> -o /tmp/shots
#   scripts/capture-store-ios.sh --list "01-home 02-scan 03-report 04-chat"
#
# Requires: Xcode command-line tools (xcrun simctl). A device must be Booted.
set -euo pipefail

OUT="${HOME}/pick-store-screenshots/ios"
UDID=""
SHOTS="01-home 02-scan-running 03-report 04-chat 05-settings"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--out)  OUT="$2"; shift 2 ;;
    -u|--udid) UDID="$2"; shift 2 ;;
    -l|--list) SHOTS="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 1 ;;
  esac
done

command -v xcrun >/dev/null 2>&1 || { echo "error: xcrun not found — run on the macOS host with Xcode installed." >&2; exit 1; }

# Resolve the target UDID: explicit -u, else the single booted sim. macOS ships
# Bash 3.2 (no `mapfile`), so collect UDIDs into a plain array the portable way.
if [[ -z "$UDID" ]]; then
  BOOTED=()
  while IFS= read -r line; do
    [[ -n "$line" ]] && BOOTED+=("$line")
  done < <(xcrun simctl list devices booted 2>/dev/null | grep -oE '[0-9A-Fa-f-]{36}')
  if [[ ${#BOOTED[@]} -eq 0 ]]; then
    echo "error: no booted simulator. Boot one (e.g. 'xcrun simctl boot \"iPhone 17 Pro\"' + open Simulator) and launch Pick, then retry." >&2
    exit 1
  elif [[ ${#BOOTED[@]} -gt 1 ]]; then
    echo "error: multiple booted sims; pick one with -u <UDID>:" >&2
    xcrun simctl list devices booted >&2; exit 1
  fi
  UDID="${BOOTED[0]}"
fi

DEV_NAME="$(xcrun simctl list devices 2>/dev/null | grep "$UDID" | sed -E 's/^ *//; s/ \(.*//')"
mkdir -p "$OUT"

echo "iOS store-screenshot capture"
echo "  sim   : ${DEV_NAME:-?}  ($UDID)"
echo "  output: $OUT"
echo "  shots : $SHOTS"
echo
echo "Drive the app to each screen in the Simulator, then press <Enter> here to snap."
echo

# Pipe-safe PNG magic check (see android script for why we avoid head|grep).
is_png() {
  local path="$1" magic
  [[ -s "$path" ]] || return 1
  magic="$(LC_ALL=C od -An -tx1 -N4 "$path" 2>/dev/null | tr -d ' \n')"
  [[ "$magic" == "89504e47" ]]
}

snap() {
  local name="$1" path="$OUT/$name.png"
  xcrun simctl io "$UDID" screenshot "$path" >/dev/null 2>&1 || return 1
  if is_png "$path"; then
    # Report dimensions when sips is available (macOS built-in).
    local dims=""
    if command -v sips >/dev/null 2>&1; then
      dims="$(sips -g pixelWidth -g pixelHeight "$path" 2>/dev/null | awk '/pixel/{printf "%s ", $2}' )"
    fi
    echo "  saved $path (${dims:-ok})"
    return 0
  fi
  echo "  WARN: capture for $name looks invalid; retry." >&2
  return 1
}

# Disable `set -e` for the interactive loop: `read` at EOF, empty input, and
# `[[ ]] &&` tests evaluating false are normal control flow here, not errors.
set +e
for name in $SHOTS; do
  while true; do
    if ! read -r -p "-> set up '$name' in the Simulator, then <Enter> (r=redo last, s=skip): " ans; then
      echo; echo "  (input closed — stopping)"; break 2
    fi
    case "$ans" in
      s) echo "  skipped $name"; break ;;
      *) if snap "$name"; then
           read -r -p "   keep? <Enter>=yes, r=redo: " k
           [[ "$k" == "r" ]] && continue
           break
         fi ;;
    esac
  done
done
set -e

echo
echo "Done. ${OUT}:"
ls -la "$OUT"/*.png 2>/dev/null || echo "  (no screenshots captured)"
