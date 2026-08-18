#!/usr/bin/env bash
# Capture Google Play store-listing screenshots from a running Android device
# or emulator.
#
# Play Store phone screenshots: PNG/JPEG, 16:9 or 9:16, each side 320-3840px.
# A booted Pixel-class emulator (1080x2400) satisfies this directly, so we grab
# the raw framebuffer with `adb exec-out screencap -p` — no scaling, no status-
# bar cropping (Play accepts the full frame).
#
# This is a MANUAL, interactive capture tool: you drive the app to each screen,
# it snaps the current frame on <Enter>. Screenshots are NOT committed (they go
# to an output dir you hand to the Play Console), so the default output is
# outside the repo tree.
#
# Usage:
#   scripts/capture-store-android.sh                 # interactive, default out dir
#   scripts/capture-store-android.sh -o ~/pick-store/android
#   scripts/capture-store-android.sh -s emulator-5554 -o /tmp/shots
#   scripts/capture-store-android.sh --list "01-home 02-scan 03-report 04-chat"
#     ^ non-interactive prompts named in order; still waits on <Enter> per shot.
#
# Requires: adb (Android platform-tools). Run inside `nix develop` so
# $ANDROID_HOME/platform-tools/adb resolves, or have adb on PATH.
set -euo pipefail

OUT="${HOME}/pick-store-screenshots/android"
SERIAL=""
SHOTS="01-home 02-scan-running 03-report 04-chat 05-settings"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--out)    OUT="$2"; shift 2 ;;
    -s|--serial) SERIAL="$2"; shift 2 ;;
    -l|--list)   SHOTS="$2"; shift 2 ;;
    -h|--help)   usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 1 ;;
  esac
done

# Resolve adb: prefer $ANDROID_HOME (nix devshell), else PATH.
ADB="adb"
if [[ -n "${ANDROID_HOME:-}" && -x "$ANDROID_HOME/platform-tools/adb" ]]; then
  ADB="$ANDROID_HOME/platform-tools/adb"
fi
command -v "$ADB" >/dev/null 2>&1 || { echo "error: adb not found (run inside 'nix develop' or install platform-tools)" >&2; exit 1; }

# Resolve the target serial: explicit -s, else the only attached device.
if [[ -z "$SERIAL" ]]; then
  mapfile -t DEVICES < <("$ADB" devices | awk 'NR>1 && $2=="device" {print $1}')
  if [[ ${#DEVICES[@]} -eq 0 ]]; then
    echo "error: no attached device/emulator. Boot one, then retry." >&2; exit 1
  elif [[ ${#DEVICES[@]} -gt 1 ]]; then
    echo "error: multiple devices; pick one with -s:" >&2
    printf '  %s\n' "${DEVICES[@]}" >&2; exit 1
  fi
  SERIAL="${DEVICES[0]}"
fi

adbx() { "$ADB" -s "$SERIAL" "$@"; }

# Report the frame size so you can confirm it meets Play's constraints.
# `adb shell` reads stdin by default; redirect from /dev/null so it can't drain
# the terminal input the interactive capture loop below needs (otherwise the
# first `read` hits EOF and the loop exits immediately).
SIZE="$(adbx shell wm size </dev/null 2>/dev/null | awk -F': ' '/Physical size/{print $2}' | tr -d '\r')"
mkdir -p "$OUT"

echo "Android store-screenshot capture"
echo "  device: $SERIAL  (frame ${SIZE:-unknown})"
echo "  output: $OUT"
echo "  shots : $SHOTS"
echo
echo "Drive the app to each screen on the device, then press <Enter> here to snap."
echo "Press 'r' then <Enter> to RE-shoot the last one, or 's' to SKIP."
echo

# Pipe-safe PNG magic check: read the first bytes with `read` (no head|grep
# pipeline, which under `set -e -o pipefail` aborts the script via SIGPIPE when
# grep -q closes the pipe early).
is_png() {
  local path="$1" magic
  [[ -s "$path" ]] || return 1
  magic="$(LC_ALL=C od -An -tx1 -N4 "$path" 2>/dev/null | tr -d ' \n')"
  [[ "$magic" == "89504e47" ]]  # \x89 P N G
}

snap() {
  local name="$1" path="$OUT/$name.png"
  adbx exec-out screencap -p > "$path"
  if is_png "$path"; then
    echo "  saved $path ($(wc -c <"$path") bytes)"
    return 0
  fi
  echo "  WARN: capture for $name looks invalid; retry." >&2
  return 1
}

# Disable `set -e` for the interactive loop: `read` at EOF, empty input, and
# `[[ ]] &&` tests that evaluate false are all normal control flow here, not
# errors — under `set -e` any of them would abort the loop mid-capture.
set +e
for name in $SHOTS; do
  while true; do
    if ! read -r -p "-> set up '$name' on device, then <Enter> (r=redo last, s=skip): " ans; then
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
