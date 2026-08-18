#!/usr/bin/env bash
# Drive Pick with Maestro and collect store-listing screenshots into a clean dir.
#
# Maestro reads Pick's Dioxus WebView DOM, so the flow
# (.maestro/store-screenshots.yaml) navigates by visible text — robust, no pixel
# taps. Maestro writes screenshots into a timestamped run dir; this wrapper runs
# the flow with --test-output-dir and copies the PNGs out to a flat folder named
# for the Play/App Store upload.
#
# PRECONDITION: the app must be SIGNED IN / connected on the target device/sim
# (Home -> Scan -> results are gated on a live connection). Sign in once, leave
# the app on the easy-mode Home, then run this.
#
# Usage:
#   Android (run inside `nix develop`, emulator/device attached):
#     scripts/capture-store-maestro.sh android
#     scripts/capture-store-maestro.sh android -o ~/pick-store/android
#   iOS (run on the macOS host, a simulator booted with Pick signed in):
#     scripts/capture-store-maestro.sh ios -o ~/pick-store/ios
#
# Requires: maestro on PATH (~/.maestro/bin) + a JDK. adb (Android) / a booted
# sim (iOS). Screenshots are NOT committed; default output is outside the repo.
set -euo pipefail

PLATFORM="${1:-}"; shift || true
OUT=""
FLOW=".maestro/store-screenshots.yaml"

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

case "$PLATFORM" in
  android|ios) ;;
  -h|--help|"") usage 0 ;;
  *) echo "error: first arg must be 'android' or 'ios' (got '$PLATFORM')" >&2; usage 1 ;;
esac

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--out) OUT="$2"; shift 2 ;;
    -h|--help) usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 1 ;;
  esac
done
: "${OUT:=${HOME}/pick-store-screenshots/${PLATFORM}}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Resolve maestro. Android: run inside `nix develop` (the flake provides
# maestro + a JDK). iOS: on the macOS host, where nix isn't used — fall back to
# the get.maestro.mobile.dev installer's ~/.maestro/bin.
if ! command -v maestro >/dev/null 2>&1; then
  if [[ -x "$HOME/.maestro/bin/maestro" ]]; then
    export PATH="$HOME/.maestro/bin:$PATH"
  else
    echo "error: maestro not found. Either run inside 'nix develop' (Android)," >&2
    echo "       or install it: curl -Ls https://get.maestro.mobile.dev | bash" >&2
    exit 1
  fi
fi
export MAESTRO_CLI_NO_ANALYTICS=1

[[ -f "$FLOW" ]] || { echo "error: flow not found: $FLOW" >&2; exit 1; }

RUN_DIR="$(mktemp -d)"
echo "Maestro store capture ($PLATFORM)"
echo "  flow  : $FLOW"
echo "  run   : $RUN_DIR"
echo "  output: $OUT"
echo

# Run the flow. Maestro auto-selects the single attached Android device or the
# single booted iOS sim; the flow's appId is the same bundle id on both.
maestro test --test-output-dir "$RUN_DIR" "$FLOW" 2>&1 \
  | grep -viE "analytics enabled|opt out|Maestro Cloud|Debug tests|Run your|cloud app|^\s*[╭╰│]|^\s*$" || true

# Collect the PNGs Maestro wrote (under <run>/**/takeScreenshot/*.png).
mkdir -p "$OUT"
found=0
while IFS= read -r png; do
  cp -f "$png" "$OUT/$(basename "$png")"
  found=$((found + 1))
done < <(find "$RUN_DIR" -path '*/takeScreenshot/*.png' 2>/dev/null | sort)

echo
if [[ "$found" -gt 0 ]]; then
  echo "Collected $found screenshot(s) into $OUT:"
  ls -la "$OUT"/*.png
else
  echo "WARN: no screenshots produced. Check the flow output above — most likely" >&2
  echo "      the app wasn't on the connected Home screen (sign in first)." >&2
  exit 1
fi
