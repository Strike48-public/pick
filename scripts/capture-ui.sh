#!/usr/bin/env bash
# Capture screenshots + a GIF of a Pick connector UI feature for PR documentation.
#
# Thin wrapper around scripts/capture_ui.py. Drives the pentest-web liveview app
# through the Strike48 connect gate and records media into docs/assets/<feature>/
# so it can be committed into the PR diff.
#
# Requires: Playwright (Python, via mise) + Chromium, and ffmpeg for GIF output.
#   pip install playwright && playwright install chromium
#
# Connection host/tenant come from --host/--tenant, else STRIKE48_HOST /
# STRIKE48_TENANT, else the repo .env if present.
#
# Examples:
#   scripts/capture-ui.sh --feature install-progress --view Settings \
#       --interaction install-first-tool
#   scripts/capture-ui.sh --feature dashboard --view Dashboard --no-video

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Source .env for STRIKE48_HOST / STRIKE48_TENANT defaults if the caller didn't
# export them. .env is gitignored and operator-specific.
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

# Prefer the mise-managed python (Playwright is installed there); fall back to python3.
PY="$(command -v python3)"
if command -v mise >/dev/null 2>&1; then
  if mise which python >/dev/null 2>&1; then
    PY="$(mise which python)"
  fi
fi

exec "$PY" "$REPO_ROOT/scripts/capture_ui.py" "$@"
