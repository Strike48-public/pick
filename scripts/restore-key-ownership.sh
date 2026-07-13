#!/usr/bin/env bash
# Restore ownership of the SDK key/credential store to the invoking user.
#
# Why this exists: WiFi hardware access needs sudo, so several launch paths run
# the whole connector as root with HOME preserved (`sudo -E ... HOME=$HOME`).
# The Strike48 SDK then writes its 0600 private key and credentials into the
# operator's ~/.strike48 owned by root. A later NON-sudo launch (as the operator)
# can no longer read that root-owned 0600 key and OTT registration fails with
# "Failed to read private key: Permission denied (os error 13)".
#
# This script re-chowns the store back to the login user so mixing sudo and
# non-sudo launches never strands the key. Safe to run when not root (no-op).
#
# Usage:
#   scripts/restore-key-ownership.sh            # uses $SUDO_USER
#   scripts/restore-key-ownership.sh <user>     # explicit target user

set -euo pipefail

# Only meaningful when running as root; otherwise the files are already ours.
if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  exit 0
fi

TARGET_USER="${1:-${SUDO_USER:-}}"
if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
  # Launched as a genuine root login (no sudo drop-back target): nothing to do.
  exit 0
fi

TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
if [[ -z "$TARGET_HOME" || ! -d "$TARGET_HOME" ]]; then
  echo "[restore-key-ownership] cannot resolve home for '$TARGET_USER'; skipping" >&2
  exit 0
fi

STORE="${STRIKE48_KEYS_DIR:-}"
# STRIKE48_KEYS_DIR points at the keys dir specifically; the store root is its
# parent. When unset, the SDK default store is ~/.strike48.
if [[ -n "$STORE" ]]; then
  STORE_ROOT="$(dirname "$STORE")"
else
  STORE_ROOT="${TARGET_HOME}/.strike48"
fi

fixed=0
for dir in "$STORE_ROOT" "${TARGET_HOME}/.pick"; do
  if [[ -e "$dir" ]]; then
    # Only touch files not already owned by the target user (idempotent, quiet).
    if find "$dir" ! -user "$TARGET_USER" -print -quit 2>/dev/null | grep -q .; then
      chown -R "${TARGET_USER}:${TARGET_USER}" "$dir" && fixed=1
    fi
  fi
done

if [[ "$fixed" -eq 1 ]]; then
  echo "[restore-key-ownership] restored ${STORE_ROOT} to ${TARGET_USER}"
fi
