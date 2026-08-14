#!/usr/bin/env bash
# Guided one-command setup for connecting Pick to any Prospector (Strike48) Studio.
#
# Turns a single Studio URL into a correct, gitignored .env: it derives the
# WebSocket host, the HTTP API URL, and the TLS flag from the URL, and picks a
# URL-scoped connector instance id so a fresh Studio never collides with a
# credential saved for a different tenant (the #1 cause of "Registration failed"
# — credentials are keyed by instance id, not tenant).
#
# The tenant UUID is still required for a working connection: without an
# interactive login there is no way to discover it, and the SDK refuses to
# register without one. Get it from the Studio dashboard. (A future
# `pick connect <url>` OIDC flow will discover it automatically — see the
# onboarding follow-up.)
#
# What it does NOT do: authenticate. After writing .env you either approve the
# connector once in Studio (post-approval), or pass a fresh dashboard OTT with
# --ott for auto-approval.
#
# Examples:
#   scripts/connect.sh https://discoball.strike48.engineering \
#       019db695-552e-7f81-9377-4643bd170e3c
#   scripts/connect.sh https://foo.example.com <tenant-uuid> --launch
#   scripts/connect.sh http://localhost:4000 <tenant-uuid>   # local dev (ws/no-TLS)
#   scripts/connect.sh https://foo.example.com <tenant-uuid> --ott ott_abc123
#
# Usage:
#   scripts/connect.sh <studio-url> [tenant-uuid] [options]
# Options:
#   --ott <token>     Bare ott_... registration token for auto-approval (no manual Studio step).
#   --instance <id>   Override the auto-derived connector instance id.
#   --reset-cred      Move aside any saved credential for this instance id (backup, non-destructive).
#   --launch          Run ./run-pentest.sh headless dev after writing .env.
#   -h, --help        Show this help.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ENV_FILE="$REPO_ROOT/.env"
# This script owns only STRIKE48_HOST / STRIKE48_API_URL / STRIKE48_TENANT /
# STRIKE48_TLS / STRIKE48_INSTANCE_ID (+ STRIKE48_REGISTRATION_TOKEN with --ott)
# in .env. Everything else (RUST_LOG, DISABLE_SANDBOX, ...) is left untouched.

log() { printf '\033[0;36m[connect]\033[0m %s\n' "$*"; }
warn() { printf '\033[0;33m[connect] WARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[0;31m[connect] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

usage() { sed -n '2,/^$/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

# ---- parse args ----
STUDIO_URL=""
TENANT=""
OTT=""
INSTANCE_OVERRIDE=""
RESET_CRED=false
LAUNCH=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)     usage 0 ;;
        --ott)         [[ -n "${2:-}" ]] || die "--ott requires a token (see --help)"; OTT="$2"; shift 2 ;;
        --instance)    [[ -n "${2:-}" ]] || die "--instance requires an ID (see --help)"; INSTANCE_OVERRIDE="$2"; shift 2 ;;
        --reset-cred)  RESET_CRED=true; shift ;;
        --launch)      LAUNCH=true; shift ;;
        --*)           die "unknown option: $1 (see --help)" ;;
        *)
            if [[ -z "$STUDIO_URL" ]]; then STUDIO_URL="$1"
            elif [[ -z "$TENANT" ]]; then TENANT="$1"
            else die "unexpected argument: $1"; fi
            shift ;;
    esac
done

[[ -n "$STUDIO_URL" ]] || usage 1

# ---- normalize the URL ----
# Honor an explicit scheme; default to secure (wss/https) when none is given,
# matching the SDK's Cloudflare-fronted default. http://ws:// => plaintext.
scheme="${STUDIO_URL%%://*}"
rest="$STUDIO_URL"
[[ "$STUDIO_URL" == *"://"* ]] && rest="${STUDIO_URL#*://}" || scheme=""
hostport="${rest%%/*}"            # strip /path
hostport="${hostport%%\?*}"       # strip ?query
hostport="${hostport%%\#*}"       # strip #fragment
[[ -n "$hostport" ]] || die "could not parse a host from: $STUDIO_URL"

case "$(printf '%s' "$scheme" | tr '[:upper:]' '[:lower:]')" in
    http|ws)          tls="false"; ws_scheme="ws";  http_scheme="http"  ;;
    https|wss|grpcs)  tls="true";  ws_scheme="wss"; http_scheme="https" ;;
    ""|grpc)          tls="true";  ws_scheme="wss"; http_scheme="https"
                      [[ -z "$scheme" ]] && warn "no scheme in URL — assuming secure (${ws_scheme}://). For a local dev Studio pass http://host:port." ;;
    *)                die "unsupported URL scheme: ${scheme}://" ;;
esac

host_only="${hostport%%:*}"
STRIKE48_HOST_V="${ws_scheme}://${hostport}"
STRIKE48_API_URL_V="${http_scheme}://${hostport}/"
STRIKE48_TLS_V="$tls"

# ---- derive a URL-scoped instance id (first host label + short hash) ----
short_hash() {
    if command -v sha256sum >/dev/null 2>&1; then printf '%s' "$1" | sha256sum | cut -c1-6
    elif command -v shasum >/dev/null 2>&1; then printf '%s' "$1" | shasum -a 256 | cut -c1-6
    else printf '%s' "$1" | cksum | tr -d ' ' | cut -c1-6; fi
}
if [[ -n "$INSTANCE_OVERRIDE" ]]; then
    INSTANCE_V="$INSTANCE_OVERRIDE"
else
    first_label="$(printf '%s' "${host_only%%.*}" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+|-+$//g')"
    INSTANCE_V="pick-${first_label}-$(short_hash "${ws_scheme}://${hostport}")"
fi

# ---- tenant validation (advisory) ----
if [[ -n "$TENANT" ]]; then
    [[ "$TENANT" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]] \
        || warn "tenant '$TENANT' is not a UUID — Studio addresses App connectors by tenant UUID; double-check it."
fi

# ---- upsert managed keys into .env (exactly one active line per key) ----
upsert_env() { # key value file
    local key="$1" val="$2" file="$3" tmp
    tmp="$(mktemp)"
    grep -vE "^[[:space:]]*${key}=" "$file" > "$tmp" 2>/dev/null || true
    printf '%s=%s\n' "$key" "$val" >> "$tmp"
    mv "$tmp" "$file"
}

if [[ ! -f "$ENV_FILE" ]]; then
    if [[ -f "$REPO_ROOT/.env.example" ]]; then
        cp "$REPO_ROOT/.env.example" "$ENV_FILE"; log "created .env from .env.example"
    else
        : > "$ENV_FILE"; log "created empty .env"
    fi
else
    backup="$ENV_FILE.bak.$(date +%Y%m%d-%H%M%S)"
    cp "$ENV_FILE" "$backup"; log "backed up existing .env -> $(basename "$backup")"
fi

upsert_env STRIKE48_HOST        "$STRIKE48_HOST_V"    "$ENV_FILE"
upsert_env STRIKE48_API_URL     "$STRIKE48_API_URL_V" "$ENV_FILE"
upsert_env STRIKE48_TLS         "$STRIKE48_TLS_V"     "$ENV_FILE"
upsert_env STRIKE48_INSTANCE_ID "$INSTANCE_V"         "$ENV_FILE"
[[ -n "$TENANT" ]] && upsert_env STRIKE48_TENANT "$TENANT" "$ENV_FILE"

if [[ -n "$OTT" ]]; then
    if [[ "$OTT" == "{"* || "$OTT" == *"localhost"* ]]; then
        warn "the --ott value looks like a JSON blob or embeds localhost; the SDK will reject a register-URL whose origin != STRIKE48_API_URL. Paste the bare 'ott_...' token from THIS Studio's dashboard."
    fi
    upsert_env STRIKE48_REGISTRATION_TOKEN "$OTT" "$ENV_FILE"
else
    # An OTT env var wins over .env in the SDK; a stale export would silently break OTT.
    [[ -n "${STRIKE48_REGISTRATION_TOKEN:-}" ]] && warn "STRIKE48_REGISTRATION_TOKEN is exported in your shell and will override .env — 'unset STRIKE48_REGISTRATION_TOKEN' before launching if you want the post-approval flow."
fi

# ---- stale credential check (credentials are keyed by instance id) ----
CRED="$HOME/.strike48/credentials/pentest-connector_${INSTANCE_V}.json"
if [[ -f "$CRED" ]]; then
    saved_tenant="$(sed -n 's/.*"tenant_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$CRED" | head -1)"
    if [[ -n "$TENANT" && -n "$saved_tenant" && "$saved_tenant" != "$TENANT" ]]; then
        if $RESET_CRED; then
            ts="$(date +%Y%m%d-%H%M%S)"
            for f in "$HOME/.strike48/credentials/pentest-connector_${INSTANCE_V}.json" \
                     "$HOME/.strike48/keys/pentest-connector_${INSTANCE_V}.pem"; do
                [[ -f "$f" ]] && mv "$f" "$f.bak.$ts" && log "moved aside stale credential: $(basename "$f")"
            done
        else
            warn "saved credential for '$INSTANCE_V' is bound to tenant '$saved_tenant' != '$TENANT'. Re-run with --reset-cred to move it aside, or it will be replayed and rejected."
        fi
    fi
fi

# ---- summary ----
log "wrote .env:"
printf '    STRIKE48_HOST        = %s\n' "$STRIKE48_HOST_V"
printf '    STRIKE48_API_URL     = %s\n' "$STRIKE48_API_URL_V"
printf '    STRIKE48_TLS         = %s\n' "$STRIKE48_TLS_V"
printf '    STRIKE48_INSTANCE_ID = %s\n' "$INSTANCE_V"
printf '    STRIKE48_TENANT      = %s\n' "${TENANT:-<unset — REQUIRED for a working connection; set it from the Studio dashboard>}"
[[ -n "$OTT" ]] && printf '    STRIKE48_REGISTRATION_TOKEN = <set>\n'

if [[ -z "$TENANT" ]]; then
    warn "no tenant set — the connector cannot register until STRIKE48_TENANT is a valid UUID for this Studio."
fi

echo
if $LAUNCH; then
    [[ -n "$TENANT" ]] || die "refusing to --launch without a tenant."
    log "launching: ./run-pentest.sh headless dev"
    exec ./run-pentest.sh headless dev
else
    log "next steps:"
    echo "    1. Launch:  ./run-pentest.sh headless dev"
    if [[ -n "$OTT" ]]; then
        echo "    2. Auto-approval via the OTT — watch for 'Registered successfully'."
    else
        echo "    2. In this Studio, approve connector '$INSTANCE_V' (Prospector -> connectors)."
    fi
fi
