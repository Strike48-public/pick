#!/usr/bin/env bash
# macos-sign-notarize.sh - Sign a macOS release binary with the Strike48
# Developer ID certificate, notarize it with Apple, and verify the result.
# Every step fails closed: a release never ships a binary that is unsigned,
# signed by the wrong team, or not accepted by the notary service.
#
# Usage:
#   scripts/macos-sign-notarize.sh <binary>
#
# Required environment (GitHub Actions secrets, see release.yml):
#   APPLE_CERTIFICATE_P12       base64 of the "Developer ID Application" .p12
#   APPLE_CERTIFICATE_PASSWORD  export password of that .p12
#   APPLE_TEAM_ID               10-character Apple team ID of the Strike48 account
#   APPLE_API_KEY_P8            contents of the App Store Connect API key (.p8)
#   APPLE_API_KEY_ID            key ID of that API key
#   APPLE_API_ISSUER_ID         issuer ID (UUID) of that API key
#
# Exit codes:
#   0 - signed, notarized, and verified
#   1 - signing, notarization, or verification failed
#   2 - usage or configuration error (bad arguments, missing secret)
#
# The signing identity is looked up by team ID from the imported certificate,
# so the legal entity name never has to be hardcoded here.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly ENTITLEMENTS="${SCRIPT_DIR}/../entitlements.plist"
readonly REQUIRED_VARS=(
    APPLE_CERTIFICATE_P12
    APPLE_CERTIFICATE_PASSWORD
    APPLE_TEAM_ID
    APPLE_API_KEY_P8
    APPLE_API_KEY_ID
    APPLE_API_ISSUER_ID
)
readonly NOTARY_ATTEMPTS=3
readonly NOTARY_RETRY_DELAY=30
readonly NOTARY_TIMEOUT=30m
# The notary CDN can lag a few seconds behind an "Accepted" verdict.
# Overridable so the self-test can check the negative path without waiting.
readonly TICKET_ATTEMPTS="${MACOS_SIGN_TICKET_ATTEMPTS:-10}"
readonly TICKET_RETRY_DELAY="${MACOS_SIGN_TICKET_RETRY_DELAY:-15}"

WORK_DIR=""
KEYCHAIN=""

log() { printf '==> %s\n' "$*"; }
err() { printf 'error: %s\n' "$*" >&2; }

# require_env - exit 2 naming every required secret that is unset or empty.
require_env() {
    local missing=() name
    for name in "${REQUIRED_VARS[@]}"; do
        [[ -n "${!name:-}" ]] || missing+=("$name")
    done
    if ((${#missing[@]})); then
        err "missing required secret(s): ${missing[*]}"
        err "a tag-triggered release must be signed; configure the secrets or dispatch with macos_signing=false"
        return 2
    fi
}

cleanup() {
    if [[ -n "$KEYCHAIN" ]]; then
        security delete-keychain "$KEYCHAIN" 2>/dev/null || true
    fi
    if [[ -n "$WORK_DIR" ]]; then
        rm -rf "$WORK_DIR"
    fi
}

# setup_keychain - import the .p12 into a throwaway keychain that is first in
# the search list. The keychain password is random and dies with the job.
setup_keychain() {
    local password
    password="$(openssl rand -base64 32)"
    KEYCHAIN="${WORK_DIR}/signing.keychain-db"

    printf '%s' "$APPLE_CERTIFICATE_P12" | base64 --decode >"${WORK_DIR}/cert.p12"
    security create-keychain -p "$password" "$KEYCHAIN"
    security set-keychain-settings -lut 21600 "$KEYCHAIN"
    security unlock-keychain -p "$password" "$KEYCHAIN"
    # `security import` takes the passphrase only as an argument; the runner is
    # an ephemeral single-tenant VM, so argv exposure is limited to this job.
    security import "${WORK_DIR}/cert.p12" -k "$KEYCHAIN" -f pkcs12 \
        -P "$APPLE_CERTIFICATE_PASSWORD" -T /usr/bin/codesign
    rm -f "${WORK_DIR}/cert.p12"
    security set-key-partition-list -S apple-tool:,apple: -k "$password" "$KEYCHAIN" >/dev/null

    local existing=()
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}"
        existing+=("${line//\"/}")
    done < <(security list-keychains -d user)
    security list-keychains -d user -s "$KEYCHAIN" "${existing[@]}"
}

# find_identity <find-identity-output> <team-id> - print the SHA-1 of the first
# valid "Developer ID Application" identity for the team, or nothing.
find_identity() {
    local listing="$1" team="$2"
    awk -v team="(${team})\"" '
        /"Developer ID Application: / && index($0, team) { print $2; exit }
    ' <<<"$listing"
}

resolve_identity() {
    local listing identity
    listing="$(security find-identity -v -p codesigning "$KEYCHAIN")"
    identity="$(find_identity "$listing" "$APPLE_TEAM_ID")"
    if [[ -z "$identity" ]]; then
        err "no valid 'Developer ID Application' identity for team ${APPLE_TEAM_ID} in the certificate"
        err "the .p12 must be a Developer ID Application cert with its private key; all identities seen:"
        security find-identity -p codesigning "$KEYCHAIN" >&2 || true
        return 1
    fi
    printf '%s\n' "$identity"
}

sign_binary() {
    local binary="$1" identity="$2"
    log "Signing ${binary}"
    codesign --force --timestamp --options runtime \
        --entitlements "$ENTITLEMENTS" \
        --keychain "$KEYCHAIN" \
        --sign "$identity" \
        "$binary"
}

# verify_signature - the binary must carry a valid Apple-anchored signature from
# OUR team with the hardened runtime that notarization requires. The requirement
# pins anchor and team only: a same-team Development certificate would pass here
# and then fail at notarization, which accepts Developer ID signatures only.
verify_signature() {
    local binary="$1"
    local requirement="anchor apple generic and certificate leaf[subject.OU] = \"${APPLE_TEAM_ID}\""
    local details
    if ! codesign --verify --strict --verbose=2 -R="$requirement" "$binary"; then
        err "${binary} is not signed with an Apple-issued certificate of team ${APPLE_TEAM_ID}"
        return 1
    fi
    # Captured first: piping into `grep -q` can SIGPIPE codesign under pipefail.
    details="$(codesign -dv "$binary" 2>&1)"
    if ! grep -q '^CodeDirectory.*flags=.*(.*runtime.*)' <<<"$details"; then
        err "${binary} is signed without the hardened runtime"
        return 1
    fi
}

# notary_field <output> <field> - print <field> from the JSON document in
# notarytool output, or nothing when there is none (a transport or auth
# failure). Parsing starts at the first line opening a JSON object, so stray
# progress text cannot hide the verdict, and the document may be compact or
# pretty-printed.
notary_field() {
    sed -n '/^[[:space:]]*{/,$p' <<<"$1" |
        jq -rs --arg f "$2" '[.[] | objects | .[$f] // empty] | last // empty' 2>/dev/null || true
}

notary_submit() {
    local archive="$1" key="$2"
    xcrun notarytool submit "$archive" \
        --key "$key" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER_ID" \
        --wait --timeout "$NOTARY_TIMEOUT" --output-format json
}

# notarize - submit and wait. "Accepted" passes, "Invalid"/"Rejected" fail at
# once with Apple's log (a resubmit would get the same verdict), and anything
# else (timeout, network, non-JSON output) is retried.
notarize() {
    local binary="$1" archive="${WORK_DIR}/notarize.zip" key="${WORK_DIR}/api-key.p8"
    local attempt output status id
    printf '%s\n' "$APPLE_API_KEY_P8" >"$key"
    ditto -c -k --keepParent "$binary" "$archive"

    for ((attempt = 1; attempt <= NOTARY_ATTEMPTS; attempt++)); do
        log "Notarization attempt ${attempt}/${NOTARY_ATTEMPTS}"
        output="$(notary_submit "$archive" "$key" 2>"${WORK_DIR}/notary.err")" || true
        status="$(notary_field "$output" status)"
        id="$(notary_field "$output" id)"
        case "$status" in
            Accepted)
                log "Notarization accepted (submission ${id})"
                return 0
                ;;
            Invalid | Rejected)
                err "notarization ${status} (submission ${id}); Apple's log follows"
                xcrun notarytool log "$id" --key "$key" --key-id "$APPLE_API_KEY_ID" \
                    --issuer "$APPLE_API_ISSUER_ID" >&2 || true
                return 1
                ;;
        esac
        err "notarization did not finish (status '${status:-none}'): ${output}"
        cat "${WORK_DIR}/notary.err" >&2 || true
        if ((attempt < NOTARY_ATTEMPTS)); then
            sleep "$NOTARY_RETRY_DELAY"
        fi
    done
    err "notarization failed after ${NOTARY_ATTEMPTS} attempts"
    return 1
}

# verify_notarized - Gatekeeper's own online check. `--check-notarization`
# alone passes ad-hoc binaries, so it is paired with the `notarized`
# requirement, which fails closed when no ticket exists.
verify_notarized() {
    local binary="$1" attempt
    for ((attempt = 1; attempt <= TICKET_ATTEMPTS; attempt++)); do
        if codesign --verify --strict --check-notarization -R='notarized' "$binary" 2>/dev/null; then
            log "Gatekeeper sees the notarization ticket for ${binary}"
            return 0
        fi
        if ((attempt < TICKET_ATTEMPTS)); then
            sleep "$TICKET_RETRY_DELAY"
        fi
    done
    err "${binary} was accepted by the notary service but Gatekeeper finds no ticket:"
    codesign --verify --strict --check-notarization -R='notarized' "$binary" || true
    return 1
}

main() {
    if [[ $# -ne 1 || ! -f "$1" ]]; then
        err "usage: $(basename "$0") <binary>"
        return 2
    fi
    local binary="$1" identity
    require_env

    # The decoded .p12 and .p8 land in WORK_DIR; keep them owner-only.
    umask 077
    WORK_DIR="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/macos-sign.XXXXXX")"
    trap cleanup EXIT

    setup_keychain
    identity="$(resolve_identity)"
    sign_binary "$binary" "$identity"
    verify_signature "$binary"
    notarize "$binary"
    verify_notarized "$binary"
}

# Run only when executed, so the test script can source the pure helpers.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
