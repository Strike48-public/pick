#!/usr/bin/env bash
# macos-sign-notarize.test.sh - Regression tests for scripts/macos-sign-notarize.sh.
#
# Pins the fail-closed behavior of the release signing path (#281): a missing
# secret, a certificate from the wrong team, a rejected notarization, or a
# binary Gatekeeper does not see as notarized must each fail the release
# rather than ship. Hermetic: no Apple secrets or network are used. The
# notarytool calls are stubbed, and the codesign checks run against an
# ad-hoc signed copy of a system binary, so it runs in CI on every PR.
#
# The codesign cases need macOS and are skipped elsewhere.

set -uo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly TEST_DIR
readonly SUBJECT="${TEST_DIR}/macos-sign-notarize.sh"
readonly TEAM="ABCDE12345"

fail=0

check() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$actual" == "$expected" ]]; then
        printf 'ok   - %s\n' "$desc"
    else
        printf 'FAIL - %s (expected [%s], got [%s])\n' "$desc" "$expected" "$actual"
        fail=1
    fi
}

# shellcheck source=scripts/macos-sign-notarize.sh
source "$SUBJECT"
set +e

# --- Identity selection: only a Developer ID Application cert of OUR team ---

listing='  1) 1111111111111111111111111111111111111111 "Apple Development: Someone (ABCDE12345)"
  2) 2222222222222222222222222222222222222222 "Developer ID Application: Other Corp (ZZZZZ99999)"
  3) 3333333333333333333333333333333333333333 "Developer ID Installer: Strike48 (ABCDE12345)"
  4) 4444444444444444444444444444444444444444 "Developer ID Application: Strike48 (ABCDE12345)"
     4 valid identities found'
check "picks our team's Developer ID Application identity" \
    "4444444444444444444444444444444444444444" "$(find_identity "$listing" "$TEAM")"
check "ignores another team's Developer ID Application identity" \
    "" "$(find_identity "$listing" "QQQQQ00000")"
check "a team ID that is a prefix of another does not match" \
    "" "$(find_identity "$listing" "ABCDE1234")"

# --- notarytool output parsing ---

check "reads Accepted from JSON" "Accepted" \
    "$(notary_field '{"id":"abc","status":"Accepted","message":"ok"}' status)"
check "reads the submission id" "abc" \
    "$(notary_field '{"id":"abc","status":"Invalid"}' id)"
check "finds the verdict after progress text" "Invalid" \
    "$(notary_field $'Waiting for processing...\nCurrent status: In Progress\n{"id":"abc","status":"Invalid"}' status)"
check "reads the verdict from pretty-printed JSON" "Accepted" \
    "$(notary_field $'Conducting pre-submission checks...\n{\n  "id" : "abc",\n  "status" : "Accepted"\n}' status)"
check "non-JSON error output yields no status" "" \
    "$(notary_field 'Error: HTTP status code: 401. Unable to authenticate.' status)"

# --- Missing secrets fail closed with exit 2 before anything is touched ---

unset_all() { unset "${REQUIRED_VARS[@]}"; }
set_all() {
    local name
    for name in "${REQUIRED_VARS[@]}"; do export "$name=x"; done
}

out="$(
    unset_all
    require_env 2>&1
)"
check "all secrets missing exits 2" "2" "$(
    unset_all
    require_env >/dev/null 2>&1
    echo $?
)"
check "error names every missing secret" "1" \
    "$(grep -c 'APPLE_CERTIFICATE_P12 APPLE_CERTIFICATE_PASSWORD APPLE_TEAM_ID APPLE_API_KEY_P8 APPLE_API_KEY_ID APPLE_API_ISSUER_ID' <<<"$out")"
check "an empty secret counts as missing" "1" \
    "$(
        set_all
        export APPLE_API_KEY_ID=""
        require_env 2>&1 | grep -c 'secret(s): APPLE_API_KEY_ID$'
    )"
check "all secrets present passes" "0" "$(
    set_all
    require_env >/dev/null 2>&1
    echo $?
)"

bin="$(mktemp "${TMPDIR:-/tmp}/sign-test.XXXXXX")"
trap 'rm -f "$bin"' EXIT
check "no argument is a usage error" "2" "$(
    bash "$SUBJECT" >/dev/null 2>&1
    echo $?
)"
check "a missing binary is a usage error" "2" "$(
    bash "$SUBJECT" /nonexistent >/dev/null 2>&1
    echo $?
)"
check "missing secrets stop main with exit 2" "2" \
    "$(
        env -u APPLE_TEAM_ID bash "$SUBJECT" "$bin" >/dev/null 2>&1
        echo $?
    )"

# --- Notarization retry policy (notarytool stubbed) ---

# run_notarize <responses...> - each call to the stub prints the next response.
# Prints "<exit> <calls>".
run_notarize() {
    local responses=("$@")
    (
        WORK_DIR="$(mktemp -d)"
        set_all
        echo 0 >"${WORK_DIR}/calls"
        ditto() { :; }
        sleep() { :; }
        xcrun() { :; }
        # notarize calls this inside $(...), so the counter lives in a file.
        notary_submit() {
            local calls
            calls="$(cat "${WORK_DIR}/calls")"
            echo $((calls + 1)) >"${WORK_DIR}/calls"
            # Past the scripted responses, keep failing transiently.
            printf '%s\n' "${responses[$calls]:-transient}"
        }
        notarize "$bin" >/dev/null 2>&1
        rc=$?
        echo "$rc $(cat "${WORK_DIR}/calls")"
        rm -rf "$WORK_DIR"
    )
}

accepted='{"id":"a","status":"Accepted"}'
invalid='{"id":"a","status":"Invalid"}'
transient='Error: network connection was lost'
check "Accepted on first try passes after one submit" "0 1" "$(run_notarize "$accepted")"
check "Invalid fails at once without resubmitting" "1 1" "$(run_notarize "$invalid")"
check "transient errors are retried until Accepted" "0 3" \
    "$(run_notarize "$transient" "$transient" "$accepted")"
check "persistent transient errors fail after 3 submits" "1 3" \
    "$(run_notarize "$transient" "$transient" "$transient")"

# --- main runs every step in order, stops at the first failure, cleans up ---

# run_main <failing-step> - run main under the script's own `set -e` with each
# step stubbed to log its name; <failing-step> (or "none") returns 1.
# Prints the step log, then "exit=<code> workdir=<gone|left>".
run_main() {
    local failing="$1" stubs log
    stubs="$(mktemp)"
    log="$(mktemp)"
    cat >"$stubs" <<EOF
security() { :; }
setup_keychain() { echo "\$WORK_DIR" >"$log.dir"; echo setup_keychain >>"$log"; }
resolve_identity() { echo resolve_identity >>"$log"; [[ "$failing" != resolve_identity ]] && echo HASH; }
EOF
    local step
    for step in sign_binary verify_signature notarize verify_notarized; do
        printf '%s() { echo %s >>"%s"; [[ "%s" != %s ]]; }\n' \
            "$step" "$step" "$log" "$failing" "$step" >>"$stubs"
    done
    (
        set_all
        bash -c "source '$SUBJECT'; source '$stubs'; main '$bin'" >/dev/null 2>&1
        echo "exit=$?" >>"$log.rc"
    )
    tr '\n' ' ' <"$log"
    printf '%s workdir=%s\n' "$(cat "$log.rc")" "$([[ -d "$(cat "$log.dir")" ]] && echo left || echo gone)"
    rm -f "$stubs" "$log" "$log.rc" "$log.dir"
}

all_steps="setup_keychain resolve_identity sign_binary verify_signature notarize verify_notarized"
check "a clean run executes every step in order and cleans up" \
    "${all_steps} exit=0 workdir=gone" "$(run_main none)"
check "a rejected notarization stops before the ticket check" \
    "setup_keychain resolve_identity sign_binary verify_signature notarize exit=1 workdir=gone" \
    "$(run_main notarize)"
check "a bad signature stops before notarization" \
    "setup_keychain resolve_identity sign_binary verify_signature exit=1 workdir=gone" \
    "$(run_main verify_signature)"
check "a missing identity stops before signing" \
    "setup_keychain resolve_identity exit=1 workdir=gone" "$(run_main resolve_identity)"

# --- Real codesign checks against an ad-hoc signed binary (macOS only) ---

if [[ "$(uname -s)" == "Darwin" ]]; then
    cp -f /bin/ls "$bin"
    # Ad-hoc WITH the hardened runtime, so only the team requirement can reject it.
    codesign --remove-signature "$bin" && codesign --force --sign - --options runtime "$bin" 2>/dev/null
    check "an ad-hoc signature fails the team check" "1" \
        "$(APPLE_TEAM_ID="$TEAM" verify_signature "$bin" >/dev/null 2>&1 && echo 0 || echo 1)"
    check "an ad-hoc binary is not seen as notarized" "1" \
        "$(MACOS_SIGN_TICKET_ATTEMPTS=1 MACOS_SIGN_TICKET_RETRY_DELAY=0 bash -c \
            "source '$SUBJECT'; verify_notarized '$bin'" >/dev/null 2>&1 && echo 0 || echo 1)"
else
    printf 'skip - codesign checks need macOS\n'
fi

if ((fail)); then
    printf '\nmacos-sign-notarize self-test FAILED\n'
    exit 1
fi
printf '\nmacos-sign-notarize self-test passed\n'
