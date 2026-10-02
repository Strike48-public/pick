#!/usr/bin/env bash
# preflight.test.sh - Regression tests for deploy/docker/preflight.sh (#491).
#
# Hermetic: every external command preflight uses (docker, curl, getent, ip,
# timeout, uname, timedatectl, df, resolvectl) is replaced by a stub on PATH
# whose behaviour each case sets through STUB_* variables. No Docker daemon,
# network, or real container is needed, so this runs in CI on every PR.
#
# Each case pins one of the faults the issue requires preflight to catch: wrong
# network mode, a host that cannot resolve internal names, a bridge subnet
# overlap, blocked egress, and an old Docker or Compose version.

# The stub bodies are single-quoted on purpose: they are code for the stub to
# run later, not strings to expand now.
# shellcheck disable=SC2016

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly PREFLIGHT="${SCRIPT_DIR}/preflight.sh"

WORK="$(mktemp -d)"
readonly WORK
trap 'rm -rf "$WORK"' EXIT

fail=0
OUT=""
RC=0

# --- Stubs ----------------------------------------------------------------------

make_stub() {
    local dir="$1" name="$2" body="$3"
    mkdir -p "$dir"
    printf '#!/usr/bin/env bash\n%s\n' "$body" >"$dir/$name"
    chmod +x "$dir/$name"
}

# In a space-separated list of key=value pairs, print the value for a key.
readonly LOOKUP='lookup() { local k="$1" p; for p in $2; do [[ "${p%%=*}" == "$k" ]] && { printf "%s" "${p#*=}"; return 0; }; done; return 1; }'

write_base_stubs() {
    local d="$WORK/base"
    make_stub "$d" uname 'case "$1" in -m) echo x86_64 ;; *) echo "${STUB_UNAME:-Linux}" ;; esac'
    make_stub "$d" timedatectl 'echo "${STUB_NTP:-yes}"'
    make_stub "$d" df 'printf "Filesystem 1024-blocks Used Available Capacity Mounted\n/dev/x 1 1 %s 1%% /\n" "${STUB_DISK_KB:-50000000}"'
    make_stub "$d" resolvectl 'exit 0'
    make_stub "$d" curl "$LOOKUP"'
url="${!#}"; host="${url#https://}"; host="${host%%/*}"
if rc="$(lookup "$host" "${STUB_CURL_FAIL:-}")"; then exit "$rc"; fi
printf 200'
    make_stub "$d" getent "$LOOKUP"'
ip="$(lookup "$2" "${STUB_DNS:-}")" || exit 2
printf "%s STREAM %s\n" "$ip" "$2"'
    make_stub "$d" timeout '
if [[ "$2" != bash ]]; then shift; exec "$@"; fi
target="${4#</dev/tcp/}"; target="${target/\//:}"
[[ " ${STUB_TCP_OPEN:-} " == *" $target "* ]]'
    make_stub "$d" ip 'printf "%b" "${STUB_ROUTES:-}"'
}

write_docker_stub() {
    make_stub "$WORK/docker" docker "$LOOKUP"'
if [[ "$1" == info ]]; then
    [[ -n "${STUB_DOCKER_HANG:-}" ]] && exec sleep 30
    [[ -n "${STUB_DOCKER_ERR:-}" ]] && { echo "$STUB_DOCKER_ERR" >&2; exit 1; }
    case "$3" in
        *ServerVersion*) echo "${STUB_ENGINE:-29.5.2}" ;;
        *OperatingSystem*) echo "${STUB_DOCKER_OS:-Ubuntu 24.04 LTS}" ;;
        *Architecture*) echo "${STUB_ARCH:-x86_64}" ;;
        *DockerRootDir*) echo /var/lib/docker ;;
        *DefaultAddressPools*) [[ -n "${STUB_POOLS_FAIL:-}" ]] && exit 1; echo "${STUB_POOLS:-null}" ;;
    esac
    exit 0
fi
if [[ "$1" == compose ]]; then [[ -n "${STUB_COMPOSE-5.5.1}" ]] && echo "${STUB_COMPOSE-5.5.1}" && exit 0; exit 1; fi
if [[ "$1" == inspect ]]; then
    [[ -n "${STUB_MODE:-}" ]] || exit 1
    case "$4" in *Status*) echo running ;; *NetworkMode*) echo "$STUB_MODE" ;; esac
    exit 0
fi
if [[ "$1" == exec && "$3" == getent ]]; then [[ " ${STUB_CONTAINER_DNS:-} " == *" $5 "* ]]; exit; fi
if [[ "$1" == exec ]]; then
    t="${7#</dev/tcp/}"; t="${t/\//:}"
    [[ " ${STUB_CONTAINER_TCP:-} " == *" $t "* ]]; exit
fi
if [[ "$1 $2" == "network ls" ]]; then [[ -n "${STUB_NETLS_FAIL:-}" ]] && exit 1; for p in ${STUB_NETWORKS:-bridge=172.17.0.0/16}; do echo "${p%%=*}"; done; exit 0; fi
if [[ "$1 $2" == "network inspect" ]]; then
    s="$(lookup "$3" "${STUB_NETWORKS:-bridge=172.17.0.0/16}")" || exit 1
    echo "$3 $s"; exit 0
fi
exit 0'
    make_stub "$WORK/compose-v1" docker-compose 'echo "docker-compose version 1.29.2"'
}

# --- Runner ---------------------------------------------------------------------

# The system tools preflight and the stubs need, linked into one directory so
# PATH holds nothing else. A runner's own docker or getent can then never leak
# into a case.
link_system_tools() {
    local tool src
    mkdir -p "$WORK/sys"
    for tool in bash env awk sed grep sort head tail tr cut seq cat mkdir dirname sleep; do
        src="$(command -v "$tool")" || {
            printf 'preflight.test: %s not found\n' "$tool" >&2
            exit 2
        }
        ln -s "$src" "$WORK/sys/$tool"
    done
}

# run_preflight <extra PATH dirs> [preflight args...]
# Runs with only the stub dirs and the linked system tools on PATH, from an
# empty folder so no real .env is read.
run_preflight() {
    local dirs="$1"
    shift
    mkdir -p "$WORK/cwd"
    OUT="$(cd "$WORK/cwd" && PATH="${dirs}:$WORK/base:$WORK/sys" \
        PREFLIGHT_RESOLV_CONF="$WORK/resolv.conf" "$PREFLIGHT" "$@" 2>&1)"
    RC=$?
}

report() {
    if [[ "$2" == ok ]]; then
        printf 'ok   - %s\n' "$1"
    else
        printf 'FAIL - %s\n%s\n' "$1" "$OUT" | sed '3,$s/^/       /'
        fail=1
    fi
}

# expect <description> <exit> <grep -E pattern that must match> [pattern that must NOT match]
expect() {
    local desc="$1" code="$2" want="$3" deny="${4:-}"
    if [[ "$RC" != "$code" ]]; then
        report "$desc (expected exit $code, got $RC)" bad
    elif ! grep -qE -- "$want" <<<"$OUT"; then
        report "$desc (missing: $want)" bad
    elif [[ -n "$deny" ]] && grep -qE -- "$deny" <<<"$OUT"; then
        report "$desc (unexpected: $deny)" bad
    else
        report "$desc" ok
    fi
}

reset_stubs() {
    unset STUB_UNAME STUB_NTP STUB_DISK_KB STUB_CURL_FAIL STUB_DNS STUB_TCP_OPEN \
        STUB_ROUTES STUB_DOCKER_ERR STUB_ENGINE STUB_DOCKER_OS STUB_ARCH STUB_POOLS \
        STUB_COMPOSE STUB_MODE STUB_CONTAINER_DNS STUB_CONTAINER_TCP STUB_NETWORKS \
        STUB_DOCKER_HANG STUB_POOLS_FAIL STUB_NETLS_FAIL PREFLIGHT_DOCKER_SECONDS
    printf 'nameserver 10.0.0.2\n' >"$WORK/resolv.conf"
    export STUB_ROUTES='10.20.0.0/24 dev eth0 proto kernel\n172.17.0.0/16 dev docker0 proto kernel\n'
}

D="$WORK/docker"
link_system_tools
write_base_stubs
write_docker_stub
export STUB_UNAME STUB_NTP STUB_DISK_KB STUB_CURL_FAIL STUB_DNS STUB_TCP_OPEN STUB_ROUTES \
    STUB_DOCKER_ERR STUB_ENGINE STUB_DOCKER_OS STUB_ARCH STUB_POOLS STUB_COMPOSE STUB_MODE \
    STUB_CONTAINER_DNS STUB_CONTAINER_TCP STUB_NETWORKS STUB_DOCKER_HANG STUB_POOLS_FAIL \
    STUB_NETLS_FAIL PREFLIGHT_DOCKER_SECONDS

# --- Healthy host ---------------------------------------------------------------

reset_stubs
run_preflight "$D" --studio https://studio.example.com/ --auth auth.example.com
expect "healthy host passes with exit 0" 0 "0 failed" "FAIL "
expect "Studio egress is checked against the host from --studio" 0 "PASS  Outbound 443 to studio.example.com \(Studio\)"

# --- Host and Docker ------------------------------------------------------------

reset_stubs
export STUB_UNAME=Darwin
run_preflight "$D"
expect "a non-Linux host warns to use the native app" 0 "WARN  This host runs Darwin.*" "FAIL "
expect "non-Linux fix names the native app" 0 "native Pick app"

reset_stubs
run_preflight ""
expect "missing Docker fails with the install link" 1 "FAIL  Docker is not installed"

reset_stubs
export STUB_DOCKER_ERR="permission denied while trying to connect to the Docker daemon socket"
run_preflight "$D"
expect "a user outside the docker group gets the usermod fix" 1 "usermod -aG docker"

reset_stubs
export STUB_DOCKER_ERR="Cannot connect to the Docker daemon"
run_preflight "$D"
expect "a stopped daemon gets the systemctl fix" 1 "systemctl enable --now docker"

reset_stubs
export STUB_DOCKER_OS="Docker Desktop"
run_preflight "$D"
expect "Docker Desktop warns that host networking is layer 4 only" 0 "WARN  Docker Desktop .* not Docker Engine"

reset_stubs
export STUB_ENGINE=20.10.24
run_preflight "$D"
expect "an old Docker Engine warns to upgrade" 0 "WARN  Docker Engine 20.10.24 is older than 25.0"

reset_stubs
export STUB_COMPOSE=2.2.3
run_preflight "$D"
expect "Compose older than 2.3.3 fails" 1 "FAIL  Docker Compose 2.2.3 is older than 2.3.3"

reset_stubs
export STUB_COMPOSE=v2.3.3
run_preflight "$D"
expect "Compose 2.3.3 exactly passes" 0 "PASS  Docker Compose 2.3.3"

reset_stubs
export STUB_COMPOSE=""
run_preflight "$D:$WORK/compose-v1"
expect "only Compose v1 installed fails with the plugin fix" 1 "FAIL  Only the old docker-compose 1.x"

reset_stubs
export STUB_ARCH=s390x
run_preflight "$D"
expect "an unsupported architecture fails" 1 "FAIL  Architecture s390x is not supported"

reset_stubs
export STUB_NTP=no STUB_DISK_KB=1000000
run_preflight "$D"
expect "an unsynchronised clock and low disk warn" 0 "WARN  System clock is not synchronised"
expect "low disk warns" 0 "WARN  Only 0 GB free"

# --- Egress ---------------------------------------------------------------------

reset_stubs
export STUB_CURL_FAIL="studio.example.com=28"
run_preflight "$D" --studio studio.example.com
expect "blocked egress to Studio fails as a timeout" 1 "FAIL  Outbound 443 to studio.example.com \(Studio\): the connection timed out"

reset_stubs
export STUB_CURL_FAIL="studio.example.com=60"
run_preflight "$D" --studio studio.example.com
expect "an untrusted certificate points at the private-CA section" 1 "Corporate proxy and private CA"

reset_stubs
export STUB_CURL_FAIL="ghcr.io=7"
run_preflight "$D"
expect "blocked egress to the registry fails" 1 "FAIL  Outbound 443 to ghcr.io"

reset_stubs
export STUB_CURL_FAIL="github.com=28"
run_preflight "$D"
expect "blocked github.com only warns (install-time and nuclei only)" 0 "WARN  Outbound 443 to github.com"

# --- .env -----------------------------------------------------------------------

readonly TENANT=11111111-2222-3333-4444-555555555555

# write_env [extra lines...]: a valid .env plus any extra lines, which override
# earlier ones because preflight reads the last match.
write_env() {
    mkdir -p "$WORK/cwd"
    {
        printf 'STRIKE48_HOST=wss://studio.from-env.example\n'
        printf 'STRIKE48_API_URL=https://studio.from-env.example/\n'
        printf 'STRIKE48_TENANT=%s\n' "$TENANT"
        printf 'STRIKE48_INSTANCE_ID=pick-lab-01\n'
        printf '# STRIKE48_REGISTRATION_TOKEN=\n'
        printf '%s\n' "$@"
    } >"$WORK/cwd/.env"
}

reset_stubs
write_env
run_preflight "$D"
expect "a valid .env passes, Studio comes from it, and no value is printed" 0 "PASS  .env has the four required values" "$TENANT|pick-lab-01"
expect "the Studio host is read from .env" 0 "Outbound 443 to studio.from-env.example"

reset_stubs
cp "$SCRIPT_DIR/.env.example" "$WORK/cwd/.env"
run_preflight "$D"
expect "an unedited copy of .env.example fails on the example values" 1 "FAIL  STRIKE48_TENANT in .env still has the example value"

reset_stubs
write_env "STRIKE48_HOST=wss://example.com" "STRIKE48_API_URL=https://example.com/"
run_preflight "$D"
expect "a real Studio host that is not the template value is not called an example" 0 "PASS  .env has the four required values" "example value"

reset_stubs
write_env "STRIKE48_TENANT="
run_preflight "$D"
expect "an empty required value fails naming the key" 1 "FAIL  STRIKE48_TENANT is missing or empty"

reset_stubs
write_env "STRIKE48_HOST=wss://studio.from-env.example:8443"
run_preflight "$D"
expect "a port in STRIKE48_HOST fails" 1 "FAIL  STRIKE48_HOST in .env has a port or a path"

reset_stubs
write_env "STRIKE48_HOST=https://studio.from-env.example"
run_preflight "$D"
expect "an https:// STRIKE48_HOST fails" 1 "FAIL  STRIKE48_HOST in .env does not start with wss://"

reset_stubs
write_env "STRIKE48_TENANT=acme-corp"
run_preflight "$D"
expect "a tenant slug instead of a UUID warns" 0 "WARN  STRIKE48_TENANT in .env is not shaped like a UUID" "acme-corp"

reset_stubs
write_env "STRIKE48_REGISTRATION_TOKEN="
run_preflight "$D"
expect "a set-but-empty registration token fails" 1 "FAIL  STRIKE48_REGISTRATION_TOKEN is set to an empty value"

reset_stubs
write_env "STRIKE48_REGISTRATION_TOKEN=ott_secretvalue123"
run_preflight "$D"
expect "a filled registration token passes and is never printed" 0 "PASS  .env has the four required values" "ott_secretvalue123"

reset_stubs
write_env "PENTEST_ALLOW_PRIVATE_IPS=false" "MATRIX_TLS_INSECURE=true"
run_preflight "$D"
expect "an unrecognised PENTEST_ALLOW_PRIVATE_IPS warns" 0 "WARN  PENTEST_ALLOW_PRIVATE_IPS in .env is not true or 1"
expect "a pinned value set in .env warns to remove it" 0 "WARN  MATRIX_TLS_INSECURE is set in .env"
rm -f "$WORK/cwd/.env"

# --- Names and targets ----------------------------------------------------------

reset_stubs
printf 'nameserver 8.8.8.8\n' >"$WORK/resolv.conf"
run_preflight "$D" --resolve intranet.corp.example
expect "a host on public DNS fails to resolve internal names and says why" 1 "public DNS \(8.8.8.8\)"

reset_stubs
export STUB_DNS="intranet.corp.example=10.20.0.9" STUB_MODE=bridge
run_preflight "$D" --resolve intranet.corp.example
expect "host resolves but container does not fails with the dns: fix" 1 "FAIL  The host resolves intranet.corp.example but container"

reset_stubs
export STUB_DNS="intranet.corp.example=10.20.0.9" STUB_MODE=bridge STUB_CONTAINER_DNS="intranet.corp.example"
run_preflight "$D" --resolve intranet.corp.example
expect "host and container both resolve" 0 "PASS  Container pick-connector resolves intranet.corp.example"

reset_stubs
run_preflight "$D" --target 10.20.0.9:22
expect "an unreachable target fails" 1 "FAIL  This host cannot reach 10.20.0.9 port 22"

reset_stubs
export STUB_TCP_OPEN="10.20.0.9:22" STUB_MODE=bridge
run_preflight "$D" --target 10.20.0.9:22
expect "host reaches a target the container cannot" 1 "FAIL  The host reaches 10.20.0.9 port 22 but container"

# --- Docker networking ----------------------------------------------------------

reset_stubs
export STUB_MODE=bridge
run_preflight "$D" --discovery
expect "bridge network with discovery planned fails" 1 "FAIL  Container pick-connector is on the bridge network"

reset_stubs
export STUB_MODE=bridge
run_preflight "$D"
expect "bridge network without discovery passes" 0 "PASS  Container pick-connector is on the bridge network"

reset_stubs
export STUB_MODE=host
run_preflight "$D" --discovery
expect "host networking with discovery passes" 0 "PASS  Container pick-connector uses host networking"

reset_stubs
run_preflight "$D" --discovery
expect "no container yet with discovery planned warns to add the override first" 0 "WARN  No pick-connector container yet"

reset_stubs
export STUB_NETWORKS="bridge=172.17.0.0/16 pick-connector_default=10.20.0.0/16"
run_preflight "$D"
expect "a Docker subnet overlapping a host route fails" 1 "FAIL  Docker network pick-connector_default \(10.20.0.0/16\) overlaps the host route 10.20.0.0/24 on eth0"

reset_stubs
run_preflight "$D"
expect "Docker's own docker0 route is not an overlap" 0 "PASS  No Docker subnet overlaps a host route" "overlaps the host route 172.17"

reset_stubs
export STUB_TCP_OPEN="172.17.5.5:443"
run_preflight "$D" --target 172.17.5.5:443
expect "a target inside an existing Docker subnet fails" 1 "FAIL  Target 172.17.5.5 is inside Docker network bridge"

reset_stubs
export STUB_TCP_OPEN="172.22.1.1:443"
run_preflight "$D" --target 172.22.1.1:443
expect "a target inside Docker's default pool warns before the network exists" 0 "WARN  Target 172.22.1.1 is inside Docker's address pool 172.22.0.0/16"

reset_stubs
export STUB_TCP_OPEN="172.22.1.1:443" STUB_DNS="intranet.corp.example=172.22.1.1"
run_preflight "$D" --target 172.22.1.1:443 --resolve intranet.corp.example
count="$(grep -c "WARN  Target 172.22.1.1" <<<"$OUT")"
if [[ "$count" == 1 ]]; then report "a name and a target sharing an address warn once" ok; else report "a name and a target sharing an address warn once (got $count)" bad; fi

reset_stubs
export STUB_TCP_OPEN="10.20.0.9:22 192.168.5.2:22"
export STUB_ROUTES='192.168.5.0/24 dev eth0 proto kernel\n'
run_preflight "$D" --target 192.168.5.2:22
expect "a target on a network the host has a route to gets no pool warning" 0 "PASS  No Docker subnet overlaps" "address pool"

reset_stubs
export STUB_TCP_OPEN="172.22.1.1:443" STUB_NETWORKS="bridge=172.17.0.0/16 pick-connector_default=172.18.0.0/16"
run_preflight "$D" --target 172.22.1.1:443
expect "no pool warning once the connector's network exists outside the target" 0 "PASS  No Docker subnet overlaps a host route or a target" "address pool"

reset_stubs
export STUB_TCP_OPEN="172.22.1.1:443" STUB_POOLS='[{"Base":"10.200.0.0/16","Size":24}]'
run_preflight "$D" --target 172.22.1.1:443
expect "a custom daemon pool replaces Docker's defaults" 0 "PASS  No Docker subnet overlaps" "address pool"

# --- Silent-failure review (a check must never pass on data it could not read) -

reset_stubs
cp "$SCRIPT_DIR/.env.example" "$WORK/cwd/.env"
sed 's/$/\r/' "$WORK/cwd/.env" >"$WORK/cwd/.env.crlf" && mv "$WORK/cwd/.env.crlf" "$WORK/cwd/.env"
run_preflight "$D"
expect "an unedited .env.example saved with Windows line endings still fails" 1 "FAIL  STRIKE48_TENANT in .env still has the example value"

reset_stubs
write_env 'STRIKE48_API_URL=https://studio.commented.example # our Studio'
run_preflight "$D"
expect "an inline comment is read the way Compose reads it" 0 "Outbound 443 to studio.commented.example \(Studio\)" "FAIL "

reset_stubs
printf 'export STRIKE48_HOST=wss://studio.exported.example\nexport STRIKE48_API_URL=https://studio.exported.example/\nexport STRIKE48_TENANT=%s\nexport STRIKE48_INSTANCE_ID=pick-lab-02\n' "$TENANT" >"$WORK/cwd/.env"
run_preflight "$D"
expect "export-prefixed lines are read the way Compose reads them" 0 "PASS  .env has the four required values" "FAIL "
rm -f "$WORK/cwd/.env"

reset_stubs
export STUB_NETLS_FAIL=1
run_preflight "$D"
expect "a failed network listing reports overlap as not checked, not clean" 0 "WARN  Could not read Docker's networks" "No Docker subnet overlaps"

reset_stubs
export STUB_POOLS_FAIL=1 STUB_TCP_OPEN="10.200.5.5:443"
run_preflight "$D" --target 10.200.5.5:443
expect "a failed address-pool query reports overlap as not checked" 0 "WARN  Could not read Docker's networks or address pools" "No Docker subnet overlaps"

reset_stubs
export STUB_NETWORKS="bridge=172.17.0.0/16 pick-connector_default=10.66.0.0/16"
export STUB_ROUTES='blackhole 10.66.0.0/16 proto static\nunreachable 10.77.0.0/16\n'
run_preflight "$D"
expect "a blackhole route is parsed by its prefix, not its type" 1 "FAIL  Docker network pick-connector_default \(10.66.0.0/16\) overlaps the host route 10.66.0.0/16"

reset_stubs
if real_timeout="$(type -P timeout || type -P gtimeout)"; then
    mkdir -p "$WORK/realtimeout" && ln -sf "$real_timeout" "$WORK/realtimeout/timeout"
    export STUB_DOCKER_HANG=1 PREFLIGHT_DOCKER_SECONDS=2
    start=$SECONDS
    run_preflight "$WORK/realtimeout:$D"
    expect "a wedged Docker daemon fails fast instead of hanging" 1 "FAIL  The Docker daemon did not answer within 2 seconds"
    if ((SECONDS - start < 15)); then report "the wedged-daemon run finished within 15 seconds" ok; else report "the wedged-daemon run finished within 15 seconds ($((SECONDS - start))s)" bad; fi
else
    printf 'skip - wedged-daemon case (no timeout or gtimeout on this machine)\n'
fi

# --- Usage ----------------------------------------------------------------------

reset_stubs
run_preflight "$D" --target 'x;id:80'
expect "a target with shell metacharacters is rejected" 2 "needs host:port"

reset_stubs
run_preflight "$D" --bogus
expect "an unknown option is a usage error" 2 "unknown option"

if ((fail)); then
    printf '\nSome preflight tests failed.\n'
    exit 1
fi
printf '\nAll preflight tests passed.\n'
