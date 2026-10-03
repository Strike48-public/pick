#!/usr/bin/env bash
# preflight.sh - Check a host before installing the Pick connector with Docker.
#
# Usage:
#   ./preflight.sh [options]
#
# Options:
#   --studio <host>       Studio hostname or URL. Default: read STRIKE48_API_URL
#                         from ./.env when that file exists.
#   --auth <host>         Strike48 authentication hostname (Strike48 gives you it).
#   --resolve <name>      An internal hostname the connector must resolve.
#                         Repeat for more than one.
#   --target <host:port>  A known-live target and an open TCP port on it.
#                         Repeat for more than one.
#   --discovery           You plan mDNS, SSDP, ARP, packet capture or Wi-Fi
#                         scans, which need host networking on a Linux host.
#   --container <name>    Container to inspect. Default: pick-connector.
#   --env-file <path>     Default: ./.env
#   -h, --help            Show this help.
#
# Every check prints PASS, WARN, FAIL or SKIP. A WARN or FAIL is followed by a
# plain-language fix. The script changes nothing on the host.
#
# When .env exists, it checks that the required values are filled in and
# shaped correctly, and takes the Studio hostname from STRIKE48_API_URL. It
# never prints a value from .env: messages name keys only, and the Studio
# hostname is the one value from that file that appears in the output.
#
# Exit codes:
#   0 - no check failed (warnings allowed)
#   1 - one or more checks failed
#   2 - usage error

set -euo pipefail

readonly COMPOSE_MIN="2.3.3" # older Compose rejects the file's top-level `name:`
readonly ENGINE_TESTED_MAJOR=25
readonly DISK_MIN_KB=$((8 * 1024 * 1024))
readonly PROBE_SECONDS=5
# A wedged Docker daemon must not hang preflight. Overridable for the tests.
readonly DOCKER_SECONDS="${PREFLIGHT_DOCKER_SECONDS:-20}"
readonly TIMED_OUT=124
# Overridable so preflight.test.sh can supply its own.
readonly RESOLV_CONF="${PREFLIGHT_RESOLV_CONF:-/etc/resolv.conf}"
# Resolvers that cannot answer for internal names.
readonly PUBLIC_RESOLVERS=" 8.8.8.8 8.8.4.4 1.1.1.1 1.0.0.1 9.9.9.9 149.112.112.112 208.67.222.222 208.67.220.220 "

STUDIO=""
AUTH=""
RESOLVE_NAMES=()
TARGETS=()
DISCOVERY=false
CONTAINER="pick-connector"
ENV_FILE="./.env"

PASSES=0
WARNS=0
FAILS=0
DOCKER_OK=false
DOCKER_OS=""
CONTAINER_STATE=""
TARGET_IPS=()

# Every docker call in this script goes through this function, so each one is
# bounded by DOCKER_SECONDS when the timeout command exists. `type -P` finds the
# binary and ignores this function.
docker() {
    local bin
    bin="$(type -P docker)" || return 127
    if type -P timeout >/dev/null; then
        timeout "$DOCKER_SECONDS" "$bin" "$@"
    else
        "$bin" "$@"
    fi
}

usage() {
    sed -n '2,/^$/{s/^# \{0,1\}//;p;}' "${BASH_SOURCE[0]}"
}

# --- Output -------------------------------------------------------------------

report_pass() {
    printf 'PASS  %s\n' "$1"
    PASSES=$((PASSES + 1))
}

report_warn() {
    printf 'WARN  %s\n      Fix: %s\n' "$1" "$2"
    WARNS=$((WARNS + 1))
}

report_fail() {
    printf 'FAIL  %s\n      Fix: %s\n' "$1" "$2"
    FAILS=$((FAILS + 1))
}

report_skip() {
    printf 'SKIP  %s\n' "$1"
}

section() {
    printf '\n== %s\n' "$1"
}

# --- Input validation -----------------------------------------------------------

# Hostnames and addresses end up inside probe commands, so accept only the
# characters a hostname or IP literal can contain.
valid_host() {
    [[ "$1" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]
}

valid_port() {
    [[ "$1" =~ ^[0-9]{1,5}$ ]] && (($1 >= 1 && $1 <= 65535))
}

# Reduce "https://studio.example.com:443/path" to "studio.example.com".
host_from_url() {
    local h="$1"
    h="${h#*://}"
    h="${h%%/*}"
    h="${h%%:*}"
    printf '%s' "$h"
}

need_value() {
    if [[ $# -lt 2 || -z "$2" ]]; then
        printf 'preflight: %s needs a value\n' "$1" >&2
        exit 2
    fi
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --studio)
                need_value "$@"
                STUDIO="$(host_from_url "$2")"
                shift 2
                ;;
            --auth)
                need_value "$@"
                AUTH="$(host_from_url "$2")"
                shift 2
                ;;
            --resolve)
                need_value "$@"
                RESOLVE_NAMES+=("$2")
                shift 2
                ;;
            --target)
                need_value "$@"
                TARGETS+=("$2")
                shift 2
                ;;
            --discovery)
                DISCOVERY=true
                shift
                ;;
            --container)
                need_value "$@"
                CONTAINER="$2"
                shift 2
                ;;
            --env-file)
                need_value "$@"
                ENV_FILE="$2"
                shift 2
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                printf 'preflight: unknown option %s (see --help)\n' "$1" >&2
                exit 2
                ;;
        esac
    done
    validate_args
}

validate_args() {
    local item
    for item in "$STUDIO" "$AUTH"; do
        if [[ -n "$item" ]] && ! valid_host "$item"; then
            printf 'preflight: %s is not a valid hostname\n' "$item" >&2
            exit 2
        fi
    done
    for item in "${RESOLVE_NAMES[@]+"${RESOLVE_NAMES[@]}"}"; do
        valid_host "$item" || {
            printf 'preflight: %s is not a valid hostname\n' "$item" >&2
            exit 2
        }
    done
    for item in "${TARGETS[@]+"${TARGETS[@]}"}"; do
        if ! valid_host "${item%:*}" || ! valid_port "${item##*:}" || [[ "$item" != *:* ]]; then
            printf 'preflight: --target needs host:port, got %s\n' "$item" >&2
            exit 2
        fi
    done
    valid_host "$CONTAINER" || {
        printf 'preflight: bad container name %s\n' "$CONTAINER" >&2
        exit 2
    }
}

# env_value <key>: the value of an uncommented key in .env, quotes stripped.
# Returns 1 when the key is absent or commented out. Values stay in memory and
# are never printed.
#
# Parsed the way Compose reads .env: Windows line endings, an optional
# `export ` prefix, single or double quotes, and a ` #` comment after an
# unquoted value.
env_value() {
    local line
    line="$(grep -E "^[[:space:]]*(export[[:space:]]+)?$1[[:space:]]*=" "$ENV_FILE" | tail -n 1 || true)"
    [[ -n "$line" ]] || return 1
    line="${line#*=}"
    line="${line#"${line%%[![:space:]]*}"}"
    if [[ "$line" == \"*\"* ]]; then
        line="${line#\"}"
        line="${line%%\"*}"
    elif [[ "$line" == \'*\'* ]]; then
        line="${line#\'}"
        line="${line%%\'*}"
    else
        # Trimming trailing whitespace also removes a Windows \r.
        line="${line%%[[:space:]]#*}"
        line="${line%"${line##*[![:space:]]}"}"
    fi
    printf '%s' "$line"
}

studio_from_env() {
    local host
    [[ -f "$ENV_FILE" ]] || return 0
    host="$(host_from_url "$(env_value STRIKE48_API_URL || true)")"
    if [[ -n "$host" ]] && valid_host "$host"; then
        STUDIO="$host"
    fi
}

# --- Version and CIDR helpers ---------------------------------------------------

# version_lt A B: true when dotted version A is older than B.
version_lt() {
    [[ "$1" != "$2" ]] && [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" == "$1" ]]
}

ip_to_int() {
    local a b c d
    [[ "$1" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
    a="${BASH_REMATCH[1]}" b="${BASH_REMATCH[2]}" c="${BASH_REMATCH[3]}" d="${BASH_REMATCH[4]}"
    ((a < 256 && b < 256 && c < 256 && d < 256)) || return 1
    printf '%d' $(((a << 24) | (b << 16) | (c << 8) | d))
}

prefix_mask() {
    if (($1 == 0)); then printf '0'; else printf '%d' $(((0xFFFFFFFF << (32 - $1)) & 0xFFFFFFFF)); fi
}

# cidrs_overlap A B: true when two IPv4 CIDRs (or bare addresses) share any address.
cidrs_overlap() {
    local n1 n2 l1 l2 len mask
    n1="$(ip_to_int "${1%/*}")" || return 1
    n2="$(ip_to_int "${2%/*}")" || return 1
    l1=32 l2=32
    [[ "$1" == */* ]] && l1="${1#*/}"
    [[ "$2" == */* ]] && l2="${2#*/}"
    len=$((l1 < l2 ? l1 : l2))
    mask="$(prefix_mask "$len")"
    (((n1 & mask) == (n2 & mask)))
}

# --- Host and Docker checks -----------------------------------------------------

check_host_os() {
    local os
    os="$(uname -s)"
    if [[ "$os" != "Linux" ]]; then
        report_warn "This host runs $os, so Docker runs inside a virtual machine here" \
            "Docker on Windows or macOS reaches the network by TCP only: ICMP, ARP, mDNS, packet capture and Wi-Fi scans do not work. On a laptop, use the native Pick app. For full discovery, use a Linux server on the network you are scanning."
    elif grep -qi microsoft /proc/version 2>/dev/null; then
        report_warn "This host is WSL, a Linux virtual machine inside Windows" \
            "WSL sits behind Windows NAT, so local discovery does not work. Use a Linux server on the network you are scanning, or the native Pick app for Windows."
    else
        report_pass "Host operating system is Linux"
    fi
}

check_docker_daemon() {
    local err rc=0
    if ! type -P docker >/dev/null; then
        report_fail "Docker is not installed" \
            "Install Docker Engine for your distribution from https://docs.docker.com/engine/install/ (step 0 of the install guide)."
        return
    fi
    err="$(docker info --format '{{.ServerVersion}}' 2>&1 >/dev/null)" || rc=$?
    if ((rc != 0)); then
        if ((rc == TIMED_OUT)); then
            report_fail "The Docker daemon did not answer within ${DOCKER_SECONDS} seconds" \
                "Restart it with: sudo systemctl restart docker. Restarting stops every container on this host."
        elif [[ "$err" == *"permission denied"* ]]; then
            report_fail "Your user cannot use Docker (permission denied)" \
                "Run: sudo usermod -aG docker \$USER, then log out and back in."
        else
            report_fail "Docker is installed but the Docker daemon is not reachable" \
                "Start it with: sudo systemctl enable --now docker"
        fi
        return
    fi
    DOCKER_OK=true
    DOCKER_OS="$(docker info --format '{{.OperatingSystem}}' 2>/dev/null || true)"
    report_pass "Docker daemon is running and your user can use it"
}

check_docker_flavour() {
    local version major
    version="$(docker info --format '{{.ServerVersion}}' 2>/dev/null || true)"
    if [[ "$DOCKER_OS" == *"Docker Desktop"* ]]; then
        report_warn "Docker Desktop $version detected, not Docker Engine" \
            "Docker Desktop's host networking is TCP and UDP only, so ICMP, ARP, mDNS and Wi-Fi scans cannot reach your network. On a laptop use the native Pick app; for full discovery use Docker Engine on a Linux server."
    else
        report_pass "Docker Engine $version ($DOCKER_OS)"
    fi
    major="${version%%.*}"
    if [[ "$major" =~ ^[0-9]+$ ]] && ((major < ENGINE_TESTED_MAJOR)); then
        report_warn "Docker Engine $version is older than $ENGINE_TESTED_MAJOR.0" \
            "Upgrade Docker Engine by following https://docs.docker.com/engine/install/ for your distribution. The install guide was tested with 29.x."
    fi
}

check_compose() {
    local version
    if ! version="$(docker compose version --short 2>/dev/null)"; then
        if command -v docker-compose >/dev/null 2>&1; then
            report_fail "Only the old docker-compose 1.x command is installed" \
                "Install the Compose v2 plugin (package docker-compose-plugin), then use 'docker compose' with a space."
        else
            report_fail "The Docker Compose plugin is not installed" \
                "Install the Compose v2 plugin (package docker-compose-plugin) from Docker's repository."
        fi
        return
    fi
    version="${version#v}"
    if version_lt "$version" "$COMPOSE_MIN"; then
        report_fail "Docker Compose $version is older than $COMPOSE_MIN and cannot read the connector's compose file" \
            "Upgrade the docker-compose-plugin package. Older versions stop with 'Additional property name is not allowed'."
    else
        report_pass "Docker Compose $version"
    fi
}

check_architecture() {
    local arch
    arch="$(docker info --format '{{.Architecture}}' 2>/dev/null || uname -m)"
    case "$arch" in
        x86_64 | amd64 | aarch64 | arm64) report_pass "Architecture $arch is supported" ;;
        *) report_fail "Architecture $arch is not supported" \
            "The image is published for linux/amd64 and linux/arm64 only. Use a host with one of those." ;;
    esac
}

check_disk() {
    local root avail
    root="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
    if [[ -z "$root" ]] || ! avail="$(df -Pk "$root" 2>/dev/null | awk 'NR==2 {print $4}')" || [[ -z "$avail" ]]; then
        report_skip "Free disk space (cannot read Docker's data directory from this host)"
        return
    fi
    if ((avail < DISK_MIN_KB)); then
        report_warn "Only $((avail / 1024 / 1024)) GB free under $root" \
            "The image needs about 8 GB free. Free space with 'docker system prune' or grow the disk."
    else
        report_pass "$((avail / 1024 / 1024)) GB free under $root"
    fi
}

check_clock() {
    local synced
    if ! command -v timedatectl >/dev/null 2>&1; then
        report_skip "Clock sync (timedatectl not available)"
        return
    fi
    synced="$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"
    if [[ "$synced" == "yes" ]]; then
        report_pass "System clock is synchronised"
    else
        report_warn "System clock is not synchronised" \
            "Enable time sync with: sudo timedatectl set-ntp true. A drifted clock makes authentication fail."
    fi
}

# --- Egress ---------------------------------------------------------------------

# Explain a curl exit code in terms a first-time user can act on.
curl_reason() {
    case "$1" in
        5) printf 'the proxy name did not resolve' ;;
        6) printf 'the hostname did not resolve' ;;
        7) printf 'the connection was refused' ;;
        28) printf 'the connection timed out' ;;
        35 | 60) printf 'the TLS certificate was not trusted' ;;
        *) printf 'curl exited with code %s' "$1" ;;
    esac
}

curl_fix() {
    case "$1" in
        6) printf 'Check the hostname for typos and that this host can resolve public names.' ;;
        35 | 60) printf 'A TLS-inspecting proxy is likely re-signing traffic. Follow "Corporate proxy and private CA" in the install guide. Do not turn off certificate checks.' ;;
        *) printf 'Allow outbound TCP 443 from this host to %s. If you must use a proxy, set HTTPS_PROXY in your shell and in .env.' "$2" ;;
    esac
}

# check_egress <host> <purpose> <fail|warn>
check_egress() {
    local host="$1" purpose="$2" level="$3" code rc=0
    code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "https://$host/" 2>/dev/null)" || rc=$?
    if ((rc == 0)); then
        report_pass "Outbound 443 to $host ($purpose) answered HTTP $code"
        return
    fi
    if [[ "$level" == "fail" ]]; then
        report_fail "Outbound 443 to $host ($purpose): $(curl_reason "$rc")" "$(curl_fix "$rc" "$host")"
    else
        report_warn "Outbound 443 to $host ($purpose): $(curl_reason "$rc")" "$(curl_fix "$rc" "$host")"
    fi
}

check_egress_all() {
    if [[ -n "$STUDIO" ]]; then
        check_egress "$STUDIO" "Studio" fail
    else
        report_skip "Studio egress (pass --studio <host>, or run from the folder with your .env)"
    fi
    if [[ -n "$AUTH" ]]; then
        check_egress "$AUTH" "authentication" fail
    else
        report_skip "Authentication egress (pass --auth <host>; Strike48 gives you this hostname)"
    fi
    check_egress ghcr.io "image registry" fail
    check_egress pkg-containers.githubusercontent.com "image layers" fail
    check_egress github.com "release downloads and nuclei templates" warn
}

# --- Container state ------------------------------------------------------------

load_container_state() {
    $DOCKER_OK || return 0
    CONTAINER_STATE="$(docker inspect "$CONTAINER" --format '{{.State.Status}}' 2>/dev/null || true)"
}

container_running() {
    [[ "$CONTAINER_STATE" == "running" ]]
}

check_network_mode() {
    local mode
    if [[ -z "$CONTAINER_STATE" ]]; then
        if $DOCKER_OK && $DISCOVERY; then
            report_warn "No $CONTAINER container yet, and you plan discovery scans" \
                "Discovery needs host networking. Create docker-compose.override.yml with 'network_mode: host' before 'docker compose up' (see \"Enable host networking\" in the install guide)."
        else
            report_skip "Network mode (no $CONTAINER container yet; run preflight again after 'docker compose up')"
        fi
        return
    fi
    mode="$(docker inspect "$CONTAINER" --format '{{.HostConfig.NetworkMode}}' 2>/dev/null || true)"
    if [[ "$mode" == "host" ]]; then
        report_pass "Container $CONTAINER uses host networking"
    elif $DISCOVERY; then
        report_fail "Container $CONTAINER is on the bridge network ($mode), which discovery scans cannot cross" \
            "Add 'network_mode: host' for the pick service in docker-compose.override.yml, then run 'docker compose up -d'. Only do this on a Linux host dedicated to the connector."
    else
        report_pass "Container $CONTAINER is on the bridge network ($mode): fine for TCP and UDP scans of routed hosts"
    fi
}

# --- .env -----------------------------------------------------------------------

readonly UUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
readonly ENV_EDIT="Open .env in an editor (nano .env) and fill in"
# The exact example values in .env.example. Matched whole, so a real hostname
# that merely contains example.com is not mistaken for one.
readonly ENV_PLACEHOLDERS="wss://studio.example.com https://studio.example.com/ 00000000-0000-0000-0000-000000000000"

# Every message names keys only, never a value from .env.
check_env_required() {
    local key value bad=0
    for key in STRIKE48_HOST STRIKE48_API_URL STRIKE48_TENANT STRIKE48_INSTANCE_ID; do
        if ! value="$(env_value "$key")" || [[ -z "$value" ]]; then
            report_fail "$key is missing or empty in .env" "$ENV_EDIT $key."
            bad=1
        elif [[ " $ENV_PLACEHOLDERS " == *" $value "* ]]; then
            report_fail "$key in .env still has the example value" "$ENV_EDIT your own $key."
            bad=1
        fi
    done
    return "$bad"
}

check_env_shapes() {
    local host tenant
    host="$(env_value STRIKE48_HOST || true)"
    if [[ "$host" != wss://* ]]; then
        report_fail "STRIKE48_HOST in .env does not start with wss://" \
            "Use your Studio hostname with wss:// in place of https://, for example wss://studio.example.com"
    elif [[ "${host#wss://}" == *:* || "${host#wss://}" == */?* ]]; then
        report_fail "STRIKE48_HOST in .env has a port or a path" \
            "Use wss:// and the hostname only. Studio is reached on 443."
    fi
    tenant="$(env_value STRIKE48_TENANT || true)"
    if ! [[ "$tenant" =~ $UUID_RE ]]; then
        report_warn "STRIKE48_TENANT in .env is not shaped like a UUID" \
            "Use the tenant UUID from Strike48 or from the Tenant badge on Studio's Gateways page, not the tenant name."
    fi
}

check_env_optional() {
    local key value
    if value="$(env_value STRIKE48_REGISTRATION_TOKEN)" && [[ -z "$value" ]]; then
        report_fail "STRIKE48_REGISTRATION_TOKEN is set to an empty value in .env" \
            "Paste a fresh token after the = sign, or put # at the start of the line. An empty token breaks registration."
    fi
    if value="$(env_value PENTEST_ALLOW_PRIVATE_IPS)" && [[ "$value" != "true" && "$value" != "1" ]]; then
        report_warn "PENTEST_ALLOW_PRIVATE_IPS in .env is not true or 1, so the connector ignores it" \
            "Set it to true only if private ranges are in scope, or put # at the start of the line."
    fi
    for key in DISABLE_SANDBOX MATRIX_TLS_INSECURE; do
        if env_value "$key" >/dev/null; then
            report_warn "$key is set in .env, but the compose file pins it and ignores .env" \
                "Remove the $key line from .env. Do not change the pinned value."
        fi
    done
}

check_env_file() {
    if [[ ! -f "$ENV_FILE" ]]; then
        report_skip ".env checks (no $ENV_FILE here yet)"
        return
    fi
    local before=$((WARNS + FAILS))
    check_env_required && check_env_shapes
    check_env_optional
    if ((WARNS + FAILS == before)); then
        report_pass ".env has the four required values in the expected shapes"
    fi
}

# --- Names and targets ----------------------------------------------------------

# A name and a target can share an address; record each address once so the
# overlap checks do not report it twice.
add_target_ip() {
    [[ -n "$1" ]] || return 0
    [[ " ${TARGET_IPS[*]+"${TARGET_IPS[*]}"} " == *" $1 "* ]] || TARGET_IPS+=("$1")
}

remember_ipv4s() {
    local ip
    while read -r ip; do
        add_target_ip "$ip"
    done < <(getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u)
}

# Name the resolvers this host uses, and call out public ones.
describe_resolvers() {
    local servers="" s public="" list=()
    if command -v resolvectl >/dev/null 2>&1; then
        servers="$(resolvectl dns 2>/dev/null | awk -F: '{print $2}' | tr '\n' ' ' || true)"
    fi
    if [[ -z "${servers// /}" && -r "$RESOLV_CONF" ]]; then
        servers="$(awk '/^nameserver/ {print $2}' "$RESOLV_CONF" | tr '\n' ' ')"
    fi
    read -r -a list <<<"$servers"
    servers="${list[*]+"${list[*]}"}"
    for s in $servers; do
        [[ "$PUBLIC_RESOLVERS" == *" $s "* ]] && public+="$s "
    done
    if [[ -n "$public" ]]; then
        printf 'This host uses public DNS (%s), which cannot answer for internal names. ' "${public% }"
    elif [[ -n "$servers" ]]; then
        printf 'This host uses DNS servers: %s. ' "$servers"
    fi
}

check_resolve() {
    local name="$1"
    if ! command -v getent >/dev/null 2>&1; then
        report_skip "Resolve $name (getent not available on this host)"
        return
    fi
    if ! getent hosts "$name" >/dev/null 2>&1; then
        report_fail "This host cannot resolve $name" \
            "$(describe_resolvers)Point the host at your internal DNS (DHCP, netplan or systemd-resolved), or give the container your internal DNS with a 'dns:' entry in docker-compose.override.yml."
        return
    fi
    remember_ipv4s "$name"
    report_pass "This host resolves $name"
    container_running || return 0
    if docker exec "$CONTAINER" getent hosts "$name" >/dev/null 2>&1; then
        report_pass "Container $CONTAINER resolves $name"
    else
        report_fail "The host resolves $name but container $CONTAINER does not" \
            "Give the container your internal DNS servers with a 'dns:' entry in docker-compose.override.yml, then run 'docker compose up -d'."
    fi
}

# tcp_probe <host> <port> [container]: 0 open, 1 closed, 2 cannot test.
tcp_probe() {
    local host="$1" port="$2" container="${3:-}"
    if [[ -n "$container" ]]; then
        docker exec "$container" timeout "$PROBE_SECONDS" bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1
        return
    fi
    command -v timeout >/dev/null 2>&1 || return 2
    timeout "$PROBE_SECONDS" bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1
}

check_target() {
    local host="${1%:*}" port="${1##*:}" rc=0
    if ip_to_int "$host" >/dev/null; then add_target_ip "$host"; else remember_ipv4s "$host"; fi
    tcp_probe "$host" "$port" || rc=$?
    if ((rc == 2)); then
        report_skip "Reach $host:$port (the timeout command is not available)"
        return
    elif ((rc != 0)); then
        report_fail "This host cannot reach $host port $port" \
            "Connect this host to the network segment or VLAN in scope and allow it through any firewall between. If Docker runs in a VM, attach the VM's adapter to that segment. If the Docker networking section below says this address is inside a Docker subnet, fix that first."
        return
    fi
    report_pass "This host reaches $host port $port"
    container_running || return 0
    if tcp_probe "$host" "$port" "$CONTAINER"; then
        report_pass "Container $CONTAINER reaches $host port $port"
    else
        report_fail "The host reaches $host port $port but container $CONTAINER does not" \
            "Check the network mode and subnet overlap results below. See \"Network requirements for scanning\" in the install guide."
    fi
}

# --- Subnet overlap -------------------------------------------------------------

DOCKER_SUBNETS=""
ADDRESS_POOLS=""

# Fill DOCKER_SUBNETS with "<network> <ipv4-subnet>" lines for every bridge
# network. Returns 1 when Docker cannot list or inspect them, so the caller
# reports the overlap check as not run rather than as clean.
load_docker_subnets() {
    local ids id out
    ids="$(docker network ls -q --filter driver=bridge 2>/dev/null)" || return 1
    for id in $ids; do
        out="$(docker network inspect "$id" --format '{{.Name}}{{range .IPAM.Config}} {{.Subnet}}{{end}}' 2>/dev/null)" || return 1
        DOCKER_SUBNETS+="$(awk '{for (i = 2; i <= NF; i++) if ($i ~ /\./) print $1, $i}' <<<"$out")"$'\n'
    done
}

# Fill ADDRESS_POOLS with the ranges the daemon allocates new networks from:
# the daemon's own pools, or Docker's built-in ones when it sets none.
load_address_pools() {
    local json i
    json="$(docker info --format '{{json .DefaultAddressPools}}' 2>/dev/null)" || return 1
    if [[ "$json" == *Base* ]]; then
        ADDRESS_POOLS="$(grep -oE '"Base":"[0-9./]+"' <<<"$json" | cut -d'"' -f4)"
    elif [[ "$json" == "null" || "$json" == "[]" ]]; then
        for i in $(seq 17 31); do ADDRESS_POOLS+="172.$i.0.0/16"$'\n'; done
        ADDRESS_POOLS+="192.168.0.0/16"
    else
        return 1
    fi
}

docker_subnets() {
    printf '%s' "$DOCKER_SUBNETS"
}

address_pools() {
    printf '%s\n' "$ADDRESS_POOLS"
}

# Lines of "<destination> <device>" for host routes Docker did not create. A
# route type such as blackhole or unreachable comes before the prefix.
host_routes() {
    command -v ip >/dev/null 2>&1 || return 0
    ip -4 route show 2>/dev/null | awk '
        $1 == "default" { next }
        { dest = $1 }
        $1 ~ /^(unicast|blackhole|unreachable|prohibit|throw|local|broadcast|multicast|anycast|nat)$/ { dest = $2 }
        dest == "default" { next }
        { dev = ""; for (i = 1; i < NF; i++) if ($i == "dev") dev = $(i + 1) }
        dev ~ /^(docker0|docker_gwbridge|br-|veth)/ { next }
        { print dest, (dev == "" ? $1 : dev) }'
}

on_host_route() {
    local dest dev
    while read -r dest dev; do
        [[ -n "$dest" ]] && cidrs_overlap "$dest" "$1" && return 0
    done < <(host_routes)
    return 1
}

readonly POOL_FIX="Set default-address-pools in /etc/docker/daemon.json to a range your network does not use, run 'sudo systemctl restart docker', then 'docker compose down' and 'docker compose up -d'. Or use host networking on a Linux host."

check_route_overlap() {
    local net subnet dest dev found=1
    while read -r net subnet; do
        while read -r dest dev; do
            [[ -n "$dest" ]] || continue
            if cidrs_overlap "$subnet" "$dest"; then
                report_fail "Docker network $net ($subnet) overlaps the host route $dest on $dev" "$POOL_FIX"
                found=0
            fi
        done < <(host_routes)
    done < <(docker_subnets)
    return "$found"
}

check_target_overlap() {
    local ip net subnet pool found=1 have_net=false
    # Compose names the network after the project in docker-compose.yml.
    [[ $'\n'"$DOCKER_SUBNETS" == *$'\n'"pick-connector_default "* ]] && have_net=true
    for ip in "${TARGET_IPS[@]+"${TARGET_IPS[@]}"}"; do
        while read -r net subnet; do
            if cidrs_overlap "$subnet" "$ip"; then
                report_fail "Target $ip is inside Docker network $net ($subnet), so traffic to it never leaves this host" "$POOL_FIX"
                found=0
            fi
        done < <(docker_subnets)
        $have_net && continue
        # Docker never allocates a pool subnet that overlaps an existing host
        # route, so a target that a host route already covers is safe.
        on_host_route "$ip" && continue
        while read -r pool; do
            if cidrs_overlap "$pool" "$ip"; then
                report_warn "Target $ip is inside Docker's address pool $pool, so the connector's network may be given a subnet that contains it" "$POOL_FIX"
                found=0
                break
            fi
        done < <(address_pools)
    done
    return "$found"
}

check_overlap() {
    local overlap=false
    if ! load_docker_subnets || ! load_address_pools; then
        report_warn "Could not read Docker's networks or address pools, so subnet overlap was not checked" \
            "Run 'docker network ls' and 'docker info' to see the error, then run preflight again."
        return
    fi
    check_route_overlap && overlap=true
    check_target_overlap && overlap=true
    $overlap && return
    if ((${#TARGET_IPS[@]} > 0)); then
        report_pass "No Docker subnet overlaps a host route or a target"
    else
        report_pass "No Docker subnet overlaps a host route (pass --target or --resolve to check targets too)"
    fi
}

# --- Main -----------------------------------------------------------------------

summary() {
    printf '\n%d passed, %d warnings, %d failed.\n' "$PASSES" "$WARNS" "$FAILS"
    if ((FAILS > 0)); then
        printf 'Fix each FAIL above, then run preflight again.\n'
        return 1
    fi
    printf 'No blocking problems found.\n'
}

main() {
    local item
    parse_args "$@"
    [[ -n "$STUDIO" ]] || studio_from_env

    section "Host and Docker"
    check_host_os
    check_docker_daemon
    if $DOCKER_OK; then
        check_docker_flavour
        check_compose
        check_architecture
        check_disk
    fi
    check_clock

    section "Configuration (.env)"
    check_env_file

    section "Outbound connections"
    check_egress_all

    load_container_state
    if ((${#RESOLVE_NAMES[@]} + ${#TARGETS[@]} > 0)); then
        section "Internal names and targets"
        for item in "${RESOLVE_NAMES[@]+"${RESOLVE_NAMES[@]}"}"; do check_resolve "$item"; done
        for item in "${TARGETS[@]+"${TARGETS[@]}"}"; do check_target "$item"; done
    fi

    if $DOCKER_OK; then
        section "Docker networking"
        check_network_mode
        check_overlap
    fi

    summary
}

main "$@"
